//! The subscription side: the link, the signed document, and the public endpoint that answers a valid token and nothing else.
use crate::{app::{bucket, App, Endpoint, Node, SigningEntry, LOCAL}, auth, crypto::{self, now}, gateway, http::Failure, mirrors, statics, usage};
use axum::{body::Body, extract::{Request, State}, http::{header::{CACHE_CONTROL, CONTENT_TYPE}, HeaderValue, Method, StatusCode}, response::Response};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use ipnet::Ipv4Net;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::{json, Value};
use std::{collections::HashSet, net::Ipv4Addr, sync::Arc};
use veilway_proto::subscription::{envelope, exchange::{self, GatewayKey}, fetch::{Op, RequestError}, link::Link, payload::PROFILES_MAX};

pub const PENDING_PLACES: i64 = 2;
pub const PENDING_LAPSE: i64 = 600;
const NODE_DEVICES_MAX: i64 = 64;
/// The shortest refresh interval a document may ask for, used while a node does not hold the device yet.
const UPDATE_SOONEST: u32 = 900;

#[derive(Clone, Debug)]
pub struct UserRow {pub id: i64, pub name: String, pub enabled: bool, pub groups: String, pub exits: String, pub quota_bytes: Option<i64>, pub quota_period: Option<String>, pub expires_at: Option<i64>, pub device_limit: i64, pub note: String, pub created: i64, pub record_id: [u8; 16], pub sub_id: String, pub token_copy: Option<Vec<u8>>, pub token_gen: i64, pub token_created: i64, pub default_exit: Option<String>, pub endpoint: Option<String>, pub proxy: bool, pub nodes: String, pub profile_order: Option<String>, pub speed_up: Option<i64>, pub speed_down: Option<i64>}

pub const USER_COLUMNS: &str = "id, name, enabled, groups, exits, quota_bytes, quota_period, expires_at, device_limit, note, created, record_id, sub_id, token_copy, token_gen, token_created, default_exit, endpoint, proxy_password is not null, nodes, profile_order, speed_up, speed_down";

impl UserRow {
	pub fn read(row: &Row) -> rusqlite::Result<Self> {
		Ok(Self {id: row.get(0)?, name: row.get(1)?, enabled: row.get(2)?, groups: row.get(3)?, exits: row.get(4)?, quota_bytes: row.get(5)?, quota_period: row.get(6)?, expires_at: row.get(7)?, device_limit: row.get(8)?, note: row.get(9)?, created: row.get(10)?, record_id: row.get::<_, Vec<u8>>(11)?.try_into().unwrap_or([0; 16]), sub_id: row.get(12)?, token_copy: row.get(13)?, token_gen: row.get(14)?, token_created: row.get(15)?, default_exit: row.get(16)?, endpoint: row.get(17)?, proxy: row.get(18)?, nodes: row.get(19)?, profile_order: row.get(20)?, speed_up: row.get(21)?, speed_down: row.get(22)?})
	}
	pub fn load(db: &Connection, id: i64) -> rusqlite::Result<Self> {db.query_row(&format!("select {USER_COLUMNS} from users where id = ?"), [id], Self::read)}
}

#[derive(Clone, Debug)]
pub struct DeviceRow {pub id: i64, pub user_id: i64, pub name: String, pub public_key: String, pub secret_hash: Vec<u8>, pub address: String, pub transport_secret: Vec<u8>, pub private_key: Option<Vec<u8>>, pub state: String, pub token_gen: i64, pub created: i64, pub confirmed_at: Option<i64>, pub last_seen: Option<i64>}

/// The `address` of a row is the device's address at node 1.
pub const DEVICE_COLUMNS: &str = "id, user_id, name, public_key, secret_hash, (select address from device_addresses where node_id = 1 and device_id = devices.id), transport_secret, private_key, state, token_gen, created, confirmed_at, last_seen";

impl DeviceRow {
	pub fn read(row: &Row) -> rusqlite::Result<Self> {
		Ok(Self {id: row.get(0)?, user_id: row.get(1)?, name: row.get(2)?, public_key: row.get(3)?, secret_hash: row.get(4)?, address: row.get(5)?, transport_secret: row.get(6)?, private_key: row.get(7)?, state: row.get(8)?, token_gen: row.get(9)?, created: row.get(10)?, confirmed_at: row.get(11)?, last_seen: row.get(12)?})
	}
	pub fn for_user(db: &Connection, user: i64) -> rusqlite::Result<Vec<Self>> {
		db.prepare(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? order by id"))?.query_map([user], Self::read)?.collect()
	}
}

/// Drops the pending devices that were not confirmed within the lapse. Pending devices are never pushed to the node.
pub fn expire_pending(db: &Connection, at: i64) -> rusqlite::Result<usize> {db.execute("delete from devices where state = 'pending' and created < ?", [at - PENDING_LAPSE])}

/// Removes the confirmed devices that have not refreshed for `days` days, the setting `idle_device_days`, and says how many went. A device whose key the panel made has no endpoint to refresh from and stays.
pub fn forget_idle(db: &Connection, at: i64, days: u32) -> rusqlite::Result<usize> {
	if days == 0 {return Ok(0)}
	let gone = db.execute("delete from devices where state = 'enrolled' and private_key is null and coalesce(last_seen, confirmed_at, created) < ?", [at - i64::from(days) * 86_400])?;
	if gone > 0 {crate::db::audit(db, "panel", "upkeep", "device.idle", "devices", &format!("{gone} devices removed after {days} days without a refresh"))}
	Ok(gone)
}

/// The lowest free host address of a node's pool, leaving the first one to the gateway.
pub fn allocate(db: &Connection, node: Node) -> Option<String> {
	let pool: Ipv4Net = db.query_row("select pool_v4 from nodes where id = ?", [node.0], |row| row.get::<_, String>(0)).ok()?.parse().ok()?;
	let taken: HashSet<String> = db.prepare("select address from device_addresses where node_id = ?").ok()?.query_map([node.0], |row| row.get(0)).ok()?.filter_map(Result::ok).collect();
	pool.hosts().skip(1).map(|address| address.to_string()).find(|address| !taken.contains(address))
}

/// The IPv4 range of a `veilway` inbound, from its `address` list (`10.9.0.1/24`: the gateway and the prefix). IPv6 entries are not read.
pub fn range_of(inbound: &Value) -> Option<Ipv4Net> {inbound["address"].as_array()?.iter().find_map(|text| text.as_str()?.parse().ok())}

/// The address a device of the pool has inside an inbound's range. A range that holds the stored address uses it. Any other range that does not overlap the pool gives the address at the same offset from its network, unless that falls outside it or on its network, broadcast or gateway address. A stored address outside the pool, or a range that overlaps the pool without holding the address, gets none. Nothing is stored: the node and the documents compute it alike, and stored addresses are unique, so each range's addresses are too.
pub fn address_in(pool: Ipv4Net, range: Ipv4Net, stored: Ipv4Addr) -> Option<Ipv4Addr> {
	if range.contains(&stored) {return Some(stored)}
	if !pool.contains(&stored) || range.contains(&pool.network()) || pool.contains(&range.network()) {return None}
	let found = Ipv4Addr::from(u32::from(range.network()).checked_add(u32::from(stored) - u32::from(pool.network()))?);
	(range.contains(&found) && found != range.network() && found != range.broadcast() && found != range.addr()).then_some(found)
}

/// The stored address of a device and its address in each other `veilway` or `wireguard` inbound of the node's config, at most one per inbound. An address in `taken` (another device's stored address, from a pool used before, or a link's) is skipped, since the node refuses a config where two peers share one.
pub fn node_addresses(pool: &str, inbounds: &[Value], stored: &str, taken: &HashSet<String>) -> Vec<String> {
	let (Ok(pool), Ok(stored_ip)) = (pool.parse::<Ipv4Net>(), stored.parse::<Ipv4Addr>()) else {return vec![stored.to_string()]};
	let mut out = vec![stored.to_string()];
	for found in inbounds.iter().filter(|inbound| inbound["type"] == "veilway" || inbound["type"] == "wireguard").filter_map(range_of).filter_map(|range| address_in(pool, range, stored_ip)).map(|found| found.to_string()) {if !out.contains(&found) && !taken.contains(&found) {out.push(found)}}
	out
}

pub struct LinkOut {pub veilway: String, pub https: String}

/// The link of a token, built from the text of the format and read back through the format's own parser, so a link the client would refuse is never handed out. A plain endpoint gives the `sub-plain` form and never a pin.
pub fn link(endpoint: &Endpoint, key: &SigningEntry, gateway: &GatewayKey, token: &[u8; 16]) -> Result<LinkOut, String> {
	let (scheme, address) = match (endpoint.url.strip_prefix("https://"), endpoint.url.strip_prefix("http://")) {(Some(rest), _) => ("sub", rest), (_, Some(rest)) => ("sub-plain", rest), _ => return Err("the endpoint URL is not an https or http URL".into())};
	if !address.contains('/') || address.contains('#') {return Err("the endpoint URL needs a path and no fragment".into())}
	let pin = endpoint.pins.first().map(|pin| STANDARD.decode(pin).map(|bytes| format!(".{}", URL_SAFE_NO_PAD.encode(bytes))).map_err(|_| "an endpoint pin is not base64")).transpose()?.unwrap_or_default();
	let text = format!("veilway://{scheme}/{address}#v1.{}.{}.{}{pin}", URL_SAFE_NO_PAD.encode(key.public()), URL_SAFE_NO_PAD.encode(gateway.link()), URL_SAFE_NO_PAD.encode(token));
	match Link::parse(&text).map_err(|error| error.to_string())? {Link::Native(native) => Ok(LinkOut {veilway: native.veilway(), https: native.https()}), _ => Err("the link did not read as a native one".into())}
}

fn sign(entry: &SigningEntry, payload: &Value) -> String {
	let pair = entry.pair();
	envelope::seal(&entry.proto(), &serde_json::to_vec(payload).unwrap_or_default(), |message| pair.sign(message).as_ref().try_into().expect("64 bytes"))
}

pub fn refusal(entry: &SigningEntry, subscription_id: &str, reason: &str) -> String {sign(entry, &json!({"v": 1, "subscription_id": subscription_id, "issued_at": now(), "refusal": reason}))}

/// Whether the user's `nodes` setting, `"all"` or a list of node ids, lets them use the node.
pub fn allowed(nodes: &str, node: Node) -> bool {
	let nodes: Value = serde_json::from_str(nodes).unwrap_or(json!("all"));
	nodes == json!("all") || nodes.as_array().is_some_and(|list| list.iter().any(|id| id.as_i64() == Some(node.0)))
}

/// How many profiles each other node has cached, by node id: what its last sync wrote. A node that has not synced yet has none.
fn cached(db: &Connection) -> rusqlite::Result<Vec<(i64, usize)>> {
	db.prepare("select id, settings from nodes where id != ?")?.query_map([LOCAL.0], |row| Ok((row.get::<_, i64>(0)?, serde_json::from_str::<Value>(&row.get::<_, String>(1)?).ok().and_then(|cache| cache["profiles"].as_array().map(Vec::len)).unwrap_or(0))))?.collect()
}

/// The profiles a subscription holds for an account whose `nodes` setting is `nodes`: the `own` published profiles of node 1 and the cached ones of each other node the account may use. An upper bound, since a document drops a profile whose device address cannot be given.
fn held(counts: &[(i64, usize)], own: usize, nodes: &str) -> usize {own + counts.iter().filter(|(id, _)| allowed(nodes, Node(*id))).map(|(_, count)| count).sum::<usize>()}

/// The most `held` over the accounts, or over the ones that may use `node`, and 0 when there is none.
pub fn most_held(db: &Connection, own: usize, node: Option<Node>) -> rusqlite::Result<usize> {
	let (counts, lists) = (cached(db)?, db.prepare("select distinct nodes from users")?.query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?);
	Ok(lists.iter().filter(|nodes| node.is_none_or(|node| allowed(nodes, node))).map(|nodes| held(&counts, own, nodes)).max().unwrap_or(0))
}

/// The refusal for a change that would make a subscription hold `count` profiles, more than a document can.
pub fn too_many(count: usize) -> Failure {Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "too_many_profiles", format!("This would make a subscription hold {count} profiles, and a subscription holds {PROFILES_MAX} at most. Give the users fewer servers, or publish fewer profiles."))}

/// Refuses a `nodes` setting that would give an account more than `PROFILES_MAX` profiles.
pub async fn profiles_fit(app: &App, nodes: &str) -> Result<(), Failure> {
	let (own, nodes) = (app.settings().profiles.len(), nodes.to_string());
	let count = app.db.call(move |db| cached(db).map(|counts| held(&counts, own, &nodes))).await??;
	if count > PROFILES_MAX {return Err(too_many(count))}
	Ok(())
}

/// Gives each enrolled device of the user (of every user when none is named) an address in the pool of every remote node the user may use that it has none in, and raises the node's wanted revision for each, so that a document tells when the node has the device. A pool with no free address leaves the node out for that device, with a warning, and the device keeps the others. Node 1 is not touched: its address is taken when the device is made.
pub fn add_addresses(db: &Connection, user: Option<i64>) -> rusqlite::Result<()> {
	let devices: Vec<(i64, String)> = db.prepare("select devices.id, users.nodes from devices join users on users.id = devices.user_id where devices.state = 'enrolled' and (?1 is null or users.id = ?1) order by devices.id")?.query_map([user], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
	let nodes: Vec<i64> = db.prepare("select id from nodes where id != ? order by id")?.query_map([LOCAL.0], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
	for (device, allowed_nodes) in devices {
		for node in nodes.iter().filter(|node| allowed(&allowed_nodes, Node(**node))) {
			if db.query_row("select exists (select 1 from device_addresses where node_id = ? and device_id = ?)", params![node, device], |row| row.get::<_, bool>(0))? {continue}
			let Some(address) = allocate(db, Node(*node)) else {tracing::warn!("the pool of node {node} has no free address, so device {device} is left out of it"); continue};
			let rev: i64 = db.query_row("update nodes set wanted_rev = wanted_rev + 1 where id = ? returning wanted_rev", [node], |row| row.get(0))?;
			db.execute("insert into device_addresses (node_id, device_id, address, added_rev) values (?, ?, ?, ?)", params![node, device, address, rev])?;
		}
	}
	Ok(())
}

/// A list of profile ids made ready to keep: at most 64 entries, each 1 to 128 characters, repeats dropped. An id that names no profile is no error, so a profile that was removed does not stop a save.
pub fn order_checked(order: Vec<String>) -> Result<Vec<String>, Failure> {
	if order.len() > PROFILES_MAX || order.iter().any(|id| id.is_empty() || id.len() > 128) {return Err(Failure::bad("A profile order is at most 64 profile ids of 1 to 128 characters."))}
	let mut seen = HashSet::new();
	Ok(order.into_iter().filter(|id| seen.insert(id.clone())).collect())
}

/// Which document is built. The endpoint's answer lists the static mirrors and carries usage. A static file has no usage, since a host may keep every version for good. A whole document, handed out as a file or in a link, lists no static mirrors, since it has no link to derive their keys from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Form {Answer, Static, Whole}

/// A signed subscription for one device of one account. Its serial comes from the device's own counter, which the endpoint and the publisher share: the larger of the time and the last serial plus one, so no serial is signed for two bodies.
pub async fn document(app: &App, user: &UserRow, this: &DeviceRow, signing: &[SigningEntry], signer: &SigningEntry, form: Form, used: Option<&Value>, reached: Option<&Endpoint>) -> Result<String, String> {
	let keys = app.keys.as_ref().ok_or("no key file")?;
	let settings = app.settings();
	if settings.profiles.is_empty() {return Err("no profile is configured".into())}
	let user_id = user.id;
	let devices = app.db.call(move |db| DeviceRow::for_user(db, user_id)).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let secret = keys.open_secret(&user.record_id, &format!("transport_secret:{}", this.public_key), &this.transport_secret).ok_or("a transport secret does not open")?;
	let mut device = json!({"public_key": this.public_key, "addresses": [this.address], "transport_secrets": [STANDARD.encode(&secret)]});
	if let Some(sealed) = &this.private_key {device["private_key"] = json!(STANDARD.encode(keys.open_secret(&user.record_id, &format!("private_key:{}", this.public_key), sealed).ok_or("a private key does not open")?));}
	let groups: Vec<String> = serde_json::from_str(&user.groups).unwrap_or_default();
	let reaching = crate::nodecfg::reaching(&settings.published_relays, Some((user.id, groups.as_slice())));
	let (pooled, taken): (String, HashSet<String>) = app.db.call(|db| -> rusqlite::Result<_> {Ok((db.query_row("select pool_v4 from nodes where id = ?", [LOCAL.0], |row| row.get(0))?, db.prepare("select address from device_addresses where node_id = ?")?.query_map([LOCAL.0], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?))}).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let (pool, stored) = (pooled.parse::<Ipv4Net>().ok(), this.address.parse::<Ipv4Addr>().ok());
	let device_id = this.id;
	let (total, remote_nodes, waiting) = app.db.call(move |db| -> rusqlite::Result<_> {
		let rows = db.prepare("select nodes.id, nodes.name, nodes.slug, nodes.uid, nodes.pool_v4, device_addresses.address, nodes.settings, nodes.relays from nodes join device_addresses on device_addresses.node_id = nodes.id and device_addresses.device_id = ? where nodes.id != ? and nodes.applied_rev >= device_addresses.added_rev order by nodes.place, nodes.id")?.query_map(params![device_id, LOCAL.0], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?, row.get::<_, String>(7)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
		let mut nodes = Vec::new();
		for (id, name, slug, uid, pool, address, cache, relays) in rows {
			let taken: HashSet<String> = db.prepare("select address from device_addresses where node_id = ?")?.query_map([id], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
			nodes.push((id, name, slug, uid, pool, address, cache, serde_json::from_str::<Vec<crate::nodecfg::Relay>>(&relays).unwrap_or_default(), taken));
		}
		// A node that does not hold the device yet is left out of this document, and the app is asked back as soon as a document allows, while that node was seen within the hour: one that is down for longer would keep every new device at the shortest interval.
		let waiting: bool = db.query_row("select exists (select 1 from device_addresses join nodes on nodes.id = device_addresses.node_id where device_addresses.device_id = ? and nodes.id != ? and nodes.applied_rev < device_addresses.added_rev and nodes.last_seen > ?)", params![device_id, LOCAL.0, now() - 3600], |row| row.get(0))?;
		Ok((usage::across(db, user_id, now())?, nodes, waiting))
	}).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let mut profiles: Vec<Value> = settings.profiles.iter().cloned().filter_map(|mut profile| {
		// A relays-only inbound is switched on at once, before the next publish: the node's own addresses of an older snapshot are dropped here, and a profile no relay reaches this account with is not given.
		let only = profile["id"].as_str().and_then(|id| settings.relay_profiles.get(id)).is_some_and(|tag| crate::nodecfg::relays_only(&settings, tag)) || crate::xray::addresses(&profile).iter().any(|host| host == crate::nodecfg::NO_ADDRESS);
		if let Some(tag) = profile["id"].as_str().and_then(|id| settings.relay_profiles.get(id)) {crate::nodecfg::carry(&mut profile, tag, &reaching, only);}
		if only && profile["transports"].as_array().is_none_or(Vec::is_empty) {return None}
		let found = profile["id"].as_str().and_then(|id| settings.relay_profiles.get(id)).and_then(|tag| settings.inbound_ranges.get(tag)).and_then(|range| range.parse().ok());
		// A profile of an inbound whose range is known carries the device's one address inside it, and is left out when it has none. Any other profile carries the stored address.
		let mut own = device.clone();
		if let (Some(range), Some(pool), Some(stored)) = (found, pool, stored) {own["addresses"] = json!([address_in(pool, range, stored).filter(|found| *found == stored || !taken.contains(&found.to_string()))?.to_string()]);}
		profile["device"] = own;
		Some(profile)
	}).collect();
	let mut remote: Vec<Value> = Vec::new();
	for (_, node_name, slug, uid, pool, address, cache, relays, taken) in remote_nodes.into_iter().filter(|row| allowed(&user.nodes, Node(row.0))) {
		let (Ok(pool), Ok(stored)) = (pool.parse::<Ipv4Net>(), address.parse::<Ipv4Addr>()) else {continue};
		let transport = STANDARD.encode(crypto::node_secret(crypto::NODE_TRANSPORT_SALT, &uid, &secret));
		// A remote node's relays reach its own profiles for the accounts they name, as node 1's reach its profiles: the node's cache holds the profiles without them.
		let reaching = crate::nodecfg::reaching(&relays, Some((user.id, groups.as_slice())));
		for entry in serde_json::from_str::<Value>(&cache).ok().and_then(|cache| cache["profiles"].as_array().cloned()).unwrap_or_default() {
			let mut own = device.clone();
			own["addresses"] = json!([stored.to_string()]);
			own["transport_secrets"] = json!([&transport]);
			if let Some(range) = entry["range"].as_str().and_then(|range| range.parse::<Ipv4Net>().ok()) {
				let Some(found) = address_in(pool, range, stored).filter(|found| *found == stored || !taken.contains(&found.to_string())) else {continue};
				own["addresses"] = json!([found.to_string()]);
			}
			let mut profile = entry["profile"].clone();
			crate::nodecfg::carry(&mut profile, entry["inbound"].as_str().unwrap_or_default(), &reaching, false);
			profile["id"] = json!(format!("{slug}-{}", profile["id"].as_str().unwrap_or_default()));
			profile["name"] = json!(format!("{node_name} · {}", profile["name"].as_str().unwrap_or_default()));
			profile["device"] = own;
			remote.push(profile);
		}
	}
	let room = PROFILES_MAX.saturating_sub(profiles.len());
	if remote.len() > room {tracing::warn!("user {}: {} profiles of other nodes are left out, a document holds {PROFILES_MAX} profiles at most", user.name, remote.len() - room)}
	profiles.extend(remote.into_iter().take(room));
	let (own_order, global_order) = (user.profile_order.as_deref().and_then(|text| serde_json::from_str::<Vec<String>>(text).ok()).unwrap_or_default(), &settings.profile_order);
	// The account's own order first, then the global one, then the rest as they came: the sort is stable.
	profiles.sort_by_key(|profile| {let id = profile["id"].as_str().unwrap_or_default(); own_order.iter().position(|listed| listed == id).or_else(|| global_order.iter().position(|listed| listed == id).map(|at| at + own_order.len())).unwrap_or(own_order.len() + global_order.len())});
	let profiles = app.names.resolve(profiles).await;
	if profiles.is_empty() {return Err("no profile has an address that resolves".into())}
	let at = now();
	let (floor, device_id) = (at * 1000 + (crypto::random::<2>()[0] as i64 % 250), this.id);
	let serial: i64 = app.db.call(move |db| db.query_row("update devices set last_serial = max(?, last_serial + 1) where id = ? returning last_serial", params![floor, device_id], |row| row.get::<_, i64>(0))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let total = total.map(|across| json!({"used_bytes": across.total_bytes, "period_start": usage::bounds(user.quota_period.as_deref(), at).0}));
	let used = total.as_ref().or(used);
	let mut payload = json!({
		"v": 1, "subscription_id": user.sub_id, "serial": serial, "issued_at": at, "expires_at": at + i64::from(settings.document_days) * 86_400,
		"signing_keys": signing.iter().map(|entry| STANDARD.encode(entry.public())).collect::<Vec<_>>(),
		"provider": {"name": settings.provider_name}, "update_interval": if waiting {UPDATE_SOONEST} else {settings.update_interval}, "profiles": profiles,
		"devices": devices.iter().map(|other| json!({"name": other.name, "enrolled_at": other.confirmed_at.unwrap_or(other.created), "this": other.id == this.id, "pending": other.state == "pending"})).collect::<Vec<_>>(),
	});
	if form != Form::Static {payload["usage"] = json!({"used_bytes": used.and_then(|user| user.get("used_bytes")).and_then(Value::as_u64).unwrap_or(0), "quota_bytes": user.quota_bytes.unwrap_or(0), "period": user.quota_period.as_deref().unwrap_or("none"), "period_start": used.and_then(|user| user.get("period_start")).and_then(Value::as_i64).unwrap_or(0).max(0), "expires_at": user.expires_at.unwrap_or(0), "device_limit": user.device_limit});}
	if form != Form::Whole {
		let listed = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).listed();
		if listed.is_empty() {return Err("no gateway key".into())}
		let keys: Vec<Value> = listed.iter().map(gateway::listed).collect();
		let resolved = settings.resolve(user.endpoint.as_deref(), &serde_json::from_str::<Vec<String>>(&user.groups).unwrap_or_default()).map(|(found, _)| found);
		// The pins are those of the endpoint the request reached, since that is the endpoint the client holds. The move names the endpoint the account is to use, even when it is this one. A request that reached no named endpoint, or a static file for an account whose move is pending, gets none: a list of pins is refused by a client that holds none of them, and absent it changes nothing.
		if let Some(reached) = reached.filter(|reached| !reached.pins.is_empty()) {payload["endpoint_pins"] = json!(reached.pins);}
		payload["gateway_keys"] = json!(keys);
		if let Some(resolved) = resolved {
			payload["main_endpoint"] = json!({"url": resolved.url, "gateway_keys": keys});
			if !resolved.pins.is_empty() {payload["main_endpoint"]["pins"] = json!(resolved.pins);}
		}
	}
	if !settings.refresh_mirrors.is_empty() {payload["refresh_urls"] = json!(settings.refresh_mirrors);}
	// The apps ask the user to accept these before the first connection, and again when either changes.
	let agreement: serde_json::Map<String, Value> = [("terms", &settings.terms_url), ("privacy", &settings.privacy_url)].into_iter().filter(|(_, url)| !url.is_empty()).map(|(name, url)| (name.into(), json!(url))).collect();
	if !agreement.is_empty() {payload["agreement"] = Value::Object(agreement);}
	if !settings.subscription_notices.is_empty() {
		payload["notices"] = settings.subscription_notices.iter().map(|notice| {
			let mut text: serde_json::Map<String, Value> = notice.translations.iter().map(|(tag, translated)| (tag.clone(), json!(translated))).collect();
			text.insert("default".into(), json!(notice.text));
			json!({"severity": notice.severity, "text": if notice.translations.is_empty() {json!(notice.text)} else {Value::Object(text)}})
		}).collect();
	}
	if form != Form::Whole && !settings.static_mirrors.is_empty() {payload["static_mirrors"] = json!(settings.static_mirrors);}
	Ok(sign(signer, &payload))
}

/// How long a signed refusal is reused, half of its age limit of a day, so the client always finds it young enough.
const REFUSAL_REUSE: i64 = 43_200;
const REFUSALS_MAX: usize = 100_000;

/// A signed refusal, signed once per account, reason and key and reused while it is fresh, so that a holder of a valid token cannot make the panel sign at will.
fn refusal_for(app: &App, signer: &SigningEntry, user: &UserRow, reason: &str) -> String {
	let (key, at) = ((user.id, reason.to_owned(), signer.proto().kid().bytes()), now());
	let mut cache = app.refusals.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	if let Some((_, text)) = cache.get(&key).filter(|(made, _)| at - made < REFUSAL_REUSE) {return text.clone()}
	if cache.len() >= REFUSALS_MAX {cache.retain(|_, (made, _)| at - *made < REFUSAL_REUSE)}
	let text = refusal(signer, &user.sub_id, reason);
	cache.insert(key, (at, text.clone()));
	text
}

/// The one answer for everything that is not a valid request. To a request with a valid relay mirror header it is status 599, which the mirror does not pass on.
fn unknown(app: &App, mirrored: bool) -> Response {
	let mut response = app.not_found();
	if mirrored {*response.status_mut() = StatusCode::from_u16(599).unwrap_or(StatusCode::NOT_FOUND)}
	response
}

/// Reads the body, opens it through the gateway and answers a valid request with a sealed document or refusal. Anything else answers as an unknown path. The endpoint a request reached is told by its path alone: the `sub_path` and the name of the endpoint, which the operator's web server puts after its public host and path. The Host header is never read, since it is whatever the sender or a relay says.
pub async fn endpoint(State(app): State<Arc<App>>, request: Request) -> Response {
	let post = request.method() == Method::POST;
	let (direct, headers) = (auth::source(&app, &request), request.headers().clone());
	let reached = match request.uri().path().strip_prefix(&app.cfg.sub_path).and_then(|rest| rest.strip_prefix('/')) {
		Some(name) => match app.settings.read().unwrap_or_else(|poisoned| poisoned.into_inner()).named(name).cloned() {Some(found) => Some(found), None => return unknown(&app, false)},
		None => None,
	};
	// "The body is read up to 1,073 bytes and no further": a longer one reads as nothing, and the gateway then takes it for a body of another size.
	let body = http_body_util::Limited::new(request.into_body(), exchange::REQUEST).collect().await.map(|body| body.to_bytes()).unwrap_or_default();
	let via = mirrors::check(&app, &headers, &body);
	let verified = via.as_ref().ok().and_then(Option::as_ref);
	let mirrored = verified.is_some();
	let source = verified.map_or(direct, |verified| verified.address.to_string());
	if let Some(verified) = verified {tracing::debug!("a subscription request relayed by the mirror {} from {source}", verified.name)}
	// The hop from a mirror to the panel is https, always: a proxy that says it was not is not taken as a mirror's hop.
	let admitted = post && via.is_ok() && !(mirrored && headers.get("x-forwarded-proto").is_some_and(|proto| proto != "https"));
	let at = now();
	let key_id = (body.len() == exchange::REQUEST).then(|| body[0]);
	// The keys open the body here, outside the lock: every request costs the same work, and only the window, the memory and the source's limit are taken under the lock. The limiter of the endpoint is its own, so a flood here fills nothing the admin side counts in.
	let keyring = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).keyring();
	let Some(keyring) = keyring else {return unknown(&app, mirrored)};
	let unsealed = keyring.unseal(&body);
	let opened = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).admit(unsealed, at, || admitted && app.sub_limits.hit(&format!("sub:{}", bucket(&source, 48)), 120, 60) && verified.is_none_or(|verified| mirrors::accept(&app, verified)));
	let Some(Ok(opened)) = opened else {return unknown(&app, mirrored)};
	let Some(keys) = app.keys.as_ref() else {return unknown(&app, mirrored)};
	let reply = opened.reply;
	let answer = |text: &str| match reply.seal(text.as_bytes(), &mut crypto::fill) {
		Ok(bytes) => {
			let mut response = Response::new(Body::from(bytes));
			response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
			response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
			response
		}
		Err(error) => {tracing::error!("an answer could not be sealed: {error}"); unknown(&app, mirrored)}
	};
	let (token, received) = match opened.request {
		Ok(received) => (*received.token().expose(), Some(received)),
		Err(RequestError::Malformed(token, _)) => (*token.expose(), None),
		Err(RequestError::Unreadable) => return unknown(&app, mirrored),
	};
	// One HMAC and one lookup in memory, so a request with a token that is not known costs the database nothing.
	let lookup = keys.token_lookup(&token);
	let Some(id) = app.lookups.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&lookup).copied() else {return unknown(&app, mirrored)};
	// Which gateway key and which endpoint this account used, for the switch and the move, kept at most hourly. It is written for every request with a known token, before any refusal, since a request refused as retired, disabled or expired is exactly one a switch has to count.
	let reached_name = reached.as_ref().map(|found| found.name.clone());
	let user = match app.db.call(move |db| -> rusqlite::Result<Option<UserRow>> {
		let Some(user) = UserRow::load(db, id).optional()? else {return Ok(None)};
		if let Some(key_id) = key_id {db.execute("insert into gateway_use (key_id, user_id, first_at, last_at) values (?, ?, ?, ?) on conflict (key_id, user_id) do update set last_at = excluded.last_at where excluded.last_at - gateway_use.last_at >= 3600", params![key_id, id, at, at])?;}
		if let Some(name) = &reached_name {db.execute("insert into endpoint_use (endpoint, user_id, last_at) values (?, ?, ?) on conflict (endpoint, user_id) do update set last_at = excluded.last_at where excluded.last_at - endpoint_use.last_at >= 3600", params![name, id, at])?;}
		Ok(Some(user))
	}).await {
		Ok(Ok(Some(user))) => user,
		Ok(Ok(None)) | Err(_) => return unknown(&app, mirrored),
		Ok(Err(error)) => {tracing::error!("the subscription lookup failed: {error}"); return unknown(&app, mirrored)}
	};
	let (signing, retired): (Vec<SigningEntry>, Vec<SigningEntry>) = {
		let held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		(held.current().into_iter().cloned().collect(), held.retired().into_iter().cloned().collect())
	};
	let Some(newest) = signing.last().cloned() else {return unknown(&app, mirrored)};
	let Some(ask) = received else {return answer(&refusal_for(&app, &newest, &user, "bad_request"))};
	let signer = signing.iter().find(|entry| ask.kids().contains(&entry.proto().kid())).cloned();
	if signer.is_none() {
		if let Some(old) = retired.iter().find(|entry| ask.kids().contains(&entry.proto().kid())) {return answer(&refusal_for(&app, old, &user, "key_retired"))}
	}
	let signer = signer.unwrap_or(newest);
	let refuse = |reason: &str| answer(&refusal_for(&app, &signer, &user, reason));
	if !user.enabled {return refuse("disabled")}
	if user.expires_at.is_some_and(|expires| expires <= at) {return refuse("expired")}
	let settings = app.settings();
	let hash = keys.device_secret_hash(ask.device_secret().expose());
	let (public_key, op, name) = (STANDARD.encode(ask.device_public_key()), match ask.op() {Op::Fetch => "fetch", Op::Confirm(_) => "confirm", Op::Release => "release", Op::Leave => "leave"}, match ask.op() {Op::Confirm(Some(name)) => Some(name.as_str().to_owned()), _ => None});
	// A key that is some inbound's public key of this node is never a device's: the node would take the device for the node itself.
	let node_key = settings.profiles.iter().chain(settings.profile_overrides.values()).filter_map(|profile| profile.get("inbound_public_key")?.as_str()).any(|key| STANDARD.decode(key).is_ok_and(|bytes| STANDARD.encode(bytes) == public_key));
	let (changed, outcome) = {
		let (handle, held, user, dirty, (new_max, window)) = (app.db.clone(), app.clone(), user.clone(), app.dirty_all(), (settings.new_devices as usize, i64::from(settings.new_devices_window_minutes) * 60));
		match handle.call(move |db| -> rusqlite::Result<(bool, Result<Option<DeviceRow>, &'static str>)> {
			let (keys, mut changed, tx) = (held.keys.as_ref().expect("checked before the lookup"), false, db.transaction()?);
			changed |= tx.execute("delete from devices where user_id = ? and state = 'pending' and created < ?", params![user.id, at - PENDING_LAPSE])? > 0;
			let device = tx.query_row(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? and public_key = ?"), params![user.id, public_key], DeviceRow::read).optional()?;
			// A device key belongs to one account across the whole panel (the table's unique index says so too): a key that another account holds is answered as a device whose secret is not the stored one, which tells nothing about the other account.
			let elsewhere = device.is_none() && tx.query_row("select exists (select 1 from devices where public_key = ?)", [&public_key], |row| row.get::<_, bool>(0))?;
			let outcome = match device {
				Some(device) if !crypto::equal(&device.secret_hash, &hash) => Err("device_mismatch"),
				Some(device) => match op {
					// An import that was cancelled or failed gives back its place in the window of new devices as well, so that trying again does not meet `rate_limited`.
					"release" if device.state == "pending" => {changed |= tx.execute("delete from devices where id = ?", [device.id])? > 0; held.sub_limits.give_back(&format!("new:{}:{}", user.id, user.token_gen), device.created); Ok(None)}
					// The user removed the subscription from the app, which proved the device's secret to ask: the device goes, confirmed or not, and its place is free.
					"leave" => {
						changed |= tx.execute("delete from devices where id = ?", [device.id])? > 0;
						crate::db::audit(&tx, "device", "subscription", "device.leave", &format!("user:{}", user.id), &format!("device:{}, removed by its app", device.id));
						Ok(None)
					}
					"confirm" => {
						tx.execute("update devices set state = 'enrolled', confirmed_at = coalesce(confirmed_at, ?), name = coalesce(?, name), last_seen = ? where id = ?", params![at, name, at, device.id])?;
						changed |= device.state == "pending";
						Ok(Some(tx.query_row(&format!("select {DEVICE_COLUMNS} from devices where id = ?"), [device.id], DeviceRow::read)?))
					}
					"fetch" if device.state == "enrolled" && !held.sub_limits.admit(&format!("dev:{}:{}", user.id, public_key), 1, 60) => Err("rate_limited"),
					_ => {tx.execute("update devices set last_seen = ? where id = ?", params![at, device.id])?; Ok(Some(device))}
				},
				None if op == "release" || op == "leave" => Ok(None),
				None if node_key || elsewhere => Err("device_mismatch"),
				None => {
					let (total, pending): (i64, i64) = tx.query_row("select count(*), coalesce(sum(state = 'pending'), 0) from devices where user_id = ?", [user.id], |row| Ok((row.get(0)?, row.get(1)?)))?;
					let limit = if user.device_limit == 0 {NODE_DEVICES_MAX} else {user.device_limit.min(NODE_DEVICES_MAX)};
					let (address, enroll) = (allocate(&tx, LOCAL), op == "confirm");
					if total >= limit || (!enroll && pending >= PENDING_PLACES) || address.is_none() {Err("device_limit")}
					else if !held.sub_limits.admit(&format!("new:{}:{}", user.id, user.token_gen), new_max, window) {Err("rate_limited")}
					else {
						let secret = keys.seal_secret(&user.record_id, &format!("transport_secret:{}", public_key), &crypto::random::<32>());
						tx.execute("insert into devices (user_id, name, public_key, secret_hash, transport_secret, state, token_gen, created, confirmed_at, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params![user.id, name.clone().unwrap_or_default(), public_key, hash.as_slice(), secret, if enroll {"enrolled"} else {"pending"}, user.token_gen, at, enroll.then_some(at), at])?;
						tx.execute("insert into device_addresses (node_id, device_id, address) values (?, last_insert_rowid(), ?)", params![LOCAL.0, address])?;
						changed = true;
						Ok(Some(tx.query_row(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? and public_key = ?"), params![user.id, public_key], DeviceRow::read)?))
					}
				}
			};
			if changed {add_addresses(&tx, Some(user.id))?}
			tx.commit()?;
			if changed {dirty.set()}
			Ok((changed, outcome))
		}).await {
			Ok(Ok(done)) => done,
			Ok(Err(error)) => {tracing::error!("a device could not be enrolled: {error}"); return unknown(&app, mirrored)}
			Err(_) => return unknown(&app, mirrored),
		}
	};
	// An app answered before the node has its new device is refused on its first connection and then waits out its retry, so the answer waits for the push, for a few seconds at most. The push goes on by itself if it takes longer.
	if changed {
		let app = app.clone();
		let push = tokio::spawn(async move {let _ = crate::users::push(&app).await;});
		let _ = tokio::time::timeout(std::time::Duration::from_secs(5), push).await;
	}
	let device = match outcome {
		Err(reason) => return refuse(reason),
		Ok(None) => return refuse("released"),
		Ok(Some(device)) => device,
	};
	if device.state == "enrolled" {statics::remember(&app, &user, &device, &token, ask.device_secret().expose()).await}
	let used = crate::node::usage(&app, LOCAL).await.remove(&user.name);
	match document(&app, &user, &device, &signing, &signer, Form::Answer, used.as_ref(), reached.as_ref()).await {
		Ok(text) => answer(&text),
		Err(error) => {
			// A fault of the panel is no word of the account's state: it answers as an unknown path and says so in the log, and never as a signed refusal such as "disabled".
			tracing::error!("a subscription document could not be built: {error}");
			unknown(&app, mirrored)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	fn at(pool: &str, range: &str, stored: &str) -> Option<String> {address_in(pool.parse().unwrap(), range.parse().unwrap(), stored.parse().unwrap()).map(|found| found.to_string())}

	#[test]
	fn a_device_has_its_stored_address_in_the_pool_range_and_the_same_offset_in_a_range_beside_it() {
		assert_eq!(at("10.66.0.0/16", "10.66.0.1/16", "10.66.0.2"), Some("10.66.0.2".into()), "the range that holds the stored address keeps it");
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.66.0.2"), Some("10.9.0.2".into()), "the offset from the pool's network is the offset from the range's");
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.66.0.77"), Some("10.9.0.77".into()));
	}

	#[test]
	fn an_offset_past_the_end_or_on_the_gateway_network_or_broadcast_gives_no_address() {
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.66.1.5"), None, "past the end of the range");
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.66.0.255"), None, "the broadcast address");
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.66.0.0"), None, "the network address");
		assert_eq!(at("10.66.0.0/16", "10.9.0.2/24", "10.66.0.2"), None, "the gateway, which is the address part of the range");
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.66.0.1"), None, "the gateway of a range written with the first host");
	}

	#[test]
	fn a_range_that_overlaps_the_pool_without_holding_the_address_and_an_address_outside_the_pool_give_none() {
		assert_eq!(at("10.66.0.0/16", "10.66.5.1/24", "10.66.0.2"), None, "a range inside the pool that does not hold the address");
		assert_eq!(at("10.66.0.0/24", "10.66.0.1/16", "10.66.0.2"), Some("10.66.0.2".into()), "a range that holds the whole pool holds the address");
		assert_eq!(at("10.66.0.0/16", "10.9.0.1/24", "10.77.0.2"), None, "the pool changed after the device was made");
		assert_eq!(at("10.66.0.0/16", "10.66.0.1/16", "10.77.0.2"), None);
	}

	#[test]
	fn the_node_gets_the_stored_address_and_one_more_for_each_other_veilway_inbound() {
		let inbounds = vec![json!({"type": "veilway", "tag": "n1", "address": ["10.66.0.1/16"]}), json!({"type": "veilway", "tag": "nn", "address": ["fd00::1/64", "10.9.0.1/24"]}), json!({"type": "veilway", "tag": "v6", "address": ["fd00::1/64"]}), json!({"type": "veilway", "tag": "nine", "address": ["10.8.0.1/24"]}), json!({"type": "xray", "tag": "x", "address": ["10.7.0.1/24"]})];
		let none = HashSet::new();
		assert_eq!(node_addresses("10.66.0.0/16", &inbounds, "10.66.0.9", &none), ["10.66.0.9", "10.9.0.9", "10.8.0.9"], "two inbounds beside the pool, and neither the IPv6 only one nor the other kind");
		assert_eq!(node_addresses("10.66.0.0/16", &inbounds, "10.77.0.9", &none), ["10.77.0.9"], "an address outside the pool gets no more");
		assert_eq!(node_addresses("not a pool", &inbounds, "10.66.0.9", &none), ["10.66.0.9"]);
		assert_eq!(node_addresses("10.66.0.0/16", &inbounds, "10.66.0.9", &HashSet::from(["10.9.0.9".to_string()])), ["10.66.0.9", "10.8.0.9"], "an address another device or a link holds is skipped");
	}
}
