//! The subscription side: the link, the signed document, and the public endpoint that answers a valid token and nothing else.
use crate::{app::{bucket, App, Endpoint, SigningEntry}, auth, crypto::{self, now}, gateway, mirrors, statics};
use axum::{body::Body, extract::{Request, State}, http::{header::{CACHE_CONTROL, CONTENT_TYPE}, HeaderValue, Method, StatusCode}, response::Response};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use ipnet::Ipv4Net;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::{atomic::Ordering, Arc}};
use veilway_proto::subscription::{envelope, exchange::{self, GatewayKey}, fetch::{Op, RequestError}, link::Link};

pub const PENDING_PLACES: i64 = 2;
pub const PENDING_LAPSE: i64 = 600;
const NODE_DEVICES_MAX: i64 = 16;

#[derive(Clone, Debug)]
pub struct UserRow {pub id: i64, pub name: String, pub enabled: bool, pub groups: String, pub exits: String, pub quota_bytes: Option<i64>, pub quota_period: Option<String>, pub expires_at: Option<i64>, pub device_limit: i64, pub note: String, pub created: i64, pub record_id: [u8; 16], pub sub_id: String, pub token_copy: Option<Vec<u8>>, pub token_gen: i64, pub token_created: i64, pub default_exit: Option<String>, pub endpoint: Option<String>}

pub const USER_COLUMNS: &str = "id, name, enabled, groups, exits, quota_bytes, quota_period, expires_at, device_limit, note, created, record_id, sub_id, token_copy, token_gen, token_created, default_exit, endpoint";

impl UserRow {
	pub fn read(row: &Row) -> rusqlite::Result<Self> {
		Ok(Self {id: row.get(0)?, name: row.get(1)?, enabled: row.get(2)?, groups: row.get(3)?, exits: row.get(4)?, quota_bytes: row.get(5)?, quota_period: row.get(6)?, expires_at: row.get(7)?, device_limit: row.get(8)?, note: row.get(9)?, created: row.get(10)?, record_id: row.get::<_, Vec<u8>>(11)?.try_into().unwrap_or([0; 16]), sub_id: row.get(12)?, token_copy: row.get(13)?, token_gen: row.get(14)?, token_created: row.get(15)?, default_exit: row.get(16)?, endpoint: row.get(17)?})
	}
	pub fn load(db: &Connection, id: i64) -> rusqlite::Result<Self> {db.query_row(&format!("select {USER_COLUMNS} from users where id = ?"), [id], Self::read)}
}

#[derive(Clone, Debug)]
pub struct DeviceRow {pub id: i64, pub user_id: i64, pub name: String, pub public_key: String, pub secret_hash: Vec<u8>, pub address: String, pub transport_secret: Vec<u8>, pub private_key: Option<Vec<u8>>, pub state: String, pub token_gen: i64, pub created: i64, pub confirmed_at: Option<i64>, pub last_seen: Option<i64>}

pub const DEVICE_COLUMNS: &str = "id, user_id, name, public_key, secret_hash, address, transport_secret, private_key, state, token_gen, created, confirmed_at, last_seen";

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

/// The lowest free host address of the pool, leaving the first one to the gateway.
pub fn allocate(db: &Connection, pool: &str) -> Option<String> {
	let pool: Ipv4Net = pool.parse().ok()?;
	let taken: HashSet<String> = db.prepare("select address from devices").ok()?.query_map([], |row| row.get(0)).ok()?.filter_map(Result::ok).collect();
	pool.hosts().skip(1).map(|address| address.to_string()).find(|address| !taken.contains(address))
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
	let mut device = json!({"public_key": this.public_key, "addresses": [this.address], "transport_secrets": [STANDARD.encode(secret)]});
	if let Some(sealed) = &this.private_key {device["private_key"] = json!(STANDARD.encode(keys.open_secret(&user.record_id, &format!("private_key:{}", this.public_key), sealed).ok_or("a private key does not open")?));}
	let groups: Vec<String> = serde_json::from_str(&user.groups).unwrap_or_default();
	let reaching = crate::nodecfg::reaching(&settings.published_relays, Some((user.id, groups.as_slice())));
	let profiles: Vec<Value> = settings.profiles.iter().cloned().map(|mut profile| {
		if let Some(tag) = profile["id"].as_str().and_then(|id| settings.relay_profiles.get(id)) {crate::nodecfg::carry(&mut profile, tag, &reaching);}
		profile["device"] = device.clone();
		profile
	}).collect();
	let profiles = app.names.resolve(profiles).await;
	if profiles.is_empty() {return Err("no profile has an address that resolves".into())}
	let at = now();
	let (floor, device_id) = (at * 1000 + (crypto::random::<2>()[0] as i64 % 250), this.id);
	let serial: i64 = app.db.call(move |db| db.query_row("update devices set last_serial = max(?, last_serial + 1) where id = ? returning last_serial", params![floor, device_id], |row| row.get::<_, i64>(0))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let mut payload = json!({
		"v": 1, "subscription_id": user.sub_id, "serial": serial, "issued_at": at, "expires_at": at + i64::from(settings.document_days) * 86_400,
		"signing_keys": signing.iter().map(|entry| STANDARD.encode(entry.public())).collect::<Vec<_>>(),
		"provider": {"name": settings.provider_name}, "update_interval": settings.update_interval, "profiles": profiles,
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
		let (handle, held, user, dirty, pool) = (app.db.clone(), app.clone(), user.clone(), app.dirty.clone(), settings.pool_v4.clone());
		match handle.call(move |db| -> rusqlite::Result<(bool, Result<Option<DeviceRow>, &'static str>)> {
			let (keys, mut changed, tx) = (held.keys.as_ref().expect("checked before the lookup"), false, db.transaction()?);
			changed |= tx.execute("delete from devices where user_id = ? and state = 'pending' and created < ?", params![user.id, at - PENDING_LAPSE])? > 0;
			let device = tx.query_row(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? and public_key = ?"), params![user.id, public_key], DeviceRow::read).optional()?;
			// A device key belongs to one account across the whole panel (the table's unique index says so too): a key that another account holds is answered as a device whose secret is not the stored one, which tells nothing about the other account.
			let elsewhere = device.is_none() && tx.query_row("select exists (select 1 from devices where public_key = ?)", [&public_key], |row| row.get::<_, bool>(0))?;
			let outcome = match device {
				Some(device) if !crypto::equal(&device.secret_hash, &hash) => Err("device_mismatch"),
				Some(device) => match op {
					"release" if device.state == "pending" => {changed |= tx.execute("delete from devices where id = ?", [device.id])? > 0; Ok(None)}
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
					"fetch" if device.state == "enrolled" && !held.sub_limits.hit(&format!("dev:{}:{}", user.id, public_key), 1, 60) => Err("rate_limited"),
					_ => {tx.execute("update devices set last_seen = ? where id = ?", params![at, device.id])?; Ok(Some(device))}
				},
				None if op == "release" || op == "leave" => Ok(None),
				None if node_key || elsewhere => Err("device_mismatch"),
				None => {
					let (total, pending): (i64, i64) = tx.query_row("select count(*), coalesce(sum(state = 'pending'), 0) from devices where user_id = ?", [user.id], |row| Ok((row.get(0)?, row.get(1)?)))?;
					let limit = if user.device_limit == 0 {NODE_DEVICES_MAX} else {user.device_limit.min(NODE_DEVICES_MAX)};
					let (address, enroll) = (allocate(&tx, &pool), op == "confirm");
					if total >= limit || (!enroll && pending >= PENDING_PLACES) || address.is_none() {Err("device_limit")}
					else if !held.sub_limits.hit(&format!("new:{}:{}", user.id, user.token_gen), 1, 600) {Err("rate_limited")}
					else {
						let secret = keys.seal_secret(&user.record_id, &format!("transport_secret:{}", public_key), &crypto::random::<32>());
						tx.execute("insert into devices (user_id, name, public_key, secret_hash, address, transport_secret, state, token_gen, created, confirmed_at, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params![user.id, name.clone().unwrap_or_default(), public_key, hash.as_slice(), address, secret, if enroll {"enrolled"} else {"pending"}, user.token_gen, at, enroll.then_some(at), at])?;
						changed = true;
						Ok(Some(tx.query_row(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? and public_key = ?"), params![user.id, public_key], DeviceRow::read)?))
					}
				}
			};
			tx.commit()?;
			if changed {dirty.store(true, Ordering::Relaxed)}
			Ok((changed, outcome))
		}).await {
			Ok(Ok(done)) => done,
			Ok(Err(error)) => {tracing::error!("a device could not be enrolled: {error}"); return unknown(&app, mirrored)}
			Err(_) => return unknown(&app, mirrored),
		}
	};
	if changed {
		let app = app.clone();
		tokio::spawn(async move {let _ = crate::node::sync(&app).await;});
	}
	let device = match outcome {
		Err(reason) => return refuse(reason),
		Ok(None) => return refuse("released"),
		Ok(Some(device)) => device,
	};
	if device.state == "enrolled" {statics::remember(&app, &user, &device, &token, ask.device_secret().expose()).await}
	let used = crate::node::usage(&app).await.remove(&user.name);
	match document(&app, &user, &device, &signing, &signer, Form::Answer, used.as_ref(), reached.as_ref()).await {
		Ok(text) => answer(&text),
		Err(error) => {
			// A fault of the panel is no word of the account's state: it answers as an unknown path and says so in the log, and never as a signed refusal such as "disabled".
			tracing::error!("a subscription document could not be built: {error}");
			unknown(&app, mirrored)
		}
	}
}
