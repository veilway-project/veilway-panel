//! The subscription side: the link, the signed document, and the public endpoint that answers a valid token and nothing else.
use crate::{app::{bucket, App, Settings, SigningEntry}, auth, crypto::{self, now}, mirrors};
use axum::{body::Body, extract::{Request, State}, http::{header::{CACHE_CONTROL, CONTENT_TYPE}, HeaderValue, Method}, response::Response};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use ipnet::Ipv4Net;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::{json, Map, Value};
use std::{collections::HashSet, sync::Arc};
use veilway_proto::subscription::{envelope::{self, Kid}, link::Link};

pub const PENDING_PLACES: i64 = 2;
pub const PENDING_LAPSE: i64 = 600;
const NODE_DEVICES_MAX: i64 = 16;

#[derive(Clone, Debug)]
pub struct UserRow {pub id: i64, pub name: String, pub enabled: bool, pub groups: String, pub exits: String, pub quota_bytes: Option<i64>, pub quota_period: Option<String>, pub expires_at: Option<i64>, pub device_limit: i64, pub note: String, pub created: i64, pub record_id: [u8; 16], pub sub_id: String, pub token_copy: Option<Vec<u8>>, pub token_gen: i64, pub token_created: i64, pub default_exit: Option<String>}

pub const USER_COLUMNS: &str = "id, name, enabled, groups, exits, quota_bytes, quota_period, expires_at, device_limit, note, created, record_id, sub_id, token_copy, token_gen, token_created, default_exit";

impl UserRow {
	pub fn read(row: &Row) -> rusqlite::Result<Self> {
		Ok(Self {id: row.get(0)?, name: row.get(1)?, enabled: row.get(2)?, groups: row.get(3)?, exits: row.get(4)?, quota_bytes: row.get(5)?, quota_period: row.get(6)?, expires_at: row.get(7)?, device_limit: row.get(8)?, note: row.get(9)?, created: row.get(10)?, record_id: row.get::<_, Vec<u8>>(11)?.try_into().unwrap_or([0; 16]), sub_id: row.get(12)?, token_copy: row.get(13)?, token_gen: row.get(14)?, token_created: row.get(15)?, default_exit: row.get(16)?})
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

/// The lowest free host address of the pool, leaving the first one to the gateway.
pub fn allocate(db: &Connection, pool: &str) -> Option<String> {
	let pool: Ipv4Net = pool.parse().ok()?;
	let taken: HashSet<String> = db.prepare("select address from devices").ok()?.query_map([], |row| row.get(0)).ok()?.filter_map(Result::ok).collect();
	pool.hosts().skip(1).map(|address| address.to_string()).find(|address| !taken.contains(address))
}

pub struct LinkOut {pub veilway: String, pub https: String}

/// The link of a token, built from the text of the format and read back through the format's own parser, so a link the client would refuse is never handed out.
pub fn link(settings: &Settings, key: &SigningEntry, token: &[u8; 16]) -> Result<LinkOut, String> {
	let endpoint = settings.endpoint_url.strip_prefix("https://").filter(|rest| rest.contains('/') && !rest.contains('#')).ok_or("the endpoint URL is not set to an https URL with a path")?;
	let pin = settings.endpoint_pins.first().map(|pin| STANDARD.decode(pin).map(|bytes| format!(".{}", URL_SAFE_NO_PAD.encode(bytes))).map_err(|_| "an endpoint pin is not base64")).transpose()?.unwrap_or_default();
	let text = format!("veilway://sub/{endpoint}#v1.{}.{}{pin}", URL_SAFE_NO_PAD.encode(key.public()), URL_SAFE_NO_PAD.encode(token));
	match Link::parse(&text).map_err(|error| error.to_string())? {Link::Native(native) => Ok(LinkOut {veilway: native.veilway(), https: native.https()}), _ => Err("the link did not read as a native one".into())}
}

fn sign(entry: &SigningEntry, payload: &Value) -> String {
	let pair = entry.pair();
	envelope::seal(&entry.proto(), &serde_json::to_vec(payload).unwrap_or_default(), |message| pair.sign(message).as_ref().try_into().expect("64 bytes"))
}

pub fn refusal(entry: &SigningEntry, subscription_id: &str, reason: &str) -> String {sign(entry, &json!({"v": 1, "subscription_id": subscription_id, "issued_at": now(), "refusal": reason}))}

/// A signed subscription for one device of one account.
pub fn document(app: &App, user: &UserRow, this: &DeviceRow, signing: &[SigningEntry], signer: &SigningEntry, used: Option<&Value>) -> Result<String, String> {
	let keys = app.keys.as_ref().ok_or("no key file")?;
	let settings = app.settings();
	if settings.profiles.is_empty() {return Err("no profile is configured".into())}
	let devices = DeviceRow::for_user(&app.db.lock(), user.id).map_err(|error| error.to_string())?;
	let secret = keys.open_secret(&user.record_id, &format!("transport_secret:{}", this.public_key), &this.transport_secret).ok_or("a transport secret does not open")?;
	let mut device = json!({"public_key": this.public_key, "addresses": [this.address], "transport_secrets": [STANDARD.encode(secret)]});
	if let Some(sealed) = &this.private_key {device["private_key"] = json!(STANDARD.encode(keys.open_secret(&user.record_id, &format!("private_key:{}", this.public_key), sealed).ok_or("a private key does not open")?));}
	let profiles: Vec<Value> = settings.profiles.iter().cloned().map(|mut profile| {profile["device"] = device.clone(); profile}).collect();
	let at = now();
	let mut payload = json!({
		"v": 1, "subscription_id": user.sub_id, "serial": at * 1000 + (crypto::random::<2>()[0] as i64 % 250), "issued_at": at, "expires_at": at + i64::from(settings.document_days) * 86_400,
		"signing_keys": signing.iter().map(|entry| STANDARD.encode(entry.public())).collect::<Vec<_>>(),
		"provider": {"name": settings.provider_name}, "update_interval": settings.update_interval, "profiles": profiles,
		"devices": devices.iter().map(|other| json!({"name": other.name, "enrolled_at": other.confirmed_at.unwrap_or(other.created), "this": other.id == this.id, "pending": other.state == "pending"})).collect::<Vec<_>>(),
		"usage": {"used_bytes": used.and_then(|user| user.get("used_bytes")).and_then(Value::as_u64).unwrap_or(0), "quota_bytes": user.quota_bytes.unwrap_or(0), "period": user.quota_period.as_deref().unwrap_or("none"), "period_start": used.and_then(|user| user.get("period_start")).and_then(Value::as_i64).unwrap_or(0).max(0), "expires_at": user.expires_at.unwrap_or(0), "device_limit": user.device_limit},
	});
	if !settings.endpoint_pins.is_empty() {payload["endpoint_pins"] = json!(settings.endpoint_pins);}
	if !settings.refresh_mirrors.is_empty() {payload["refresh_urls"] = json!(settings.refresh_mirrors);}
	Ok(sign(signer, &payload))
}

fn signed_response(text: String) -> Response {
	let mut response = Response::new(Body::from(text));
	response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/jose"));
	response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
	response
}

const MEMBERS: [&str; 7] = ["v", "token", "kids", "device_public_key", "device_secret", "op", "device_name"];

struct Asked {kids: Vec<Kid>, public_key: String, secret: [u8; 16], op: String, name: Option<String>}

fn asked(map: &Map<String, Value>) -> Option<Asked> {
	if map.keys().any(|key| !MEMBERS.contains(&key.as_str())) || map.get("v")?.as_u64()? != 1 {return None}
	let kids: Vec<Kid> = map.get("kids")?.as_array()?.iter().map(|kid| Kid::read(kid.as_str()?)).collect::<Option<_>>()?;
	if !(1..=2).contains(&kids.len()) {return None}
	let public_key = map.get("device_public_key")?.as_str()?;
	let raw: [u8; 32] = STANDARD.decode(public_key).ok()?.try_into().ok()?;
	if raw == [0; 32] || STANDARD.encode(raw) != public_key {return None}
	let secret_text = map.get("device_secret")?.as_str()?;
	let secret: [u8; 16] = URL_SAFE_NO_PAD.decode(secret_text).ok()?.try_into().ok()?;
	if URL_SAFE_NO_PAD.encode(secret) != secret_text {return None}
	let op = map.get("op")?.as_str()?;
	if !["fetch", "confirm", "release"].contains(&op) {return None}
	let name = match map.get("device_name") {
		None => None,
		Some(name) => {
			if op != "confirm" || name.as_str()?.chars().count() > 32 {return None}
			let shown = veilway_proto::control::display(name.as_str()?, 32, 128);
			if shown.is_empty() {return None}
			Some(shown)
		}
	};
	Some(Asked {kids, public_key: public_key.to_string(), secret, op: op.to_string(), name})
}

/// Reads the body and says whether it is a valid request. Anything that is not answers as an unknown path.
pub async fn endpoint(State(app): State<Arc<App>>, request: Request) -> Response {
	let post = request.method() == Method::POST;
	// A valid mirror header names the real source of the request. One that is not valid, or a source over its limit, is an unknown request.
	let (via, direct) = (mirrors::check(&app, request.headers()), auth::source(&app, &request));
	let source = via.as_ref().ok().and_then(Option::as_ref).map_or(direct, |(_, address)| address.to_string());
	if let Ok(Some((name, _))) = &via {tracing::debug!("a subscription request relayed by the mirror {name} from {source}")}
	let admitted = via.is_ok() && app.limits.hit(&format!("sub:{}", bucket(&source)), 120, 60);
	// The body is drained to the cap whatever it holds, and the lookup always runs, so an invalid request costs what a valid one does.
	let body = http_body_util::Limited::new(request.into_body(), 1024).collect().await.map(|body| body.to_bytes()).unwrap_or_default();
	let map = match serde_json::from_slice::<Value>(&body) {Ok(Value::Object(map)) => Some(map), _ => None};
	let token: Option<[u8; 16]> = map.as_ref().and_then(|map| map.get("token")).and_then(Value::as_str).filter(|text| text.len() == 22).and_then(|text| URL_SAFE_NO_PAD.decode(text).ok()).and_then(|bytes| bytes.try_into().ok());
	let Some(keys) = app.keys.as_ref() else {return app.not_found()};
	// One HMAC, one lookup and one comparison, against a dummy value when nothing was found.
	let lookup = keys.token_lookup(&token.unwrap_or([0; 16]));
	let found = app.db.lock().query_row(&format!("select {USER_COLUMNS}, token_lookup from users where token_lookup = ?"), [lookup.as_slice()], |row| Ok((UserRow::read(row)?, row.get::<_, Vec<u8>>(17)?))).optional().unwrap_or(None);
	let stored = found.as_ref().map_or(vec![0u8; 32], |(_, stored)| stored.clone());
	let Some((user, _)) = found.filter(|_| post && admitted && token.is_some() && crypto::equal(&stored, &lookup)) else {return app.not_found()};
	let Some(map) = map else {return app.not_found()};
	let at = now();
	let (signing, retired): (Vec<SigningEntry>, Vec<SigningEntry>) = {
		let held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		(held.current().into_iter().cloned().collect(), held.retired().into_iter().cloned().collect())
	};
	let Some(newest) = signing.last().cloned() else {return app.not_found()};
	let Some(ask) = asked(&map) else {return signed_response(refusal(&newest, &user.sub_id, "bad_request"))};
	let signer = signing.iter().find(|entry| ask.kids.contains(&entry.proto().kid())).cloned();
	if signer.is_none() {
		if let Some(old) = retired.iter().find(|entry| ask.kids.contains(&entry.proto().kid())) {return signed_response(refusal(old, &user.sub_id, "key_retired"))}
	}
	let signer = signer.unwrap_or(newest);
	let refuse = |reason: &str| signed_response(refusal(&signer, &user.sub_id, reason));
	if !user.enabled {return refuse("disabled")}
	if user.expires_at.is_some_and(|expires| expires <= at) {return refuse("expired")}
	let (mut changed, pool) = (false, app.settings().pool_v4);
	let hash = keys.device_secret_hash(&ask.secret);
	let outcome: Result<Option<DeviceRow>, &str> = {
		let db = app.db.lock();
		changed |= db.execute("delete from devices where user_id = ? and state = 'pending' and created < ?", params![user.id, at - PENDING_LAPSE]).unwrap_or(0) > 0;
		let device = db.query_row(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? and public_key = ?"), params![user.id, ask.public_key], DeviceRow::read).optional().unwrap_or(None);
		match device {
			Some(device) if !crypto::equal(&device.secret_hash, &hash) => Err("device_mismatch"),
			Some(device) => match ask.op.as_str() {
				"release" if device.state == "pending" => {changed |= db.execute("delete from devices where id = ?", [device.id]).unwrap_or(0) > 0; Ok(None)}
				"confirm" => {
					let _ = db.execute("update devices set state = 'enrolled', confirmed_at = coalesce(confirmed_at, ?), name = coalesce(?, name), last_seen = ? where id = ?", params![at, ask.name, at, device.id]);
					changed |= device.state == "pending";
					Ok(db.query_row(&format!("select {DEVICE_COLUMNS} from devices where id = ?"), [device.id], DeviceRow::read).ok())
				}
				"fetch" if device.state == "enrolled" && !app.limits.hit(&format!("dev:{}:{}", user.id, ask.public_key), 1, 60) => Err("rate_limited"),
				_ => {let _ = db.execute("update devices set last_seen = ? where id = ?", params![at, device.id]); Ok(Some(device))}
			},
			None if ask.op == "release" => Ok(None),
			None => {
				let (total, pending): (i64, i64) = db.query_row("select count(*), coalesce(sum(state = 'pending'), 0) from devices where user_id = ?", [user.id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap_or((0, 0));
				let limit = if user.device_limit == 0 {NODE_DEVICES_MAX} else {user.device_limit.min(NODE_DEVICES_MAX)};
				let (address, enroll) = (allocate(&db, &pool), ask.op == "confirm");
				if total >= limit || (!enroll && pending >= PENDING_PLACES) || address.is_none() {Err("device_limit")}
				else if !app.limits.hit(&format!("new:{}:{}", user.id, user.token_gen), 1, 600) {Err("rate_limited")}
				else {
					let secret = keys.seal_secret(&user.record_id, &format!("transport_secret:{}", ask.public_key), &crypto::random::<32>());
					let _ = db.execute("insert into devices (user_id, name, public_key, secret_hash, address, transport_secret, state, token_gen, created, confirmed_at, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params![user.id, ask.name.clone().unwrap_or_default(), ask.public_key, hash.as_slice(), address, secret, if enroll {"enrolled"} else {"pending"}, user.token_gen, at, enroll.then_some(at), at]);
					changed = true;
					Ok(db.query_row(&format!("select {DEVICE_COLUMNS} from devices where user_id = ? and public_key = ?"), params![user.id, ask.public_key], DeviceRow::read).ok())
				}
			}
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
	let used = crate::node::usage(&app).await.remove(&user.name);
	match document(&app, &user, &device, &signing, &signer, used.as_ref()) {
		Ok(text) => signed_response(text),
		Err(error) => {
			tracing::error!("a subscription document could not be built: {error}");
			refuse("disabled")
		}
	}
}
