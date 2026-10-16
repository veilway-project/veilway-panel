//! Users, their devices and their subscription links.
use crate::{app::App, crypto::{self, now}, db::audit, http::{ok, Body, Ctx, Failure}, node, subs::{self, DeviceRow, UserRow, USER_COLUMNS}};
use axum::{extract::{Path, Query, State}, http::StatusCode, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::{atomic::Ordering, Arc}};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use veilway_proto::subscription::{link::{Carried, Link}, sealed_file};

/// Whether the node took the change. The panel's database is changed either way and the next successful push brings the node up to date.
#[derive(Serialize, JsonSchema)]
pub struct NodeState {pub synced: bool, pub error: Option<String>}

pub async fn push(app: &Arc<App>) -> NodeState {
	let held = app.clone();
	// Its own task, so a client that goes away mid-push does not stop the push half way.
	match tokio::spawn(async move {node::sync(&held).await}).await.map_err(|error| error.to_string()).and_then(|done| done) {Ok(()) => NodeState {synced: true, error: None}, Err(error) => NodeState {synced: false, error: Some(error)}}
}

pub(crate) fn name_ok(name: &str, dots: bool) -> bool {
	let mut bytes = name.bytes();
	name.len() <= 64 && bytes.next().is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit()) && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_' || (dots && byte == b'.'))
}

fn double<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {Ok(Some(Option::deserialize(d)?))}

#[derive(Serialize, JsonSchema)]
pub struct UserOut {
	pub id: i64, pub name: String, pub enabled: bool, pub groups: Vec<String>,
	/// "all" or a list of exit tags.
	pub exits: Value,
	/// The exit the user's devices leave through when they choose none. Null is the node's default.
	pub exit: Option<String>,
	pub quota_bytes: Option<i64>, pub quota_period: Option<String>, pub expires_at: Option<i64>,
	/// 0 is no limit beyond the node's own 16.
	pub device_limit: i64, pub note: String, pub created: i64, pub subscription_id: String,
	pub devices: i64, pub pending_devices: i64,
	/// The node's own record of the user: usage, denial and traffic. Null when the node cannot be reached.
	pub node: Option<Value>,
}

fn out(user: &UserRow, devices: i64, pending: i64, node: Option<Value>) -> UserOut {
	UserOut {id: user.id, name: user.name.clone(), enabled: user.enabled, groups: serde_json::from_str(&user.groups).unwrap_or_default(), exits: serde_json::from_str(&user.exits).unwrap_or(json!("all")), exit: user.default_exit.clone(), quota_bytes: user.quota_bytes, quota_period: user.quota_period.clone(), expires_at: user.expires_at, device_limit: user.device_limit, note: user.note.clone(), created: user.created, subscription_id: user.sub_id.clone(), devices, pending_devices: pending, node}
}

async fn counts(app: &App, id: i64) -> Result<(i64, i64), Failure> {
	Ok(app.db.call(move |db| db.query_row("select count(*), coalesce(sum(state = 'pending'), 0) from devices where user_id = ?", [id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))).await??)
}

#[derive(Deserialize, JsonSchema)]
pub struct UserQuery {pub q: Option<String>, pub group: Option<String>, pub enabled: Option<bool>}

#[derive(Serialize, JsonSchema)]
pub struct UsersOut {pub users: Vec<UserOut>}

pub async fn list(State(app): State<Arc<App>>, Query(query): Query<UserQuery>) -> Result<Response, Failure> {
	let (rows, counted) = app.db.call(|db| -> rusqlite::Result<(Vec<UserRow>, HashMap<i64, (i64, i64)>)> {
		let rows = db.prepare(&format!("select {USER_COLUMNS} from users order by name"))?.query_map([], UserRow::read)?.collect::<Result<Vec<_>, _>>()?;
		let counted = db.prepare("select user_id, count(*), coalesce(sum(state = 'pending'), 0) from devices group by user_id")?.query_map([], |row| Ok((row.get::<_, i64>(0)?, (row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))))?.collect::<Result<HashMap<_, _>, _>>()?;
		Ok((rows, counted))
	}).await??;
	let nodes = node::usage(&app).await;
	let mut users = Vec::new();
	for user in rows.iter().filter(|user| query.q.as_ref().is_none_or(|q| user.name.contains(q.as_str())) && query.enabled.is_none_or(|enabled| user.enabled == enabled) && query.group.as_ref().is_none_or(|group| serde_json::from_str::<Vec<String>>(&user.groups).unwrap_or_default().contains(group))) {
		let (devices, pending) = counted.get(&user.id).copied().unwrap_or((0, 0));
		users.push(out(user, devices, pending, nodes.get(&user.name).cloned()));
	}
	ok(&UsersOut {users})
}

pub async fn get(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let (devices, pending) = counts(&app, id).await?;
	ok(&out(&user, devices, pending, node::usage(&app).await.remove(&user.name)))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserIn {
	pub name: String, pub enabled: Option<bool>, pub groups: Option<Vec<String>>, pub exits: Option<Value>,
	/// One of the user's exits, or null for the node's default.
	pub exit: Option<String>,
	pub quota_bytes: Option<u64>,
	/// "daily", "weekly" or "monthly". Needs quota_bytes.
	pub quota_period: Option<String>,
	/// Unix seconds.
	pub expires_at: Option<i64>, pub device_limit: Option<u16>, pub note: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserPatch {
	pub name: Option<String>, pub enabled: Option<bool>, pub groups: Option<Vec<String>>, pub exits: Option<Value>,
	/// One of the user's exits, or null for the node's default. A default the new exits leave out is cleared.
	#[serde(default, deserialize_with = "double")] pub exit: Option<Option<String>>,
	#[serde(default, deserialize_with = "double")] pub quota_bytes: Option<Option<u64>>,
	#[serde(default, deserialize_with = "double")] pub quota_period: Option<Option<String>>,
	#[serde(default, deserialize_with = "double")] pub expires_at: Option<Option<i64>>,
	pub device_limit: Option<u16>, pub note: Option<String>,
}

/// Whether `exit` may be the default of a user with these exits. Whether the node has it is decided at the next sync.
fn default_ok(exits: &Value, exit: &str) -> bool {name_ok(exit, false) && (exits == &json!("all") || exits.as_array().is_some_and(|tags| tags.iter().any(|tag| tag == exit)))}

const DEFAULT_REFUSED: &str = "exit is one of the user's exits, or null for the node's default.";

fn check(groups: Option<&Vec<String>>, exits: Option<&Value>, quota: Option<u64>, period: Option<&str>) -> Result<(), Failure> {
	if groups.is_some_and(|groups| groups.len() > 256 || groups.iter().any(|group| !name_ok(group, true))) {return Err(Failure::bad("A group is 1 to 64 characters of a-z, 0-9, dot, dash and underscore, and a user has at most 256."))}
	if exits.is_some_and(|exits| !(exits == &json!("all") || exits.as_array().is_some_and(|tags| tags.iter().all(|tag| tag.as_str().is_some_and(|tag| name_ok(tag, false)))))) {return Err(Failure::bad("exits is \"all\" or a list of exit tags."))}
	if quota == Some(0) {return Err(Failure::bad("quota_bytes is above 0, or null for no quota."))}
	if period.is_some_and(|period| !["daily", "weekly", "monthly"].contains(&period)) {return Err(Failure::bad("quota_period is daily, weekly or monthly."))}
	if period.is_some() && quota.is_none() {return Err(Failure::bad("quota_period needs quota_bytes."))}
	Ok(())
}

#[derive(Serialize, JsonSchema)]
pub struct LinkView {
	/// The link in the form providers hand out. A secret: it is shown to the one who asked and stored nowhere but in the sealed copy.
	pub veilway: String, pub https: String,
	/// The same link as an SVG QR code.
	pub qr_svg: String,
}

fn view(settings: &crate::app::Settings, app: &App, token: &[u8; 16]) -> Result<LinkView, String> {
	let key = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).current().last().cloned().cloned().ok_or("no signing key")?;
	let link = subs::link(settings, &key, token)?;
	let qr = qrcode::QrCode::new(link.veilway.as_bytes()).map_err(|error| error.to_string())?.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).build();
	Ok(LinkView {veilway: link.veilway, https: link.https, qr_svg: qr})
}

#[derive(Serialize, JsonSchema)]
pub struct Created {pub user: UserOut, pub link: Option<LinkView>, pub link_error: Option<String>}

pub async fn create(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<UserIn>) -> Result<Response, Failure> {
	if !name_ok(&input.name, true) {return Err(Failure::bad("name is 1 to 64 characters of a-z, 0-9, dot, dash and underscore, starting with a letter or digit."))}
	check(input.groups.as_ref(), input.exits.as_ref(), input.quota_bytes, input.quota_period.as_deref())?;
	if input.exit.as_deref().is_some_and(|exit| !default_ok(input.exits.as_ref().unwrap_or(&json!("all")), exit)) {return Err(Failure::bad(DEFAULT_REFUSED))}
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing, so no account can be made."))?;
	let settings = app.settings();
	let (token, record, sub_id) = (crypto::random::<16>(), crypto::random::<16>(), URL_SAFE_NO_PAD.encode(crypto::random::<16>()));
	let lookup = keys.token_lookup(&token);
	let (held, cache) = (app.clone(), app.settings.clone());
	let id = app.db.call(move |db| -> rusqlite::Result<i64> {
		let once = cache.read().unwrap_or_else(|poisoned| poisoned.into_inner()).show_links_once;
		let copy = (!once).then(|| held.keys.as_ref().expect("checked before the lookup").seal_copy(&record, &token));
		db.execute("insert into users (name, enabled, groups, exits, quota_bytes, quota_period, expires_at, device_limit, note, created, record_id, sub_id, token_lookup, token_copy, token_created, default_exit) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params![input.name, input.enabled.unwrap_or(true), serde_json::to_string(&input.groups.unwrap_or_default()).unwrap_or_default(), serde_json::to_string(&input.exits.unwrap_or(json!("all"))).unwrap_or_default(), input.quota_bytes.map(|quota| quota as i64), input.quota_bytes.and(input.quota_period), input.expires_at, input.device_limit.unwrap_or(settings.default_device_limit), input.note.unwrap_or_default(), now(), record.as_slice(), sub_id, lookup.as_slice(), copy, now(), input.exit])?;
		let id = db.last_insert_rowid();
		audit(db, &ctx.actor, &ctx.source, "user.create", &format!("user:{id}"), &input.name);
		Ok(id)
	}).await??;
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let (link, link_error) = match view(&settings, &app, &token) {Ok(link) => (Some(link), None), Err(error) => (None, Some(error))};
	ok(&Created {user: out(&user, 0, 0, None), link, link_error})
}

#[derive(Serialize, JsonSchema)]
pub struct Changed {pub user: UserOut, pub node: NodeState}

pub async fn patch(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<UserPatch>) -> Result<Response, Failure> {
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let quota = input.quota_bytes.unwrap_or(user.quota_bytes.map(|quota| quota as u64));
	let period = input.quota_period.unwrap_or(user.quota_period.clone());
	check(input.groups.as_ref(), input.exits.as_ref(), quota, period.as_deref())?;
	let exits = input.exits.clone().unwrap_or_else(|| serde_json::from_str(&user.exits).unwrap_or(json!("all")));
	if input.exit.as_ref().is_some_and(|exit| exit.as_deref().is_some_and(|exit| !default_ok(&exits, exit))) {return Err(Failure::bad(DEFAULT_REFUSED))}
	let exit = input.exit.clone().unwrap_or(user.default_exit.clone()).filter(|exit| default_ok(&exits, exit));
	if input.name.as_ref().is_some_and(|name| !name_ok(name, true)) {return Err(Failure::bad("name is 1 to 64 characters of a-z, 0-9, dot, dash and underscore, starting with a letter or digit."))}
	let dirty = app.dirty.clone();
	app.db.call(move |db| -> rusqlite::Result<()> {
		db.execute("update users set name = ?, enabled = ?, groups = ?, exits = ?, quota_bytes = ?, quota_period = ?, expires_at = ?, device_limit = ?, note = ?, default_exit = ? where id = ?", params![input.name.unwrap_or(user.name.clone()), input.enabled.unwrap_or(user.enabled), input.groups.map_or(user.groups.clone(), |groups| serde_json::to_string(&groups).unwrap_or_default()), serde_json::to_string(&exits).unwrap_or_default(), quota.map(|quota| quota as i64), quota.and(period), input.expires_at.unwrap_or(user.expires_at), input.device_limit.map_or(user.device_limit, i64::from), input.note.unwrap_or(user.note.clone()), exit, id])?;
		audit(db, &ctx.actor, &ctx.source, "user.update", &format!("user:{id}"), &user.name);
		dirty.store(true, Ordering::Relaxed);
		Ok(())
	}).await??;
	let node = push(&app).await;
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let (devices, pending) = counts(&app, id).await?;
	ok(&Changed {user: out(&user, devices, pending, None), node})
}

#[derive(Serialize, JsonSchema)]
pub struct Deleted {pub node: NodeState}

pub async fn remove(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let dirty = app.dirty.clone();
	app.db.call(move |db| -> rusqlite::Result<()> {
		let name: String = db.query_row("select name from users where id = ?", [id], |row| row.get(0))?;
		db.execute("delete from users where id = ?", [id])?;
		audit(db, &ctx.actor, &ctx.source, "user.delete", &format!("user:{id}"), &name);
		dirty.store(true, Ordering::Relaxed);
		Ok(())
	}).await??;
	ok(&Deleted {node: push(&app).await})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bulk {
	pub ids: Vec<i64>,
	/// enable, disable, delete, reset_usage, add_group, remove_group, set_quota, set_expiry, set_device_limit or set_exits.
	pub action: String,
	/// The group name, the quota (an object with quota_bytes and quota_period), the expiry in Unix seconds or null, the device limit, or the exits ("all" or a list of exit tags). A default exit the new exits leave out is cleared.
	pub value: Option<Value>,
}

#[derive(Serialize, JsonSchema)]
pub struct BulkResult {pub done: usize, pub failed: Vec<BulkFailure>, pub node: NodeState}

#[derive(Serialize, JsonSchema)]
pub struct BulkFailure {pub id: i64, pub error: String}

pub async fn bulk(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Bulk>) -> Result<Response, Failure> {
	if input.ids.len() > 1000 {return Err(Failure::bad("A bulk action takes at most 1000 users."))}
	let (mut done, mut failed) = (0, Vec::new());
	for id in &input.ids {
		let result: Result<(), String> = async {
			let id = *id;
			let user = app.db.call(move |db| UserRow::load(db, id)).await.map_err(|error| error.to_string())?.map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) {"no such user".to_string()} else {error.to_string()})?;
			let (value, dirty) = (input.value.clone(), app.dirty.clone());
			match input.action.as_str() {
				"enable" | "disable" => {let enable = input.action == "enable"; app.db.call(move |db| db.execute("update users set enabled = ? where id = ?", params![enable, id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;}
				"delete" => {app.db.call(move |db| db.execute("delete from users where id = ?", [id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;}
				"reset_usage" => {let (status, _) = node::request(&app.cfg.node_socket, "POST", &format!("/v1/users/{}/usage/reset", user.name), None, Some(&json!({"totals": false}))).await?; if status != 200 {return Err(format!("the node answered {status}"))}}
				"add_group" | "remove_group" => {
					let group = value.as_ref().and_then(Value::as_str).filter(|group| name_ok(group, true)).ok_or("value is a group name")?;
					let mut groups: Vec<String> = serde_json::from_str(&user.groups).unwrap_or_default();
					groups.retain(|held| held != group);
					if input.action == "add_group" {groups.push(group.to_string());}
					check(Some(&groups), None, None, None).map_err(|error| error.message)?;
					let groups = serde_json::to_string(&groups).unwrap_or_default();
					app.db.call(move |db| db.execute("update users set groups = ? where id = ?", params![groups, id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
				}
				"set_quota" => {
					let quota = value.as_ref().and_then(|value| value.get("quota_bytes")).and_then(Value::as_u64);
					let period = value.as_ref().and_then(|value| value.get("quota_period")).and_then(Value::as_str);
					check(None, None, quota, period).map_err(|error| error.message)?;
					let period = period.filter(|_| quota.is_some()).map(str::to_owned);
					app.db.call(move |db| db.execute("update users set quota_bytes = ?, quota_period = ? where id = ?", params![quota.map(|quota| quota as i64), period, id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
				}
				"set_expiry" => {let expiry = value.as_ref().and_then(Value::as_i64); app.db.call(move |db| db.execute("update users set expires_at = ? where id = ?", params![expiry, id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;}
				"set_device_limit" => {let limit = value.as_ref().and_then(Value::as_u64).filter(|limit| *limit <= 65535).ok_or("value is a number from 0 to 65535")?; app.db.call(move |db| db.execute("update users set device_limit = ? where id = ?", params![limit, id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;}
				"set_exits" => {
					let exits = value.ok_or("value is \"all\" or a list of exit tags")?;
					check(None, Some(&exits), None, None).map_err(|error| error.message)?;
					let (stored, default_exit) = (serde_json::to_string(&exits).unwrap_or_default(), user.default_exit.filter(|exit| default_ok(&exits, exit)));
					app.db.call(move |db| db.execute("update users set exits = ?, default_exit = ? where id = ?", params![stored, default_exit, id]).inspect(|_| dirty.store(true, Ordering::Relaxed))).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
				}
				other => return Err(format!("unknown action {other}")),
			}
			Ok(())
		}.await;
		match result {Ok(()) => done += 1, Err(error) => failed.push(BulkFailure {id: *id, error})}
	}
	app.db.audit(&ctx.actor, &ctx.source, "user.bulk", &input.action, &format!("{} users, {} failed", input.ids.len(), failed.len())).await;
	ok(&BulkResult {done, failed, node: push(&app).await})
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ResetUsage {#[serde(default)] pub totals: bool}

pub async fn reset_usage(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<ResetUsage>) -> Result<Response, Failure> {
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let (status, body) = node::request(&app.cfg.node_socket, "POST", &format!("/v1/users/{}/usage/reset", user.name), None, Some(&json!({"totals": input.totals}))).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	if status != 200 {return Err(Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node answered {status}.")))}
	app.db.audit(&ctx.actor, &ctx.source, "user.usage_reset", &format!("user:{id}"), if input.totals {"with totals"} else {"quota count"}).await;
	ok(&serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null))
}

#[derive(Serialize, JsonSchema)]
pub struct DeviceOut {
	pub id: i64, pub name: String, pub public_key: String, pub address: String,
	/// "pending" or "enrolled".
	pub state: String,
	/// "device" when the device made its key, "panel" when the panel did. The second is the weaker choice: the private key sits in the panel's database and travels in the document.
	pub key_origin: String, pub created: i64, pub confirmed_at: Option<i64>, pub last_seen: Option<i64>,
	/// The link generation the device enrolled with.
	pub token_gen: i64,
}

fn device_out(device: &DeviceRow) -> DeviceOut {
	DeviceOut {id: device.id, name: device.name.clone(), public_key: device.public_key.clone(), address: device.address.clone(), state: device.state.clone(), key_origin: if device.private_key.is_some() {"panel"} else {"device"}.into(), created: device.created, confirmed_at: device.confirmed_at, last_seen: device.last_seen, token_gen: device.token_gen}
}

#[derive(Serialize, JsonSchema)]
pub struct DevicesOut {pub devices: Vec<DeviceOut>}

pub async fn devices(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let devices = app.db.call(move |db| -> rusqlite::Result<Vec<DeviceRow>> {
		UserRow::load(db, id)?;
		DeviceRow::for_user(db, id)
	}).await??;
	ok(&DevicesOut {devices: devices.iter().map(device_out).collect()})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceIn {pub name: String}

#[derive(Serialize, JsonSchema)]
pub struct DeviceCreated {pub device: DeviceOut, pub weaker: bool, pub node: NodeState}

/// A device whose key the panel makes. The default is that the device enrolls itself through the endpoint, which needs nothing here.
pub async fn make_device(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<DeviceIn>) -> Result<Response, Failure> {
	app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	if input.name.chars().count() > 32 {return Err(Failure::bad("A device name is at most 32 characters."))}
	let (secret, public) = {
		let secret = x25519_dalek::StaticSecret::from(crypto::random::<32>());
		(secret.to_bytes(), x25519_dalek::PublicKey::from(&secret).to_bytes())
	};
	let (public_key, pool, held, dirty) = (STANDARD.encode(public), app.settings().pool_v4, app.clone(), app.dirty.clone());
	let device = app.db.call(move |db| -> Result<DeviceRow, Failure> {
		let keys = held.keys.as_ref().expect("checked before the lookup");
		let user = UserRow::load(db, id)?;
		let total: i64 = db.query_row("select count(*) from devices where user_id = ?", [id], |row| row.get(0))?;
		if total >= if user.device_limit == 0 {16} else {user.device_limit.min(16)} {return Err(Failure::conflict("Every device place of this account is taken."))}
		let address = subs::allocate(db, &pool).ok_or_else(|| Failure::conflict("The address pool is full."))?;
		db.execute("insert into devices (user_id, name, public_key, secret_hash, address, transport_secret, private_key, state, token_gen, created, confirmed_at) values (?, ?, ?, ?, ?, ?, ?, 'enrolled', ?, ?, ?)", params![id, veilway_proto::control::display(&input.name, 32, 128), public_key, keys.device_secret_hash(&crypto::random::<16>()).as_slice(), address, keys.seal_secret(&user.record_id, &format!("transport_secret:{public_key}"), &crypto::random::<32>()), keys.seal_secret(&user.record_id, &format!("private_key:{public_key}"), &secret), user.token_gen, now(), now()])?;
		audit(db, &ctx.actor, &ctx.source, "device.create", &format!("user:{id}"), "key made by the panel");
		dirty.store(true, Ordering::Relaxed);
		DeviceRow::for_user(db, id)?.into_iter().find(|device| device.public_key == public_key).ok_or_else(|| Failure::internal("the new device is gone"))
	}).await??;
	ok(&DeviceCreated {device: device_out(&device), weaker: true, node: push(&app).await})
}

pub async fn remove_device(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path((id, device)): Path<(i64, i64)>) -> Result<Response, Failure> {
	let dirty = app.dirty.clone();
	app.db.call(move |db| -> Result<(), Failure> {
		if db.execute("delete from devices where id = ? and user_id = ?", params![device, id])? == 0 {return Err(Failure::missing("device"))}
		audit(db, &ctx.actor, &ctx.source, "device.remove", &format!("user:{id}"), &format!("device:{device}"));
		dirty.store(true, Ordering::Relaxed);
		Ok(())
	}).await??;
	ok(&Deleted {node: push(&app).await})
}

#[derive(Serialize, JsonSchema)]
pub struct Exported {
	/// A whole signed document in a link, when it is small enough for one. Null otherwise.
	pub link: Option<String>,
	/// The same as the content of a file the client imports.
	pub file: String,
}

/// The signed document of a device whose key the panel made, for a client that has no endpoint to enroll with. It holds the private key.
pub async fn export_device(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path((id, device)): Path<(i64, i64)>) -> Result<Response, Failure> {
	let (user, row) = app.db.call(move |db| -> Result<(UserRow, DeviceRow), Failure> {
		Ok((UserRow::load(db, id)?, DeviceRow::for_user(db, id)?.into_iter().find(|row| row.id == device).ok_or_else(|| Failure::missing("device"))?))
	}).await??;
	if row.private_key.is_none() {return Err(Failure::bad("This device made its own key, so there is no private key to export."))}
	let (signing, signer) = {
		let held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let signing: Vec<_> = held.current().into_iter().cloned().collect();
		(signing.clone(), signing.last().cloned().ok_or_else(|| Failure::internal("no signing key"))?)
	};
	let document = subs::document(&app, &user, &row, &signing, &signer, subs::Form::Whole, node::usage(&app).await.get(&user.name)).await.map_err(Failure::bad)?;
	let carried = Carried::file(format!("v1.{}.{}", URL_SAFE_NO_PAD.encode(signer.public()), document).as_bytes()).map_err(|error| Failure::bad(error.to_string()))?;
	app.db.audit(&ctx.actor, &ctx.source, "device.export", &format!("user:{id}"), &format!("device:{device}")).await;
	ok(&Exported {link: carried.veilway(), file: carried.file_content()})
}

#[derive(Serialize, JsonSchema)]
pub struct SubscriptionInfo {
	pub subscription_id: String, pub endpoint_url: String, pub token_generation: i64, pub token_created: i64,
	/// Whether the panel holds a sealed copy, so the link can be shown again. False with "show links once".
	pub can_show: bool,
	/// Fingerprints of the current signing keys, which are not secret.
	pub key_fingerprints: Vec<String>,
}

pub async fn sub_info(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let fingerprints = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).current().iter().map(|entry| entry.proto().fingerprint().to_string()).collect();
	ok(&SubscriptionInfo {subscription_id: user.sub_id, endpoint_url: app.settings().endpoint_url, token_generation: user.token_gen, token_created: user.token_created, can_show: user.token_copy.is_some() && app.keys.is_some(), key_fingerprints: fingerprints})
}

/// Opening the sealed copy is an export of a secret: the route needs a recent re-authentication, and the audit log says that a link was shown, not what it was.
pub async fn sub_show(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let user = app.db.call(move |db| UserRow::load(db, id)).await??;
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	let token = user.token_copy.as_deref().and_then(|copy| keys.open_copy(&user.record_id, copy)).ok_or_else(|| Failure::new(StatusCode::GONE, "no_copy", "No copy of this link is kept. Reset the link to get a new one."))?;
	app.db.audit(&ctx.actor, &ctx.source, "link.show", &format!("user:{id}"), "").await;
	ok(&view(&app.settings(), &app, &token).map_err(Failure::bad)?)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedIn {
	/// At least 10 characters. It locks the file and the panel keeps no copy of it, so it cannot be recovered. Send it another way than the file.
	pub password: String,
	/// The user's current link in the `veilway` form, for a link the panel keeps no copy of: one just made, or any link when the panel shows links once. It has to be the user's current token. Left out, the panel opens its own sealed copy.
	pub link: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct Sealed {
	pub filename: String,
	/// The sealed file, standard base64.
	pub file: String,
}

/// Each file runs a memory-hard hash of 64 MiB, so one at a time.
static SEALING: Semaphore = Semaphore::const_new(1);

/// A sealed subscription file of the user's link (subscription format page, "Sealed subscription file"). It is an export of a secret like `sub_show`: the route needs a recent re-authentication, and the audit log says that a file was made, never the password or the link.
pub async fn sub_sealed(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<SealedIn>) -> Result<Response, Failure> {
	if input.password.chars().count() < sealed_file::PASSWORD_MIN || input.password.len() > sealed_file::PASSWORD_MAX {return Err(Failure::bad(format!("The password needs at least {} characters and at most {} bytes.", sealed_file::PASSWORD_MIN, sealed_file::PASSWORD_MAX)))}
	let _turn = SEALING.try_acquire().map_err(|_| Failure::conflict("Another sealed file is being made."))?;
	let (user, lookup) = app.db.call(move |db| -> rusqlite::Result<(UserRow, Vec<u8>)> {
		Ok((UserRow::load(db, id)?, db.query_row("select token_lookup from users where id = ?", [id], |row| row.get::<_, Vec<u8>>(0))?))
	}).await??;
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	// Only the token is taken from a link the browser sends, and only when it is this user's current one. The endpoint, key and pin of the file are always the panel's own.
	let token = match input.link {
		Some(text) => match Link::parse(text.trim()) {
			Ok(Link::Native(native)) if bool::from(keys.token_lookup(native.token().expose()).as_slice().ct_eq(&lookup)) => *native.token().expose(),
			_ => return Err(Failure::bad("That is not this user's current link.")),
		},
		None => user.token_copy.as_deref().and_then(|copy| keys.open_copy(&user.record_id, copy)).ok_or_else(|| Failure::new(StatusCode::GONE, "no_copy", "No copy of this link is kept. Reset the link to get a new one, or send the link you just made."))?,
	};
	let key = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).current().last().cloned().cloned().ok_or_else(|| Failure::bad("no signing key"))?;
	let link = subs::link(&app.settings(), &key, &token).map_err(Failure::bad)?.veilway;
	let (salt, nonce) = (crypto::random::<16>(), crypto::random::<12>());
	let file = tokio::task::spawn_blocking(move || sealed_file::seal(&input.password, &link, salt, nonce)).await.map_err(Failure::internal)?.map_err(Failure::internal)?;
	app.db.audit(&ctx.actor, &ctx.source, "link.sealed", &format!("user:{id}"), "").await;
	ok(&Sealed {filename: format!("veilway-{}.vwsealed", user.name), file: STANDARD.encode(file)})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResetLink {
	/// Remove the devices that were enrolled with the old link. They are listed in the answer either way.
	#[serde(default)] pub remove_devices: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct LinkReset {pub link: Option<LinkView>, pub link_error: Option<String>, pub old_devices: Vec<DeviceOut>, pub removed: bool, pub node: NodeState}

pub async fn sub_reset(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<ResetLink>) -> Result<Response, Failure> {
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	let (settings, token, held, cache, dirty) = (app.settings(), crypto::random::<16>(), app.clone(), app.settings.clone(), app.dirty.clone());
	let (lookup, remove_devices) = (keys.token_lookup(&token), input.remove_devices);
	let old = app.db.call(move |db| -> Result<Vec<DeviceRow>, Failure> {
		let keys = held.keys.as_ref().expect("checked before the lookup");
		let user = UserRow::load(db, id)?;
		let once = cache.read().unwrap_or_else(|poisoned| poisoned.into_inner()).show_links_once;
		let copy = (!once).then(|| keys.seal_copy(&user.record_id, &token));
		let old: Vec<DeviceRow> = DeviceRow::for_user(db, id)?.into_iter().filter(|device| device.token_gen == user.token_gen).collect();
		db.execute("update users set token_lookup = ?, token_copy = ?, token_gen = token_gen + 1, token_created = ? where id = ?", params![lookup.as_slice(), copy, now(), id])?;
		if remove_devices {db.execute("delete from devices where user_id = ? and token_gen = ?", params![id, user.token_gen])?;}
		// A link that was reset is a link that may have leaked, and the Xray share links are the same user's, so they are made new with it and the push below carries them to the node.
		db.execute("delete from xray_clients where user_id = ?", [id])?;
		audit(db, &ctx.actor, &ctx.source, "link.reset", &format!("user:{id}"), &format!("{} devices of the old link, removed: {}, Xray credentials made new", old.len(), remove_devices));
		dirty.store(true, Ordering::Relaxed);
		Ok(old)
	}).await??;
	let (link, link_error) = match view(&settings, &app, &token) {Ok(link) => (Some(link), None), Err(error) => (None, Some(error))};
	ok(&LinkReset {link, link_error, old_devices: old.iter().map(device_out).collect(), removed: input.remove_devices, node: push(&app).await})
}
