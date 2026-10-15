//! Users, their devices and their subscription links.
use crate::{app::App, crypto::{self, now}, db::audit, http::{ok, Body, Ctx, Failure}, node, subs::{self, DeviceRow, UserRow, USER_COLUMNS}};
use axum::{extract::{Path, Query, State}, http::StatusCode, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use veilway_proto::subscription::link::Carried;

/// Whether the node took the change. The panel's database is changed either way and the next successful push brings the node up to date.
#[derive(Serialize, JsonSchema)]
pub struct NodeState {pub synced: bool, pub error: Option<String>}

pub async fn push(app: &Arc<App>) -> NodeState {
	match node::sync(app).await {Ok(()) => NodeState {synced: true, error: None}, Err(error) => NodeState {synced: false, error: Some(error)}}
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
	pub quota_bytes: Option<i64>, pub quota_period: Option<String>, pub expires_at: Option<i64>,
	/// 0 is no limit beyond the node's own 16.
	pub device_limit: i64, pub note: String, pub created: i64, pub subscription_id: String,
	pub devices: i64, pub pending_devices: i64,
	/// The node's own record of the user: usage, denial and traffic. Null when the node cannot be reached.
	pub node: Option<Value>,
}

fn out(user: &UserRow, devices: i64, pending: i64, node: Option<Value>) -> UserOut {
	UserOut {id: user.id, name: user.name.clone(), enabled: user.enabled, groups: serde_json::from_str(&user.groups).unwrap_or_default(), exits: serde_json::from_str(&user.exits).unwrap_or(json!("all")), quota_bytes: user.quota_bytes, quota_period: user.quota_period.clone(), expires_at: user.expires_at, device_limit: user.device_limit, note: user.note.clone(), created: user.created, subscription_id: user.sub_id.clone(), devices, pending_devices: pending, node}
}

fn counts(app: &App, id: i64) -> (i64, i64) {
	app.db.lock().query_row("select count(*), coalesce(sum(state = 'pending'), 0) from devices where user_id = ?", [id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap_or((0, 0))
}

#[derive(Deserialize, JsonSchema)]
pub struct UserQuery {pub q: Option<String>, pub group: Option<String>, pub enabled: Option<bool>}

#[derive(Serialize, JsonSchema)]
pub struct UsersOut {pub users: Vec<UserOut>}

pub async fn list(State(app): State<Arc<App>>, Query(query): Query<UserQuery>) -> Result<Response, Failure> {
	let rows: Vec<UserRow> = {
		let db = app.db.lock();
		let mut statement = db.prepare(&format!("select {USER_COLUMNS} from users order by name"))?;
		let rows = statement.query_map([], UserRow::read)?.collect::<Result<_, _>>()?;
		rows
	};
	let nodes = node::usage(&app).await;
	let users = rows.iter().filter(|user| query.q.as_ref().is_none_or(|q| user.name.contains(q.as_str())) && query.enabled.is_none_or(|enabled| user.enabled == enabled) && query.group.as_ref().is_none_or(|group| serde_json::from_str::<Vec<String>>(&user.groups).unwrap_or_default().contains(group))).map(|user| {
		let (devices, pending) = counts(&app, user.id);
		out(user, devices, pending, nodes.get(&user.name).cloned())
	}).collect();
	ok(&UsersOut {users})
}

pub async fn get(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let user = UserRow::load(&app.db.lock(), id)?;
	let (devices, pending) = counts(&app, id);
	ok(&out(&user, devices, pending, node::usage(&app).await.remove(&user.name)))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserIn {
	pub name: String, pub enabled: Option<bool>, pub groups: Option<Vec<String>>, pub exits: Option<Value>,
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
	#[serde(default, deserialize_with = "double")] pub quota_bytes: Option<Option<u64>>,
	#[serde(default, deserialize_with = "double")] pub quota_period: Option<Option<String>>,
	#[serde(default, deserialize_with = "double")] pub expires_at: Option<Option<i64>>,
	pub device_limit: Option<u16>, pub note: Option<String>,
}

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
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing, so no account can be made."))?;
	let settings = app.settings();
	let (token, record, sub_id) = (crypto::random::<16>(), crypto::random::<16>(), URL_SAFE_NO_PAD.encode(crypto::random::<16>()));
	let copy = (!settings.show_links_once).then(|| keys.seal_copy(&record, &token));
	let id = {
		let db = app.db.lock();
		db.execute("insert into users (name, enabled, groups, exits, quota_bytes, quota_period, expires_at, device_limit, note, created, record_id, sub_id, token_lookup, token_copy, token_created) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", params![input.name, input.enabled.unwrap_or(true), serde_json::to_string(&input.groups.unwrap_or_default()).unwrap_or_default(), serde_json::to_string(&input.exits.unwrap_or(json!("all"))).unwrap_or_default(), input.quota_bytes.map(|quota| quota as i64), input.quota_bytes.and(input.quota_period), input.expires_at, input.device_limit.unwrap_or(settings.default_device_limit), input.note.unwrap_or_default(), now(), record.as_slice(), sub_id, keys.token_lookup(&token).as_slice(), copy, now()])?;
		let id = db.last_insert_rowid();
		audit(&db, &ctx.actor, &ctx.source, "user.create", &format!("user:{id}"), &input.name);
		id
	};
	let user = UserRow::load(&app.db.lock(), id)?;
	let (link, link_error) = match view(&settings, &app, &token) {Ok(link) => (Some(link), None), Err(error) => (None, Some(error))};
	ok(&Created {user: out(&user, 0, 0, None), link, link_error})
}

#[derive(Serialize, JsonSchema)]
pub struct Changed {pub user: UserOut, pub node: NodeState}

pub async fn patch(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<UserPatch>) -> Result<Response, Failure> {
	let user = UserRow::load(&app.db.lock(), id)?;
	let quota = input.quota_bytes.unwrap_or(user.quota_bytes.map(|quota| quota as u64));
	let period = input.quota_period.unwrap_or(user.quota_period.clone());
	check(input.groups.as_ref(), input.exits.as_ref(), quota, period.as_deref())?;
	if input.name.as_ref().is_some_and(|name| !name_ok(name, true)) {return Err(Failure::bad("name is 1 to 64 characters of a-z, 0-9, dot, dash and underscore, starting with a letter or digit."))}
	{
		let db = app.db.lock();
		db.execute("update users set name = ?, enabled = ?, groups = ?, exits = ?, quota_bytes = ?, quota_period = ?, expires_at = ?, device_limit = ?, note = ? where id = ?", params![input.name.unwrap_or(user.name.clone()), input.enabled.unwrap_or(user.enabled), input.groups.map_or(user.groups.clone(), |groups| serde_json::to_string(&groups).unwrap_or_default()), input.exits.map_or(user.exits.clone(), |exits| serde_json::to_string(&exits).unwrap_or_default()), quota.map(|quota| quota as i64), quota.and(period), input.expires_at.unwrap_or(user.expires_at), input.device_limit.map_or(user.device_limit, i64::from), input.note.unwrap_or(user.note.clone()), id])?;
		audit(&db, &ctx.actor, &ctx.source, "user.update", &format!("user:{id}"), &user.name);
	}
	let node = push(&app).await;
	let user = UserRow::load(&app.db.lock(), id)?;
	let (devices, pending) = counts(&app, id);
	ok(&Changed {user: out(&user, devices, pending, None), node})
}

#[derive(Serialize, JsonSchema)]
pub struct Deleted {pub node: NodeState}

pub async fn remove(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	{
		let db = app.db.lock();
		let name: String = db.query_row("select name from users where id = ?", [id], |row| row.get(0))?;
		db.execute("delete from users where id = ?", [id])?;
		audit(&db, &ctx.actor, &ctx.source, "user.delete", &format!("user:{id}"), &name);
	}
	ok(&Deleted {node: push(&app).await})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bulk {
	pub ids: Vec<i64>,
	/// enable, disable, delete, reset_usage, add_group, remove_group, set_quota, set_expiry or set_device_limit.
	pub action: String,
	/// The group name, the quota (an object with quota_bytes and quota_period), the expiry in Unix seconds or null, or the device limit.
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
			let user = UserRow::load(&app.db.lock(), *id).map_err(|_| "no such user".to_string())?;
			let value = input.value.clone();
			match input.action.as_str() {
				"enable" | "disable" => {app.db.lock().execute("update users set enabled = ? where id = ?", params![input.action == "enable", id]).map_err(|error| error.to_string())?;}
				"delete" => {app.db.lock().execute("delete from users where id = ?", [id]).map_err(|error| error.to_string())?;}
				"reset_usage" => {let (status, _) = node::request(&app.cfg.node_socket, "POST", &format!("/v1/users/{}/usage/reset", user.name), None, Some(&json!({"totals": false}))).await?; if status != 200 {return Err(format!("the node answered {status}"))}}
				"add_group" | "remove_group" => {
					let group = value.as_ref().and_then(Value::as_str).filter(|group| name_ok(group, true)).ok_or("value is a group name")?;
					let mut groups: Vec<String> = serde_json::from_str(&user.groups).unwrap_or_default();
					groups.retain(|held| held != group);
					if input.action == "add_group" {groups.push(group.to_string());}
					check(Some(&groups), None, None, None).map_err(|error| error.message)?;
					app.db.lock().execute("update users set groups = ? where id = ?", params![serde_json::to_string(&groups).unwrap_or_default(), id]).map_err(|error| error.to_string())?;
				}
				"set_quota" => {
					let quota = value.as_ref().and_then(|value| value.get("quota_bytes")).and_then(Value::as_u64);
					let period = value.as_ref().and_then(|value| value.get("quota_period")).and_then(Value::as_str);
					check(None, None, quota, period).map_err(|error| error.message)?;
					app.db.lock().execute("update users set quota_bytes = ?, quota_period = ? where id = ?", params![quota.map(|quota| quota as i64), period.filter(|_| quota.is_some()), id]).map_err(|error| error.to_string())?;
				}
				"set_expiry" => {app.db.lock().execute("update users set expires_at = ? where id = ?", params![value.as_ref().and_then(Value::as_i64), id]).map_err(|error| error.to_string())?;}
				"set_device_limit" => {app.db.lock().execute("update users set device_limit = ? where id = ?", params![value.as_ref().and_then(Value::as_u64).filter(|limit| *limit <= 65535).ok_or("value is a number from 0 to 65535")?, id]).map_err(|error| error.to_string())?;}
				other => return Err(format!("unknown action {other}")),
			}
			Ok(())
		}.await;
		match result {Ok(()) => done += 1, Err(error) => failed.push(BulkFailure {id: *id, error})}
	}
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "user.bulk", &input.action, &format!("{} users, {} failed", input.ids.len(), failed.len()));
	ok(&BulkResult {done, failed, node: push(&app).await})
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ResetUsage {#[serde(default)] pub totals: bool}

pub async fn reset_usage(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<ResetUsage>) -> Result<Response, Failure> {
	let user = UserRow::load(&app.db.lock(), id)?;
	let (status, body) = node::request(&app.cfg.node_socket, "POST", &format!("/v1/users/{}/usage/reset", user.name), None, Some(&json!({"totals": input.totals}))).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	if status != 200 {return Err(Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node answered {status}.")))}
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "user.usage_reset", &format!("user:{id}"), if input.totals {"with totals"} else {"quota count"});
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
	let db = app.db.lock();
	UserRow::load(&db, id)?;
	ok(&DevicesOut {devices: DeviceRow::for_user(&db, id)?.iter().map(device_out).collect()})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceIn {pub name: String}

#[derive(Serialize, JsonSchema)]
pub struct DeviceCreated {pub device: DeviceOut, pub weaker: bool, pub node: NodeState}

/// A device whose key the panel makes. The default is that the device enrolls itself through the endpoint, which needs nothing here.
pub async fn make_device(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<DeviceIn>) -> Result<Response, Failure> {
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	if input.name.chars().count() > 32 {return Err(Failure::bad("A device name is at most 32 characters."))}
	let (secret, public) = {
		let secret = x25519_dalek::StaticSecret::from(crypto::random::<32>());
		(secret.to_bytes(), x25519_dalek::PublicKey::from(&secret).to_bytes())
	};
	let (public_key, pool) = (STANDARD.encode(public), app.settings().pool_v4);
	let device = {
		let db = app.db.lock();
		let user = UserRow::load(&db, id)?;
		let total: i64 = db.query_row("select count(*) from devices where user_id = ?", [id], |row| row.get(0))?;
		if total >= if user.device_limit == 0 {16} else {user.device_limit.min(16)} {return Err(Failure::conflict("Every device place of this account is taken."))}
		let address = subs::allocate(&db, &pool).ok_or_else(|| Failure::conflict("The address pool is full."))?;
		db.execute("insert into devices (user_id, name, public_key, secret_hash, address, transport_secret, private_key, state, token_gen, created, confirmed_at) values (?, ?, ?, ?, ?, ?, ?, 'enrolled', ?, ?, ?)", params![id, veilway_proto::control::display(&input.name, 32, 128), public_key, keys.device_secret_hash(&crypto::random::<16>()).as_slice(), address, keys.seal_secret(&user.record_id, &format!("transport_secret:{public_key}"), &crypto::random::<32>()), keys.seal_secret(&user.record_id, &format!("private_key:{public_key}"), &secret), user.token_gen, now(), now()])?;
		audit(&db, &ctx.actor, &ctx.source, "device.create", &format!("user:{id}"), "key made by the panel");
		DeviceRow::for_user(&db, id)?.into_iter().find(|device| device.public_key == public_key).ok_or_else(|| Failure::internal("the new device is gone"))?
	};
	ok(&DeviceCreated {device: device_out(&device), weaker: true, node: push(&app).await})
}

pub async fn remove_device(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path((id, device)): Path<(i64, i64)>) -> Result<Response, Failure> {
	{
		let db = app.db.lock();
		if db.execute("delete from devices where id = ? and user_id = ?", params![device, id])? == 0 {return Err(Failure::missing("device"))}
		audit(&db, &ctx.actor, &ctx.source, "device.remove", &format!("user:{id}"), &format!("device:{device}"));
	}
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
	let (user, row) = {
		let db = app.db.lock();
		(UserRow::load(&db, id)?, DeviceRow::for_user(&db, id)?.into_iter().find(|row| row.id == device).ok_or_else(|| Failure::missing("device"))?)
	};
	if row.private_key.is_none() {return Err(Failure::bad("This device made its own key, so there is no private key to export."))}
	let (signing, signer) = {
		let held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let signing: Vec<_> = held.current().into_iter().cloned().collect();
		(signing.clone(), signing.last().cloned().ok_or_else(|| Failure::internal("no signing key"))?)
	};
	let document = subs::document(&app, &user, &row, &signing, &signer, node::usage(&app).await.get(&user.name)).map_err(Failure::bad)?;
	let carried = Carried::file(format!("v1.{}.{}", URL_SAFE_NO_PAD.encode(signer.public()), document).as_bytes()).map_err(|error| Failure::bad(error.to_string()))?;
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "device.export", &format!("user:{id}"), &format!("device:{device}"));
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
	let user = UserRow::load(&app.db.lock(), id)?;
	let fingerprints = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).current().iter().map(|entry| entry.proto().fingerprint().to_string()).collect();
	ok(&SubscriptionInfo {subscription_id: user.sub_id, endpoint_url: app.settings().endpoint_url, token_generation: user.token_gen, token_created: user.token_created, can_show: user.token_copy.is_some() && app.keys.is_some(), key_fingerprints: fingerprints})
}

/// Opening the sealed copy is an export of a secret: the route needs a recent re-authentication, and the audit log says that a link was shown, not what it was.
pub async fn sub_show(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let user = UserRow::load(&app.db.lock(), id)?;
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	let token = user.token_copy.as_deref().and_then(|copy| keys.open_copy(&user.record_id, copy)).ok_or_else(|| Failure::new(StatusCode::GONE, "no_copy", "No copy of this link is kept. Reset the link to get a new one."))?;
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "link.show", &format!("user:{id}"), "");
	ok(&view(&app.settings(), &app, &token).map_err(Failure::bad)?)
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
	let (settings, token) = (app.settings(), crypto::random::<16>());
	let old = {
		let db = app.db.lock();
		let user = UserRow::load(&db, id)?;
		let copy = (!settings.show_links_once).then(|| keys.seal_copy(&user.record_id, &token));
		let old: Vec<DeviceRow> = DeviceRow::for_user(&db, id)?.into_iter().filter(|device| device.token_gen == user.token_gen).collect();
		db.execute("update users set token_lookup = ?, token_copy = ?, token_gen = token_gen + 1, token_created = ? where id = ?", params![keys.token_lookup(&token).as_slice(), copy, now(), id])?;
		if input.remove_devices {db.execute("delete from devices where user_id = ? and token_gen = ?", params![id, user.token_gen])?;}
		// A link that was reset is a link that may have leaked, and the Xray share links are the same user's, so they are made new with it and the push below carries them to the node.
		db.execute("delete from xray_clients where user_id = ?", [id])?;
		audit(&db, &ctx.actor, &ctx.source, "link.reset", &format!("user:{id}"), &format!("{} devices of the old link, removed: {}, Xray credentials made new", old.len(), input.remove_devices));
		old
	};
	let (link, link_error) = match view(&settings, &app, &token) {Ok(link) => (Some(link), None), Err(error) => (None, Some(error))};
	ok(&LinkReset {link, link_error, old_devices: old.iter().map(device_out).collect(), removed: input.remove_devices, node: push(&app).await})
}
