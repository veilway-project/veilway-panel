//! Golden tests: a fixture database in the layout of schema version 2 (what shipped before several nodes), and the outputs of the panel for it. Each must stay byte-identical across the move to the node abstraction and the migration to node 1. Set `VEILWAY_GOLDEN_WRITE=1` to write the files again, only when a change is meant to alter an output.
use axum::{body::Body, extract::{ConnectInfo, State}, http::{header::{CONTENT_TYPE, COOKIE, HOST, SET_COOKIE}, HeaderMap, Method, Request, StatusCode}, routing::get, Json, Router};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{net::SocketAddr, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use tower::ServiceExt;
use veilway_panel::{app::{App, Node, LOCAL}, build, node, config::Config, crypto::{self, Keys}, router, subs::{self, DeviceRow, Form, UserRow}};
use veilway_proto::subscription::{envelope::{self, SigningKey}, BODY_MAX};

const PASSWORD: &str = "correct horse battery";
const SCHEMA_V2: &str = include_str!("golden/schema_v2.sql");

struct FakeNode {document: Mutex<Value>, generation: Mutex<u64>, applied: Mutex<Vec<Value>>}

fn node_document() -> Value {
	json!({"version": 1, "dns": {}, "inbounds": [
		{"tag": "Main", "type": "veilway", "private_key": "<redacted>", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "udp-obfs", "listen": "0.0.0.0:51821"}]},
		{"tag": "Second", "type": "veilway", "private_key": "<redacted>", "address": ["10.9.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51822"}]}
	], "outbounds": [{"tag": "plain", "type": "direct"}], "exits": [{"tag": "main"}], "routing": {"default": "main", "rules": []}, "xray": {"inbounds": [{"tag": "xr", "protocol": "vless", "clients": []}]}, "users": [{"name": "ghost"}]})
}

async fn start_node(dir: &Path) -> (Arc<FakeNode>, PathBuf) {
	let socket = dir.join("control.sock");
	let node = Arc::new(FakeNode {document: Mutex::new(node_document()), generation: Mutex::new(1), applied: Mutex::new(Vec::new())});
	let router = Router::new()
		.route("/v1/config", get(|State(node): State<Arc<FakeNode>>| async move {
			let generation = *node.generation.lock().unwrap();
			Json(json!({"revision": format!("rev{generation}"), "generation": generation, "document": node.document.lock().unwrap().clone()}))
		}).put(|State(node): State<Arc<FakeNode>>, headers: HeaderMap, Json(document): Json<Value>| async move {
			let mut generation = node.generation.lock().unwrap();
			if headers.get("if-match").unwrap() != &format!("\"rev{generation}\"") {return (StatusCode::CONFLICT, Json(json!({"error": {"code": "stale"}})))}
			*generation += 1;
			node.applied.lock().unwrap().push(document.clone());
			*node.document.lock().unwrap() = document;
			(StatusCode::OK, Json(json!({"revision": format!("rev{generation}"), "generation": *generation, "saved": true, "diff": {}, "report": {}})))
		}))
		.route("/v1/status", get(|| async {Json(json!({"version": "0.0.0", "uptime_secs": 5, "generation": 1}))}))
		.route("/v1/users", get(|| async {Json(json!({"users": [{"name": "alice", "used_bytes": 1234, "up_bytes": 200, "down_bytes": 1034, "quota_bytes": 5000000000u64}, {"name": "bob", "used_bytes": 7, "up_bytes": 3, "down_bytes": 4}]}))}))
		.route("/v1/inbounds", get(|State(node): State<Arc<FakeNode>>| async move {Json(json!({"inbounds": node.document.lock().unwrap()["inbounds"].as_array().into_iter().flatten().map(|inbound| json!({"tag": inbound["tag"], "kind": inbound["type"], "public_key": STANDARD.encode([9u8; 32]), "transport_public_key": null, "transports": []})).collect::<Vec<_>>(), "public_addresses": []}))}))
		.route("/v1/exits", get(|| async {Json(json!({"exits": [{"tag": "main", "udp": true}]}))}))
		.route("/v1/links", get(|| async {Json(json!({"links": []}))}))
		.with_state(node.clone());
	let listener = tokio::net::UnixListener::bind(&socket).unwrap();
	tokio::spawn(async move {axum::serve(listener, router).await.unwrap();});
	(node, socket)
}

fn keys_file(path: &Path) -> Keys {
	crypto::write_private(path, &[[1u8; 32], [2u8; 32], [3u8; 32]].concat(), false).unwrap();
	Keys::load(path).unwrap()
}

/// The database of a panel that ran before several nodes: three accounts, five devices (one pending, one with a key the panel made, addresses in two pools' worth of places), a proxy password, an Xray inbound and its clients, and settings with two published profiles.
fn fixture(cfg: &Config) {
	let keys = keys_file(&cfg.keys);
	let seed = URL_SAFE_NO_PAD.encode([9u8; 32]);
	crypto::write_private(&cfg.signing, json!([{"seed": seed, "created": 1_700_000_000, "retired_at": null}]).to_string().as_bytes(), false).unwrap();
	let db = Connection::open(&cfg.database).unwrap();
	db.execute_batch(SCHEMA_V2).unwrap();
	db.pragma_update(None, "user_version", 2).unwrap();
	let settings = json!({"provider_name": "Golden Net", "endpoints": [{"name": "main", "url": "https://panel.example.org/s", "pins": []}], "default_endpoint": "main", "pool_v4": "10.66.0.0/24", "node_host": "192.0.2.10", "default_device_limit": 3, "document_days": 14, "update_interval": 3600,
		"relays": [{"name": "edge", "address": "198.51.100.7", "enabled": true}],
		"relay_profiles": {"main": "Main", "second": "Second"}, "inbound_ranges": {"Main": "10.66.0.1/24", "Second": "10.9.0.1/24"},
		"profiles": [
			{"id": "main", "name": "Main", "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}, {"type": "udp-obfs", "endpoints": ["192.0.2.10:51821"]}]},
			{"id": "second", "name": "Second", "type": "veilway", "inbound_public_key": STANDARD.encode([8u8; 32]), "gateways": ["10.9.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51822"]}]}
		]});
	db.execute("insert into settings (key, value) values ('settings', ?)", [settings.to_string()]).unwrap();
	for (id, name, enabled, groups, quota, period, expires, proxy) in [(1, "alice", true, "[\"office\"]", Some(5_000_000_000i64), Some("monthly"), None, true), (2, "bob", true, "[]", None, None, Some(4_102_444_800i64), false), (3, "carol", false, "[]", None, None, None, false)] {
		let record = [id as u8; 16];
		let token = [id as u8 + 100; 16];
		let proxy = proxy.then(|| keys.seal_secret(&record, "proxy_password", b"proxy-password-of-alice-1234567890"));
		db.execute("insert into users (id, name, enabled, groups, exits, quota_bytes, quota_period, expires_at, device_limit, note, created, record_id, sub_id, token_lookup, token_copy, token_gen, token_created, proxy_password) values (?, ?, ?, ?, '\"all\"', ?, ?, ?, 3, '', ?, ?, ?, ?, ?, 1, ?, ?)", params![id, name, enabled, groups, quota, period, expires, 1_700_000_000 + id, record.to_vec(), format!("sub-{name}"), keys.token_lookup(&token).to_vec(), keys.seal_copy(&record, &token), 1_700_000_000 + id, proxy]).unwrap();
	}
	db.execute("update users set default_exit = 'main' where id = 1", []).unwrap();
	for (id, user, address, state, own_key) in [(1, 1, "10.66.0.2", "enrolled", false), (2, 1, "10.66.0.5", "enrolled", true), (3, 2, "10.66.0.3", "enrolled", false), (4, 2, "10.66.0.4", "pending", false), (5, 2, "10.66.0.9", "enrolled", false)] {
		let record = [user as u8; 16];
		let public = STANDARD.encode([id as u8 + 20; 32]);
		let private = own_key.then(|| keys.seal_secret(&record, format!("private_key:{public}"), &[id as u8 + 40; 32]));
		db.execute("insert into devices (id, user_id, name, public_key, secret_hash, address, transport_secret, private_key, state, token_gen, created, confirmed_at, last_seen) values (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)", params![id, user, format!("device {id}"), public, vec![id as u8; 32], address, keys.seal_secret(&record, format!("transport_secret:{public}"), &[id as u8 + 60; 32]), private, state, if state == "pending" {4_102_444_800i64} else {1_700_000_100 + id}, (state == "enrolled").then_some(1_700_000_200 + id), (id == 1).then_some(1_700_000_300i64)]).unwrap();
	}
	db.execute("insert into xray_inbounds (tag, protocol, host, created) values ('xr', 'vless', '', 1700000000)", []).unwrap();
	for user in [1, 2] {db.execute("insert into xray_clients (tag, user_id, secret) values ('xr', ?, ?)", params![user, keys.seal_secret(&[user as u8; 16], "xray:xr", format!("00000000-0000-4000-8000-00000000000{user}").as_bytes())]).unwrap();}
}

struct Panel {app: Arc<App>, router: Router, cookie: String, csrf: String, dir: PathBuf, node: Arc<FakeNode>}

impl Panel {
	async fn start() -> Self {
		let dir = std::env::temp_dir().join(format!("vwgolden-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		std::fs::create_dir_all(&dir).unwrap();
		let (node, socket) = start_node(&dir).await;
		let cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), gateway: dir.join("gateway.keys"), gateway_next: dir.join("gateway.next"), node_socket: socket, ..Config::default()};
		fixture(&cfg);
		let app = build(cfg).unwrap();
		let router = router(app.clone());
		let mut panel = Self {app, router, cookie: String::new(), csrf: String::new(), dir, node};
		let token = panel.app.setup_token.lock().unwrap().clone().unwrap();
		let setup = panel.call(Method::POST, "/p/api/setup", Some(json!({"token": token, "username": "owner", "password": PASSWORD, "accepted_terms": true}))).await;
		let secret = data_encoding::BASE32_NOPAD.decode(setup["totp_secret"].as_str().unwrap().as_bytes()).unwrap();
		let code = format!("{:06}", crypto::totp_at(&secret, (crypto::now() / 30) as u64));
		let request = Request::builder().method(Method::POST).uri("/p/api/login").header(HOST, "panel.test").header(CONTENT_TYPE, "application/json");
		let mut request = request.body(Body::from(json!({"username": "owner", "password": PASSWORD, "totp": code}).to_string())).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>("10.0.0.1:5000".parse().unwrap()));
		let response = panel.router.clone().oneshot(request).await.unwrap();
		let cookie = response.headers().get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
		let body: Value = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
		(panel.cookie, panel.csrf) = (cookie, body["csrf"].as_str().unwrap().to_string());
		panel
	}
	async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Value {
		let mut request = Request::builder().method(method.clone()).uri(path).header(HOST, "panel.test");
		if !self.cookie.is_empty() {
			request = request.header(COOKIE, &self.cookie);
			if method != Method::GET {request = request.header("x-csrf-token", &self.csrf);}
		}
		if body.is_some() {request = request.header(CONTENT_TYPE, "application/json");}
		let mut request = request.body(Body::from(body.map(|body| body.to_string()).unwrap_or_default())).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>("10.0.0.1:5000".parse().unwrap()));
		let response = self.router.clone().oneshot(request).await.unwrap();
		let status = response.status();
		let bytes = response.into_body().collect().await.unwrap().to_bytes();
		assert_eq!(status, StatusCode::OK, "{} {}", path, String::from_utf8_lossy(&bytes));
		serde_json::from_slice(&bytes).unwrap()
	}
}

impl Drop for Panel {
	fn drop(&mut self) {let _ = std::fs::remove_dir_all(&self.dir);}
}

/// Compares an output with its golden file, byte for byte. With `VEILWAY_GOLDEN_WRITE=1` the file is written instead.
fn golden(name: &str, value: &Value) {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(name);
	let text = format!("{}\n", serde_json::to_string_pretty(value).unwrap());
	if std::env::var("VEILWAY_GOLDEN_WRITE").is_ok() {return std::fs::write(&path, text).unwrap()}
	assert!(std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{name}: {error}")) == text, "{name} differs from its golden file");
}

#[tokio::test]
async fn the_node_document_the_panel_pushes_is_the_golden_one() {
	let panel = Panel::start().await;
	panel.call(Method::POST, "/p/api/node/sync", None).await;
	let pushed = panel.node.applied.lock().unwrap().last().cloned().unwrap();
	golden("node_document.json", &pushed);
}

#[tokio::test]
async fn derived_profiles_and_the_account_views_are_the_golden_ones() {
	let panel = Panel::start().await;
	golden("derived_profiles.json", &panel.call(Method::GET, "/p/api/profiles/derived", None).await);
	golden("users.json", &panel.call(Method::GET, "/p/api/users", None).await);
	let mut views = Vec::new();
	for id in 1..=3 {views.push(json!({"user": panel.call(Method::GET, &format!("/p/api/users/{id}"), None).await, "devices": panel.call(Method::GET, &format!("/p/api/users/{id}/devices"), None).await}));}
	golden("user_views.json", &Value::Array(views));
}

#[tokio::test]
async fn the_subscription_documents_of_every_enrolled_device_are_the_golden_ones() {
	let panel = Panel::start().await;
	let signing = panel.app.signing.lock().unwrap().entries.clone();
	let held: Vec<SigningKey> = signing.iter().map(|entry| entry.proto()).collect();
	let used = json!({"name": "alice", "used_bytes": 1234, "up_bytes": 200, "down_bytes": 1034, "quota_bytes": 5000000000u64});
	let mut documents = Vec::new();
	for user in 1..=2i64 {
		let row = panel.app.db.call(move |db| UserRow::load(db, user)).await.unwrap().unwrap();
		let devices = panel.app.db.call(move |db| DeviceRow::for_user(db, user)).await.unwrap().unwrap();
		for device in devices.iter().filter(|device| device.state == "enrolled") {
			let text = subs::document(&panel.app, &row, device, &signing, &signing[0], Form::Whole, Some(&used), None).await.unwrap();
			let mut payload: Value = serde_json::from_slice(envelope::verify(text.as_bytes(), &held, BODY_MAX).unwrap().payload()).unwrap();
			for volatile in ["serial", "issued_at", "expires_at"] {payload[volatile] = json!(0);}
			documents.push(json!({"user": row.name, "device": device.id, "payload": payload}));
		}
	}
	assert_eq!(documents.len(), 4);
	golden("subscription_documents.json", &Value::Array(documents));
}

#[tokio::test]
async fn only_node_1_can_be_reached_and_a_push_is_written_to_its_row() {
	let panel = Panel::start().await;
	assert!(node::request(&panel.app, Node(2), "GET", "/v1/status", None, None).await.unwrap_err().contains("node 2 cannot be reached"));
	assert_eq!(node::request(&panel.app, LOCAL, "GET", "/v1/status", None, None).await.unwrap().0, 200);
	panel.call(Method::POST, "/p/api/node/sync", None).await;
	let (revision, seen, failure): (Option<String>, Option<i64>, Option<String>) = panel.app.db.call(|db| db.query_row("select config_rev, last_seen, last_error from nodes where id = 1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))).await.unwrap().unwrap();
	assert_eq!((revision, seen.is_some(), failure), (Some("rev2".into()), true, None));
}

#[tokio::test]
async fn the_pool_setting_is_the_pool_of_node_1_and_new_devices_take_addresses_from_it() {
	let panel = Panel::start().await;
	let pool = |panel: &Panel| panel.app.db.blocking(|db| db.query_row("select pool_v4 from nodes where id = 1", [], |row| row.get::<_, String>(0)).unwrap()).unwrap();
	assert_eq!(pool(&panel), "10.66.0.0/24");
	let mut settings = panel.call(Method::GET, "/p/api/settings", None).await;
	settings["pool_v4"] = json!("10.77.0.0/24");
	panel.call(Method::PUT, "/p/api/settings", Some(settings)).await;
	assert_eq!(pool(&panel), "10.77.0.0/24");
	let made = panel.call(Method::POST, "/p/api/users/3/devices", Some(json!({"name": "new"}))).await;
	assert_eq!(made["device"]["address"], "10.77.0.2", "the first host after the gateway of the new pool");
}
