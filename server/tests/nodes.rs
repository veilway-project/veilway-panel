//! Several nodes from one panel: node 1 on a fake control socket that also relays to fake remote nodes the way the core's relay route does, so the panel's per-node sync, addresses, names, secrets, usage and cut run against it.
use axum::{body::Body, extract::{ConnectInfo, Request, State}, http::{header::{CONTENT_TYPE, COOKIE, HOST, SET_COOKIE}, Method, StatusCode}, response::{IntoResponse, Response}, Json, Router};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, time::{Duration, Instant}};
use tower::ServiceExt;
use veilway_panel::{app::{App, Node, LOCAL}, build, config::{Config, Confirm}, crypto, node, router, subs::{self, DeviceRow, Form, UserRow}, upkeep_once, usage, Upkeep};
use veilway_proto::{pairing::{self, Direction, Manage, Offer, Offers, Pastes, Terms}, subscription::{envelope::{self, SigningKey}, BODY_MAX}};

const PASSWORD: &str = "correct horse battery";
/// The time a node takes a request as the confirmation of a config pushed through its link, and the time it keeps the config on trial before it puts the one before back. The panel asks at `SETTLE` and gives up well before `TRIAL`.
const SETTLE: Duration = Duration::from_millis(300);
const TRIAL: Duration = Duration::from_secs(5);

/// One fake node: the document it runs, how often it was pushed to, what its users counted and which usage resets reached it. `reset_missing` makes it lack the usage reset route and `refuse` makes it refuse every config. The config on trial is the one pushed and not confirmed yet: `confirmed` and `early` count the requests that confirmed it and the ones answered before the settle time without doing so. `hold` cuts the status answers of its link, so nothing is confirmed, and `cut` cuts the answer to the next push once it is applied.
struct Fake {document: Mutex<Value>, generation: Mutex<u64>, applied: Mutex<Vec<Value>>, users: Mutex<Vec<Value>>, resets: Mutex<Vec<(String, Value)>>, up: AtomicBool, reset_missing: AtomicBool, refuse: AtomicBool, calls: Mutex<Vec<String>>, trial: Mutex<Option<(Instant, Value)>>, confirmed: Mutex<u64>, early: Mutex<u64>, hold: AtomicBool, cut: AtomicBool}

impl Fake {
	fn new(document: Value) -> Arc<Self> {Arc::new(Self {document: Mutex::new(document), generation: Mutex::new(1), applied: Mutex::new(Vec::new()), users: Mutex::new(Vec::new()), resets: Mutex::new(Vec::new()), up: AtomicBool::new(true), reset_missing: AtomicBool::new(false), refuse: AtomicBool::new(false), calls: Mutex::new(Vec::new()), trial: Mutex::new(None), confirmed: Mutex::new(0), early: Mutex::new(0), hold: AtomicBool::new(false), cut: AtomicBool::new(false)})}
	fn last(&self) -> Value {self.applied.lock().unwrap().last().cloned().unwrap_or(Value::Null)}
	fn user_names(&self) -> Vec<String> {self.document.lock().unwrap()["users"].as_array().into_iter().flatten().map(|user| user["name"].as_str().unwrap().to_string()).collect()}
	fn user(&self, name: &str) -> Value {self.document.lock().unwrap()["users"].as_array().into_iter().flatten().find(|user| user["name"] == name).cloned().unwrap_or(Value::Null)}
	fn serve(&self, method: &Method, path: &str, if_match: Option<String>, body: Value) -> (u16, Value) {
		self.calls.lock().unwrap().push(format!("{} {path}", method.as_str()));
		if let Some((_, previous)) = self.trial.lock().unwrap().take_if(|(at, _)| at.elapsed() >= TRIAL) {
			*self.document.lock().unwrap() = previous;
			*self.generation.lock().unwrap() += 1;
		}
		match (method.as_str(), path) {
			("GET", "/v1/config") => {let generation = *self.generation.lock().unwrap(); (200, json!({"revision": format!("rev{generation}"), "generation": generation, "document": self.document.lock().unwrap().clone()}))}
			("PUT", "/v1/config") => {
				if self.refuse.load(Ordering::Relaxed) {return (500, json!({"error": {"code": "internal", "message": "refused"}}))}
				let mut generation = self.generation.lock().unwrap();
				if if_match.as_deref() != Some(&format!("\"rev{generation}\"")) {return (409, json!({"error": {"code": "stale", "message": "stale"}}))}
				*generation += 1;
				self.applied.lock().unwrap().push(body.clone());
				let previous = std::mem::replace(&mut *self.document.lock().unwrap(), body);
				*self.trial.lock().unwrap() = Some((Instant::now(), previous));
				(200, json!({"revision": format!("rev{generation}"), "generation": *generation, "saved": true, "diff": {}, "report": {}}))
			}
			("POST", "/v1/config/validate") => (200, json!({"valid": true, "report": {"errors": [], "warnings": []}})),
			("GET", "/v1/status") => {
				// Only a request from the settle time after the push confirms the config on trial: an earlier one is answered and confirms nothing.
				let settled = self.trial.lock().unwrap().as_ref().map(|(at, _)| at.elapsed() >= SETTLE);
				match settled {
					Some(true) => {self.trial.lock().unwrap().take(); *self.confirmed.lock().unwrap() += 1}
					Some(false) => *self.early.lock().unwrap() += 1,
					None => {}
				}
				let generation = *self.generation.lock().unwrap();
				(200, json!({"version": "0.3.0", "uptime_secs": 5, "generation": generation, "revision": format!("rev{generation}")}))
			}
			("GET", "/v1/users") => (200, json!({"users": self.users.lock().unwrap().clone()})),
			("GET", "/v1/inbounds") => {let document = self.document.lock().unwrap().clone(); (200, json!({"inbounds": document["inbounds"].as_array().into_iter().flatten().map(|inbound| json!({"tag": inbound["tag"], "kind": inbound["type"], "enabled": true, "public_key": STANDARD.encode([9u8; 32]), "transport_public_key": null, "transports": []})).collect::<Vec<_>>(), "public_addresses": document["public_addresses"].clone()}))}
			("GET", "/v1/exits") => (200, json!({"exits": []})),
			("GET", "/v1/stats") => (200, json!({"users": [], "inbounds": [], "exits": [], "outbounds": []})),
			("GET", "/v1/sessions") => (200, json!({"sessions": []})),
			("GET", "/v1/busy") => (503, json!({"error": {"code": "busy", "message": "the node is busy"}})),
			("GET", "/v1/upstreams") => (200, json!({"upstreams": []})),
			("POST", path) if path.starts_with("/v1/upstreams/") && path.ends_with("/retry") => (200, json!({"tag": path.trim_start_matches("/v1/upstreams/").trim_end_matches("/retry")})),
			("POST", path) if path.starts_with("/v1/users/") && path.ends_with("/usage/reset") => {if self.reset_missing.load(Ordering::Relaxed) {return (404, json!({"error": {"code": "not_found", "message": "no such route"}}))} self.resets.lock().unwrap().push((path["/v1/users/".len()..path.len() - "/usage/reset".len()].to_string(), body)); (200, json!({}))}
			_ => (404, json!({"error": {"code": "not_found", "message": "no such route"}})),
		}
	}
}

/// Node 1 and the remote nodes behind its links. `ids` gives a link another id than its tag's default, as a tag that node 1 reuses for another link has.
struct World {local: Arc<Fake>, remotes: Mutex<HashMap<String, Arc<Fake>>>, states: Mutex<HashMap<String, &'static str>>, ids: Mutex<HashMap<String, String>>}

fn document(address: &str, port: u16, exit: &str) -> Value {
	json!({"version": 1, "dns": {}, "inbounds": [{"tag": "Main", "type": "veilway", "private_key": "<redacted>", "address": [address], "transports": [{"type": "udp", "listen": format!("0.0.0.0:{port}")}]}], "outbounds": [{"tag": "plain", "type": "direct"}], "exits": [{"tag": exit}], "routing": {"default": exit, "rules": []}, "links": [], "users": []})
}

async fn relay(State(world): State<Arc<World>>, request: Request<Body>) -> Response {
	let (parts, body) = request.into_parts();
	let bytes = body.collect().await.unwrap().to_bytes();
	let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
	let if_match = parts.headers.get("if-match").map(|value| value.to_str().unwrap().to_string());
	let path = parts.uri.path().to_string();
	let answer = |(status, body): (u16, Value)| (StatusCode::from_u16(status).unwrap(), Json(body)).into_response();
	let fail = |status: u16, code: &str| (StatusCode::from_u16(status).unwrap(), [("veilway-relay", "node1")], Json(json!({"error": {"code": code, "message": code}}))).into_response();
	if let Some(rest) = path.strip_prefix("/v1/links/") {
		let (tag, rest) = rest.split_once("/api").unwrap_or((rest, ""));
		let Some(remote) = world.remotes.lock().unwrap().get(tag).cloned() else {return fail(404, "no_such_link")};
		if !remote.up.load(Ordering::Relaxed) || world.states.lock().unwrap().get(tag) != Some(&"up") || (rest == "/v1/status" && remote.hold.load(Ordering::Relaxed)) {return fail(503, "link_down")}
		let cut = parts.method == Method::PUT && remote.cut.swap(false, Ordering::Relaxed);
		let served = remote.serve(&parts.method, rest, if_match, body);
		if cut {return fail(502, "bad_answer")}
		return answer(served);
	}
	if path == "/v1/links" {
		let states = world.states.lock().unwrap().clone();
		let ids = world.ids.lock().unwrap().clone();
		let mut links: Vec<Value> = states.iter().map(|(tag, state)| json!({"tag": tag, "id": ids.get(tag).cloned().unwrap_or(format!("id-{tag}")), "manage": "peer", "state": state})).collect();
		links.extend(world.local.document.lock().unwrap()["links"].as_array().into_iter().flatten().filter(|link| !states.contains_key(link["tag"].as_str().unwrap_or_default())).map(|link| json!({"tag": link["tag"], "id": link["id"], "manage": link["manage"], "state": "up"})));
		links.sort_by_key(|link| link["tag"].as_str().unwrap().to_string());
		return answer((200, json!({"links": links})));
	}
	answer(world.local.serve(&parts.method, &path, if_match, body))
}

struct Panel {app: Arc<App>, router: Router, cookie: String, csrf: String, dir: PathBuf, world: Arc<World>}

impl Panel {
	async fn start() -> Self {
		let dir = std::env::temp_dir().join(format!("vwnodes-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		std::fs::create_dir_all(&dir).unwrap();
		let world = Arc::new(World {local: Fake::new(document("10.66.0.1/24", 51820, "main")), remotes: Mutex::new(HashMap::new()), states: Mutex::new(HashMap::new()), ids: Mutex::new(HashMap::new())});
		let socket = dir.join("control.sock");
		let listener = tokio::net::UnixListener::bind(&socket).unwrap();
		let served = Router::new().fallback(relay).with_state(world.clone());
		tokio::spawn(async move {axum::serve(listener, served).await.unwrap();});
		let cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), gateway: dir.join("gateway.keys"), gateway_next: dir.join("gateway.next"), node_socket: socket, two_step: "off".into(), confirm: Confirm {settle: SETTLE, every: Duration::from_millis(100), within: Duration::from_secs(2)}, ..Config::default()};
		let app = build(cfg).unwrap();
		let mut panel = Self {router: router(app.clone()), app, cookie: String::new(), csrf: String::new(), dir, world};
		let token = panel.app.setup_token.lock().unwrap().clone().unwrap();
		panel.call(Method::POST, "/p/api/setup", Some(json!({"token": token, "username": "owner", "password": PASSWORD, "accepted_terms": true}))).await;
		let (status, headers, body) = panel.send(Method::POST, "/p/api/login", Some(json!({"username": "owner", "password": PASSWORD}))).await;
		assert_eq!(status, StatusCode::OK);
		panel.cookie = headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
		panel.csrf = body["csrf"].as_str().unwrap().to_string();
		panel.call(Method::POST, "/p/api/session/reauth", Some(json!({"password": PASSWORD}))).await;
		panel
	}
	async fn send(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, axum::http::HeaderMap, Value) {
		let mut request = Request::builder().method(method.clone()).uri(path).header(HOST, "panel.test");
		if !self.cookie.is_empty() {
			request = request.header(COOKIE, &self.cookie);
			if method != Method::GET {request = request.header("x-csrf-token", &self.csrf);}
		}
		if body.is_some() {request = request.header(CONTENT_TYPE, "application/json");}
		let mut request = request.body(Body::from(body.map(|body| body.to_string()).unwrap_or_default())).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>("10.0.0.1:5000".parse().unwrap()));
		let response = self.router.clone().oneshot(request).await.unwrap();
		let (parts, body) = response.into_parts();
		(parts.status, parts.headers, serde_json::from_slice(&body.collect().await.unwrap().to_bytes()).unwrap_or(Value::Null))
	}
	/// The answer's body, which must be a success.
	async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Value {
		let (status, _, body) = self.send(method, path, body).await;
		assert_eq!(status, StatusCode::OK, "{path} {body}");
		body
	}
	async fn refused(&self, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
		let (status, _, body) = self.send(method, path, body).await;
		assert_ne!(status, StatusCode::OK, "{path} was taken: {body}");
		(status, body)
	}
	/// A remote node that node 1 holds a managed link `tag` to, added to the panel with its own pool.
	async fn add_node(&self, tag: &str, name: &str, pool: &str) -> (i64, Arc<Fake>) {
		let remote = Fake::new(document(&format!("{}1/24", pool.trim_end_matches("0/24")), 51820, "exit2"));
		self.world.remotes.lock().unwrap().insert(tag.into(), remote.clone());
		self.world.states.lock().unwrap().insert(tag.into(), "up");
		let id = self.call(Method::POST, "/p/api/nodes", Some(json!({"name": name, "link": tag, "pool_v4": pool}))).await["id"].as_i64().unwrap();
		(id, remote)
	}
	/// Takes the pushes the panel starts by itself to an end: waits for the ones that run, then does the ones still owed.
	async fn settle(&self) {
		tokio::time::sleep(Duration::from_millis(50)).await;
		for node in self.app.nodes() {
			drop(self.app.turn(node).await);
			if self.app.node(node).dirty.load(Ordering::Relaxed) {let _ = node::sync(&self.app, node).await;}
		}
	}
	async fn user(&self, name: &str, extra: Value) -> i64 {
		let mut body = json!({"name": name});
		body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		self.call(Method::POST, "/p/api/users", Some(body)).await["user"]["id"].as_i64().unwrap()
	}
	async fn shown(&self, user: i64) -> Value {self.call(Method::GET, &format!("/p/api/users/{user}"), None).await}
	async fn device(&self, user: i64) -> Value {self.call(Method::POST, &format!("/p/api/users/{user}/devices"), Some(json!({"name": "phone"}))).await["device"].clone()}
	fn query<T: Send + 'static>(&self, sql: &'static str, params: Vec<rusqlite::types::Value>) -> Vec<T> where T: rusqlite::types::FromSql {
		self.app.db.blocking(move |db| db.prepare(sql).unwrap().query_map(rusqlite::params_from_iter(params), |row| row.get::<_, T>(0)).unwrap().map(Result::unwrap).collect()).unwrap()
	}
	fn uid(&self, node: i64) -> Vec<u8> {self.query::<Vec<u8>>("select uid from nodes where id = ?", vec![node.into()]).remove(0)}
	fn record(&self, user: i64) -> [u8; 16] {self.query::<Vec<u8>>("select record_id from users where id = ?", vec![user.into()]).remove(0).try_into().unwrap()}
	fn opaque(&self, node: i64, user: i64) -> String {self.app.keys.as_ref().unwrap().node_user(&self.uid(node), &self.record(user))}
	/// One pass of upkeep with nothing remembered, so every node that is due is read and pushed to.
	async fn upkeep(&self) {upkeep_once(&self.app, &mut Upkeep::default()).await}
	/// Node 1 is left with `count` published profiles, written by hand.
	async fn own(&self, count: usize) {self.app.update_settings(move |settings| settings.profiles = (0..count).map(|i| profile(&format!("p{i}"), "192.0.2.10")).collect()).await.unwrap();}
}

impl Drop for Panel {
	fn drop(&mut self) {let _ = std::fs::remove_dir_all(&self.dir);}
}

fn month_start() -> i64 {usage::bounds(Some("monthly"), crypto::now()).0}

/// A profile of node 1 as a published one looks, reached at `address`.
fn profile(id: &str, address: &str) -> Value {json!({"id": id, "name": id, "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": [format!("{address}:51820")]}]})}

/// The document of a remote node with `count` `veilway` inbounds that each make a profile, reached at a public address.
fn crowded(count: usize) -> Value {
	let mut config = document("10.67.0.1/24", 51820, "exit2");
	config["inbounds"] = json!((0..count).map(|i| json!({"tag": format!("In{i}"), "type": "veilway", "private_key": "<redacted>", "address": ["10.67.0.1/24"], "transports": [{"type": "udp", "listen": format!("0.0.0.0:{}", 51820 + i)}]})).collect::<Vec<_>>());
	config["public_addresses"] = json!(["192.0.2.20"]);
	config
}

/// The refusal of a change that would make a subscription hold `count` profiles.
fn too_many((status, error): (StatusCode, Value), count: usize) {
	assert_eq!((status, error["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("too_many_profiles")), "{error}");
	assert!(error["error"]["message"].as_str().unwrap().contains(&format!("would make a subscription hold {count} profiles, and a subscription holds 64 at most")), "{error}");
}

/// The payload of the subscription document a device gets, read back through its signature.
async fn signed_payload(panel: &Panel, user: i64, device: i64) -> Value {
	let signing = panel.app.signing.lock().unwrap().entries.clone();
	let held: Vec<SigningKey> = signing.iter().map(|entry| entry.proto()).collect();
	let row = panel.app.db.call(move |db| UserRow::load(db, user)).await.unwrap().unwrap();
	let devices = panel.app.db.call(move |db| DeviceRow::for_user(db, user)).await.unwrap().unwrap();
	let text = subs::document(&panel.app, &row, devices.iter().find(|found| found.id == device).unwrap(), &signing, &signing[0], Form::Whole, None, None).await.unwrap();
	serde_json::from_slice(envelope::verify(text.as_bytes(), &held, BODY_MAX).unwrap().payload()).unwrap()
}

/// The other node's side of a pairing, made the way its own operator makes it: its answer to an offer, and the groups it reads out.
fn other_side(code: &str) -> (String, String) {
	let (answer, agreed) = Pastes::default().answer(&Offer::parse(code).unwrap(), crypto::now() as u64, &mut crypto::fill).unwrap();
	(answer, agreed.shown())
}

#[tokio::test]
async fn two_nodes_get_the_users_with_their_own_names_secrets_and_addresses_and_node_1_keeps_its_own() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({})).await;
	let made = panel.device(alice).await;
	assert_eq!(made["address"], "10.66.0.2", "node 1 gives the first address of its pool as before");
	panel.call(Method::POST, "/p/api/users/1/proxy", None).await;
	panel.settle().await;
	let (first, second) = (panel.world.local.user("alice"), remote.user(&panel.opaque(two, alice)));
	assert!(first.is_object(), "node 1 keeps the real name");
	assert!(second.is_object(), "{:?}", remote.user_names());
	assert_eq!(remote.user_names().len(), 1);
	let name = second["name"].as_str().unwrap();
	assert!(name.starts_with('u') && name.len() == 17 && name != "alice", "{name}");
	assert_eq!(first["devices"][0]["name"], format!("d{}", made["id"]), "node 1 names a device by its id, as before");
	assert_eq!(second["devices"][0]["name"], panel.app.keys.as_ref().unwrap().node_device(&panel.uid(two), made["id"].as_i64().unwrap()), "node 2 names the device for itself alone");
	let (a, b) = (&first["devices"][0], &second["devices"][0]);
	assert_eq!(a["public_key"], b["public_key"], "one key for a device, nodes hold the public half");
	assert!(a["addresses"][0].as_str().unwrap().starts_with("10.66.0."), "{a}");
	assert!(b["addresses"][0].as_str().unwrap().starts_with("10.67.0."), "{b}");
	let key = made["public_key"].as_str().unwrap().to_string();
	let sealed = panel.query::<Vec<u8>>("select transport_secret from devices where public_key = ?", vec![key.clone().into()]).remove(0);
	let secret = panel.app.keys.as_ref().unwrap().open_secret(&panel.record(alice), format!("transport_secret:{key}"), &sealed).unwrap();
	assert_eq!(a["transport_secrets"][0], STANDARD.encode(&secret), "node 1's document carries the stored secret, as before");
	assert_eq!(b["transport_secrets"][0], STANDARD.encode(crypto::node_secret(crypto::NODE_TRANSPORT_SALT, &panel.uid(two), &secret)));
	assert_ne!(a["transport_secrets"][0], b["transport_secrets"][0]);
	let (password, derived) = (first["proxy_password"].as_str().unwrap(), second["proxy_password"].as_str().unwrap());
	assert_eq!(password.len(), 32);
	assert_ne!(derived, password);
	assert_eq!(derived.len(), 43, "base64url of 32 derived bytes");
	let row = panel.query::<i64>("select applied_rev from nodes where id = ?", vec![two.into()]);
	let wanted = panel.query::<i64>("select wanted_rev from nodes where id = ?", vec![two.into()]);
	assert!(row[0] >= wanted[0] && wanted[0] >= 1, "the node took what was wanted: {row:?} {wanted:?}");
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!(listed["nodes"].as_array().unwrap().len(), 2);
	assert_eq!((listed["nodes"][1]["link"].as_str(), listed["nodes"][1]["link_state"].as_str(), listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["version"].as_str()), (Some("n2"), Some("up"), Some(false), Some("0.3.0")));
}

#[tokio::test]
async fn a_node_that_is_down_holds_nothing_up_and_catches_up_at_its_next_pass() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let (_, third) = panel.add_node("n3", "Oslo", "10.68.0.0/24").await;
	let alice = panel.user("alice", json!({})).await;
	panel.device(alice).await;
	panel.settle().await;
	remote.up.store(false, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "ended");
	let started = Instant::now();
	let bob = panel.user("bob", json!({})).await;
	panel.device(bob).await;
	panel.settle().await;
	assert!(started.elapsed() < Duration::from_secs(5), "a down node never costs a timeout");
	assert!(panel.world.local.user("bob").is_object() && third.user_names().len() == 2, "node 1 and the third node took the change");
	assert_eq!(remote.user_names().len(), 1, "the down node keeps serving what it had");
	panel.upkeep().await;
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["link_state"].as_str()), (Some(true), Some("ended")));
	assert!(listed["nodes"][1]["down_since"].is_number());
	assert_eq!(listed["nodes"][2]["behind"], false);
	let (status, error) = panel.refused(Method::PUT, &format!("/p/api/nodes/{two}/config/exits"), Some(json!({"revision": "rev1", "value": []}))).await;
	assert_eq!((status, error["error"]["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("node_offline")));
	assert!(error["error"]["message"].as_str().unwrap().contains("Users and devices can change now"));
	let error = node::request(&panel.app, Node(two), "GET", "/v1/status", None, None).await.unwrap_err();
	assert!(error.contains("the link is down") && error.contains("link_down"), "{error}");
	remote.up.store(true, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "up");
	panel.upkeep().await;
	assert_eq!(remote.user_names().len(), 2, "the whole users list arrives at the next pass");
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["down_since"].is_null()), (Some(false), true));
	panel.call(Method::PUT, &format!("/p/api/nodes/{two}/config/exits"), Some(json!({"revision": format!("rev{}", *remote.generation.lock().unwrap()), "value": [{"tag": "exit2"}, {"tag": "extra"}]}))).await;
	assert_eq!(remote.document.lock().unwrap()["exits"].as_array().unwrap().len(), 2, "a node's own settings are its own document");
	assert_eq!(panel.world.local.document.lock().unwrap()["exits"].as_array().unwrap().len(), 1);
	let unknown = node::request(&panel.app, Node(9), "GET", "/v1/status", None, None).await.unwrap_err();
	assert!(unknown.contains("node 9 cannot be reached"), "{unknown}");
}

#[tokio::test]
async fn a_device_has_an_address_in_the_pool_of_each_node_its_user_may_use_and_they_are_freed() {
	let panel = Panel::start().await;
	let (two, _) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let (three, _) = panel.add_node("n3", "Oslo", "10.68.0.0/24").await;
	let (alice, bob) = (panel.user("alice", json!({})).await, panel.user("bob", json!({"nodes": [1, two]})).await);
	let (a, b) = (panel.device(alice).await, panel.device(bob).await);
	let addresses = |device: i64| panel.query::<String>("select node_id || '=' || address from device_addresses where device_id = ? order by node_id", vec![device.into()]);
	assert_eq!(addresses(a["id"].as_i64().unwrap()), ["1=10.66.0.2", "2=10.67.0.2", "3=10.68.0.2"]);
	assert_eq!(addresses(b["id"].as_i64().unwrap()), ["1=10.66.0.3", "2=10.67.0.3"], "no address at a node the user may not use");
	let shown = panel.call(Method::GET, &format!("/p/api/users/{bob}"), None).await;
	assert_eq!(shown["nodes"], json!([1, two]));
	assert!(panel.call(Method::GET, &format!("/p/api/users/{alice}"), None).await.get("nodes").is_none(), "every node is left out of the answer, so one node's panel looks as before");
	panel.call(Method::PATCH, &format!("/p/api/users/{bob}"), Some(json!({"nodes": [1, two, three]}))).await;
	assert_eq!(addresses(b["id"].as_i64().unwrap()), ["1=10.66.0.3", "2=10.67.0.3", "3=10.68.0.3"]);
	panel.call(Method::PATCH, &format!("/p/api/users/{bob}"), Some(json!({"nodes": [1]}))).await;
	assert_eq!(addresses(b["id"].as_i64().unwrap()), ["1=10.66.0.3"], "taking a node away frees the address");
	let c = panel.device(alice).await;
	assert_eq!(addresses(c["id"].as_i64().unwrap())[1], "2=10.67.0.3", "the lowest free address of the pool is used again");
	panel.call(Method::DELETE, &format!("/p/api/users/{alice}/devices/{}", a["id"]), None).await;
	assert!(addresses(a["id"].as_i64().unwrap()).is_empty(), "removing a device frees every address");
	assert_eq!(panel.refused(Method::PATCH, &format!("/p/api/users/{bob}"), Some(json!({"nodes": []}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.refused(Method::PATCH, &format!("/p/api/users/{bob}"), Some(json!({"nodes": [1, 7]}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.refused(Method::PATCH, &format!("/p/api/users/{bob}"), Some(json!({"nodes": [1, 1]}))).await.0, StatusCode::BAD_REQUEST);
	panel.settle().await;
	let document = panel.world.remotes.lock().unwrap()["n2"].clone();
	assert_eq!(document.user_names().len(), 1, "only the user that may use the node is on it");
}

#[tokio::test]
async fn the_sum_over_the_nodes_cuts_a_user_on_every_node_and_a_raised_quota_or_a_reset_lets_them_back() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({"quota_bytes": 100, "quota_period": "monthly"})).await;
	panel.device(alice).await;
	panel.settle().await;
	let name = panel.opaque(two, alice);
	let counted = |node: &Arc<Fake>, name: &str, used: i64| *node.users.lock().unwrap() = vec![json!({"name": name, "used_bytes": used, "period_start": month_start(), "traffic": {"up_bytes": used / 2, "down_bytes": used - used / 2}})];
	counted(&panel.world.local, "alice", 30);
	counted(&remote, &name, 50);
	panel.upkeep().await;
	let shown = panel.shown(alice).await;
	assert_eq!((shown["usage"]["total_bytes"].as_i64(), shown["usage"]["cut"].as_bool()), (Some(80), Some(false)));
	assert_eq!(panel.world.local.user("alice")["quota_bytes"], 100, "under the quota every node holds the whole quota");
	counted(&remote, &name, 70);
	panel.upkeep().await;
	assert_eq!(panel.shown(alice).await["usage"]["cut"], true);
	panel.settle().await;
	assert_eq!(panel.world.local.user("alice")["quota_bytes"], 30, "node 1 is set to what it counted, so it cuts the user with the quota reason");
	assert_eq!(remote.user(&name)["quota_bytes"], 70);
	panel.call(Method::PATCH, &format!("/p/api/users/{alice}"), Some(json!({"quota_bytes": 1000}))).await;
	panel.upkeep().await;
	assert_eq!(panel.shown(alice).await["usage"]["cut"], false);
	panel.settle().await;
	assert_eq!((panel.world.local.user("alice")["quota_bytes"].as_i64(), remote.user(&name)["quota_bytes"].as_i64()), (Some(1000), Some(1000)), "the cut is lifted on both when the quota is raised");
	panel.call(Method::PATCH, &format!("/p/api/users/{alice}"), Some(json!({"quota_bytes": 100}))).await;
	panel.upkeep().await;
	assert_eq!(panel.shown(alice).await["usage"]["cut"], true);
	remote.up.store(false, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "ended");
	panel.call(Method::POST, &format!("/p/api/users/{alice}/usage/reset"), Some(json!({}))).await;
	counted(&panel.world.local, "alice", 0);
	counted(&remote, &name, 0);
	assert_eq!(panel.world.local.resets.lock().unwrap().len(), 1, "node 1 is reset at once");
	assert!(remote.resets.lock().unwrap().is_empty(), "the node that is down is told at its next push");
	let shown = panel.shown(alice).await;
	assert_eq!((shown["usage"]["total_bytes"].as_i64(), shown["usage"]["cut"].as_bool()), (Some(0), Some(false)));
	remote.up.store(true, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "up");
	node::sync(&panel.app, Node(two)).await.unwrap();
	panel.upkeep().await;
	assert_eq!(remote.resets.lock().unwrap().clone(), vec![(name.clone(), json!({"totals": false}))], "the reset reaches the node under its opaque name");
	assert_eq!(panel.query::<i64>("select count(*) from node_resets", vec![]), [0]);
	assert_eq!(remote.user(&name)["quota_bytes"], 100);
}

#[tokio::test]
async fn a_node_that_is_not_counted_adds_nothing_and_node_1_alone_is_never_summed() {
	let panel = Panel::start().await;
	let alice = panel.user("alice", json!({"quota_bytes": 100, "quota_period": "monthly"})).await;
	panel.device(alice).await;
	*panel.world.local.users.lock().unwrap() = vec![json!({"name": "alice", "used_bytes": 500, "period_start": month_start()})];
	panel.upkeep().await;
	assert_eq!(panel.query::<i64>("select count(*) from node_usage", vec![]), [0], "a panel with one node reads no usage and cuts nobody: the node enforces its quota alone");
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let name = panel.opaque(two, alice);
	*panel.world.local.users.lock().unwrap() = vec![json!({"name": "alice", "used_bytes": 10, "period_start": month_start()})];
	*remote.users.lock().unwrap() = vec![json!({"name": name, "used_bytes": 400, "period_start": month_start()})];
	panel.call(Method::PATCH, &format!("/p/api/nodes/{two}"), Some(json!({"counted": false}))).await;
	panel.upkeep().await;
	let shown = panel.call(Method::GET, &format!("/p/api/users/{alice}"), None).await;
	assert_eq!((shown["usage"]["total_bytes"].as_i64(), shown["usage"]["cut"].as_bool(), shown["usage"]["nodes"][1]["counted"].as_bool()), (Some(10), Some(false), Some(false)), "the node that reports false usage is shown and not counted");
	panel.call(Method::PATCH, &format!("/p/api/nodes/{two}"), Some(json!({"counted": true}))).await;
	panel.upkeep().await;
	assert_eq!(panel.call(Method::GET, &format!("/p/api/users/{alice}"), None).await["usage"]["total_bytes"], 410);
}

#[tokio::test]
async fn removing_a_node_empties_it_drops_its_link_and_frees_its_addresses_and_a_taken_node_is_removed_without_asking() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let (three, gone) = panel.add_node("n3", "Oslo", "10.68.0.0/24").await;
	let alice = panel.user("alice", json!({"nodes": [two, three]})).await;
	panel.device(alice).await;
	panel.settle().await;
	let bob = panel.user("bob", json!({"nodes": [1, two]})).await;
	panel.device(bob).await;
	panel.settle().await;
	for tag in ["n2", "n3"] {
		let mut document = panel.world.local.document.lock().unwrap();
		document["links"].as_array_mut().unwrap().push(json!({"tag": tag, "id": format!("id-{tag}"), "manage": "peer"}));
	}
	remote.document.lock().unwrap()["links"] = json!([{"tag": "up", "id": "x", "manage": "by_peer"}, {"tag": "other"}]);
	panel.call(Method::DELETE, &format!("/p/api/nodes/{two}"), None).await;
	let emptied = remote.last();
	assert_eq!(emptied["users"], json!([]));
	assert_eq!(emptied["links"], json!([{"tag": "other"}]), "the one change a managed node takes of its managing link");
	let links: Vec<Value> = panel.world.local.document.lock().unwrap()["links"].as_array().unwrap().clone();
	assert_eq!(links.iter().map(|link| link["tag"].as_str().unwrap()).collect::<Vec<_>>(), ["n3"], "the link leaves node 1's config");
	assert_eq!(panel.app.nodes(), vec![LOCAL, Node(three)]);
	assert_eq!(panel.query::<i64>("select count(*) from device_addresses where node_id = ?", vec![two.into()]), [0]);
	assert_eq!(panel.query::<String>("select nodes from users where id = ?", vec![bob.into()]), ["[1]"], "a user's list forgets the node");
	assert_eq!(panel.refused(Method::DELETE, &format!("/p/api/nodes/{LOCAL}", LOCAL = LOCAL.0), None).await.0, StatusCode::BAD_REQUEST);
	gone.up.store(false, Ordering::Relaxed);
	let (status, error) = panel.refused(Method::DELETE, &format!("/p/api/nodes/{three}"), None).await;
	assert_eq!(status, StatusCode::BAD_GATEWAY, "{error}");
	assert_eq!(panel.app.nodes().len(), 2, "a node that cannot be asked is kept");
	panel.call(Method::DELETE, &format!("/p/api/nodes/{three}?taken=true"), None).await;
	assert_eq!(panel.app.nodes(), vec![LOCAL]);
	assert!(panel.world.local.document.lock().unwrap()["links"].as_array().unwrap().is_empty());
	assert_eq!(panel.query::<i64>("select count(*) from device_addresses", vec![]), [2], "only node 1's addresses are left");
	let after = panel.user("carol", json!({})).await;
	panel.device(after).await;
	assert_eq!(panel.query::<i64>("select count(*) from device_addresses where node_id != 1", vec![]), [0]);
}

#[tokio::test]
async fn a_node_needs_a_managed_link_a_pool_and_a_name_of_its_own() {
	let panel = Panel::start().await;
	panel.world.states.lock().unwrap().insert("n9".into(), "up");
	panel.world.remotes.lock().unwrap().insert("n9".into(), Fake::new(document("10.69.0.1/24", 51820, "e")));
	assert_eq!(panel.refused(Method::POST, "/p/api/nodes", Some(json!({"name": "A", "link": "nope", "pool_v4": "10.67.0.0/24"}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.refused(Method::POST, "/p/api/nodes", Some(json!({"name": " A", "link": "n9", "pool_v4": "10.67.0.0/24"}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.refused(Method::POST, "/p/api/nodes", Some(json!({"name": "A", "link": "n9", "pool_v4": "10.67.0.0/31"}))).await.0, StatusCode::BAD_REQUEST);
	let added = panel.call(Method::POST, "/p/api/nodes", Some(json!({"name": "Fra nk-furt!", "link": "n9", "pool_v4": "10.67.0.0/24"}))).await;
	assert_eq!((added["slug"].as_str(), added["id"].as_i64(), added["link"].as_str()), (Some("fra-nk-furt"), Some(2), Some("n9")));
	assert_eq!(panel.refused(Method::POST, "/p/api/nodes", Some(json!({"name": "B", "link": "n9", "pool_v4": "10.68.0.0/24"}))).await.0, StatusCode::CONFLICT, "one node per link");
	let patched = panel.call(Method::PATCH, "/p/api/nodes/2", Some(json!({"name": "Berlin", "max_rate": 1000, "pool_v4": "10.70.0.0/24"}))).await;
	assert_eq!((patched["name"].as_str(), patched["max_rate"].as_i64(), patched["pool_v4"].as_str()), (Some("Berlin"), Some(1000), Some("10.70.0.0/24")));
	assert_eq!(panel.refused(Method::PATCH, "/p/api/nodes/1", Some(json!({"pool_v4": "10.70.0.0/24"}))).await.0, StatusCode::BAD_REQUEST, "node 1's pool is the setting");
	let alice = panel.user("alice", json!({})).await;
	panel.device(alice).await;
	assert_eq!(panel.refused(Method::PATCH, "/p/api/nodes/2", Some(json!({"pool_v4": "10.71.0.0/24"}))).await.0, StatusCode::CONFLICT, "not once a device has an address in it");
}

#[test]
fn the_names_and_secrets_of_a_node_are_made_for_it_alone() {
	let dir = std::env::temp_dir().join(format!("vwkeys-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	crypto::write_private(&dir.join("k"), &[[1u8; 32], [2u8; 32], [3u8; 32]].concat(), false).unwrap();
	let keys = crypto::Keys::load(&dir.join("k")).unwrap();
	let (one, two, record, other) = ([1u8; 16], [2u8; 16], [7u8; 16], [8u8; 16]);
	assert_eq!(keys.node_user(&one, &record), keys.node_user(&one, &record));
	assert_ne!(keys.node_user(&one, &record), keys.node_user(&two, &record));
	assert_ne!(keys.node_user(&one, &record), keys.node_user(&one, &other));
	assert!(keys.node_user(&one, &record).bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()));
	let secret = [5u8; 32];
	let (a, b) = (crypto::node_secret(crypto::NODE_TRANSPORT_SALT, &one, &secret), crypto::node_secret(crypto::NODE_TRANSPORT_SALT, &two, &secret));
	assert!(a != b && a != secret && b != secret);
	assert_ne!(a, crypto::node_secret(crypto::NODE_PROXY_SALT, &one, &secret), "a transport secret and a proxy password of one node differ");
	let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_remote_node_adds_its_profiles_once_it_has_the_device_and_keeps_them_while_it_is_down() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	remote.document.lock().unwrap()["public_addresses"] = json!(["192.0.2.20"]);
	panel.app.update_settings(|settings| settings.profiles = vec![profile("main", "192.0.2.10")]).await.unwrap();
	node::sync(&panel.app, Node(two)).await.unwrap();
	remote.up.store(false, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "ended");
	let alice = panel.user("alice", json!({"quota_bytes": 1000, "quota_period": "monthly"})).await;
	let made = panel.device(alice).await;
	let id = made["id"].as_i64().unwrap();
	let before = signed_payload(&panel, alice, id).await;
	assert_eq!(before["profiles"].as_array().unwrap().len(), 1, "a node that has not taken the device gives no profile of its own");
	remote.up.store(true, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "up");
	node::sync(&panel.app, Node(two)).await.unwrap();
	let up = signed_payload(&panel, alice, id).await;
	let profiles = up["profiles"].as_array().unwrap();
	assert_eq!(profiles.len(), 2);
	assert_eq!(profiles[0], before["profiles"][0], "node 1's profile is the same as before the node had the device");
	let second = &profiles[1];
	assert_eq!((second["id"].clone(), second["name"].clone()), (json!("frankfurt-main"), json!("Frankfurt · Main")));
	assert_eq!(second["transports"], json!([{"type": "udp", "endpoints": ["192.0.2.20:51820"]}]));
	assert_eq!((second["device"]["addresses"].clone(), second["device"]["public_key"].clone()), (json!(["10.67.0.2"]), made["public_key"].clone()), "the device's address at the node, and its one key");
	let key = made["public_key"].as_str().unwrap().to_string();
	let sealed = panel.query::<Vec<u8>>("select transport_secret from devices where public_key = ?", vec![key.clone().into()]).remove(0);
	let secret = panel.app.keys.as_ref().unwrap().open_secret(&panel.record(alice), format!("transport_secret:{key}"), &sealed).unwrap();
	assert_eq!(second["device"]["transport_secrets"], json!([STANDARD.encode(crypto::node_secret(crypto::NODE_TRANSPORT_SALT, &panel.uid(two), &secret))]), "the secret of the node, derived for it alone");
	remote.up.store(false, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "ended");
	assert_eq!(signed_payload(&panel, alice, id).await["profiles"], up["profiles"], "a node that is down keeps its profiles");
	remote.up.store(true, Ordering::Relaxed);
	panel.world.states.lock().unwrap().insert("n2".into(), "up");
	*panel.world.local.users.lock().unwrap() = vec![json!({"name": "alice", "used_bytes": 30, "period_start": month_start(), "traffic": {"up_bytes": 15, "down_bytes": 15}})];
	*remote.users.lock().unwrap() = vec![json!({"name": panel.opaque(two, alice), "used_bytes": 50, "period_start": month_start(), "traffic": {"up_bytes": 25, "down_bytes": 25}})];
	panel.upkeep().await;
	assert_eq!(signed_payload(&panel, alice, id).await["usage"]["used_bytes"], 80, "the usage of a document is the total across the nodes");
}

#[tokio::test]
async fn the_profiles_of_other_nodes_stop_at_the_cap_of_a_document_and_the_document_is_still_given() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	let mut config = document("10.67.0.1/24", 51820, "exit2");
	config["inbounds"] = json!((0..10).map(|i| json!({"tag": format!("In{i}"), "type": "veilway", "private_key": "<redacted>", "address": ["10.67.0.1/24"], "transports": [{"type": "udp", "listen": format!("0.0.0.0:{}", 51820 + i)}]})).collect::<Vec<_>>());
	config["public_addresses"] = json!(["192.0.2.20"]);
	*remote.document.lock().unwrap() = config;
	panel.app.update_settings(|settings| settings.profiles = (0..60).map(|i| profile(&format!("p{i}"), "192.0.2.10")).collect()).await.unwrap();
	let alice = panel.user("alice", json!({})).await;
	let id = panel.device(alice).await["id"].as_i64().unwrap();
	node::sync(&panel.app, Node(two)).await.unwrap();
	let ids: Vec<String> = signed_payload(&panel, alice, id).await["profiles"].as_array().unwrap().iter().map(|profile| profile["id"].as_str().unwrap().to_string()).collect();
	assert_eq!(ids.len(), 64, "a document holds 64 profiles at most");
	assert_eq!(ids[..60].to_vec(), (0..60).map(|i| format!("p{i}")).collect::<Vec<_>>(), "node 1 is first and whole");
	assert_eq!(ids[60..].iter().map(String::as_str).collect::<Vec<_>>(), ["frankfurt-in0", "frankfurt-in1", "frankfurt-in2", "frankfurt-in3"]);
}

#[tokio::test]
async fn a_managed_link_is_offered_and_answered_through_the_api_and_the_node_on_it_is_added() {
	let panel = Panel::start().await;
	let mut managed = json!({"tag": "north", "inbound": "Main", "direction": "forward", "name": "North", "inbound_public_key": STANDARD.encode([3u8; 32]), "dialler": ["10.90.0.3"], "transports": [{"type": "udp", "endpoints": ["192.0.2.30:51820"]}], "managed": true});
	assert_eq!(panel.refused(Method::POST, "/p/api/links/offers", Some(managed.clone())).await.0, StatusCode::BAD_REQUEST, "a managed link needs this node's link address");
	managed["listener"] = json!(["10.90.0.2"]);
	let code = panel.call(Method::POST, "/p/api/links/offers", Some(managed)).await["code"].as_str().unwrap().to_string();
	let (answer, groups) = other_side(&code);
	let taken = panel.call(Method::POST, "/p/api/links/offers/answer", Some(json!({"code": answer}))).await;
	let revision = format!("rev{}", *panel.world.local.generation.lock().unwrap());
	panel.call(Method::POST, &format!("/p/api/links/pairings/{}/confirm", taken["id"].as_str().unwrap()), Some(json!({"typed": groups, "revision": revision}))).await;
	let links = panel.world.local.document.lock().unwrap()["links"].clone();
	let entry = links.as_array().unwrap().iter().find(|link| link["tag"] == "north").unwrap().clone();
	assert_eq!((entry["manage"].clone(), entry["addresses"]["listener"].clone()), (json!("peer"), json!(["10.90.0.2"])), "node 1 manages the link");
	panel.world.remotes.lock().unwrap().insert("north".into(), Fake::new(document("10.67.0.1/24", 51820, "exit2")));
	panel.world.states.lock().unwrap().insert("north".into(), "up");
	let added = panel.call(Method::POST, "/p/api/nodes", Some(json!({"name": "North", "link": "north", "pool_v4": "10.67.0.0/24"}))).await;
	assert_eq!((added["link"].clone(), added["link_state"].clone()), (json!("north"), json!("up")), "the node is added right after the pairing");
	let mut theirs = Offers::default();
	let edge = Terms {direction: Direction::Forward, name: "Edge".into(), inbound_public_key: [4u8; 32], transport_public_key: None, dialler: vec!["10.91.0.3".parse().unwrap()], listener: vec!["10.91.0.2".parse().unwrap()], manage: Some(Manage::Dialler), mtu: 1420, transports: pairing::transports(br#"[{"type": "udp", "endpoints": ["192.0.2.31:51820"]}]"#).unwrap()};
	let code = theirs.issue(&edge, crypto::now() as u64, 600, &mut crypto::fill).unwrap();
	assert_eq!(panel.call(Method::POST, "/p/api/links/paste", Some(json!({"code": code}))).await["manage"], "this_node");
	let paste = json!({"code": code, "tag": "edge", "accept": true});
	assert_eq!(panel.refused(Method::POST, "/p/api/links/paste/answer", Some(paste.clone())).await.0, StatusCode::BAD_REQUEST, "an offer that makes this node the manager is answered as managed");
	let mut answered_managed = paste.clone();
	answered_managed["managed"] = json!(true);
	let answered = panel.call(Method::POST, "/p/api/links/paste/answer", Some(answered_managed)).await;
	let agreed = theirs.answer(answered["answer"].as_str().unwrap(), crypto::now() as u64).unwrap();
	let revision = format!("rev{}", *panel.world.local.generation.lock().unwrap());
	panel.call(Method::POST, &format!("/p/api/links/pairings/{}/confirm", answered["id"].as_str().unwrap()), Some(json!({"typed": agreed.shown(), "revision": revision}))).await;
	let links = panel.world.local.document.lock().unwrap()["links"].clone();
	assert_eq!(links.as_array().unwrap().iter().find(|link| link["tag"] == "edge").unwrap()["manage"], "peer", "an answer that makes this node the manager is managed from it");
	let refused = Offers::default().issue(&Terms {manage: Some(Manage::Listener), ..edge}, crypto::now() as u64, 600, &mut crypto::fill).unwrap();
	assert_eq!(panel.call(Method::POST, "/p/api/links/paste", Some(json!({"code": refused}))).await["manage"], "other_node");
	assert_eq!(panel.refused(Method::POST, "/p/api/links/paste/answer", Some(json!({"code": refused, "tag": "other", "accept": true, "managed": true}))).await.0, StatusCode::CONFLICT, "a node that would manage this one is not paired");
}

#[tokio::test]
async fn a_remote_node_is_given_only_the_groups_its_config_declares() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	remote.document.lock().unwrap()["groups"] = json!(["office"]);
	let alice = panel.user("alice", json!({"groups": ["office", "other"]})).await;
	panel.device(alice).await;
	// A sync that is still running when the first settle looks is waited for: a slow runner can need more than one round.
	for _ in 0..50 {panel.settle().await; if remote.user(&panel.opaque(two, alice))["groups"] == json!(["office"]) {break}}
	assert_eq!(remote.user(&panel.opaque(two, alice))["groups"], json!(["office"]), "a group the node does not declare is left out");
	assert_eq!(panel.world.local.user("alice")["groups"], json!(["office", "other"]), "node 1 keeps every group");
}

#[tokio::test]
async fn an_answer_is_the_remote_nodes_own_unless_node_1_marks_it_as_its_relay_failure() {
	let panel = Panel::start().await;
	let (two, _) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let (status, body) = node::request(&panel.app, Node(two), "GET", "/v1/busy", None, None).await.unwrap();
	assert_eq!((status, String::from_utf8_lossy(&body).contains("the node is busy")), (503, true), "a busy answer of the node itself is not a relay failure");
	panel.world.states.lock().unwrap().insert("n2".into(), "ended");
	let error = node::request(&panel.app, Node(two), "GET", "/v1/status", None, None).await.unwrap_err();
	assert!(error.contains("the link is down") && error.contains("link_down"), "{error}");
}

#[tokio::test]
async fn a_tag_that_node_1_gives_to_another_link_pushes_nothing_until_the_link_has_the_id_it_was_added_with() {
	let panel = Panel::start().await;
	let (_, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({})).await;
	panel.device(alice).await;
	panel.settle().await;
	let pushed = remote.applied.lock().unwrap().len();
	panel.world.ids.lock().unwrap().insert("n2".into(), "another-link".into());
	let bob = panel.user("bob", json!({})).await;
	panel.device(bob).await;
	panel.settle().await;
	assert_eq!((remote.applied.lock().unwrap().len(), remote.user_names().len()), (pushed, 1), "nothing is pushed through a tag that names another link");
	panel.upkeep().await;
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["last_error"].as_str(), listed["nodes"][1]["down_since"].is_number()), (Some("the link with this name is not the one this server was added with"), true));
	panel.world.ids.lock().unwrap().insert("n2".into(), "id-n2".into());
	panel.upkeep().await;
	assert_eq!(remote.user_names().len(), 2, "the node takes the users again once its link has the id it was added with");
}

#[tokio::test]
async fn a_removal_that_node_1_fails_is_retried_without_asking_the_emptied_node_again() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({"nodes": [1, two]})).await;
	panel.device(alice).await;
	panel.settle().await;
	panel.world.local.document.lock().unwrap()["links"].as_array_mut().unwrap().push(json!({"tag": "n2", "id": "id-n2", "manage": "peer"}));
	panel.world.local.refuse.store(true, Ordering::Relaxed);
	panel.refused(Method::DELETE, &format!("/p/api/nodes/{two}"), None).await;
	assert_eq!(remote.last()["users"], json!([]), "the node is emptied first");
	assert_eq!(panel.app.nodes(), vec![LOCAL, Node(two)], "and kept while node 1 still has its link");
	remote.up.store(false, Ordering::Relaxed);
	panel.world.local.refuse.store(false, Ordering::Relaxed);
	panel.call(Method::DELETE, &format!("/p/api/nodes/{two}"), None).await;
	assert_eq!(panel.app.nodes(), vec![LOCAL]);
	assert!(panel.world.local.document.lock().unwrap()["links"].as_array().unwrap().is_empty(), "the link leaves node 1's config");
}

#[tokio::test]
async fn a_usage_reset_that_the_node_answers_with_404_waits_for_a_node_with_the_route_while_it_still_lists_the_user() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({"quota_bytes": 1000, "quota_period": "monthly"})).await;
	panel.device(alice).await;
	panel.settle().await;
	let name = panel.opaque(two, alice);
	*remote.users.lock().unwrap() = vec![json!({"name": name, "used_bytes": 5, "period_start": month_start()})];
	remote.reset_missing.store(true, Ordering::Relaxed);
	panel.call(Method::POST, &format!("/p/api/users/{alice}/usage/reset"), Some(json!({}))).await;
	panel.settle().await;
	assert_eq!(panel.query::<i64>("select count(*) from node_resets", vec![]), [1], "a 404 for a user the node still lists is no reset");
	assert!(panel.query::<String>("select last_error from nodes where id = ?", vec![two.into()])[0].contains("404"));
	remote.reset_missing.store(false, Ordering::Relaxed);
	panel.upkeep().await;
	assert_eq!(remote.resets.lock().unwrap().clone(), vec![(name.clone(), json!({"totals": false}))], "the reset reaches the node once it has the route");
	assert_eq!(panel.query::<i64>("select count(*) from node_resets", vec![]), [0]);
}

#[tokio::test]
async fn a_usage_reset_answered_with_404_for_a_user_the_node_no_longer_lists_is_done() {
	let panel = Panel::start().await;
	let (_, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({"quota_bytes": 1000, "quota_period": "monthly"})).await;
	panel.device(alice).await;
	panel.settle().await;
	remote.reset_missing.store(true, Ordering::Relaxed);
	panel.call(Method::POST, &format!("/p/api/users/{alice}/usage/reset"), Some(json!({}))).await;
	panel.settle().await;
	assert_eq!(panel.query::<i64>("select count(*) from node_resets", vec![]), [0], "the node has no such user, so there is nothing to reset there");
	assert!(remote.resets.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_reading_for_a_period_that_is_not_the_current_one_is_not_kept() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({"quota_bytes": 1000, "quota_period": "monthly"})).await;
	panel.device(alice).await;
	panel.settle().await;
	let name = panel.opaque(two, alice);
	let previous = usage::bounds(Some("monthly"), month_start() - 1).0;
	for period in [9_000_000_000_000i64, previous] {
		*remote.users.lock().unwrap() = vec![json!({"name": name, "used_bytes": 900, "period_start": period})];
		panel.upkeep().await;
		assert_eq!(panel.query::<i64>("select count(*) from node_usage where node_id = ?", vec![two.into()]), [0], "a period starting at {period} is not kept");
	}
	*remote.users.lock().unwrap() = vec![json!({"name": name, "used_bytes": 10, "period_start": month_start()})];
	panel.upkeep().await;
	assert_eq!(panel.shown(alice).await["usage"]["total_bytes"], 10, "the current period is kept");
}

#[tokio::test]
async fn a_node_that_reports_growth_for_all_its_users_at_once_cannot_cut_them_in_one_reading() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.call(Method::PATCH, &format!("/p/api/nodes/{two}"), Some(json!({"max_rate": 1000}))).await;
	let mut ids = Vec::new();
	for i in 0..20 {
		let id = panel.user(&format!("user{i}"), json!({"quota_bytes": 1000, "quota_period": "monthly"})).await;
		panel.device(id).await;
		ids.push(id);
	}
	panel.settle().await;
	let names: Vec<String> = ids.iter().map(|id| panel.opaque(two, *id)).collect();
	let reading = |used: i64| names.iter().map(|name| json!({"name": name, "used_bytes": used, "period_start": month_start()})).collect::<Vec<_>>();
	*remote.users.lock().unwrap() = reading(0);
	panel.upkeep().await;
	*remote.users.lock().unwrap() = reading(1_000_000_000);
	panel.upkeep().await;
	for id in &ids {assert_eq!(panel.shown(*id).await["usage"]["cut"], false, "one reading that asks for far more cuts nobody");}
	assert!(panel.query::<i64>("select max(used_bytes) from node_usage where node_id = ?", vec![two.into()])[0] < 1000, "no user reaches the quota of 1000 in one reading");
}

#[tokio::test]
async fn the_usage_intervals_are_panel_settings_checked_on_save_and_a_pass_inside_the_interval_reads_nothing() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let shown = panel.call(Method::GET, "/p/api/settings", None).await;
	assert_eq!((shown["usage_poll_secs"].clone(), shown["node_poll_secs"].clone()), (json!(10), json!(30)), "the defaults");
	for (field, value) in [("usage_poll_secs", 9), ("node_poll_secs", 601)] {
		let mut body = shown.clone();
		body[field] = json!(value);
		assert_eq!(panel.refused(Method::PUT, "/p/api/settings", Some(body)).await.0, StatusCode::BAD_REQUEST, "{field}");
	}
	let mut body = shown.clone();
	body["node_poll_secs"] = json!(600);
	panel.call(Method::PUT, "/p/api/settings", Some(body)).await;
	let alice = panel.user("alice", json!({})).await;
	panel.device(alice).await;
	panel.settle().await;
	let name = panel.opaque(two, alice);
	let mut state = Upkeep::default();
	upkeep_once(&panel.app, &mut state).await;
	*remote.users.lock().unwrap() = vec![json!({"name": name, "used_bytes": 50, "period_start": 0})];
	upkeep_once(&panel.app, &mut state).await;
	assert_eq!(panel.query::<i64>("select count(*) from node_usage where node_id = ?", vec![two.into()]), [0], "a node read less than node_poll_secs ago is not read again");
}

#[tokio::test]
async fn the_upstreams_of_another_server_go_through_its_link_and_node_1_is_not_called_for_them() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	assert_eq!(panel.call(Method::GET, &format!("/p/api/nodes/{two}/upstreams"), None).await, json!({"upstreams": []}));
	assert_eq!(panel.call(Method::POST, &format!("/p/api/nodes/{two}/upstreams/edge/retry"), None).await, json!({"tag": "edge"}));
	assert_eq!(panel.call(Method::GET, "/p/api/upstreams", None).await, json!({"upstreams": []}), "node 1 keeps its own endpoints");
	let seen = remote.calls.lock().unwrap().clone();
	assert!(seen.contains(&"GET /v1/upstreams".to_string()) && seen.contains(&"POST /v1/upstreams/edge/retry".to_string()), "{seen:?}");
	assert!(panel.world.local.calls.lock().unwrap().iter().all(|call| !call.contains("/retry")), "node 1 is not called for another server's retry");
}

#[tokio::test]
async fn a_node_list_that_would_make_a_subscription_hold_more_than_64_profiles_is_refused_and_exactly_64_is_allowed() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	*remote.document.lock().unwrap() = crowded(10);
	node::sync(&panel.app, Node(two)).await.unwrap();
	panel.own(55).await;
	let alice = panel.user("alice", json!({"nodes": [1]})).await;
	let path = format!("/p/api/users/{alice}");
	let nodes = || panel.query::<String>("select nodes from users where id = ?", vec![alice.into()]);
	too_many(panel.refused(Method::PATCH, &path, Some(json!({"nodes": [1, two]}))).await, 65);
	too_many(panel.refused(Method::PATCH, &path, Some(json!({"nodes": null}))).await, 65);
	assert_eq!(nodes(), ["[1]"], "the account keeps its list");
	panel.own(54).await;
	panel.call(Method::PATCH, &path, Some(json!({"nodes": [1, two]}))).await;
	assert_eq!(nodes(), ["[1,2]"], "54 and the 10 of the other node are exactly 64");
	panel.own(60).await;
	panel.call(Method::PATCH, &path, Some(json!({"nodes": [1, two], "note": "kept"}))).await;
	assert_eq!(panel.shown(alice).await["note"], "kept", "a list that does not change is no change to refuse, even above the cap from before");
}

#[tokio::test]
async fn a_new_account_that_would_hold_more_than_64_profiles_is_refused_and_not_made() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	*remote.document.lock().unwrap() = crowded(10);
	node::sync(&panel.app, Node(two)).await.unwrap();
	panel.own(55).await;
	too_many(panel.refused(Method::POST, "/p/api/users", Some(json!({"name": "alice"}))).await, 65);
	too_many(panel.refused(Method::POST, "/p/api/users", Some(json!({"name": "alice", "nodes": [1, two]}))).await, 65);
	assert_eq!(panel.query::<i64>("select count(*) from users", vec![]), [0], "no account was made");
	panel.user("alice", json!({"nodes": [1]})).await;
	panel.own(54).await;
	panel.user("bob", json!({})).await;
}

#[tokio::test]
async fn a_publish_that_would_make_a_subscription_hold_more_than_64_profiles_is_refused_and_exactly_64_is_allowed() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	*remote.document.lock().unwrap() = crowded(10);
	node::sync(&panel.app, Node(two)).await.unwrap();
	panel.app.update_settings(|settings| {settings.node_host = "192.0.2.10".into(); settings.inbound_keys.insert("Main".into(), STANDARD.encode([7u8; 32]));}).await.unwrap();
	panel.own(54).await;
	panel.user("alice", json!({})).await;
	let lines = || panel.query::<i64>("select count(*) from audit where action = 'settings.update'", vec![])[0];
	let before = lines();
	too_many(panel.refused(Method::POST, "/p/api/profiles/publish", None).await, 65);
	assert_eq!((panel.app.settings().profiles.len(), lines()), (54, before), "nothing was published");
	panel.own(53).await;
	panel.call(Method::POST, "/p/api/profiles/publish", None).await;
	assert_eq!((panel.app.settings().profiles.len(), lines()), (54, before + 1), "53 written by hand and the one of node 1's inbound make exactly 64 with the 10 of the other node");
	panel.own(60).await;
	panel.app.update_settings(|settings| settings.profiles.push(profile("main", "192.0.2.10"))).await.unwrap();
	panel.call(Method::POST, "/p/api/profiles/publish", None).await;
	assert_eq!(panel.app.settings().profiles.len(), 61, "a publish that adds no profile goes through even above the cap from before");
}

#[tokio::test]
async fn a_node_that_would_make_a_subscription_hold_more_than_64_profiles_is_refused_and_leaves_nothing_behind() {
	let panel = Panel::start().await;
	panel.own(55).await;
	let alice = panel.user("alice", json!({})).await;
	panel.device(alice).await;
	let remote = Fake::new(crowded(10));
	panel.world.remotes.lock().unwrap().insert("n2".into(), remote.clone());
	panel.world.states.lock().unwrap().insert("n2".into(), "up");
	let offer = json!({"name": "Frankfurt", "link": "n2", "pool_v4": "10.67.0.0/24"});
	too_many(panel.refused(Method::POST, "/p/api/nodes", Some(offer.clone())).await, 65);
	panel.settle().await;
	assert_eq!((panel.app.nodes(), panel.query::<i64>("select count(*) from nodes", vec![])), (vec![LOCAL], vec![1]), "the node is not kept");
	assert_eq!(panel.query::<i64>("select count(*) from device_addresses where node_id != 1", vec![]), [0], "and the addresses it was given are gone");
	assert_eq!(panel.query::<i64>("select count(*) from audit where action = 'node.add'", vec![]), [0], "a refused add writes no line");
	assert!(remote.applied.lock().unwrap().is_empty(), "nothing was pushed to it");
	panel.own(54).await;
	panel.call(Method::POST, "/p/api/nodes", Some(offer)).await;
	assert_eq!(panel.app.nodes(), vec![LOCAL, Node(2)], "54 and the 10 of the node are exactly 64");
	assert_eq!((panel.query::<i64>("select count(*) from audit where action = 'node.add'", vec![]), panel.query::<i64>("select count(*) from device_addresses where node_id = 2", vec![])), (vec![1], vec![1]));
	panel.own(70).await;
	panel.add_node("n3", "Oslo", "10.68.0.0/24").await;
	assert_eq!(panel.app.nodes().len(), 3, "a node that gives no profile is added even above the cap from before");
}

#[tokio::test]
async fn an_inbounds_change_on_a_remote_node_that_would_make_a_subscription_hold_more_than_64_profiles_is_refused_before_it_is_applied() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	*remote.document.lock().unwrap() = crowded(5);
	node::sync(&panel.app, Node(two)).await.unwrap();
	panel.own(54).await;
	panel.user("alice", json!({})).await;
	let path = format!("/p/api/nodes/{two}/config/inbounds");
	let change = |count: usize| Some(json!({"revision": format!("rev{}", *remote.generation.lock().unwrap()), "value": crowded(count)["inbounds"]}));
	let inbounds = || remote.document.lock().unwrap()["inbounds"].as_array().unwrap().len();
	let pushed = || remote.applied.lock().unwrap().len();
	let before = pushed();
	too_many(panel.refused(Method::PUT, &path, change(11)).await, 65);
	assert_eq!((inbounds(), pushed()), (5, before), "nothing reached the node");
	panel.call(Method::PUT, &path, change(10)).await;
	assert_eq!(inbounds(), 10, "54, the 5 it gave and 5 more are exactly 64");
	node::sync(&panel.app, Node(two)).await.unwrap();
	panel.own(60).await;
	panel.call(Method::PUT, &path, change(10)).await;
	too_many(panel.refused(Method::PUT, &path, change(11)).await, 71);
	assert_eq!(inbounds(), 10);
	panel.call(Method::PUT, &path, change(9)).await;
	assert_eq!(inbounds(), 9, "a change that adds no profile goes through even above the cap from before");
}

#[tokio::test]
async fn an_upstream_change_on_an_offline_server_is_refused_as_offline_and_sends_nothing() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.world.states.lock().unwrap().insert("n2".into(), "ended");
	let (status, body) = panel.refused(Method::POST, &format!("/p/api/nodes/{two}/upstreams/edge/retry"), None).await;
	assert_eq!((status, body["error"]["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("node_offline")));
	assert!(remote.calls.lock().unwrap().iter().all(|call| !call.contains("/retry")), "nothing is sent to an offline server");
}

#[tokio::test]
async fn a_config_pushed_through_a_link_counts_once_a_request_confirms_it_after_the_settle_time() {
	let panel = Panel::start().await;
	let (_, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({})).await;
	panel.settle().await;
	let (applied, confirmed) = (remote.applied.lock().unwrap().len(), *remote.confirmed.lock().unwrap());
	let started = Instant::now();
	panel.device(alice).await;
	panel.settle().await;
	assert!(started.elapsed() >= SETTLE, "the panel asks no sooner than the settle time after the push");
	assert_eq!(remote.applied.lock().unwrap().len(), applied + 1);
	assert_eq!((*remote.confirmed.lock().unwrap(), *remote.early.lock().unwrap()), (confirmed + 1, 0), "the node confirmed the push, and no request came before the settle time");
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["last_error"].is_null()), (Some(false), true), "{listed}");
}

#[tokio::test]
async fn a_config_pushed_through_a_link_that_is_never_confirmed_stays_behind_and_is_pushed_again() {
	let panel = Panel::start().await;
	let (_, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({})).await;
	panel.settle().await;
	let applied = remote.applied.lock().unwrap().len();
	remote.hold.store(true, Ordering::Relaxed);
	panel.device(alice).await;
	panel.settle().await;
	assert!(remote.applied.lock().unwrap().len() > applied, "the node took the push");
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!(listed["nodes"][1]["behind"], true, "{listed}");
	assert!(listed["nodes"][1]["last_error"].as_str().unwrap().contains("did not confirm"), "{listed}");
	remote.hold.store(false, Ordering::Relaxed);
	panel.settle().await;
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["last_error"].is_null()), (Some(false), true), "{listed}");
}

#[tokio::test]
async fn a_push_whose_answer_is_cut_counts_when_the_node_runs_it() {
	let panel = Panel::start().await;
	let (_, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let alice = panel.user("alice", json!({})).await;
	panel.settle().await;
	let applied = remote.applied.lock().unwrap().len();
	remote.cut.store(true, Ordering::Relaxed);
	let started = Instant::now();
	panel.device(alice).await;
	panel.settle().await;
	assert!(started.elapsed() >= SETTLE, "the revision is read only after the settle time");
	assert_eq!(remote.applied.lock().unwrap().len(), applied + 1, "the node took one push, and none was sent again");
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["last_error"].is_null()), (Some(false), true), "{listed}");
}

#[tokio::test]
async fn a_remote_nodes_relays_reach_its_own_profiles_in_a_subscription_and_no_other_nodes() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let (three, other) = panel.add_node("n3", "Oslo", "10.68.0.0/24").await;
	remote.document.lock().unwrap()["public_addresses"] = json!(["192.0.2.20"]);
	other.document.lock().unwrap()["public_addresses"] = json!(["192.0.2.30"]);
	let relay = |name: &str, address: &str| json!({"name": name, "address": address, "enabled": true});
	panel.app.update_settings(|settings| {
		settings.profiles = vec![profile("main", "192.0.2.10")];
		settings.relay_profiles.insert("main".into(), "Main".into());
		settings.published_relays = vec![serde_json::from_value(json!({"name": "home", "address": "198.51.100.1", "enabled": true})).unwrap()];
	}).await.unwrap();
	let alice = panel.user("alice", json!({})).await;
	let made = panel.device(alice).await;
	panel.call(Method::PATCH, &format!("/p/api/nodes/{two}"), Some(json!({"relays": [relay("cdn2", "203.0.113.5"), {"name": "mine2", "address": "203.0.113.8", "enabled": true, "users": [alice]}]}))).await;
	panel.call(Method::PATCH, &format!("/p/api/nodes/{three}"), Some(json!({"relays": [relay("cdn3", "203.0.113.7")]}))).await;
	panel.settle().await;
	let payload = signed_payload(&panel, alice, made["id"].as_i64().unwrap()).await;
	let profiles = payload["profiles"].as_array().unwrap();
	let endpoints = |id: &str| profiles.iter().find(|profile| profile["id"] == id).map(|profile| profile["transports"][0]["endpoints"].clone()).unwrap_or(Value::Null);
	assert_eq!(endpoints("main"), json!(["192.0.2.10:51820", "198.51.100.1:51820"]), "node 1's relay reaches node 1's profile only");
	assert_eq!(endpoints("frankfurt-main"), json!(["192.0.2.20:51820", "203.0.113.8:51820", "203.0.113.5:51820"]), "the account's own relay comes before the one for everyone");
	assert_eq!(endpoints("oslo-main"), json!(["192.0.2.30:51820", "203.0.113.7:51820"]), "node 2's relays do not reach node 3");
	let shown = panel.call(Method::GET, "/p/api/nodes", None).await["nodes"][1].clone();
	assert_eq!((shown["relays"][0]["name"].as_str(), shown["relays"][1]["users"].clone()), (Some("cdn2"), json!([alice])));
	let (_, error) = panel.refused(Method::PATCH, &format!("/p/api/nodes/{two}"), Some(json!({"relays": [relay("local", "127.0.0.1")]}))).await;
	assert!(error["error"]["message"].as_str().unwrap().contains("not a loopback"), "{error}");
	let (_, error) = panel.refused(Method::PATCH, &format!("/p/api/nodes/{two}"), Some(json!({"relays": [{"name": "ghost", "address": "203.0.113.9", "enabled": true, "users": [999]}]}))).await;
	assert!(error["error"]["message"].as_str().unwrap().contains("which does not exist"), "{error}");
	let (_, error) = panel.refused(Method::PATCH, &format!("/p/api/nodes/{}", LOCAL.0), Some(json!({"relays": []}))).await;
	assert!(error["error"]["message"].as_str().unwrap().contains("set in Settings"), "{error}");
	panel.call(Method::DELETE, &format!("/p/api/users/{alice}"), None).await;
	let shown = panel.call(Method::GET, "/p/api/nodes", None).await["nodes"][1].clone();
	assert_eq!(shown["relays"][1]["users"], json!([]), "a deleted account leaves the relays of every node, so its id can be given to a new account");
}

#[tokio::test]
async fn a_section_change_whose_answer_is_cut_is_confirmed_by_the_sync_that_follows() {
	let panel = Panel::start().await;
	let (two, remote) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	panel.settle().await;
	let confirmed = *remote.confirmed.lock().unwrap();
	remote.cut.store(true, Ordering::Relaxed);
	let revision = format!("rev{}", *remote.generation.lock().unwrap());
	panel.refused(Method::PUT, &format!("/p/api/nodes/{two}/config/exits"), Some(json!({"revision": revision, "value": [{"tag": "exit2"}, {"tag": "extra"}]}))).await;
	assert_eq!(remote.document.lock().unwrap()["exits"].as_array().unwrap().len(), 2, "the node took the change");
	panel.settle().await;
	assert_eq!(*remote.confirmed.lock().unwrap(), confirmed + 1, "the next push confirms the change the node was sent");
	let listed = panel.call(Method::GET, "/p/api/nodes", None).await;
	assert_eq!((listed["nodes"][1]["behind"].as_bool(), listed["nodes"][1]["last_error"].is_null()), (Some(false), true), "{listed}");
	assert_eq!(remote.document.lock().unwrap()["exits"].as_array().unwrap().len(), 2, "the change stays in force");
}

/// The ids of the profiles a device's document lists, in order.
async fn listed(panel: &Panel, user: i64, device: i64) -> Vec<String> {signed_payload(panel, user, device).await["profiles"].as_array().unwrap().iter().map(|profile| profile["id"].as_str().unwrap().to_string()).collect()}

#[tokio::test]
async fn the_profiles_of_other_nodes_come_by_place_then_id_and_a_global_and_a_own_order_move_them() {
	let panel = Panel::start().await;
	let (two, first) = panel.add_node("n2", "Frankfurt", "10.67.0.0/24").await;
	let (three, second) = panel.add_node("n3", "Amsterdam", "10.68.0.0/24").await;
	panel.settle().await;
	for remote in [&first, &second] {remote.document.lock().unwrap()["public_addresses"] = json!(["192.0.2.20"]);}
	panel.app.update_settings(|settings| settings.profiles = vec![profile("a", "192.0.2.10"), profile("b", "192.0.2.10")]).await.unwrap();
	node::sync(&panel.app, Node(two)).await.unwrap();
	node::sync(&panel.app, Node(three)).await.unwrap();
	let alice = panel.user("alice", json!({})).await;
	let id = panel.device(alice).await["id"].as_i64().unwrap();
	node::sync(&panel.app, Node(two)).await.unwrap();
	node::sync(&panel.app, Node(three)).await.unwrap();
	assert_eq!(listed(&panel, alice, id).await, ["a", "b", "frankfurt-main", "amsterdam-main"], "the same place keeps the order of the ids");
	panel.call(Method::PATCH, &format!("/p/api/nodes/{three}"), Some(json!({"place": -1}))).await;
	assert_eq!(listed(&panel, alice, id).await, ["a", "b", "amsterdam-main", "frankfurt-main"], "a lower place comes first");
	let shown = panel.call(Method::GET, "/p/api/profiles/order", None).await;
	assert_eq!(shown["order"], json!([]));
	assert_eq!(shown["profiles"].as_array().unwrap().iter().map(|profile| (profile["id"].as_str().unwrap(), profile["node"].as_str().unwrap())).collect::<Vec<_>>(), [("a", "Node 1"), ("b", "Node 1"), ("amsterdam-main", "Amsterdam"), ("frankfurt-main", "Frankfurt")]);
	let set = panel.call(Method::PUT, "/p/api/profiles/order", Some(json!({"order": ["frankfurt-main", "gone", "b", "b"]}))).await;
	assert_eq!(set["order"], json!(["frankfurt-main", "gone", "b"]), "an unknown id is kept and ignored, a repeat is dropped");
	assert_eq!(listed(&panel, alice, id).await, ["frankfurt-main", "b", "a", "amsterdam-main"], "listed ids first, the rest in the default order");
	assert_eq!(panel.query::<String>("select action from audit order by id desc limit 1", vec![]), ["profiles.order"]);
	let path = format!("/p/api/users/{alice}");
	let patched = panel.call(Method::PATCH, &path, Some(json!({"profile_order": ["amsterdam-main", "nothing", "b"]}))).await;
	assert_eq!(patched["user"]["profile_order"], json!(["amsterdam-main", "nothing", "b"]));
	assert_eq!(listed(&panel, alice, id).await, ["amsterdam-main", "b", "frankfurt-main", "a"], "the account's ids first, then the global order");
	panel.call(Method::PATCH, &path, Some(json!({"note": "x"}))).await;
	assert_eq!(panel.shown(alice).await["profile_order"], json!(["amsterdam-main", "nothing", "b"]), "a change of something else keeps the order");
	assert_eq!(panel.call(Method::PATCH, &path, Some(json!({"profile_order": null}))).await["user"]["profile_order"], Value::Null);
	assert_eq!(listed(&panel, alice, id).await, ["frankfurt-main", "b", "a", "amsterdam-main"], "null follows the global order");
	let bob = panel.user("bob", json!({"profile_order": ["b"]})).await;
	assert_eq!(panel.shown(bob).await["profile_order"], json!(["b"]), "an order can be given when the account is made");
	panel.call(Method::PUT, "/p/api/settings", Some({let mut body = panel.call(Method::GET, "/p/api/settings", None).await; body["profile_order"] = json!(["a"]); body})).await;
	assert_eq!(panel.call(Method::GET, "/p/api/profiles/order", None).await["order"], json!(["frankfurt-main", "gone", "b"]), "a settings update does not write the order");
}

#[tokio::test]
async fn an_order_of_more_than_64_ids_or_an_id_that_cannot_be_one_is_refused() {
	let panel = Panel::start().await;
	let many: Vec<String> = (0..65).map(|i| format!("p{i}")).collect();
	let few: Vec<String> = many[..64].to_vec();
	assert_eq!(panel.refused(Method::PUT, "/p/api/profiles/order", Some(json!({"order": many}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.refused(Method::PUT, "/p/api/profiles/order", Some(json!({"order": [""]}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.refused(Method::PUT, "/p/api/profiles/order", Some(json!({"order": ["x".repeat(129)]}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.call(Method::PUT, "/p/api/profiles/order", Some(json!({"order": few}))).await["order"].as_array().unwrap().len(), 64);
	assert_eq!(panel.refused(Method::POST, "/p/api/users", Some(json!({"name": "carol", "profile_order": many}))).await.0, StatusCode::BAD_REQUEST);
	let alice = panel.user("alice", json!({})).await;
	assert_eq!(panel.refused(Method::PATCH, &format!("/p/api/users/{alice}"), Some(json!({"profile_order": many}))).await.0, StatusCode::BAD_REQUEST);
	assert_eq!(panel.shown(alice).await["profile_order"], Value::Null);
}
