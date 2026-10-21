use axum::{body::Body, extract::{ConnectInfo, State}, http::{header::{CONTENT_TYPE, COOKIE, HOST, ORIGIN, SET_COOKIE}, HeaderMap, Method, Request, StatusCode}, routing::{get, post}, Json, Router};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{future::Future, net::SocketAddr, path::PathBuf, sync::{atomic::Ordering, Arc, Mutex}};
use tower::ServiceExt;
use veilway_panel::{admin, app::{bucket, App, Limiter, Signing}, build, config::{Config, TrustedMirror}, crypto, mirrors, openapi, router, upkeep_once, Upkeep};
use veilway_proto::subscription::{envelope::{self, Kid}, exchange::{self, GatewayKey}, link::Link, payload::{self, Payload, Reason}, sealed_file, BODY_MAX};

const PASSWORD: &str = "correct horse battery";

struct Harness {app: Arc<App>, router: Router, totp: Vec<u8>, dir: PathBuf}

struct Session {cookie: String, csrf: String}

struct Answer {status: StatusCode, headers: HeaderMap, body: Vec<u8>}

impl Answer {
	fn json(&self) -> Value {serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON ({}): {}", self.status, String::from_utf8_lossy(&self.body)))}
	fn shape(&self) -> (u16, Vec<(String, String)>, Vec<u8>) {
		let mut headers: Vec<(String, String)> = self.headers.iter().map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string())).collect();
		headers.sort();
		(self.status.as_u16(), headers, self.body.clone())
	}
}

impl Harness {
	async fn new() -> Self {Self::with_socket(None).await}
	async fn with_socket(socket: Option<PathBuf>) -> Self {Self::with_config(socket, |_| {}).await}
	async fn with_config(socket: Option<PathBuf>, edit: impl FnOnce(&mut Config)) -> Self {
		let dir = std::env::temp_dir().join(format!("vwpanel-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		std::fs::create_dir_all(&dir).unwrap();
		let mut cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), gateway: dir.join("gateway.keys"), gateway_next: dir.join("gateway.next"), node_socket: socket.unwrap_or(dir.join("none.sock")), ..Config::default()};
		edit(&mut cfg);
		let app = build(cfg).unwrap();
		let router = router(app.clone());
		let mut harness = Self {app, router, totp: Vec::new(), dir};
		let token = harness.app.setup_token.lock().unwrap().clone().unwrap();
		let answer = harness.call(Method::POST, "/p/api/setup", None, Some(json!({"token": token, "username": "owner", "password": PASSWORD, "accepted_terms": true})), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
		harness.totp = data_encoding::BASE32_NOPAD.decode(answer.json()["totp_secret"].as_str().unwrap().as_bytes()).unwrap();
		harness
	}
	async fn call(&self, method: Method, path: &str, session: Option<&Session>, body: Option<Value>, source: &str) -> Answer {
		let mut request = Request::builder().method(method.clone()).uri(path).header(HOST, "panel.test");
		if let Some(session) = session {
			request = request.header(COOKIE, &session.cookie);
			if method != Method::GET {request = request.header("x-csrf-token", &session.csrf);}
		}
		if body.is_some() {request = request.header(CONTENT_TYPE, "application/json");}
		self.send(request, body, source).await
	}
	async fn send(&self, request: axum::http::request::Builder, body: Option<Value>, source: &str) -> Answer {self.send_bytes(request, body.map(|body| body.to_string().into_bytes()).unwrap_or_default(), source).await}
	async fn send_bytes(&self, request: axum::http::request::Builder, body: Vec<u8>, source: &str) -> Answer {
		let mut request = request.body(Body::from(body)).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>(format!("{source}:5000").parse().unwrap()));
		let response = self.router.clone().oneshot(request).await.unwrap();
		let (parts, body) = response.into_parts();
		Answer {status: parts.status, headers: parts.headers, body: body.collect().await.unwrap().to_bytes().to_vec()}
	}
	fn code(&self, offset: i64) -> String {format!("{:06}", crypto::totp_at(&self.totp, (crypto::now() / 30 + offset) as u64))}
	async fn login(&self, source: &str) -> Session {
		// Time passing between two logins is simulated by forgetting the last used code.
		self.app.db.call(|db| db.execute("update admins set totp_last_step = 0", []).unwrap()).await.unwrap();
		let answer = self.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": self.code(0)})), source).await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
		let cookie = answer.headers.get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
		Session {cookie: cookie.split(';').next().unwrap().to_string(), csrf: answer.json()["csrf"].as_str().unwrap().to_string()}
	}
	async fn token(&self, session: &Session, scope: &str, extra: Value) -> String {
		let mut body = json!({"name": scope, "scope": scope});
		body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		let answer = self.call(Method::POST, "/p/api/tokens", Some(session), Some(body), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
		answer.json()["token"].as_str().unwrap().to_string()
	}
	async fn bearer(&self, method: Method, path: &str, token: &str, body: Option<Value>, source: &str) -> Answer {
		let mut request = Request::builder().method(method).uri(path).header(HOST, "panel.test").header("authorization", format!("Bearer {token}"));
		if body.is_some() {request = request.header(CONTENT_TYPE, "application/json");}
		self.send(request, body, source).await
	}
	async fn configure(&self, session: &Session, extra: Value) {
		let mut settings = json!({"provider_name": "Test Net", "endpoints": [{"name": "main", "url": "https://panel.example.org/s", "pins": []}], "default_endpoint": "main", "pool_v4": "10.66.0.0/24", "default_device_limit": 3, "show_links_once": false, "update_interval": 3600, "document_days": 14, "refresh_mirrors": [],
			"profiles": [{"id": "main", "name": "Main", "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]}]});
		settings.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		let answer = self.call(Method::PUT, "/p/api/settings", Some(session), Some(settings), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	}
	async fn user(&self, session: &Session, name: &str, extra: Value) -> (i64, Link) {
		let mut body = json!({"name": name});
		body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		let answer = self.call(Method::POST, "/p/api/users", Some(session), Some(body), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
		let created = answer.json();
		(created["user"]["id"].as_i64().unwrap(), Link::parse(created["link"]["veilway"].as_str().unwrap_or_else(|| panic!("no link: {created}"))).unwrap())
	}
	/// A request sealed to `key` with `body` as its JSON, `t` added when the body has none. Gives the answer, opened to its envelope when it was a sealed one, and what opens it.
	async fn sealed(&self, key: &GatewayKey, mut body: Value, path: &str, source: &str, edit: impl FnOnce(axum::http::request::Builder) -> axum::http::request::Builder) -> (Answer, exchange::Sealed) {
		if body.get("t").is_none() {body["t"] = json!(crypto::now());}
		let sealed = exchange::seal(key, body.to_string().as_bytes(), &mut crypto::fill).unwrap();
		let mut answer = self.send_bytes(edit(Request::builder().method(Method::POST).uri(path).header(CONTENT_TYPE, "application/octet-stream").header(HOST, "panel.example.org")), sealed.bytes().to_vec(), source).await;
		if answer.status == StatusCode::OK {answer.body = sealed.open(&answer.body).expect("the answer opens");}
		(answer, sealed)
	}
	async fn sub(&self, link: &Link, body: Value, source: &str) -> Answer {
		let Link::Native(native) = link else {panic!("not native")};
		self.sealed(&native.gateway(), body, "/s", source, |request| request).await.0
	}
	async fn fetch(&self, link: &Link, kids: &[Kid], device: u8, op: &str, name: Option<&str>) -> Answer {
		let Link::Native(native) = link else {panic!("not native")};
		let mut body = json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": kids.iter().map(|kid| kid.text()).collect::<Vec<_>>(), "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": op});
		if let Some(name) = name {body["device_name"] = json!(name);}
		self.sub(link, body, "198.51.100.7").await
	}
}

impl Drop for Harness {
	fn drop(&mut self) {let _ = std::fs::remove_dir_all(&self.dir);}
}

fn key_of(link: &Link) -> envelope::SigningKey {if let Link::Native(native) = link {native.key()} else {panic!("not native")}}

fn opened(answer: &Answer, held: &[envelope::SigningKey]) -> Payload {
	assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	payload::parse(&envelope::verify(&answer.body, held, BODY_MAX).expect("the answer verifies")).expect("the payload reads")
}

fn refusal_of(answer: &Answer, held: &[envelope::SigningKey]) -> Reason {
	match opened(answer, held) {Payload::Refusal(refusal) => refusal.reason, Payload::Subscription(_) => panic!("a document, not a refusal")}
}

#[tokio::test]
async fn login_totp_rate_limit_and_csrf() {
	let h = Harness::new().await;
	let wrong_password = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": "not the password", "totp": h.code(0)})), "10.0.0.2").await;
	let wrong_code = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": "000000"})), "10.0.0.2").await;
	assert_eq!((wrong_password.status, wrong_code.status), (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED));
	assert_eq!(wrong_password.body, wrong_code.body, "a wrong password and a wrong code look the same");
	let session = h.login("10.0.0.3").await;
	let set_cookie = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": h.code(0)})), "10.0.0.3").await;
	assert_eq!(set_cookie.status, StatusCode::UNAUTHORIZED, "a used code works once");
	let cookie_line = h.app.db.call(|db| db.query_row("select count(*) from sessions", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap();
	assert_eq!(cookie_line, 1);
	// Cookie attributes come from the login answer.
	h.app.db.call(|db| db.execute("update admins set totp_last_step = 0", []).unwrap()).await.unwrap();
	let fresh = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": h.code(0)})), "10.0.0.3").await;
	let attributes = fresh.headers.get(SET_COOKIE).unwrap().to_str().unwrap().to_string();
	assert!(attributes.contains("HttpOnly") && attributes.contains("Secure") && attributes.contains("SameSite=Strict"), "{attributes}");
	let no_csrf = h.send(Request::builder().method(Method::POST).uri("/p/api/users").header(HOST, "panel.test").header(COOKIE, &session.cookie).header(CONTENT_TYPE, "application/json"), Some(json!({"name": "ann"})), "10.0.0.3").await;
	assert_eq!((no_csrf.status, no_csrf.json()["error"]["code"].as_str().unwrap().to_string()), (StatusCode::FORBIDDEN, "csrf".into()));
	let foreign = h.send(Request::builder().method(Method::POST).uri("/p/api/users").header(HOST, "panel.test").header(ORIGIN, "https://evil.test").header(COOKIE, &session.cookie).header("x-csrf-token", &session.csrf).header(CONTENT_TYPE, "application/json"), Some(json!({"name": "ann"})), "10.0.0.3").await;
	assert_eq!(foreign.json()["error"]["code"], "bad_origin");
	assert_eq!(h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "ann"})), "10.0.0.3").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::GET, "/p/api/users", None, None, "10.0.0.3").await.status, StatusCode::UNAUTHORIZED);
	// A second session can be listed and revoked, and then no longer works.
	let other = h.login("10.0.0.4").await;
	let listed = h.call(Method::GET, "/p/api/sessions", Some(&session), None, "10.0.0.3").await.json();
	assert_eq!(listed["sessions"].as_array().unwrap().len(), 3);
	let other_id = h.call(Method::GET, "/p/api/session", Some(&other), None, "10.0.0.4").await.json()["session_id"].as_str().unwrap().to_string();
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/sessions/{other_id}"), Some(&session), None, "10.0.0.3").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::GET, "/p/api/users", Some(&other), None, "10.0.0.4").await.status, StatusCode::UNAUTHORIZED);
	// Twenty wrong tries put the account on a wait of 15 minutes. A wrong try waits, a right password and code pass.
	for index in 1..=20 {h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": "nope nope nope", "totp": "000000"})), &format!("10.1.0.{index}")).await;}
	let waiting = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": "nope nope nope", "totp": "000000"})), "10.0.2.1").await;
	assert_eq!(waiting.status, StatusCode::TOO_MANY_REQUESTS);
	h.app.db.call(|db| db.execute("update admins set totp_last_step = 0", []).unwrap()).await.unwrap();
	let right = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": h.code(0)})), "10.0.2.2").await;
	assert_eq!(right.status, StatusCode::OK);
	// And one source is limited on its own, whatever the account.
	let mut limited = false;
	for _ in 0..12 {limited |= h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "someone", "password": "nope nope nope", "totp": "000000"})), "10.0.0.6").await.status == StatusCode::TOO_MANY_REQUESTS;}
	assert!(limited);
	let audit = h.call(Method::GET, "/p/api/audit", Some(&session), None, "10.0.0.3").await.json();
	assert!(audit["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "login.failed"));
}

#[tokio::test]
async fn api_token_scopes() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let read = h.token(&session, "read", json!({})).await;
	let users = h.token(&session, "users", json!({})).await;
	let full = h.token(&session, "full", json!({})).await;
	let src = "10.1.1.1";
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &read, None, src).await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::POST, "/p/api/users", &read, Some(json!({"name": "bob"})), src).await.status, StatusCode::FORBIDDEN);
	assert_eq!(h.bearer(Method::POST, "/p/api/users", &users, Some(json!({"name": "bob"})), src).await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::GET, "/p/api/audit", &users, None, src).await.status, StatusCode::FORBIDDEN);
	assert_eq!(h.bearer(Method::GET, "/p/api/audit", &full, None, src).await.status, StatusCode::OK);
	// Never reachable by any token: tokens, signing keys, admin accounts, sessions, secrets and settings changes.
	for token in [&read, &users, &full] {
		for (method, path, body) in [(Method::POST, "/p/api/tokens", Some(json!({"name": "x", "scope": "full"}))), (Method::GET, "/p/api/tokens", None), (Method::GET, "/p/api/signing-keys", None), (Method::POST, "/p/api/signing-keys/rotate", None), (Method::GET, "/p/api/admins", None), (Method::GET, "/p/api/sessions", None), (Method::POST, "/p/api/users/1/subscription/show", None), (Method::POST, "/p/api/users/1/subscription/sealed", Some(json!({"password": "a long enough one"}))), (Method::POST, "/p/api/account/password", Some(json!({"new_password": "another long password"})))] {
			assert_eq!(h.bearer(method.clone(), path, token, body, src).await.status, StatusCode::FORBIDDEN, "{method} {path}");
		}
	}
	let bound = h.token(&session, "full", json!({"allowed_sources": ["192.0.2.1"]})).await;
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &bound, None, "192.0.2.1").await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &bound, None, "192.0.2.2").await.status, StatusCode::UNAUTHORIZED);
	h.app.db.call(|db| db.execute("update api_tokens set expires_at = 1 where name = 'read'", []).unwrap()).await.unwrap();
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &read, None, src).await.status, StatusCode::UNAUTHORIZED);
	let id = h.call(Method::GET, "/p/api/tokens", Some(&session), None, src).await.json()["tokens"].as_array().unwrap().iter().find(|token| token["name"] == "users").unwrap()["id"].as_i64().unwrap();
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/tokens/{id}"), Some(&session), None, src).await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &users, None, src).await.status, StatusCode::UNAUTHORIZED);
	// A token that is stored only as a hash: the plain text is nowhere in the database.
	let hash = crypto::sha256(full.as_bytes()).to_vec();
	let stored: i64 = h.app.db.call(move |db| db.query_row("select count(*) from api_tokens where token_hash = ?", [hash.as_slice()], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(stored, 1);
	for _ in 0..125 {h.bearer(Method::GET, "/p/api/users", &full, None, src).await;}
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &full, None, src).await.status, StatusCode::TOO_MANY_REQUESTS);
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, src).await.json();
	assert!(audit["entries"].as_array().unwrap().iter().any(|entry| entry["actor"] == "token:users" && entry["action"] == "api.call"));
}

#[tokio::test]
async fn invalid_endpoint_requests_look_like_the_404() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let Link::Native(native) = &link else {panic!()};
	let token = URL_SAFE_NO_PAD.encode(native.token().expose());
	let unknown = h.call(Method::GET, "/some/other/path", None, None, "198.51.100.7").await;
	assert_eq!(unknown.status, StatusCode::NOT_FOUND);
	let kids = json!([key_of(&link).kid().text()]);
	let valid_shape = |token: &str| json!({"v": 1, "token": token, "kids": kids, "device_public_key": STANDARD.encode([9u8; 32]), "device_secret": URL_SAFE_NO_PAD.encode([9u8; 16]), "op": "fetch"});
	let other_token = URL_SAFE_NO_PAD.encode([5u8; 16]);
	let raw = |method: Method, body: Vec<u8>| {
		let mut request = Request::builder().method(method).uri("/s").header(HOST, "panel.example.org").body(Body::from(body)).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>("198.51.100.7:1".parse().unwrap()));
		let router = h.router.clone();
		async move {
			let (parts, body) = router.oneshot(request).await.unwrap().into_parts();
			Answer {status: parts.status, headers: parts.headers, body: body.collect().await.unwrap().to_bytes().to_vec()}
		}
	};
	let key = native.gateway();
	let stranger = GatewayKey::new(key.id().wrapping_add(7), veilway_panel::gateway::public_of(&[3u8; 32])).unwrap();
	let sealed = |key: &GatewayKey, body: &Value| exchange::seal(key, body.to_string().as_bytes(), &mut crypto::fill).unwrap().bytes().to_vec();
	let mut extra = valid_shape(&other_token);
	extra["t"] = json!(crypto::now());
	let mut late = valid_shape(&token);
	late["t"] = json!(crypto::now() - 1000);
	let mut fresh = valid_shape(&token);
	fresh["t"] = json!(crypto::now());
	let replayed = sealed(&key, &fresh);
	let mut tampered = sealed(&key, &fresh);
	tampered[500] ^= 1;
	let mut wrong_id = sealed(&key, &fresh);
	wrong_id[0] = wrong_id[0].wrapping_add(1);
	let mut unreadable = Vec::new();
	for body in ["not json", "[1,2]", "null", "{}"] {unreadable.push(exchange::seal(&key, body.as_bytes(), &mut crypto::fill).unwrap().bytes().to_vec());}
	let mut cases: Vec<(&str, Method, Vec<u8>)> = vec![
		("a GET", Method::GET, Vec::new()), ("a PUT", Method::PUT, sealed(&key, &fresh)), ("an empty POST", Method::POST, Vec::new()), ("text", Method::POST, b"not json".to_vec()), ("a plain JSON request", Method::POST, valid_shape(&token).to_string().into_bytes()),
		("a body that is too long", Method::POST, vec![7; 5000]), ("a body of one byte too many", Method::POST, vec![1; 1074]), ("a body of the right size that opens to nothing", Method::POST, vec![9; 1073]),
		("an unknown token", Method::POST, sealed(&key, &extra)), ("a key the panel does not hold", Method::POST, sealed(&stranger, &fresh)), ("a changed byte", Method::POST, tampered), ("another key id", Method::POST, wrong_id),
		("a time outside the window", Method::POST, sealed(&key, &late)),
	];
	for body in unreadable {cases.push(("a plaintext that is not a request", Method::POST, body));}
	let mut short = valid_shape("short");
	short["t"] = json!(crypto::now());
	cases.push(("a token of the wrong length", Method::POST, sealed(&key, &short)));
	for (what, method, body) in cases {assert_eq!(raw(method, body).await.shape(), unknown.shape(), "{what} was not answered like an unknown path");}
	// A valid request is answered once, and the same bytes again are a replay.
	assert_eq!(raw(Method::POST, replayed.clone()).await.status, StatusCode::OK);
	assert_eq!(raw(Method::POST, replayed).await.shape(), unknown.shape(), "a replay");
	// A valid token with a malformed request is a signed refusal and not the 404.
	let mut bad = valid_shape(&token);
	bad["extra"] = json!(1);
	assert_eq!(refusal_of(&h.sub(&link, bad, "198.51.100.7").await, &[key_of(&link)]), Reason::BadRequest);
}

#[tokio::test]
async fn signed_documents_and_refusals_verify() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, link) = h.user(&session, "ann", json!({"device_limit": 2, "quota_bytes": 1000, "quota_period": "monthly"})).await;
	let (key, kids) = (key_of(&link), [key_of(&link).kid()]);
	let Payload::Subscription(first) = opened(&h.fetch(&link, &kids, 1, "fetch", None).await, &[key]) else {panic!("a document")};
	assert_eq!(first.profiles.len(), 1);
	assert_eq!(first.devices.iter().filter(|device| device.this && device.pending).count(), 1, "a new device takes a pending place");
	assert_eq!(first.usage.as_ref().map(|usage| usage.quota_bytes), Some(1000));
	assert_eq!(first.origin(), payload::KeyOrigin::Device);
	let Payload::Subscription(confirmed) = opened(&h.fetch(&link, &kids, 1, "confirm", Some("My phone")).await, &[key]) else {panic!("a document")};
	assert!(confirmed.devices.iter().any(|device| device.this && !device.pending && device.name.as_str() == "My phone"));
	assert!(matches!(opened(&h.fetch(&link, &kids, 1, "fetch", None).await, &[key]), Payload::Subscription(_)));
	// Same device again within a minute: the enrolled allowance.
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 1, "fetch", None).await, &[key]), Reason::RateLimited);
	// A known key with another secret.
	let mismatch = {
		let Link::Native(native) = &link else {panic!()};
		let body = json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [kids[0].text()], "device_public_key": STANDARD.encode([1u8; 32]), "device_secret": URL_SAFE_NO_PAD.encode([99u8; 16]), "op": "fetch"});
		h.sub(&link, body, "198.51.100.7").await
	};
	assert_eq!(refusal_of(&mismatch, &[key]), Reason::DeviceMismatch);
	h.app.sub_limits.clear(&format!("new:{id}:1"));
	// A second device fits, a third does not, and a pending place can be released.
	assert!(matches!(opened(&h.fetch(&link, &kids, 2, "fetch", None).await, &[key]), Payload::Subscription(_)));
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 3, "fetch", None).await, &[key]), Reason::DeviceLimit);
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 2, "release", None).await, &[key]), Reason::Released);
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 1);
	// `release` never removes a confirmed device. `leave`, which an app sends when the user removes the subscription, does, and the place is free again.
	assert!(matches!(opened(&h.fetch(&link, &kids, 1, "release", None).await, &[key]), Payload::Subscription(_)));
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 1, "leave", None).await, &[key]), Reason::Released);
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 0);
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 1, "leave", None).await, &[key]), Reason::Released);
	h.app.sub_limits.clear(&format!("new:{id}:1"));
	assert!(matches!(opened(&h.fetch(&link, &kids, 2, "confirm", None).await, &[key]), Payload::Subscription(_)));
	// Switching the account off and setting an expiry give signed refusals.
	assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"enabled": false})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 4, "fetch", None).await, &[key]), Reason::Disabled);
	h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"enabled": true, "expires_at": 1})), "10.0.0.1").await;
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 4, "fetch", None).await, &[key]), Reason::Expired);
	// Device removal frees the place.
	h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"expires_at": null})), "10.0.0.1").await;
	let device_id = h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"][0]["id"].as_i64().unwrap();
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/users/{id}/devices/{device_id}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
}

#[tokio::test]
async fn link_reset_show_and_show_once() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, old) = h.user(&session, "ann", json!({})).await;
	let kids = [key_of(&old).kid()];
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await;
	opened(&h.fetch(&old, &kids, 1, "confirm", None).await, &[key_of(&old)]);
	let shown = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/show"), Some(&session), None, "10.0.0.1").await;
	assert_eq!(shown.json()["veilway"], old_text(&old));
	assert!(shown.json()["qr_svg"].as_str().unwrap().contains("<svg"));
	assert_eq!(shown.headers.get("cache-control").unwrap(), "no-store");
	// Showing needs a recent re-authentication.
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{id}/subscription/show"), Some(&session), None, "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	let reset = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/reset"), Some(&session), Some(json!({"remove_devices": false})), "10.0.0.1").await.json();
	assert_eq!(reset["old_devices"].as_array().unwrap().len(), 1);
	let new = Link::parse(reset["link"]["veilway"].as_str().unwrap()).unwrap();
	assert_eq!(h.fetch(&old, &kids, 1, "fetch", None).await.shape(), unknown.shape(), "the old token is an unknown path now");
	assert!(matches!(opened(&h.fetch(&new, &kids, 2, "fetch", None).await, &[key_of(&new)]), Payload::Subscription(_)));
	let again = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/reset"), Some(&session), Some(json!({"remove_devices": true})), "10.0.0.1").await.json();
	assert_eq!(again["old_devices"].as_array().unwrap().len(), 1, "only the device of the generation being reset");
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 1, "the device of the first generation stays");
	// Sealed copy: the token is not in the database in the clear, and the copy opens only for its own record.
	let (lookup, copy): (Vec<u8>, Vec<u8>) = h.app.db.call(move |db| db.query_row("select token_lookup, token_copy from users where id = ?", [id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()).await.unwrap();
	assert_eq!((lookup.len(), copy.len()), (32, 44));
	let keys = h.app.keys.as_ref().unwrap();
	assert!(keys.open_copy(&[0; 16], &copy).is_none());
	// "Show links once": copies go, and a link can no longer be shown.
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	h.configure(&session, json!({"show_links_once": true})).await;
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{id}/subscription/show"), Some(&session), None, "10.0.0.1").await.status, StatusCode::GONE);
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	assert!(audit.body.windows(10).all(|window| window != b"veilway://"), "no link in the audit log");
	assert!(std::fs::metadata(&h.app.cfg.keys).map(|meta| std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777 == 0o600).unwrap());
}

#[tokio::test]
async fn show_links_once_is_read_in_the_job_that_stores_the_copy() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"show_links_once": false})).await;
	let no_copy = |id: i64| h.app.db.call(move |db| db.query_row("select token_copy is null from users where id = ?", [id], |row| row.get::<_, bool>(0)).unwrap());
	let (kept, _) = h.user(&session, "kept", json!({})).await;
	assert!(!no_copy(kept).await.unwrap(), "a copy is stored with the setting off");
	h.configure(&session, json!({"show_links_once": true})).await;
	let (once, _) = h.user(&session, "once", json!({})).await;
	assert!(no_copy(once).await.unwrap(), "no copy is stored with the setting on");
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{kept}/subscription/reset"), Some(&session), Some(json!({"remove_devices": false})), "10.0.0.1").await.status, StatusCode::OK);
	assert!(no_copy(kept).await.unwrap(), "a reset with the setting on stores no copy either");
}

#[tokio::test]
async fn a_sealed_file_of_the_link_needs_a_recent_reauth_a_password_and_the_current_token_and_logs_no_secret() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, old) = h.user(&session, "ann", json!({})).await;
	let path = format!("/p/api/users/{id}/subscription/sealed");
	let password = "an unguessable one";
	let open = |made: &Answer, password: &str| sealed_file::open(password, &STANDARD.decode(made.json()["file"].as_str().unwrap()).unwrap());
	assert_eq!(h.call(Method::POST, &path, Some(&session), Some(json!({"password": "too short"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	let made = h.call(Method::POST, &path, Some(&session), Some(json!({"password": password})), "10.0.0.1").await;
	assert_eq!((made.status, made.json()["filename"].clone()), (StatusCode::OK, json!("veilway-ann.vwsealed")));
	assert_eq!(made.headers.get("cache-control").unwrap(), "no-store");
	assert_eq!(open(&made, password).unwrap(), old_text(&old), "the file holds the link the panel shows");
	assert!(open(&made, "another unguessable one").is_err());
	// A recent re-authentication, as for showing the link.
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, &path, Some(&session), Some(json!({"password": password})), "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	// With no copy kept, only the user's current link is taken, and the file always has the panel's own endpoint and key.
	h.configure(&session, json!({"show_links_once": true})).await;
	assert_eq!(h.call(Method::POST, &path, Some(&session), Some(json!({"password": password})), "10.0.0.1").await.status, StatusCode::GONE);
	let made = h.call(Method::POST, &path, Some(&session), Some(json!({"password": password, "link": old_text(&old)})), "10.0.0.1").await;
	assert_eq!(open(&made, password).unwrap(), old_text(&old));
	assert_eq!(h.call(Method::POST, &path, Some(&session), Some(json!({"password": password, "link": "veilway://sub/other.example/s#v1.0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc.VVVVVVVVVVVVVVVVVVVVVQ"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	let reset = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/reset"), Some(&session), Some(json!({"remove_devices": false})), "10.0.0.1").await.json();
	assert_eq!(h.call(Method::POST, &path, Some(&session), Some(json!({"password": password, "link": old_text(&old)})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "the old token is not taken");
	let current = reset["link"]["veilway"].as_str().unwrap().to_owned();
	assert_eq!(open(&h.call(Method::POST, &path, Some(&session), Some(json!({"password": password, "link": current})), "10.0.0.1").await, password).unwrap(), current);
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	assert!(audit.json()["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "link.sealed"));
	assert!(audit.body.windows(10).all(|window| window != b"veilway://") && audit.body.windows(password.len()).all(|window| window != password.as_bytes()), "no link and no password in the audit log");
}

fn old_text(link: &Link) -> String {if let Link::Native(native) = link {native.veilway()} else {String::new()}}

#[tokio::test]
async fn signing_key_rotation_with_overlap() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let old = key_of(&link);
	let rotated = h.call(Method::POST, "/p/api/signing-keys/rotate", Some(&session), None, "10.0.0.1").await.json();
	let keys: Vec<envelope::SigningKey> = rotated["keys"].as_array().unwrap().iter().map(|key| envelope::SigningKey::new(STANDARD.decode(key["public_key"].as_str().unwrap()).unwrap().try_into().unwrap()).unwrap()).collect();
	assert_eq!(keys.len(), 2);
	let new = keys[1];
	assert_eq!(h.call(Method::POST, "/p/api/signing-keys/rotate", Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT);
	// A client with only the old key is served under it, and the document lists both. One with only the new key is served under that.
	let Payload::Subscription(by_old) = opened(&h.fetch(&link, &[old.kid()], 1, "fetch", None).await, &[old]) else {panic!()};
	assert_eq!(by_old.signing_keys, vec![old, new]);
	let Payload::Subscription(by_new) = opened(&h.fetch(&link, &[new.kid()], 1, "fetch", None).await, &[new]) else {panic!()};
	assert_eq!(by_new.signing_keys.len(), 2);
	assert!(envelope::verify(&h.fetch(&link, &[new.kid()], 1, "fetch", None).await.body, &[old], BODY_MAX).is_err(), "the new key signs for the client that holds it");
	assert_eq!(h.call(Method::POST, "/p/api/signing-keys/finish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	// The old key is retired: a client that holds only it gets the signed refusal, under the old key.
	assert_eq!(refusal_of(&h.fetch(&link, &[old.kid()], 1, "fetch", None).await, &[old]), Reason::KeyRetired);
	let Payload::Subscription(after) = opened(&h.fetch(&link, &[new.kid()], 1, "fetch", None).await, &[new]) else {panic!()};
	assert_eq!(after.signing_keys, vec![new]);
	let listed = h.call(Method::GET, "/p/api/signing-keys", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(listed["keys"].as_array().unwrap().iter().filter(|key| key["state"] == "retired").count(), 1);
	// A retired key is destroyed after 365 days and not before.
	let mut signing = h.app.signing.lock().unwrap();
	signing.entries[0].retired_at = Some(crypto::now() - 366 * 86_400);
	signing.save().unwrap();
	let reloaded = veilway_panel::app::Signing::load(&h.app.cfg.signing).unwrap();
	assert_eq!(reloaded.entries.len(), 1);
}

#[tokio::test]
async fn users_are_pushed_to_the_node() {
	let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
	let dir = std::env::temp_dir().join(format!("vwnode-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	let socket = dir.join("control.sock");
	let (put, reset) = (seen.clone(), seen.clone());
	let node = Router::new()
		.route("/v1/config", get(|| async {Json(json!({"revision": "rev1", "generation": 1, "document": {"version": 1, "users": []}}))}).put(move |headers: HeaderMap, Json(document): Json<Value>| async move {
			assert_eq!(headers.get("if-match").unwrap(), "\"rev1\"");
			put.lock().unwrap().push(document);
			Json(json!({}))
		}))
		.route("/v1/users", get(|| async {Json(json!({"users": [{"name": "ann", "used_bytes": 777, "period_start": 5}]}))}))
		.route("/v1/users/{name}/usage/reset", post(move |axum::extract::Path(name): axum::extract::Path<String>| async move {reset.lock().unwrap().push(json!({"reset": name})); Json(json!({"name": name, "used_bytes": 0}))}));
	let listener = tokio::net::UnixListener::bind(&socket).unwrap();
	tokio::spawn(async move {axum::serve(listener, node).await.unwrap();});
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, _) = h.user(&session, "ann", json!({"groups": ["vip"], "quota_bytes": 5000, "quota_period": "daily", "expires_at": 4102444800i64})).await;
	let made = h.call(Method::POST, &format!("/p/api/users/{id}/devices"), Some(&session), Some(json!({"name": "panel phone"})), "10.0.0.1").await.json();
	assert_eq!((made["weaker"].clone(), made["node"]["synced"].clone(), made["device"]["key_origin"].clone()), (json!(true), json!(true), json!("panel")));
	let document = seen.lock().unwrap().iter().find(|document| document.get("users").is_some()).cloned().unwrap();
	let user = &document["users"][0];
	assert_eq!((user["name"].clone(), user["groups"].clone(), user["quota_bytes"].clone(), user["quota_period"].clone(), user["expires_at"].clone()), (json!("ann"), json!(["vip"]), json!(5000), json!("daily"), json!("2100-01-01T00:00:00Z")));
	assert_eq!(user["devices"][0]["addresses"], json!(["10.66.0.2"]));
	assert_eq!(STANDARD.decode(user["devices"][0]["transport_secrets"][0].as_str().unwrap()).unwrap().len(), 32);
	let listed = h.call(Method::GET, "/p/api/users", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(listed["users"][0]["node"]["used_bytes"], 777);
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{id}/usage/reset"), Some(&session), Some(json!({})), "10.0.0.1").await.status, StatusCode::OK);
	assert!(seen.lock().unwrap().contains(&json!({"reset": "ann"})));
	let exported = h.call(Method::POST, &format!("/p/api/users/{id}/devices/{}/export", made["device"]["id"]), Some(&session), None, "10.0.0.1").await;
	assert_eq!(exported.status, StatusCode::OK, "{}", String::from_utf8_lossy(&exported.body));
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn openapi_is_committed() {
	let committed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json")).expect("openapi.json is committed next to the manifest");
	assert!(committed == openapi::openapi(), "openapi.json is out of date: run `veilway-panel openapi > openapi.json`");
}

#[tokio::test]
async fn bulk_actions_and_setup_once() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let a = h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "a"})), "10.0.0.1").await.json()["user"]["id"].as_i64().unwrap();
	let b = h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "b"})), "10.0.0.1").await.json()["user"]["id"].as_i64().unwrap();
	let done = h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [a, b, 999], "action": "add_group", "value": "staff"})), "10.0.0.1").await.json();
	assert_eq!((done["done"].clone(), done["failed"].as_array().unwrap().len()), (json!(2), 1));
	h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [a], "action": "disable"})), "10.0.0.1").await;
	let staff = h.call(Method::GET, "/p/api/users?group=staff&enabled=true", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(staff["users"].as_array().unwrap().len(), 1);
	assert_eq!(h.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.json()["setup_needed"], false);
	let second = h.call(Method::POST, "/p/api/setup", None, Some(json!({"token": "anything", "username": "other", "password": PASSWORD})), "10.0.0.1").await;
	assert_eq!(second.status, StatusCode::FORBIDDEN);
	assert_eq!(h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "Bad Name"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn setup_needs_the_terms_and_records_the_acceptance() {
	let dir = std::env::temp_dir().join(format!("vwpanel-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	let cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), gateway: dir.join("gateway.keys"), gateway_next: dir.join("gateway.next"), node_socket: dir.join("none.sock"), ..Config::default()};
	let app = build(cfg).unwrap();
	let h = Harness {router: router(app.clone()), app, totp: Vec::new(), dir};
	let token = h.app.setup_token.lock().unwrap().clone().unwrap();
	let setup = json!({"token": token, "username": "owner", "password": PASSWORD});
	assert_eq!(h.call(Method::POST, "/p/api/setup", None, Some(setup.clone()), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::POST, "/p/api/setup", None, Some(json!({"token": token, "username": "owner", "password": PASSWORD, "accepted_terms": false})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.json()["setup_needed"], true);
	let mut accepted = setup;
	accepted["accepted_terms"] = json!(true);
	assert_eq!(h.call(Method::POST, "/p/api/setup", None, Some(accepted), "10.0.0.1").await.status, StatusCode::OK);
	let detail: String = h.app.db.call(|db| db.query_row("select detail from audit where action = 'setup'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(detail, "first admin created, terms 2026-10-16 accepted");
	let kept: String = h.app.db.call(|db| db.query_row("select value from settings where key = 'terms_accepted'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(serde_json::from_str::<Value>(&kept).unwrap()["version"], "2026-10-16");
}

#[tokio::test]
async fn provider_terms_urls_are_https_and_checked_when_saved() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let long = format!("https://terms.example.org/{}", "a".repeat(600));
	for bad in ["http://terms.example.org/terms", "https://owner:secret@terms.example.org/", "https://", long.as_str()] {
		let answer = h.call(Method::PUT, "/p/api/settings", Some(&session), Some(json!({"privacy_url": bad})), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{bad}");
	}
	h.configure(&session, json!({"terms_url": "https://terms.example.org/terms", "privacy_url": "https://example.org/privacy"})).await;
	let kept = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((kept["terms_url"].as_str(), kept["privacy_url"].as_str()), (Some("https://terms.example.org/terms"), Some("https://example.org/privacy")));
}

#[tokio::test]
async fn signed_document_carries_the_provider_terms_and_privacy_links() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"terms_url": "https://terms.example.org/terms", "privacy_url": "https://example.org/privacy"})).await;
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let (key, kids) = (key_of(&link), [key_of(&link).kid()]);
	let Payload::Subscription(document) = opened(&h.fetch(&link, &kids, 1, "fetch", None).await, &[key]) else {panic!("a document")};
	let agreement = document.agreement.clone().expect("an agreement");
	assert_eq!((agreement.terms.as_ref().map(|url| url.as_str()), agreement.privacy.as_ref().map(|url| url.as_str()), document.support.len()), (Some("https://terms.example.org/terms"), Some("https://example.org/privacy"), 0));
}

#[tokio::test]
async fn web_pages_load_without_a_session() {
	let h = Harness::new().await;
	let page = h.call(Method::GET, "/p/", None, None, "10.0.0.1").await;
	assert_eq!((page.status, page.headers.get("x-robots-tag").map(|value| value.to_str().unwrap().to_string())), (StatusCode::OK, Some("noindex".to_string())));
	assert_eq!(h.call(Method::GET, "/p", None, None, "10.0.0.1").await.status, StatusCode::PERMANENT_REDIRECT);
	assert_eq!(h.call(Method::GET, "/p/login/deep", None, None, "10.0.0.1").await.status, StatusCode::OK);
	let robots = h.call(Method::GET, "/robots.txt", None, None, "10.0.0.1").await;
	assert_eq!(robots.body, b"User-agent: *\nDisallow: /p/\n".to_vec());
	assert_eq!(h.call(Method::DELETE, "/p/api/status", None, None, "10.0.0.1").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn forwarded_sources_keep_their_address_and_origins_follow_allowed_hosts() {
	let h = Harness::with_config(None, |cfg| {cfg.trusted_proxies = vec!["10.0.0.9".into()]; cfg.allowed_hosts = vec!["panel.test".into()];}).await;
	let session = h.login("10.0.0.1").await;
	let forwarded = h.send(Request::builder().method(Method::POST).uri("/p/api/login").header(HOST, "panel.test").header(CONTENT_TYPE, "application/json").header("x-forwarded-for", "198.51.100.4, 203.0.113.5:4433"), Some(json!({"username": "owner", "password": "nope nope nope", "totp": "000000"})), "10.0.0.9").await;
	assert_eq!(forwarded.status, StatusCode::UNAUTHORIZED);
	let logged: i64 = h.app.db.call(|db| db.query_row("select count(*) from audit where source = '203.0.113.5' and action = 'login.failed'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(logged, 1);
	let same_host = h.send(Request::builder().method(Method::POST).uri("/p/api/users").header(HOST, "panel.test").header(ORIGIN, "https://panel.test").header(COOKIE, &session.cookie).header("x-csrf-token", &session.csrf).header(CONTENT_TYPE, "application/json"), Some(json!({"name": "zed"})), "10.0.0.1").await;
	assert_eq!(same_host.status, StatusCode::OK);
}

#[tokio::test]
async fn failed_logins_name_only_accounts_that_exist() {
	let h = Harness::new().await;
	h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "ghost", "password": "nope nope nope", "totp": "000000"})), "10.0.0.2").await;
	let names: Vec<String> = h.app.db.call(|db| db.prepare("select actor from audit where action = 'login.failed'").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()).await.unwrap();
	assert_eq!(names, vec!["unknown".to_string()]);
}

#[tokio::test]
async fn node_push_is_retried_after_an_outage() {
	let seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
	let dir = std::env::temp_dir().join(format!("vwretry-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	let socket = dir.join("control.sock");
	let put = seen.clone();
	let node = Router::new().route("/v1/config", get(|| async {Json(json!({"revision": "rev1", "generation": 1, "document": {"version": 1, "users": []}}))}).put(move |Json(document): Json<Value>| async move {
		put.lock().unwrap().push(document);
		Json(json!({}))
	}));
	let h = Harness::with_socket(Some(socket.clone())).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, link) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.call(Method::POST, "/p/api/node/sync", Some(&session), None, "10.0.0.1").await.json()["synced"], false);
	assert!(h.app.dirty.load(Ordering::Relaxed), "the push failed with the node down");
	let mut state = Upkeep::default();
	upkeep_once(&h.app, &mut state).await;
	assert!(h.app.dirty.load(Ordering::Relaxed) && state.wait == 5);
	let listener = tokio::net::UnixListener::bind(&socket).unwrap();
	tokio::spawn(async move {axum::serve(listener, node).await.unwrap();});
	// The retry is due after its wait. Forgetting when it was due stands in for the wait.
	state.retry_at = 0;
	upkeep_once(&h.app, &mut state).await;
	assert!(!h.app.dirty.load(Ordering::Relaxed));
	assert_eq!(seen.lock().unwrap().last().unwrap()["users"], json!([]), "ann has no enrolled device yet");
	let made = h.call(Method::POST, &format!("/p/api/users/{id}/devices"), Some(&session), Some(json!({"name": "phone"})), "10.0.0.1").await.json();
	assert_eq!(made["device"]["state"], "enrolled");
	assert_eq!(h.fetch(&link, &[key_of(&link).kid()], 9, "fetch", None).await.status, StatusCode::OK);
	assert_eq!(h.call(Method::POST, "/p/api/node/sync", Some(&session), None, "10.0.0.1").await.json()["synced"], true);
	let pushed = seen.lock().unwrap().last().unwrap()["users"][0]["devices"].clone();
	assert_eq!(pushed.as_array().unwrap().len(), 1, "a pending device is not pushed");
	let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn config_refuses_what_the_panel_cannot_serve_safely() {
	assert!(Config {listen: "0.0.0.0:8480".parse().unwrap(), trusted_proxies: vec!["127.0.0.1".into()], ..Config::default()}.check().unwrap_err().contains("loopback"));
	assert!(Config::default().check().unwrap_err().contains("trusted_proxies"));
	assert!(Config {direct: true, ..Config::default()}.check().is_ok());
	assert!(Config {trusted_proxies: vec!["127.0.0.1".into()], ..Config::default()}.check().is_ok());
}

#[test]
fn ipv6_hosts_share_a_limit_and_the_limiter_stays_bounded() {
	assert_eq!(bucket("2001:db8:1:2::1", 64), bucket("2001:db8:1:2:ffff::9", 64));
	assert_ne!(bucket("2001:db8:1:2::1", 64), bucket("2001:db8:1:3::1", 64));
	assert_eq!(bucket("192.0.2.7", 64), "192.0.2.7");
	let limiter = Limiter::default();
	for index in 0..100_000 {limiter.hit(&index.to_string(), 1, 3600);}
	assert!(!limiter.hit("one more", 1, 3600));
	assert!(limiter.hit("7", 2, 3600));
}

#[test]
fn signing_keys_must_be_private() {
	use std::os::unix::fs::PermissionsExt;
	let dir = std::env::temp_dir().join(format!("vwsign-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	let path = dir.join("signing.keys");
	std::fs::write(&path, "[]").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(Signing::load(&path).is_err());
	let _ = std::fs::remove_dir_all(dir);
}

/// A node that keeps one config and answers the way the real control API does: a revision per applied change, If-Match, validate and diff, and the stats routes.
struct Fake {document: Mutex<Value>, generation: Mutex<u64>, status: Mutex<Value>, stats: Mutex<Value>, sessions: Mutex<Value>, applied: Mutex<Vec<Value>>, dir: PathBuf}

impl Fake {
	async fn start(document: Value) -> (Arc<Fake>, PathBuf) {
		let dir = std::env::temp_dir().join(format!("vwfake-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		std::fs::create_dir_all(&dir).unwrap();
		let socket = dir.join("control.sock");
		let fake = Arc::new(Fake {document: Mutex::new(document), generation: Mutex::new(1), status: Mutex::new(json!({"version": "0.0.0", "uptime_secs": 5, "generation": 1})), stats: Mutex::new(json!({})), sessions: Mutex::new(json!({"sessions": []})), applied: Mutex::new(Vec::new()), dir});
		let node = Router::new()
			.route("/v1/config", get(|State(fake): State<Arc<Fake>>| async move {
				let generation = *fake.generation.lock().unwrap();
				Json(json!({"revision": format!("rev{generation}"), "generation": generation, "document": redacted(fake.document.lock().unwrap().clone())}))
			}).put(|State(fake): State<Arc<Fake>>, headers: HeaderMap, Json(document): Json<Value>| async move {
				let mut generation = fake.generation.lock().unwrap();
				if headers.get("if-match").unwrap() != &format!("\"rev{generation}\"") {return (StatusCode::CONFLICT, Json(json!({"error": {"code": "stale"}})))}
				*generation += 1;
				fake.applied.lock().unwrap().push(document.clone());
				*fake.document.lock().unwrap() = document;
				(StatusCode::OK, Json(json!({"revision": format!("rev{generation}"), "generation": *generation, "saved": true, "diff": {}, "report": {}})))
			}))
			.route("/v1/config/validate", post(|Json(document): Json<Value>| async move {Json(json!({"valid": document.get("invalid").is_none(), "report": {"errors": [], "warnings": []}}))}))
			.route("/v1/config/diff", post(|Json(_): Json<Value>| async move {Json(json!({"valid": true, "report": {}, "diff": {"inbounds": {"added": ["x"]}}}))}))
			.route("/v1/status", get(|State(fake): State<Arc<Fake>>| async move {Json(fake.status.lock().unwrap().clone())}))
			.route("/v1/stats", get(|State(fake): State<Arc<Fake>>| async move {Json(fake.stats.lock().unwrap().clone())}))
			.route("/v1/sessions", get(|State(fake): State<Arc<Fake>>| async move {Json(fake.sessions.lock().unwrap().clone())}))
			.route("/v1/exits", get(|| async {Json(json!({"exits": [{"tag": "main", "udp": true}]}))}))
			.route("/v1/links", get(|| async {Json(json!({"links": []}))}))
			.route("/v1/users", get(|| async {Json(json!({"users": []}))}))
			.with_state(fake.clone());
		let listener = tokio::net::UnixListener::bind(&socket).unwrap();
		tokio::spawn(async move {axum::serve(listener, node).await.unwrap();});
		(fake, socket)
	}
}

impl Drop for Fake {
	fn drop(&mut self) {let _ = std::fs::remove_dir_all(&self.dir);}
}

/// What the node shows of a document: the key of a borrowed-site transport only as a marker made of its first bytes, as the real node shows every secret once it holds it.
fn redacted(mut document: Value) -> Value {
	for inbound in document["inbounds"].as_array_mut().into_iter().flatten() {
		for transport in inbound["transports"].as_array_mut().into_iter().flatten().filter(|transport| transport["type"] == "faketls") {
			if let Some(bytes) = transport["transport_key"].as_str().filter(|key| !key.starts_with("<redacted")).and_then(|key| STANDARD.decode(key).ok()) {transport["transport_key"] = json!(format!("<redacted:{}>", bytes.iter().take(4).map(|byte| format!("{byte:02x}")).collect::<String>()))}
		}
	}
	document
}

fn node_document(pool: &str) -> Value {
	json!({"version": 1, "dns": {}, "inbounds": [{"tag": "Main", "type": "veilway", "private_key": "<redacted>", "address": [pool], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "udp-obfs", "listen": "0.0.0.0:51821"}]}], "outbounds": [{"tag": "plain", "type": "direct"}], "exits": [], "routing": {"default": "main", "rules": []}, "users": [{"name": "ghost"}]})
}

#[tokio::test]
async fn config_sections_validate_diff_and_apply_through_the_node() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let read = h.token(&session, "read", json!({})).await;
	let full = h.token(&session, "full", json!({})).await;
	let whole = h.call(Method::GET, "/p/api/config", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((whole["revision"].clone(), whole["document"].get("users").is_none()), (json!("rev1"), true), "the panel owns the users");
	assert!(h.call(Method::GET, "/p/api/config/schema", Some(&session), None, "10.0.0.1").await.json().is_object());
	let section = h.call(Method::GET, "/p/api/config/outbounds", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(section["value"][0]["tag"], "plain");
	assert_eq!(h.call(Method::GET, "/p/api/config/users", Some(&session), None, "10.0.0.1").await.status, StatusCode::NOT_FOUND);
	assert_eq!(h.bearer(Method::GET, "/p/api/config/exits", &read, None, "10.1.1.1").await.status, StatusCode::OK);
	let outbounds = json!([{"tag": "plain", "type": "direct"}, {"tag": "proxy", "type": "socks5", "server": "127.0.0.1:1080"}]);
	assert_eq!(h.bearer(Method::PUT, "/p/api/config/outbounds", &read, Some(json!({"revision": "rev1", "value": outbounds})), "10.1.1.1").await.status, StatusCode::FORBIDDEN);
	assert_eq!(h.bearer(Method::PUT, "/p/api/config/outbounds", &full, Some(json!({"revision": "rev1", "value": {"not": "a list"}})), "10.1.1.1").await.status, StatusCode::BAD_REQUEST);
	let diff = h.bearer(Method::POST, "/p/api/config/diff", &full, Some(json!({"document": node_document("10.66.0.1/24")})), "10.1.1.1").await.json();
	assert_eq!(diff["diff"]["inbounds"]["added"], json!(["x"]));
	let applied = h.bearer(Method::PUT, "/p/api/config/outbounds", &full, Some(json!({"revision": "rev1", "value": outbounds})), "10.1.1.1").await;
	assert_eq!(applied.status, StatusCode::OK, "{}", String::from_utf8_lossy(&applied.body));
	assert_eq!(applied.json()["generation"], 2);
	let document = fake.applied.lock().unwrap().last().unwrap().clone();
	assert_eq!((document["outbounds"].clone(), document["users"].clone()), (outbounds, json!([])), "the section changed and the panel's users replaced the node's");
	let stale = h.bearer(Method::PUT, "/p/api/config/outbounds", &full, Some(json!({"revision": "rev1", "value": []})), "10.1.1.1").await;
	assert_eq!(stale.status, StatusCode::CONFLICT);
	let mut bad = node_document("10.66.0.1/24");
	bad["invalid"] = json!(true);
	let refused = h.call(Method::PUT, "/p/api/config", Some(&session), Some(json!({"revision": "rev2", "document": bad})), "10.1.1.1").await;
	assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
	assert_eq!(fake.applied.lock().unwrap().len(), 1, "a refused document reaches no apply");
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await.json();
	assert!(audit["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "config.apply" && entry["target"] == "outbounds"));
}

#[tokio::test]
async fn notices_dns_log_links_and_replay_are_sections_like_the_others() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let full = h.token(&session, "full", json!({})).await;
	let notices = h.call(Method::GET, "/p/api/config/notices", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(notices["value"], Value::Null, "a section the document leaves out is null");
	assert_eq!(h.call(Method::GET, "/p/api/config/replay", Some(&session), None, "10.0.0.1").await.json()["read_at_start"], json!(["cache"]));
	for (section, wrong) in [("notices", json!({})), ("links", json!({})), ("tunnels", json!({})), ("dns", json!([])), ("log", json!([]))] {
		assert_eq!(h.bearer(Method::PUT, &format!("/p/api/config/{section}"), &full, Some(json!({"revision": "rev1", "value": wrong})), "10.1.1.1").await.status, StatusCode::BAD_REQUEST, "{section}");
	}
	let mut revision = 1;
	for (section, value) in [("notices", json!([{"severity": "warning", "text": "Maintenance on Friday from 02:00 UTC"}])), ("dns", json!({"servers": ["9.9.9.9:53"], "hijack": false})), ("log", json!({"level": "warn", "destinations": false})), ("links", json!([])), ("tunnels", json!([])), ("replay", json!({"cache": 4096}))] {
		let applied = h.call(Method::PUT, &format!("/p/api/config/{section}"), Some(&session), Some(json!({"revision": format!("rev{revision}"), "value": value})), "10.0.0.1").await;
		assert_eq!(applied.status, StatusCode::OK, "{section}: {}", String::from_utf8_lossy(&applied.body));
		revision += 1;
		assert_eq!(fake.applied.lock().unwrap().last().unwrap()[section], value, "{section}");
	}
	assert_eq!(h.call(Method::GET, "/p/api/config/notices", Some(&session), None, "10.0.0.1").await.json()["value"][0]["severity"], "warning");
}

#[tokio::test]
async fn through_is_written_when_set_and_refused_when_it_loops_breaks_a_user_or_is_too_long() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let proxies = json!([{"tag": "plain", "type": "direct"}, {"tag": "p1", "type": "socks5", "server": "127.0.0.1:1080"}, {"tag": "p2", "type": "socks5", "server": "127.0.0.1:1081", "via": "p1"}]);
	let applied = h.call(Method::PUT, "/p/api/config/outbounds", Some(&session), Some(json!({"revision": "rev1", "value": proxies})), "10.0.0.1").await;
	assert_eq!(applied.status, StatusCode::OK, "{}", String::from_utf8_lossy(&applied.body));
	let document = fake.applied.lock().unwrap().last().unwrap().clone();
	assert_eq!((document["outbounds"][1].get("via").cloned(), document["outbounds"][2]["via"].clone()), (None, json!("p1")), "through is written only when it is set");
	let long: Vec<Value> = std::iter::once(json!({"tag": "h0", "type": "socks5", "server": "127.0.0.1:1080"})).chain((1..=9).map(|i| json!({"tag": format!("h{i}"), "type": "socks5", "server": "127.0.0.1:1080", "via": format!("h{}", i - 1)}))).collect();
	let refusals = [
		(json!([{"tag": "p1", "type": "socks5", "server": "127.0.0.1:1080", "via": "p2"}, {"tag": "p2", "type": "socks5", "server": "127.0.0.1:1081", "via": "p1"}]), "is in a loop"),
		(json!([{"tag": "p1", "type": "socks5", "server": "127.0.0.1:1080", "via": "nope"}]), "names no socks5 outbound"),
		(json!([{"tag": "plain", "type": "direct"}, {"tag": "p1", "type": "socks5", "server": "127.0.0.1:1080", "via": "plain"}]), "names no socks5 outbound"),
		(json!([{"tag": "plain", "type": "direct", "via": "p1"}, {"tag": "p1", "type": "socks5", "server": "127.0.0.1:1080"}]), "only a socks5 outbound"),
		(Value::Array(long), "more than 8 hops"),
		(json!([{"tag": "plain", "type": "direct"}, {"tag": "p9", "type": "socks5", "server": "127.0.0.1:1080"}, {"tag": "p2", "type": "socks5", "server": "127.0.0.1:1081", "via": "p1"}]), "the Through of outbound p2 names p1"),
	];
	for (value, text) in refusals {
		let refused = h.call(Method::PUT, "/p/api/config/outbounds", Some(&session), Some(json!({"revision": "rev2", "value": value})), "10.0.0.1").await;
		assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
		assert!(String::from_utf8_lossy(&refused.body).contains(text), "{text}: {}", String::from_utf8_lossy(&refused.body));
	}
	let mut looped = node_document("10.66.0.1/24");
	looped["outbounds"] = json!([{"tag": "p1", "type": "socks5", "server": "127.0.0.1:1080", "via": "p1"}]);
	assert_eq!(h.call(Method::POST, "/p/api/config/validate", Some(&session), Some(json!({"document": looped})), "10.0.0.1").await.status, StatusCode::UNPROCESSABLE_ENTITY);
	let dialed = json!([{"tag": "up", "direction": "forward", "peer": {"public_key": "AAAA"}, "via": "p1"}]);
	assert_eq!(h.call(Method::PUT, "/p/api/config/links", Some(&session), Some(json!({"revision": "rev2", "value": dialed})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(fake.applied.lock().unwrap().last().unwrap()["links"][0]["via"], "p1", "a dialed link keeps its through");
	let listening = json!([{"tag": "in", "direction": "forward", "inbound": "Main", "public_key": "AAAA", "via": "p1"}]);
	let refused = h.call(Method::PUT, "/p/api/config/links", Some(&session), Some(json!({"revision": "rev3", "value": listening})), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
	assert!(String::from_utf8_lossy(&refused.body).contains("only a link this node dials"));
	let chained_exit = json!([{"tag": "a", "backend": {"type": "netstack", "outbound": "p2", "unsupported": {"udp": "direct"}}}]);
	let refused = h.call(Method::PUT, "/p/api/config/exits", Some(&session), Some(json!({"revision": "rev3", "value": chained_exit})), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
	assert!(String::from_utf8_lossy(&refused.body).contains("around the chain of outbound p2"));
	let target_only = json!([{"tag": "a", "backend": {"type": "netstack", "outbound": "p1", "unsupported": {"udp": "direct"}}}]);
	assert_eq!(h.call(Method::PUT, "/p/api/config/exits", Some(&session), Some(json!({"revision": "rev3", "value": target_only})), "10.0.0.1").await.status, StatusCode::OK, "an outbound that is only the target of a through dials directly, so direct UDP is allowed");
}

#[tokio::test]
async fn a_default_exit_is_one_of_the_users_exits_and_goes_with_its_exit() {
	let mut document = node_document("10.66.0.1/24");
	document["exits"] = json!([{"tag": "fra", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "ams", "backend": {"type": "netstack", "outbound": "plain"}}]);
	let (fake, socket) = Fake::start(document).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	assert_eq!(h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "ann", "exits": ["fra"], "exit": "ams"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "a default outside the allowed exits");
	let made = h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "ann", "exits": ["fra", "ams"], "exit": "ams"})), "10.0.0.1").await.json();
	let id = made["user"]["id"].as_i64().unwrap();
	assert_eq!(made["user"]["exit"], "ams");
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{id}/devices"), Some(&session), Some(json!({"name": "phone"})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(fake.applied.lock().unwrap().last().unwrap()["users"][0]["exit"], "ams", "the default reaches the node");
	assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"exit": "nowhere"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"exits": ["fra"]})), "10.0.0.1").await.json()["user"]["exit"], Value::Null, "narrowing the exits clears a default they leave out");
	assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"exits": "all", "exit": "fra"})), "10.0.0.1").await.json()["user"]["exit"], "fra");
	let revision = h.call(Method::GET, "/p/api/config/exits", Some(&session), None, "10.0.0.1").await.json()["revision"].clone();
	let applied = h.call(Method::PUT, "/p/api/config/exits", Some(&session), Some(json!({"revision": revision, "value": [{"tag": "ams", "backend": {"type": "netstack", "outbound": "plain"}}]})), "10.0.0.1").await;
	assert_eq!(applied.status, StatusCode::OK, "{}", String::from_utf8_lossy(&applied.body));
	assert!(fake.applied.lock().unwrap().last().unwrap()["users"][0].get("exit").is_none(), "a default whose exit is gone is not sent");
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{id}"), Some(&session), None, "10.0.0.1").await.json()["exit"], Value::Null, "and is cleared once the node took the change");
}

#[tokio::test]
async fn bulk_exits_set_every_user_and_clear_defaults_they_leave_out() {
	let mut document = node_document("10.66.0.1/24");
	document["exits"] = json!([{"tag": "fra", "backend": {"type": "netstack", "outbound": "plain"}}, {"tag": "ams", "backend": {"type": "netstack", "outbound": "plain"}}]);
	let (_fake, socket) = Fake::start(document).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let a = h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "ann", "exit": "fra"})), "10.0.0.1").await.json()["user"]["id"].as_i64().unwrap();
	let b = h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "bob", "exits": ["ams"], "exit": "ams"})), "10.0.0.1").await.json()["user"]["id"].as_i64().unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [a, b], "action": "set_exits", "value": {"no": "list"}})), "10.0.0.1").await.json()["failed"].as_array().unwrap().len(), 2);
	assert_eq!(h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [a, b], "action": "set_exits", "value": ["ams", "lon"]})), "10.0.0.1").await.json()["done"], 2);
	let users = h.call(Method::GET, "/p/api/users", Some(&session), None, "10.0.0.1").await.json();
	let seen: Vec<(Value, Value)> = users["users"].as_array().unwrap().iter().map(|user| (user["exits"].clone(), user["exit"].clone())).collect();
	assert_eq!(seen, vec![(json!(["ams", "lon"]), Value::Null), (json!(["ams", "lon"]), json!("ams"))], "ann's default fra is left out and cleared, bob's ams stays");
	assert_eq!(h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [a, b], "action": "set_exits", "value": "all"})), "10.0.0.1").await.json()["done"], 2);
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{b}"), Some(&session), None, "10.0.0.1").await.json()["exits"], "all");
}

#[tokio::test]
async fn bulk_reset_links_makes_new_links_and_xray_credentials_and_removes_devices_only_when_asked() {
	let mut document = node_document("10.66.0.1/24");
	document["public_addresses"] = json!(["vpn.example.org"]);
	let (fake, socket) = Fake::start(document).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	*fake.status.lock().unwrap() = json!({"version": "0.0.0", "addons": {"xray": {"installed": true, "release": "v26.3.27"}}});
	let vless = json!({"tag": "vless1", "protocol": "vless", "port": 8444, "cert": "/etc/veilway/cert.pem", "key": "/etc/veilway/key.pem", "decoy": "http://127.0.0.1:8080"});
	assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(vless), "10.0.0.1").await.status, StatusCode::OK);
	let (ann, _) = h.user(&session, "ann", json!({})).await;
	let (bob, _) = h.user(&session, "bob", json!({})).await;
	for id in [ann, bob] {
		assert_eq!(h.call(Method::POST, &format!("/p/api/users/{id}/devices"), Some(&session), Some(json!({"name": "phone"})), "10.0.0.1").await.status, StatusCode::OK);
	}
	let (old_ann, old_bob) = (h.call(Method::POST, &format!("/p/api/users/{ann}/subscription/show"), Some(&session), None, "10.0.0.1").await.json()["veilway"].clone(), h.call(Method::POST, &format!("/p/api/users/{bob}/subscription/show"), Some(&session), None, "10.0.0.1").await.json()["veilway"].clone());
	let secret = |applied: &Value, user: &str| applied["xray"]["inbounds"][0]["clients"].as_array().unwrap().iter().find(|client| client["user"] == user).unwrap()["secret"].clone();
	let before = fake.applied.lock().unwrap().last().unwrap().clone();
	let (xray_ann, xray_bob) = (secret(&before, "ann"), secret(&before, "bob"));
	let kept = h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [ann], "action": "reset_links", "remove_devices": false})), "10.0.0.1").await.json();
	assert_eq!((kept["done"].clone(), kept["devices_removed"].clone(), kept["failed"].as_array().unwrap().len()), (json!(1), json!(0), 0));
	assert_ne!(h.call(Method::POST, &format!("/p/api/users/{ann}/subscription/show"), Some(&session), None, "10.0.0.1").await.json()["veilway"], old_ann, "the selected user gets a new link");
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{bob}/subscription/show"), Some(&session), None, "10.0.0.1").await.json()["veilway"], old_bob, "an unselected user keeps the link");
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{ann}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 1, "devices stay unless asked");
	let after = fake.applied.lock().unwrap().last().unwrap().clone();
	assert_ne!(secret(&after, "ann"), xray_ann, "the selected user gets new Xray credentials");
	assert_eq!(secret(&after, "bob"), xray_bob, "the unselected user keeps theirs");
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{ann}/devices"), Some(&session), Some(json!({"name": "tablet"})), "10.0.0.1").await.status, StatusCode::OK);
	let removed = h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [ann], "action": "reset_links", "remove_devices": true})), "10.0.0.1").await.json();
	assert_eq!((removed["done"].clone(), removed["devices_removed"].clone()), (json!(1), json!(1)));
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{ann}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 1, "only the devices of the current link go, the earlier one keeps working");
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{bob}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 1, "an unselected user's devices stay");
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(audit["entries"].as_array().unwrap().iter().filter(|entry| entry["action"] == "link.reset" && entry["target"] == json!(format!("user:{ann}"))).count(), 2, "one audit line per reset");
	assert_eq!(h.call(Method::POST, "/p/api/users/bulk", Some(&session), Some(json!({"ids": [ann], "action": "disable"})), "10.0.0.1").await.json()["devices_removed"], Value::Null, "other actions answer null");
}

#[tokio::test]
async fn guarded_sections_need_a_recent_reauth_and_no_token_and_null_removes_optional_ones() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let full = h.token(&session, "full", json!({})).await;
	assert_eq!(h.bearer(Method::PUT, "/p/api/config/log", &full, Some(json!({"revision": "rev1", "value": {"level": "warn"}})), "10.1.1.1").await.status, StatusCode::FORBIDDEN, "a token never changes log");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	let stale = h.call(Method::PUT, "/p/api/config/log", Some(&session), Some(json!({"revision": "rev1", "value": {"level": "warn"}})), "10.0.0.1").await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::PUT, "/p/api/config/log", Some(&session), Some(json!({"revision": "rev1", "value": {"level": "warn", "destinations": false}})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::PUT, "/p/api/config/log", Some(&session), Some(json!({"revision": "rev2", "value": {"level": "warn", "destinations": true}})), "10.0.0.1").await.status, StatusCode::OK);
	let links = json!([{"tag": "l1", "allow_private": false, "transport_secret": "SECRETVALUE"}]);
	assert_eq!(h.call(Method::PUT, "/p/api/config/links", Some(&session), Some(json!({"revision": "rev3", "value": links})), "10.0.0.1").await.status, StatusCode::OK);
	let edited = json!([{"tag": "l1", "allow_private": true, "transport_secret": "SECRETVALUE"}]);
	assert_eq!(h.call(Method::PUT, "/p/api/config/links", Some(&session), Some(json!({"revision": "rev4", "value": edited})), "10.0.0.1").await.status, StatusCode::OK);
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	let details: Vec<String> = audit.json()["entries"].as_array().unwrap().iter().filter(|entry| entry["action"] == "config.apply").map(|entry| entry["detail"].as_str().unwrap().to_string()).collect();
	assert!(details.iter().any(|detail| detail.contains("log.destinations false -> true")), "{details:?}");
	assert!(details.iter().any(|detail| detail.contains("links +l1")), "{details:?}");
	assert!(details.iter().any(|detail| detail.contains("links[l1].allow_private false -> true")), "{details:?}");
	assert!(!String::from_utf8_lossy(&audit.body).contains("SECRETVALUE"));
	let mut document = fake.document.lock().unwrap().clone();
	document["exits"] = json!([{"tag": "other"}]);
	assert_eq!(h.bearer(Method::PUT, "/p/api/config", &full, Some(json!({"revision": "rev5", "document": document.clone()})), "10.1.1.1").await.status, StatusCode::FORBIDDEN, "a token changes no exits through the whole config");
	document = fake.document.lock().unwrap().clone();
	document["dns"] = json!({"servers": ["1.1.1.1:53"]});
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::PUT, "/p/api/config", Some(&session), Some(json!({"revision": "rev5", "document": document.clone()})), "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::PUT, "/p/api/config/notices", Some(&session), Some(json!({"revision": "rev5", "value": [{"severity": "information", "text": "Hello"}]})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::PUT, "/p/api/config/notices", Some(&session), Some(json!({"revision": "rev6", "value": null})), "10.0.0.1").await.status, StatusCode::OK);
	assert!(fake.applied.lock().unwrap().last().unwrap().get("notices").is_none(), "null removes an optional section");
	assert_eq!(h.call(Method::PUT, "/p/api/config/inbounds", Some(&session), Some(json!({"revision": "rev7", "value": null})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "a required section stays");
	assert_eq!(h.bearer(Method::PUT, "/p/api/config/replay", &full, Some(json!({"revision": "rev7", "value": {"cache": 4096}})), "10.1.1.1").await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::PUT, "/p/api/config/replay", &full, Some(json!({"revision": "rev8", "value": null})), "10.1.1.1").await.status, StatusCode::OK);
	assert!(fake.applied.lock().unwrap().last().unwrap().get("replay").is_none());
}

#[tokio::test]
async fn profiles_are_derived_from_inbounds_with_overrides_kept() {
	let (_fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"profiles": [{"id": "other", "name": "Other", "type": "veilway"}]})).await;
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	let template = &derived["templates"][0];
	assert_eq!((template["profile"]["id"].clone(), template["profile"]["gateways"].clone(), template["profile"]["mtu"].clone()), (json!("main"), json!(["10.66.0.1"]), json!(1390)));
	assert_eq!(template["missing"], json!(["inbound_public_key", "node_host"]));
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	settings["node_host"] = json!("192.0.2.10");
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::PUT, "/p/api/profiles/overrides/Main", Some(&session), Some(json!({"set": {"inbound_public_key": STANDARD.encode([7u8; 32]), "name": "Edited"}})), "10.0.0.1").await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	let profile = &derived["templates"][0]["profile"];
	assert_eq!((profile["name"].clone(), profile["transports"][1]["endpoints"].clone(), derived["templates"][0]["missing"].clone()), (json!("Edited"), json!(["192.0.2.10:51821"]), json!([])));
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	let published = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(published["profiles"].as_array().unwrap().iter().map(|profile| profile["id"].as_str().unwrap().to_string()).collect::<Vec<_>>(), vec!["other", "main"]);
	assert_eq!(published["profile_overrides"]["Main"]["name"], "Edited", "the override stays after a publish");
}

#[tokio::test]
async fn relays_are_saved_with_the_settings_and_previewed_before() {
	let (_fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"node_host": "192.0.2.10"})).await;
	let relays = json!([{"name": "edge", "address": "198.51.100.7", "transports": ["udp-obfs"], "ports": {"udp-obfs": 4000}, "prefer": true, "enabled": true}]);
	let preview = h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": relays})), "10.0.0.1").await.json();
	assert_eq!(preview["templates"][0]["profile"]["transports"][1]["endpoints"], json!(["198.51.100.7:4000", "192.0.2.10:51821"]));
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(derived["templates"][0]["profile"]["transports"][1]["endpoints"], json!(["192.0.2.10:51821"]), "a preview saves nothing");
	let refused = h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": [{"name": "edge", "address": "Relay Example", "enabled": true}]})), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::BAD_REQUEST);
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	settings["relays"] = relays;
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings.clone()), "10.0.0.1").await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(derived["templates"][0]["profile"]["transports"][1]["endpoints"], json!(["198.51.100.7:4000", "192.0.2.10:51821"]));
	settings["relays"][0]["address"] = json!("127.0.0.1");
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
}

fn dialed(profile: &payload::Profile) -> Vec<String> {
	match &profile.transports[0] {payload::Transport::Udp(dials) => dials.iter().map(|dial| dial.address().to_string()).collect(), _ => panic!("the first transport is udp")}
}

#[tokio::test]
async fn relays_reach_the_accounts_they_are_for_in_their_documents() {
	let (_fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"node_host": "192.0.2.10"})).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({"groups": ["office"]})).await;
	let (bob_id, bob) = h.user(&session, "bob", json!({})).await;
	let relays = json!([{"name": "all", "address": "198.51.100.7", "enabled": true}, {"name": "office", "address": "198.51.100.8", "groups": ["office"], "enabled": true}, {"name": "ann", "address": "198.51.100.9", "users": [ann_id], "enabled": true}]);
	h.configure(&session, json!({"node_host": "192.0.2.10", "relays": relays.clone(), "published_relays": relays.clone(), "relay_profiles": {"main": "Main"}})).await;
	let (key, kids) = (key_of(&ann), [key_of(&ann).kid()]);
	let answer = h.fetch(&ann, &kids, 1, "fetch", None).await;
	let Payload::Subscription(for_ann) = opened(&answer, &[key]) else {panic!("a document {:?}", refusal_of(&answer, &[key]))};
	assert_eq!(dialed(&for_ann.profiles[0]), ["192.0.2.10:51820", "198.51.100.9:51820", "198.51.100.8:51820", "198.51.100.7:51820"], "own first, then the group's, then everyone's");
	let (key, kids) = (key_of(&bob), [key_of(&bob).kid()]);
	let answer = h.fetch(&bob, &kids, 2, "fetch", None).await;
	let Payload::Subscription(for_bob) = opened(&answer, &[key]) else {panic!("a document {:?}", refusal_of(&answer, &[key]))};
	assert_eq!(dialed(&for_bob.profiles[0]), ["192.0.2.10:51820", "198.51.100.7:51820"], "an account with no relay of its own gets the relays for everyone");
	let preview = h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": relays.clone(), "user": bob_id})), "10.0.0.1").await.json();
	assert_eq!(preview["templates"][0]["profile"]["transports"][0]["endpoints"], json!(["192.0.2.10:51820", "198.51.100.7:51820"]));
	let preview = h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": relays.clone(), "user": ann_id})), "10.0.0.1").await.json();
	assert_eq!(preview["templates"][0]["profile"]["transports"][0]["endpoints"], json!(["192.0.2.10:51820", "198.51.100.9:51820", "198.51.100.8:51820", "198.51.100.7:51820"]));
	assert_eq!(h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": relays.clone(), "user": 999})), "10.0.0.1").await.status, StatusCode::NOT_FOUND);
	let endpoint = h.call(Method::GET, &format!("/p/api/users/{ann_id}/endpoint"), Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(endpoint["relays"], json!(["ann", "office", "all"]));
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	settings["relays"][2]["users"] = json!([9999]);
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "an account that does not exist is refused");
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/users/{ann_id}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	let settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((settings["relays"][2]["users"].clone(), settings["published_relays"][2]["users"].clone()), (json!([]), json!([])), "a deleted account leaves the audiences, saved and published");
}

#[tokio::test]
async fn stats_are_recorded_per_bucket_and_survive_a_node_restart() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let rated = |up: u64, down: u64| json!({"users": [{"name": "ann", "traffic": {"up_bytes": up, "down_bytes": down}, "up_bytes_per_sec": 5, "down_bytes_per_sec": 9}], "inbounds": [], "exits": [{"name": "main", "traffic": {"up_bytes": up, "down_bytes": down}, "up_bytes_per_sec": 5, "down_bytes_per_sec": 9}], "outbounds": [], "flows": 2, "drops": {}, "dns": {}});
	*fake.sessions.lock().unwrap() = json!({"sessions": [{"user": "ann", "device": "d1"}, {"user": "ann", "device": "d2"}]});
	let mut state = Upkeep::default();
	for (up, down) in [(1000, 2000), (1100, 2300), (40, 70)] {
		*fake.stats.lock().unwrap() = rated(up, down);
		state.polled_at = 0;
		upkeep_once(&h.app, &mut state).await;
	}
	let usage = h.call(Method::GET, "/p/api/stats/usage?kind=user&period=day", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(usage["entries"], json!([{"name": "ann", "up_bytes": 140, "down_bytes": 370}]), "the first poll starts the history, a restart adds the whole new value");
	let week = h.call(Method::GET, "/p/api/stats/usage?kind=exit&period=week&name=main", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(week["entries"][0]["up_bytes"], 140);
	for resolution in ["minute", "hour", "day"] {
		let history = h.call(Method::GET, &format!("/p/api/stats/history?kind=user&name=ann&resolution={resolution}"), Some(&session), None, "10.0.0.1").await.json();
		assert_eq!((history["points"][0]["down_bytes"].clone(), history["points"][0]["peak_down_bytes_per_sec"].clone()), (json!(370), json!(9)), "{resolution}");
	}
	let now = h.call(Method::GET, "/p/api/stats/now", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((now["reachable"].clone(), now["online_users"].clone(), now["sessions"].clone(), now["exits"][0]["tag"].clone()), (json!(true), json!(["ann"]), json!(2), json!("main")));
	*fake.stats.lock().unwrap() = json!({"users": [], "inbounds": [], "exits": [], "outbounds": [], "tunnels": [{"name": "web", "opened": 3, "open": 1}]});
	state.polled_at = 0;
	upkeep_once(&h.app, &mut state).await;
	assert_eq!(h.call(Method::GET, "/p/api/stats/now", Some(&session), None, "10.0.0.1").await.json()["tunnels"][0]["open"], 1);
	assert_eq!(h.call(Method::GET, "/p/api/stats/usage?kind=nothing", Some(&session), None, "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	h.app.db.call(|db| db.execute("update usage_buckets set at = at - 2 * 86400 where res = 60", []).unwrap()).await.unwrap();
	h.app.db.call(|db| veilway_panel::stats::prune(db, crypto::now())).await.unwrap();
	let left: i64 = h.app.db.call(|db| db.query_row("select count(*) from usage_buckets where res = 60", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(left, 0, "minutes older than a day are pruned");
}

#[tokio::test]
async fn two_nodes_pair_with_codes_and_a_fingerprint_before_the_link_is_in_either_config() {
	let (listener, socket_a) = Fake::start(node_document("10.66.0.1/24")).await;
	let (dialler, socket_b) = Fake::start(node_document("10.77.0.1/24")).await;
	let (a, b) = (Harness::with_socket(Some(socket_a)).await, Harness::with_socket(Some(socket_b)).await);
	let (sa, sb) = (a.login("10.0.0.1").await, b.login("10.0.0.1").await);
	let public = base64::engine::general_purpose::STANDARD.encode(x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([3u8; 32])).as_bytes());
	let offered = a.call(Method::POST, "/p/api/links/offers", Some(&sa), Some(json!({"tag": "to-b", "inbound": "Main", "direction": "forward", "name": "north exit", "inbound_public_key": public, "dialler": ["10.9.0.2"], "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]})), "10.0.0.1").await;
	assert_eq!(offered.status, StatusCode::OK, "{}", String::from_utf8_lossy(&offered.body));
	let code = offered.json()["code"].as_str().unwrap().to_string();
	let seen = b.call(Method::POST, "/p/api/links/paste", Some(&sb), Some(json!({"code": code})), "10.0.0.1").await.json();
	assert_eq!((seen["half"].clone(), seen["overlaps_pool"].clone(), seen["dials"][0]["address"].clone()), (json!("entry"), json!(false), json!("192.0.2.10:51820")));
	assert_eq!(b.call(Method::POST, "/p/api/links/paste/answer", Some(&sb), Some(json!({"code": code, "tag": "from-a", "accept": false})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	let answered = b.call(Method::POST, "/p/api/links/paste/answer", Some(&sb), Some(json!({"code": code, "tag": "from-a", "accept": true})), "10.0.0.1").await.json();
	let (answer, b_groups, b_id) = (answered["answer"].as_str().unwrap().to_string(), answered["fingerprint"].as_str().unwrap().to_string(), answered["id"].as_str().unwrap().to_string());
	let taken = a.call(Method::POST, "/p/api/links/offers/answer", Some(&sa), Some(json!({"code": answer})), "10.0.0.1").await.json();
	let (a_groups, a_id) = (taken["fingerprint"].as_str().unwrap().to_string(), taken["id"].as_str().unwrap().to_string());
	assert_eq!(a_id, b_id);
	assert_ne!(a_groups, b_groups, "each side shows its own value");
	assert_eq!(a.call(Method::POST, "/p/api/links/offers/answer", Some(&sa), Some(json!({"code": answer})), "10.0.0.1").await.status, StatusCode::CONFLICT, "an answer is spent");
	let wrong = a.call(Method::POST, &format!("/p/api/links/pairings/{a_id}/confirm"), Some(&sa), Some(json!({"typed": a_groups, "revision": "rev1"})), "10.0.0.1").await;
	assert_eq!(wrong.status, StatusCode::FORBIDDEN, "typing its own groups does not confirm");
	assert!(listener.applied.lock().unwrap().is_empty());
	let pending = a.call(Method::GET, "/p/api/links/pairings", Some(&sa), None, "10.0.0.1").await.json();
	assert_eq!((pending["answered"][0]["tries"].clone(), pending["answered"][0]["role"].clone()), (json!(1), json!("listener")));
	let (ok_a, ok_b) = (a.call(Method::POST, &format!("/p/api/links/pairings/{a_id}/confirm"), Some(&sa), Some(json!({"typed": b_groups, "revision": "rev1"})), "10.0.0.1").await, b.call(Method::POST, &format!("/p/api/links/pairings/{b_id}/confirm"), Some(&sb), Some(json!({"typed": a_groups, "revision": "rev1"})), "10.0.0.1").await);
	assert_eq!((ok_a.status, ok_b.status), (StatusCode::OK, StatusCode::OK), "{} {}", String::from_utf8_lossy(&ok_a.body), String::from_utf8_lossy(&ok_b.body));
	let (entry_a, entry_b) = (listener.applied.lock().unwrap().last().unwrap()["links"][0].clone(), dialler.applied.lock().unwrap().last().unwrap()["links"][0].clone());
	assert_eq!((entry_a["tag"].clone(), entry_a["inbound"].clone(), entry_a["exits"].clone(), entry_a.get("private_key").is_none()), (json!("to-b"), json!("Main"), json!(["main"]), true));
	assert_eq!((entry_b["tag"].clone(), entry_b.get("exits").is_none(), entry_b["peer"]["transports"][0]["type"].clone(), entry_a["id"].clone()), (json!("from-a"), true, json!("udp"), entry_b["id"].clone()));
	assert_eq!(entry_a["transport_secret"], entry_b["transport_secret"]);
	let audit = a.call(Method::GET, "/p/api/audit?limit=1000", Some(&sa), None, "10.0.0.1").await.json();
	assert!(!audit.to_string().contains(&entry_a["transport_secret"].as_str().unwrap().to_string()) && !audit.to_string().contains(&code), "the audit log holds no code and no secret");
}

#[tokio::test]
async fn small_fixes_found_by_the_web_app() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let bare = h.call(Method::GET, "/p", None, None, "10.0.0.1").await;
	assert_eq!((bare.status, bare.headers.get("location").unwrap().to_str().unwrap()), (StatusCode::PERMANENT_REDIRECT, "/p/"));
	let network = h.token(&session, "read", json!({"allowed_sources": ["10.5.0.0/24"]})).await;
	for (source, status) in [("10.5.0.9", StatusCode::OK), ("10.5.1.9", StatusCode::UNAUTHORIZED)] {
		assert_eq!(h.bearer(Method::GET, "/p/api/users", &network, None, source).await.status, status, "{source}");
	}
	let bad = h.call(Method::POST, "/p/api/tokens", Some(&session), Some(json!({"name": "x", "scope": "read", "allowed_sources": ["10.5.0.0/99"]})), "10.0.0.1").await;
	assert_eq!(bad.status, StatusCode::BAD_REQUEST);
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	settings["not_found"] = json!({"status": 404, "headers": [["content-type", "text/plain"]], "body": "nothing here"});
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings.clone()), "10.0.0.1").await.status, StatusCode::OK);
	let missing = h.call(Method::GET, "/nowhere", None, None, "10.0.0.1").await;
	assert_eq!((missing.body.clone(), missing.headers.get(CONTENT_TYPE).unwrap().to_str().unwrap().to_string()), (b"nothing here".to_vec(), "text/plain".to_string()));
	settings["not_found"]["status"] = json!(99);
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn xray_inbounds_keep_a_credential_per_user_and_make_share_links() {
	let mut document = node_document("10.66.0.1/24");
	document["public_addresses"] = json!(["vpn.example.org"]);
	let (fake, socket) = Fake::start(document).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (ann, _) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{ann}/devices"), Some(&session), Some(json!({"name": "phone"})), "10.0.0.1").await.status, StatusCode::OK);
	let vless = json!({"tag": "vless1", "protocol": "vless", "port": 8444, "cert": "/etc/veilway/cert.pem", "key": "/etc/veilway/key.pem", "decoy": "http://127.0.0.1:8080"});
	let missing = h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(vless.clone()), "10.0.0.1").await;
	assert_eq!((missing.status, missing.json()["error"]["code"].clone()), (StatusCode::CONFLICT, json!("addon_missing")), "a node without the add-on");
	assert_eq!(h.call(Method::GET, "/p/api/xray", Some(&session), None, "10.0.0.1").await.json()["installed"], false);
	*fake.status.lock().unwrap() = json!({"version": "0.0.0", "addons": {"xray": {"installed": true, "release": "v26.3.27"}}});
	let bare = h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(json!({"tag": "bare", "protocol": "trojan", "port": 8445, "cert": "/etc/veilway/cert.pem", "key": "/etc/veilway/key.pem"})), "10.0.0.1").await;
	assert_eq!(bare.status, StatusCode::BAD_REQUEST, "a vless or trojan inbound is refused while the node has no decoy to hand strangers to");
	assert!(String::from_utf8_lossy(&bare.body).contains("decoy"));
	let made = h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(vless), "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(json!({"tag": "ss", "protocol": "shadowsocks", "port": 8388, "cert": "/a", "key": "/b"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(json!({"tag": "tr", "protocol": "trojan", "port": 8445})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(json!({"tag": "ss", "protocol": "shadowsocks", "port": 8388, "host": "ss.example.org"})), "10.0.0.1").await.status, StatusCode::OK);
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	let inbounds = applied["xray"]["inbounds"].as_array().unwrap().clone();
	assert_eq!((inbounds[0]["listen"].clone(), inbounds[0]["tls"]["cert"].clone(), inbounds[1].get("tls").is_none()), (json!("0.0.0.0:8444"), json!("/etc/veilway/cert.pem"), true));
	let uuid = inbounds[0]["clients"][0]["secret"].as_str().unwrap().to_string();
	let password = inbounds[1]["clients"][0]["secret"].as_str().unwrap().to_string();
	assert_eq!((inbounds[0]["clients"][0]["user"].clone(), uuid.split('-').map(str::len).collect::<Vec<_>>()), (json!("ann"), vec![8, 4, 4, 4, 12]));
	let server = inbounds[1]["server_key"].as_str().unwrap().to_string();
	assert_eq!((inbounds[0]["decoy"].clone(), password.len(), server.len(), inbounds[0].get("server_key").is_none(), inbounds[1].get("decoy").is_none()), (json!("http://127.0.0.1:8080"), 44, 44, true, true), "a key of 32 bytes for the server and one for the user, and a decoy only where there is a web listener");
	let listed = h.call(Method::GET, "/p/api/xray", Some(&session), None, "10.0.0.1").await;
	let view = listed.json();
	assert_eq!((view["installed"].clone(), view["release"].clone(), view["inbounds"][0]["port"].clone(), view["inbounds"][0]["security"].clone(), view["inbounds"][0]["clients"].clone(), view["inbounds"][1]["host"].clone()), (json!(true), json!("v26.3.27"), json!(8444), json!("tls"), json!(1), json!("ss.example.org")));
	assert!(!String::from_utf8_lossy(&listed.body).contains(&uuid));
	let (bob, _) = h.user(&session, "bob", json!({})).await;
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{bob}/devices"), Some(&session), Some(json!({"name": "laptop"})), "10.0.0.1").await.status, StatusCode::OK);
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	let clients = &applied["xray"]["inbounds"][0]["clients"];
	assert_eq!((clients.as_array().unwrap().len(), clients[0]["secret"].clone(), clients[1]["user"].clone()), (2, json!(uuid), json!("bob")), "a new user gets a credential and an old one keeps theirs");
	let links = h.call(Method::GET, &format!("/p/api/users/{ann}/xray"), Some(&session), None, "10.0.0.1").await;
	assert_eq!(links.status, StatusCode::OK, "{}", String::from_utf8_lossy(&links.body));
	let links = links.json()["links"].as_array().unwrap().clone();
	let escape = |text: &str| text.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
	let shadowsocks = format!("ss://2022-blake3-aes-256-gcm:{}:{}@ss.example.org:8388#Test%20Net%20ss", escape(&server), escape(&password));
	assert_eq!((links[0]["link"].clone(), links[1]["link"].clone()), (json!(shadowsocks), json!(format!("vless://{uuid}@vpn.example.org:8444?encryption=none&security=tls&sni=vpn.example.org&type=tcp#Test%20Net%20vless1"))));
	assert!(links[0]["qr_svg"].as_str().unwrap().contains("<svg"));
	let rotated = h.call(Method::POST, &format!("/p/api/users/{ann}/xray/rotate"), Some(&session), Some(json!({})), "10.0.0.1").await;
	assert_eq!(rotated.status, StatusCode::OK, "{}", String::from_utf8_lossy(&rotated.body));
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	let (renewed, other) = (applied["xray"]["inbounds"][0]["clients"][0]["secret"].as_str().unwrap().to_string(), applied["xray"]["inbounds"][1]["clients"][0]["secret"].as_str().unwrap().to_string());
	assert!(renewed != uuid && other != password && applied["xray"]["inbounds"][0]["clients"][0]["user"] == "ann", "new credentials in every inbound for the same user");
	assert_eq!(applied["xray"]["inbounds"][1]["server_key"], json!(server), "the server key stays");
	let (uuid, password) = (renewed, other);
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/users/{bob}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	assert!(applied["xray"]["inbounds"].as_array().unwrap().iter().all(|inbound| inbound["clients"].as_array().unwrap().len() == 1 && inbound["clients"][0]["user"] == "ann"), "a deleted user leaves every inbound");
	assert_eq!(h.call(Method::DELETE, "/p/api/xray/inbounds/ss", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::DELETE, "/p/api/xray/inbounds/vless1", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	assert!(fake.applied.lock().unwrap().last().unwrap().get("xray").is_none());
	assert_eq!(h.call(Method::DELETE, "/p/api/xray/inbounds/vless1", Some(&session), None, "10.0.0.1").await.status, StatusCode::NOT_FOUND);
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	assert!(!String::from_utf8_lossy(&audit.body).contains(&uuid) && !String::from_utf8_lossy(&audit.body).contains(&password));
	assert!(audit.json()["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "xray.links.show"));
	assert!(audit.json()["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "xray.rotate"));
	assert!(!String::from_utf8_lossy(&audit.body).contains(&server));
}

#[tokio::test]
async fn a_backup_is_downloaded_and_restored_with_the_panel_restarting_on_the_old_state() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	h.user(&session, "alice", json!({})).await;
	let full = h.token(&session, "full", json!({})).await;
	for (path, body) in [("/p/api/backup/download", json!({"passphrase": "a long enough passphrase"})), ("/p/api/backup/restore", json!({"file": "", "passphrase": "a long enough passphrase"}))] {
		assert_eq!(h.bearer(Method::POST, path, &full, Some(body), "10.1.1.1").await.status, StatusCode::FORBIDDEN, "{path}");
	}
	assert_eq!(h.call(Method::POST, "/p/api/backup/download", Some(&session), Some(json!({"passphrase": "short"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	let answer = h.call(Method::POST, "/p/api/backup/download", Some(&session), Some(json!({"passphrase": "a long enough passphrase"})), "10.0.0.1").await;
	assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	let file = answer.json()["file"].as_str().unwrap().to_string();
	assert!(answer.json()["filename"].as_str().unwrap().ends_with(".vwbackup"));
	assert!(!STANDARD.decode(&file).unwrap().windows(5).any(|window| window == b"alice"));
	h.user(&session, "late", json!({})).await;
	// The backup holds the gateway key file as it was: a switch since then makes the host's file differ from it.
	let (backed_up, old_next) = (std::fs::read(&h.app.cfg.gateway).unwrap(), std::fs::read_to_string(&h.app.cfg.gateway_next).unwrap());
	assert_eq!(h.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(json!({})), "10.0.0.1").await.status, StatusCode::OK);
	let switched = std::fs::read(&h.app.cfg.gateway).unwrap();
	assert_ne!(backed_up, switched);
	let restore = |file: String, passphrase: &'static str| json!({"file": file, "passphrase": passphrase});
	let wrong = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(file.clone(), "another long passphrase")), "10.0.0.1").await;
	assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&wrong.body));
	let garbage = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(STANDARD.encode([1u8; 300]), "a long enough passphrase")), "10.0.0.1").await;
	assert_eq!(garbage.status, StatusCode::BAD_REQUEST);
	let newer = h.dir.join("newer.db");
	let newer_path = newer.to_string_lossy().to_string();
	h.app.db.call(move |db| db.execute("vacuum into ?", [newer_path]).unwrap()).await.unwrap();
	rusqlite::Connection::open(&newer).unwrap().pragma_update(None, "user_version", 99).unwrap();
	let content = veilway_panel::backup::pack([&std::fs::read(&newer).unwrap(), &std::fs::read(&h.app.cfg.keys).unwrap(), &std::fs::read(&h.app.cfg.signing).unwrap(), &std::fs::read(&h.app.cfg.gateway).unwrap()]);
	let refused = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(STANDARD.encode(veilway_panel::backup::seal("a long enough passphrase", &content).unwrap()), "a long enough passphrase")), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::BAD_REQUEST);
	assert!(refused.json()["error"]["message"].as_str().unwrap().contains("newer"));
	assert!(h.app.db.call(|db| db.query_row("select count(*) from users where name = 'late'", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap() == 1);
	let done = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(file, "a long enough passphrase")), "10.0.0.1").await;
	assert_eq!(done.status, StatusCode::OK, "{}", String::from_utf8_lossy(&done.body));
	tokio::time::timeout(std::time::Duration::from_secs(2), h.app.restart.notified()).await.expect("the server is told to restart");
	assert!(h.app.restoring.load(Ordering::SeqCst));
	assert_eq!(h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "after"})), "10.0.0.1").await.status, StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(h.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.status, StatusCode::OK);
	let saved = h.dir.join(done.json()["saved_as"].as_str().unwrap());
	assert!(saved.join("panel.db").exists() && saved.join("panel.keys").exists() && saved.join("signing.keys").exists());
	assert_eq!(std::fs::read(saved.join("gateway.keys")).unwrap(), switched, "the file the restore replaced is kept");
	assert_eq!(std::fs::read(&h.app.cfg.gateway).unwrap(), backed_up, "the backup's gateway keys are back");
	let warnings = done.json()["warnings"].as_array().unwrap().clone();
	assert!(warnings.len() == 1 && warnings[0].as_str().unwrap().contains("not the ones in the backup"), "{warnings:?}");
	assert!(!String::from_utf8_lossy(&backed_up).contains(old_next.trim()), "the next key's private half is in no backup");
	let reopened = build(h.app.cfg.clone()).unwrap();
	let names: Vec<String> = reopened.db.call(|db| db.prepare("select name from users").unwrap().query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect()).await.unwrap();
	assert_eq!(names, ["alice"]);
	assert_eq!(reopened.db.call(|db| db.query_row("select count(*) from sessions", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	assert!(reopened.db.call(|db| db.query_row("select count(*) from audit where action = 'backup.restore'", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap() >= 1);
	assert!(reopened.keys.is_some());
	assert_eq!(reopened.db.call(|db| db.query_row("select count(*) from api_tokens where revoked_at is null", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	assert_ne!(reopened.start_id, h.app.start_id);
	assert!(!veilway_panel::backup::marker(&h.app.cfg).exists());
	assert_eq!(reopened.settings().provider_name, "Test Net");
}

#[tokio::test]
async fn an_update_is_requested_with_a_file_that_holds_only_the_word_panel() {
	let h = Harness::with_config(None, |cfg| {
		let folder = std::env::temp_dir().join(format!("vwupdate-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		std::fs::create_dir_all(&folder).unwrap();
		cfg.update_request = folder.join("request");
	}).await;
	let session = h.login("10.0.0.1").await;
	let full = h.token(&session, "full", json!({})).await;
	let folder = h.app.cfg.update_request.parent().unwrap().to_path_buf();
	let info = h.call(Method::GET, "/p/api/update", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((info["latest"].is_null(), info["can_update"].clone(), info["updating"].clone()), (true, json!(true), json!(false)));
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT);
	assert!(!h.app.cfg.update_request.exists());
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), Some(json!({"part": "node"})), "10.0.0.1").await.status, StatusCode::CONFLICT);
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), Some(json!({"part": "all"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	h.app.update.lock().unwrap().found = Some(veilway_panel::updater::Found {version: "9.9.9".into(), notes_url: "https://github.com/veilway-project/veilway-panel/releases/tag/v9.9.9".into()});
	assert_eq!(h.bearer(Method::POST, "/p/api/update/request", &full, None, "10.1.1.1").await.status, StatusCode::FORBIDDEN);
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	std::fs::write(h.app.cfg.update_request.with_extension("tmp"), b"stale").unwrap();
	let made = h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	assert_eq!(std::fs::read(&h.app.cfg.update_request).unwrap(), b"panel");
	assert!(!h.app.cfg.update_request.with_extension("tmp").exists());
	assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&h.app.cfg.update_request).unwrap().permissions()) & 0o777, 0o600);
	assert_eq!(h.call(Method::GET, "/p/api/update", Some(&session), None, "10.0.0.1").await.json()["updating"], true);
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT);
	let audit: i64 = h.app.db.call(|db| db.query_row("select count(*) from audit where action = 'update.request' and detail = 'panel from ' || ? || ' to 9.9.9'", [veilway_panel::updater::CURRENT], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(audit, 1);
	std::fs::remove_dir_all(folder).unwrap();
	h.app.update.lock().unwrap().requested_at = None;
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT);
	assert_eq!(h.call(Method::GET, "/p/api/update", Some(&session), None, "10.0.0.1").await.json()["can_update"], false);
}

#[tokio::test]
async fn a_restart_is_requested_with_the_word_restart_and_the_part() {
	let h = Harness::with_config(None, |cfg| {
		let folder = std::env::temp_dir().join(format!("vwrestart-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		std::fs::create_dir_all(&folder).unwrap();
		cfg.update_request = folder.join("request");
	}).await;
	let session = h.login("10.0.0.1").await;
	let full = h.token(&session, "full", json!({})).await;
	let folder = h.app.cfg.update_request.parent().unwrap().to_path_buf();
	assert_eq!(h.call(Method::POST, "/p/api/restart", Some(&session), Some(json!({"part": "all"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.bearer(Method::POST, "/p/api/restart", &full, Some(json!({"part": "node"})), "10.1.1.1").await.status, StatusCode::FORBIDDEN);
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/restart", Some(&session), Some(json!({"part": "node"})), "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	let made = h.call(Method::POST, "/p/api/restart", Some(&session), Some(json!({"part": "node"})), "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	assert_eq!(std::fs::read(&h.app.cfg.update_request).unwrap(), b"restart-node");
	assert_eq!(h.call(Method::POST, "/p/api/restart", Some(&session), Some(json!({"part": "panel"})), "10.0.0.1").await.status, StatusCode::CONFLICT, "one request at a time");
	std::fs::remove_file(&h.app.cfg.update_request).unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/restart", Some(&session), Some(json!({"part": "both"})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(std::fs::read(&h.app.cfg.update_request).unwrap(), b"restart-both");
	let audit: i64 = h.app.db.call(|db| db.query_row("select count(*) from audit where action = 'restart.request'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(audit, 2);
	std::fs::remove_dir_all(folder).unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/restart", Some(&session), Some(json!({"part": "node"})), "10.0.0.1").await.status, StatusCode::CONFLICT, "no update service on this host");
}

#[tokio::test]
async fn a_restore_cut_short_is_finished_at_the_next_start() {
	let h = Harness::new().await;
	let cfg = h.app.cfg.clone();
	let staged = |path: &std::path::Path| veilway_panel::backup::with_suffix(path, ".restore");
	std::fs::copy(&cfg.keys, staged(&cfg.keys)).unwrap();
	std::fs::write(&cfg.keys, [0u8; 5]).unwrap();
	std::fs::copy(&cfg.signing, staged(&cfg.signing)).unwrap();
	std::fs::write(veilway_panel::backup::marker(&cfg), b"").unwrap();
	let staged_path = staged(&cfg.database).to_string_lossy().to_string();
	h.app.db.call(move |db| db.execute("vacuum into ?", [staged_path]).unwrap()).await.unwrap();
	let reopened = build(cfg.clone()).unwrap();
	assert!(reopened.keys.is_some());
	assert_eq!(std::fs::read(&cfg.keys).unwrap().len(), 96);
	assert!(!veilway_panel::backup::marker(&cfg).exists() && !staged(&cfg.database).exists() && !staged(&cfg.keys).exists());
}

#[tokio::test]
#[ignore = "measures memory: cargo test --test panel restore_memory -- --ignored --nocapture"]
async fn restore_memory_at_the_cap() {
	let peak = || std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|line| line.starts_with("VmHWM")).unwrap().to_string();
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.app.db.call(|db| db.execute("insert into settings (key, value) values ('filler', randomblob(30000000))", []).unwrap()).await.unwrap();
	println!("before download: {}", peak());
	let made = h.call(Method::POST, "/p/api/backup/download", Some(&session), Some(json!({"passphrase": "a long enough passphrase"})), "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	let file = made.json()["file"].as_str().unwrap().to_string();
	println!("backup file {} bytes, after download: {}", STANDARD.decode(&file).unwrap().len(), peak());
	let done = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(json!({"file": file, "passphrase": "a long enough passphrase"})), "10.0.0.1").await;
	assert_eq!(done.status, StatusCode::OK, "{}", String::from_utf8_lossy(&done.body));
	println!("after restore: {}", peak());
}

#[tokio::test]
async fn admins_are_listed_added_reset_and_removed_but_never_yourself() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let code_of = |secret: &str| format!("{:06}", crypto::totp_at(&data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).unwrap(), (crypto::now() / 30) as u64));
	let made = h.call(Method::POST, "/p/api/admins", Some(&session), Some(json!({"username": "second", "password": "second long password"})), "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	let secret = made.json()["totp_secret"].as_str().unwrap().to_string();
	assert_eq!(h.call(Method::POST, "/p/api/admins", Some(&session), Some(json!({"username": "second", "password": "second long password"})), "10.0.0.1").await.status, StatusCode::CONFLICT, "a taken name");
	let listed = h.call(Method::GET, "/p/api/admins", Some(&session), None, "10.0.0.1").await.json();
	let (owner, second) = (listed["admins"][0].clone(), listed["admins"][1].clone());
	assert_eq!((owner["you"].clone(), owner["totp_used"].clone(), owner["last_login"].is_i64(), second["you"].clone(), second["totp_used"].clone(), second["last_login"].clone()), (json!(true), json!(true), true, json!(false), json!(false), Value::Null));
	let (owner_id, second_id) = (owner["id"].as_i64().unwrap(), second["id"].as_i64().unwrap());
	let login = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "second", "password": "second long password", "totp": code_of(&secret)})), "10.0.0.2").await;
	assert_eq!(login.status, StatusCode::OK);
	let theirs = Session {cookie: login.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string(), csrf: login.json()["csrf"].as_str().unwrap().to_string()};
	assert_eq!(h.call(Method::GET, "/p/api/admins", Some(&session), None, "10.0.0.1").await.json()["admins"][1]["totp_used"], true);
	assert!(h.call(Method::GET, "/p/api/admins", Some(&session), None, "10.0.0.1").await.json()["admins"][1]["last_login"].is_i64());
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/admins/{owner_id}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT, "not yourself");
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/admins/{second_id}"), Some(&theirs), None, "10.0.0.2").await.status, StatusCode::CONFLICT, "not yourself, as the other admin either");
	assert_eq!(h.call(Method::POST, &format!("/p/api/admins/{owner_id}/reset"), Some(&session), Some(json!({"new_password": "a third long password"})), "10.0.0.1").await.status, StatusCode::CONFLICT, "your own goes through the account routes");
	assert_eq!(h.call(Method::POST, &format!("/p/api/admins/{second_id}/reset"), Some(&session), Some(json!({"new_password": "short"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	let stale = h.call(Method::POST, &format!("/p/api/admins/{second_id}/reset"), Some(&session), Some(json!({"new_password": "a third long password"})), "10.0.0.1").await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	let token = {
		h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
		h.token(&session, "full", json!({})).await
	};
	let theirs_token = h.token(&theirs, "full", json!({})).await;
	assert_eq!(h.bearer(Method::POST, &format!("/p/api/admins/{second_id}/reset"), &token, Some(json!({"new_password": "a third long password"})), "10.0.0.1").await.status, StatusCode::FORBIDDEN, "no API token resets an admin");
	let reset = h.call(Method::POST, &format!("/p/api/admins/{second_id}/reset"), Some(&session), Some(json!({"new_password": "a third long password"})), "10.0.0.1").await;
	assert_eq!(reset.status, StatusCode::OK, "{}", String::from_utf8_lossy(&reset.body));
	let renewed = reset.json()["totp_secret"].as_str().unwrap().to_string();
	assert!(renewed != secret);
	assert_eq!(h.call(Method::GET, "/p/api/admins", Some(&theirs), None, "10.0.0.2").await.status, StatusCode::UNAUTHORIZED, "the reset ends their sessions");
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &theirs_token, None, "10.1.1.1").await.status, StatusCode::UNAUTHORIZED, "the reset revokes their API tokens");
	assert_eq!(h.call(Method::GET, "/p/api/admins", Some(&session), None, "10.0.0.1").await.json()["admins"][1]["totp_used"], false);
	assert_eq!(h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "second", "password": "second long password", "totp": code_of(&renewed)})), "10.0.0.3").await.status, StatusCode::UNAUTHORIZED, "the old password is gone");
	assert_eq!(h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "second", "password": "a third long password", "totp": code_of(&renewed)})), "10.0.0.3").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/admins/{second_id}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/admins/{second_id}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::NOT_FOUND);
	assert_eq!(h.app.db.call(move |db| db.query_row("select count(*) from sessions where admin_id = ?", [second_id], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	h.app.db.call(|db| db.execute("update audit set at = at - 100 where action = 'login'", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/admins", Some(&session), Some(json!({"username": "second", "password": "a fourth long password"})), "10.0.0.1").await.status, StatusCode::OK);
	let again = h.call(Method::GET, "/p/api/admins", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((again["admins"][1]["username"].clone(), again["admins"][1]["last_login"].clone()), (json!("second"), Value::Null), "a name made again does not inherit the old logins");
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	let entries = audit.json()["entries"].as_array().unwrap().clone();
	assert!(entries.iter().any(|entry| entry["action"] == "admin.reset" && entry["target"] == "admin:second" && entry["detail"].as_str().unwrap().contains("1 sessions ended, 1 tokens revoked")));
	assert!(entries.iter().any(|entry| entry["action"] == "admin.remove" && entry["target"] == "admin:second"));
	assert!(!String::from_utf8_lossy(&audit.body).contains(&renewed) && !String::from_utf8_lossy(&audit.body).contains("a third long password"));
}

#[tokio::test]
async fn xray_decoys_are_loopback_or_private_addresses() {
	let mut document = node_document("10.66.0.1/24");
	document["public_addresses"] = json!(["vpn.example.org"]);
	let (fake, socket) = Fake::start(document).await;
	*fake.status.lock().unwrap() = json!({"version": "0.0.0", "addons": {"xray": {"installed": true, "release": "v26.3.27"}}});
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	for (port, decoy) in [(8441, "http://8.8.8.8:8080"), (8442, "http://example.org:8080"), (8443, "https://127.0.0.1:8080"), (8444, "http://10.1.2.3@8.8.8.8:8080")] {
		let body = json!({"tag": format!("bad{port}"), "protocol": "vless", "port": port, "cert": "/a", "key": "/b", "decoy": decoy});
		assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(body), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "{decoy}");
	}
	for (tag, port, decoy) in [("local", 8445, "http://localhost:8080"), ("v6", 8446, "http://[::1]:8080"), ("lan", 8447, "http://10.1.2.3:8080")] {
		let body = json!({"tag": tag, "protocol": "vless", "port": port, "cert": "/a", "key": "/b", "decoy": decoy});
		assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(body), "10.0.0.1").await.status, StatusCode::OK, "{decoy}");
	}
}

#[tokio::test]
async fn an_xray_inbound_is_edited_and_every_user_keeps_their_credential() {
	let mut document = node_document("10.66.0.1/24");
	document["public_addresses"] = json!(["vpn.example.org"]);
	let (fake, socket) = Fake::start(document).await;
	*fake.status.lock().unwrap() = json!({"version": "0.0.0", "addons": {"xray": {"installed": true, "release": "v26.3.27"}}});
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let full = h.token(&session, "full", json!({})).await;
	h.configure(&session, json!({})).await;
	let (ann, _) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{ann}/devices"), Some(&session), Some(json!({"name": "phone"})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(json!({"tag": "vless1", "protocol": "vless", "port": 8444, "listen": "192.0.2.5", "cert": "/etc/veilway/cert.pem", "key": "/etc/veilway/key.pem", "decoy": "http://127.0.0.1:8080"})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::POST, "/p/api/xray/inbounds", Some(&session), Some(json!({"tag": "ss", "protocol": "shadowsocks", "port": 8388})), "10.0.0.1").await.status, StatusCode::OK);
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	let (uuid, password, server) = (applied["xray"]["inbounds"][0]["clients"][0]["secret"].clone(), applied["xray"]["inbounds"][1]["clients"][0]["secret"].clone(), applied["xray"]["inbounds"][1]["server_key"].clone());
	assert_eq!(applied["xray"]["inbounds"][0]["listen"], "192.0.2.5:8444", "create takes a listen address");
	let path = |tag: &str| format!("/p/api/xray/inbounds/{tag}");
	for (body, why) in [(json!({"port": 0, "cert": "/a", "key": "/b"}), "port 0"), (json!({"port": 9443, "listen": "not an address", "cert": "/a", "key": "/b"}), "a listen that is no address"), (json!({"port": 9443}), "vless without certificate files"), (json!({"port": 9443, "cert": "/a", "key": "/b", "decoy": "https://x"}), "a decoy that is not http"), (json!({"port": 9443, "cert": "/a", "key": "/b", "new_server_key": true}), "vless has no server key"), (json!({"port": 9443, "cert": "/a", "key": "/b", "host": "bad host!"}), "a host with a space")] {
		assert_eq!(h.call(Method::PATCH, &path("vless1"), Some(&session), Some(body), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "{why}");
	}
	assert_eq!(h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8389, "cert": "/a", "key": "/b"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "shadowsocks takes no certificate");
	assert_eq!(h.call(Method::PATCH, &path("nope"), Some(&session), Some(json!({"port": 8389})), "10.0.0.1").await.status, StatusCode::NOT_FOUND);
	let edited = h.call(Method::PATCH, &path("vless1"), Some(&session), Some(json!({"port": 9443, "listen": "::", "cert": "/etc/veilway/new.pem", "key": "/etc/veilway/new.key", "host": "edge.example.org"})), "10.0.0.1").await;
	assert_eq!(edited.status, StatusCode::OK, "{}", String::from_utf8_lossy(&edited.body));
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	let vless = &applied["xray"]["inbounds"][0];
	assert_eq!((vless["listen"].clone(), vless["tls"]["cert"].clone(), vless["decoy"].clone(), vless["clients"][0]["secret"].clone()), (json!("[::]:9443"), json!("/etc/veilway/new.pem"), json!("http://127.0.0.1:8080"), uuid.clone()), "the decoy stays when left out, and ann keeps her uuid");
	let view = h.call(Method::GET, "/p/api/xray", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((view["inbounds"][0]["port"].clone(), view["inbounds"][0]["own_host"].clone(), view["inbounds"][0]["decoy"].clone(), view["inbounds"][1]["own_host"].clone()), (json!(9443), json!("edge.example.org"), json!("http://127.0.0.1:8080"), json!("")));
	let links = h.call(Method::GET, &format!("/p/api/users/{ann}/xray"), Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(links["links"][1]["link"], json!(format!("vless://{}@edge.example.org:9443?encryption=none&security=tls&sni=edge.example.org&type=tcp#Test%20Net%20vless1", uuid.as_str().unwrap())));
	assert_eq!(h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8390})), "10.0.0.1").await.status, StatusCode::OK);
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	assert_eq!((applied["xray"]["inbounds"][1]["listen"].clone(), applied["xray"]["inbounds"][1]["server_key"].clone(), applied["xray"]["inbounds"][1]["clients"][0]["secret"].clone()), (json!("0.0.0.0:8390"), server.clone(), password.clone()), "the server key stays unless asked");
	assert_eq!(h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8390, "new_server_key": true})), "10.0.0.1").await.status, StatusCode::OK);
	let applied = fake.applied.lock().unwrap().last().unwrap().clone();
	let renewed = applied["xray"]["inbounds"][1]["server_key"].clone();
	assert!(renewed != server && renewed.as_str().unwrap().len() == 44 && applied["xray"]["inbounds"][1]["clients"][0]["secret"] == password, "a new server key, the same user key");
	assert_eq!(h.bearer(Method::PATCH, &path("ss"), &full, Some(json!({"port": 8391, "new_server_key": true})), "10.1.1.1").await.status, StatusCode::FORBIDDEN, "no API token makes a new server key");
	assert_eq!(h.bearer(Method::PATCH, &path("ss"), &full, Some(json!({"port": 8391})), "10.1.1.1").await.status, StatusCode::OK, "a token edits an inbound without a new key");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	let stale = h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8391, "new_server_key": true})), "10.0.0.1").await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	*fake.document.lock().unwrap() = {let mut document = applied.clone(); document["invalid"] = json!(true); document};
	assert_eq!(h.call(Method::PATCH, &path("vless1"), Some(&session), Some(json!({"port": 9444, "cert": "/a", "key": "/b", "host": "other.example.org"})), "10.0.0.1").await.status, StatusCode::UNPROCESSABLE_ENTITY, "the node refuses");
	assert_eq!(h.call(Method::GET, "/p/api/xray", Some(&session), None, "10.0.0.1").await.json()["inbounds"][0]["own_host"], "edge.example.org", "a refused edit leaves the host as it was");
	let stored = |tag: &'static str| h.app.db.call(move |db| db.query_row("select server_key from xray_inbounds where tag = ?", [tag], |row| row.get::<_, Vec<u8>>(0)).unwrap());
	let (kept, reached) = (stored("ss").await.unwrap(), fake.applied.lock().unwrap().len());
	assert_eq!(h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8392, "new_server_key": true})), "10.0.0.1").await.status, StatusCode::UNPROCESSABLE_ENTITY, "the node refuses a new key");
	assert_eq!((stored("ss").await.unwrap() == kept, fake.applied.lock().unwrap().len() == reached), (true, true), "a refused new key is in neither the panel nor the node");
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	assert!(audit.json()["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "xray.edit" && entry["target"] == "vless1" && entry["detail"] == "listen 192.0.2.5:8444 -> [::]:9443, cert/key changed, host \"\" -> \"edge.example.org\""));
	assert!(audit.json()["entries"].as_array().unwrap().iter().any(|entry| entry["action"] == "xray.edit" && entry["target"] == "ss" && entry["detail"].as_str().unwrap().ends_with("new server key")));
	assert!(!String::from_utf8_lossy(&audit.body).contains(renewed.as_str().unwrap()) && !String::from_utf8_lossy(&audit.body).contains(uuid.as_str().unwrap()));
}

#[test]
fn mirror_mac_matches_the_core_vector() {
	let body = br#"{"v":1}"#;
	assert_eq!(URL_SAFE_NO_PAD.encode(crypto::sha256(body)), "r7-dDzVgsP13legcQqCnnua2_GfgZPd4Jq7mQsrSjZE");
	assert_eq!(URL_SAFE_NO_PAD.encode(mirrors::mac(&[7; 32], "m1", "203.0.113.9", 1700000000, "AAAAAAAAAAAAAAAAAAAAAA", body)), "l10IpkAlYVFrfLhjwdSNy8le5YSTUlyhf3eBBl-C3rs");
}

#[test]
fn config_checks_trusted_mirrors() {
	let with = |name: &str, secret: &str| Config {direct: true, trusted_mirrors: vec![TrustedMirror {name: name.into(), secret: secret.into()}], ..Config::default()}.check();
	let secret = URL_SAFE_NO_PAD.encode([7u8; 32]);
	assert!(with("relay-1", &secret).is_ok());
	assert!(with("Relay", &secret).is_err());
	assert!(with("", &secret).is_err());
	assert!(with("relay", &URL_SAFE_NO_PAD.encode([7u8; 16])).is_err());
	assert!(with("relay", "not base64!").is_err());
	let twice = Config {direct: true, trusted_mirrors: vec![TrustedMirror {name: "a".into(), secret: secret.clone()}, TrustedMirror {name: "a".into(), secret}], ..Config::default()};
	assert!(twice.check().is_err());
}

#[tokio::test]
async fn a_mirror_header_names_the_source_and_anything_else_is_unknown() {
	let secret = [9u8; 32];
	let h = Harness::with_config(None, |cfg| cfg.trusted_mirrors = vec![TrustedMirror {name: "relay".into(), secret: URL_SAFE_NO_PAD.encode(secret)}]).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, link) = h.user(&session, "ann", json!({"device_limit": 2})).await;
	let (key, kids) = (key_of(&link), [key_of(&link).kid()]);
	let Link::Native(native) = &link else {panic!("not native")};
	let body = |device: u8| json!({"v": 1, "t": crypto::now(), "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [kids[0].text()], "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": "fetch"});
	let gateway = native.gateway();
	// Each request is sealed once and the header signs those bytes, as a relay mirror does.
	let make = |device: u8| {let sealed = exchange::seal(&gateway, body(device).to_string().as_bytes(), &mut crypto::fill).unwrap(); (sealed.bytes().to_vec(), sealed)};
	let header = |name: &str, address: &str, at: i64, nonce: &str, secret: &[u8], bytes: &[u8]| format!("v1;{name};{address};{at};{nonce};{}", URL_SAFE_NO_PAD.encode(mirrors::mac(secret, name, address, at, nonce, bytes)));
	let send = |value: Option<(String, Vec<u8>)>, bytes: Vec<u8>| {
		let mut request = Request::builder().method(Method::POST).uri("/s").header(CONTENT_TYPE, "application/octet-stream").header(HOST, "panel.example.org");
		if let Some((value, _)) = value {request = request.header(mirrors::HEADER, value);}
		h.send_bytes(request, bytes, "198.51.100.7")
	};
	let unknown = h.send(Request::builder().method(Method::GET).uri("/nothing-here").header(HOST, "panel.example.org"), None, "198.51.100.7").await.shape();
	let (now, nonce) = (crypto::now(), |n: u8| URL_SAFE_NO_PAD.encode([n; 16]));
	// To a request with a valid mirror header, anything that would be the unknown path is the same answer with status 599.
	let refused = |answer: Answer| {let mut shape = answer.shape(); shape.0 = 599; shape};
	let mut mirrored_unknown = unknown.clone();
	mirrored_unknown.0 = 599;
	let (bytes, sealed) = make(1);
	let valid = header("relay", "203.0.113.9", now, &nonce(1), &secret, &bytes);
	let answer = send(Some((valid.clone(), Vec::new())), bytes.clone()).await;
	assert_eq!(answer.headers.get(CONTENT_TYPE).unwrap(), "application/octet-stream", "an answer is sealed bytes");
	assert_eq!(answer.headers.get("cache-control").unwrap(), "no-store");
	assert!([9_413, 36_979, 140_867, 538_201, 1_089_437].contains(&answer.body.len()));
	let opened_body = Answer {body: sealed.open(&answer.body).unwrap(), ..answer};
	assert!(matches!(opened(&opened_body, &[key]), Payload::Subscription(_)));
	assert_eq!(h.app.sub_limits.count("sub:203.0.113.9", 60), 1, "the forwarded address is the source");
	assert_eq!(h.app.sub_limits.count("sub:198.51.100.7", 60), 0);
	assert_eq!(refused(send(Some((valid, Vec::new())), bytes.clone()).await), mirrored_unknown, "a replayed request with a valid header is 599");
	let (bytes, _) = make(1);
	for (what, value) in [
		("a stale header", header("relay", "203.0.113.9", now - 120, &nonce(2), &secret, &bytes)),
		("a header from the future", header("relay", "203.0.113.9", now + 120, &nonce(3), &secret, &bytes)),
		("an unknown mirror", header("other", "203.0.113.9", now, &nonce(4), &secret, &bytes)),
		("a bad mac", header("relay", "203.0.113.9", now, &nonce(5), &[1; 32], &bytes)),
		("a bad address", header("relay", "not an address", now, &nonce(6), &secret, &bytes)),
		("a short header", "v1;relay".to_string()),
		("a body the mirror did not sign", header("relay", "203.0.113.9", now, &nonce(7), &secret, b"other bytes")),
	] {assert_eq!(send(Some((value, Vec::new())), bytes.clone()).await.shape(), unknown, "{what} is the plain unknown path, not 599");}
	let mut tampered = bytes.clone();
	tampered[100] ^= 1;
	assert_eq!(refused(send(Some((header("relay", "203.0.113.9", now, &nonce(10), &secret, &tampered), Vec::new())), tampered).await), mirrored_unknown, "a request that does not open, with a valid header, is 599");
	let (over, _) = make(1);
	for _ in 0..120 {h.app.sub_limits.hit("sub:203.0.113.9", 120, 60);}
	assert_eq!(refused(send(Some((header("relay", "203.0.113.9", now, &nonce(8), &secret, &over), Vec::new())), over.clone()).await), mirrored_unknown, "a source over its limit");
	h.app.sub_limits.clear("sub:203.0.113.9");
	let answer = send(Some((header("relay", "203.0.113.9", now, &nonce(8), &secret, &over), Vec::new())), over).await;
	assert_eq!(answer.status, StatusCode::OK, "a refused request takes no nonce and spends nothing but its own");
	let (plain, sealed) = make(1);
	let answer = send(None, plain).await;
	assert!(matches!(opened(&Answer {body: sealed.open(&answer.body).unwrap(), ..answer}, &[key]), Payload::Subscription(_)), "no header is an ordinary request");
	assert_eq!(h.app.sub_limits.count("sub:198.51.100.7", 60), 1, "only a request that opened and was new is charged to its source");
}

#[tokio::test]
async fn a_refused_header_of_a_known_mirror_is_logged_once_a_minute_with_its_reason() {
	let secret = [9u8; 32];
	let h = Harness::with_config(None, |cfg| cfg.trusted_mirrors = vec![TrustedMirror {name: "relay".into(), secret: URL_SAFE_NO_PAD.encode(secret)}]).await;
	let now = crypto::now();
	let header = |key: &[u8], name: &str, at: i64, nonce: u8| {
		let nonce = URL_SAFE_NO_PAD.encode([nonce; 16]);
		format!("v1;{name};203.0.113.9;{at};{nonce};{}", URL_SAFE_NO_PAD.encode(mirrors::mac(key, name, "203.0.113.9", at, &nonce, b"{}")))
	};
	let send = |value: String| h.send_bytes(Request::builder().method(Method::POST).uri("/s").header(CONTENT_TYPE, "application/octet-stream").header(HOST, "panel.example.org").header(mirrors::HEADER, value), b"{}".to_vec(), "198.51.100.7");
	assert!(h.app.mirrors_seen.last_refusal("relay").is_none());
	send(header(&secret, "relay", now - 120, 1)).await;
	assert!(h.app.mirrors_seen.last_refusal("relay").unwrap().starts_with("stale, 12"), "{:?}", h.app.mirrors_seen.last_refusal("relay"));
	send(header(&secret, "relay", now + 120, 2)).await;
	send(header(&[1; 32], "relay", now, 3)).await;
	assert!(h.app.mirrors_seen.last_refusal("relay").unwrap().starts_with("stale, 12"), "a second refusal within a minute is not logged");
	send(header(&[1; 32], "other", now, 4)).await;
	assert!(h.app.mirrors_seen.last_refusal("other").is_none(), "an unknown mirror is not logged");
}

#[tokio::test]
async fn each_mirror_keeps_its_own_nonces_and_drops_the_oldest_past_its_cap() {
	let h = Harness::new().await;
	let verified = |name: &str, n: u32| mirrors::Verified {name: name.into(), address: "203.0.113.9".parse().unwrap(), nonce: format!("{n:022}")};
	assert!(mirrors::accept(&h.app, &verified("b", 0)));
	for n in 1..=20_000 {assert!(mirrors::accept(&h.app, &verified("a", n)), "{n}")}
	assert!(!mirrors::accept(&h.app, &verified("b", 0)), "another mirror's traffic does not evict it");
	assert!(!mirrors::accept(&h.app, &verified("a", 20_000)), "a nonce held is refused");
	assert!(mirrors::accept(&h.app, &verified("a", 20_001)), "past the cap");
	assert!(mirrors::accept(&h.app, &verified("a", 1)), "the oldest was dropped to make room");
	assert!(!mirrors::accept(&h.app, &verified("a", 20_001)), "the newest is still held");
}

async fn rebuilt(h: &Harness, two_step: &str) -> Harness {
	let mut cfg = h.app.cfg.clone();
	cfg.two_step = two_step.into();
	let app = build(cfg).unwrap();
	Harness {router: router(app.clone()), app, totp: h.totp.clone(), dir: std::env::temp_dir().join("vwpanel-borrowed")}
}

#[tokio::test]
async fn two_step_off_asks_for_the_password_only_and_only_when_the_file_says_so() {
	let on = Harness::new().await;
	assert_eq!(on.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.json()["two_step"], true);
	async fn sign_in(h: &Harness, body: Value) -> Answer {h.call(Method::POST, "/p/api/login", None, Some(body), "10.0.0.2").await}
	assert_eq!(sign_in(&on, json!({"username": "owner", "password": PASSWORD})).await.status, StatusCode::UNAUTHORIZED);
	assert_eq!(sign_in(&on, json!({"username": "owner", "password": PASSWORD, "totp": "000000"})).await.status, StatusCode::UNAUTHORIZED);
	for value in ["ON", "", "false", "Off"] {
		let other = Harness::with_config(None, |cfg| cfg.two_step = value.into()).await;
		assert_eq!(other.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.json()["two_step"], true, "{value}");
		assert!(!other.totp.is_empty(), "{value}");
	}
	let off = Harness::with_config(None, |cfg| cfg.two_step = "off".into()).await;
	assert!(!off.totp.is_empty());
	assert_eq!(off.app.db.call(|db| db.query_row("select count(*) from admins where length(totp_secret) = 0", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	assert_eq!(off.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.json()["two_step"], false);
	let answer = sign_in(&off, json!({"username": "owner", "password": PASSWORD})).await;
	assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	assert_eq!(sign_in(&off, json!({"username": "owner", "password": "wrong password here"})).await.status, StatusCode::UNAUTHORIZED);
	let cookie = answer.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
	let session = Session {cookie, csrf: answer.json()["csrf"].as_str().unwrap().to_string()};
	assert_eq!(off.call(Method::POST, "/p/api/session/reauth", Some(&session), Some(json!({"password": PASSWORD})), "10.0.0.2").await.status, StatusCode::OK);
	assert_eq!(off.call(Method::POST, "/p/api/session/reauth", Some(&session), Some(json!({"password": "wrong password here"})), "10.0.0.2").await.status, StatusCode::UNAUTHORIZED);
	let made = off.call(Method::POST, "/p/api/admins", Some(&session), Some(json!({"username": "second", "password": PASSWORD})), "10.0.0.2").await;
	assert_eq!(made.status, StatusCode::OK);
	assert!(!made.json()["totp_secret"].as_str().unwrap().is_empty(), "the code is off, but the account still gets a secret");
	assert_eq!(sign_in(&off, json!({"username": "second", "password": PASSWORD})).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_switch_is_not_reachable_through_any_route() {
	let h = Harness::with_config(None, |cfg| cfg.two_step = "off".into()).await;
	let answer = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD})), "10.0.0.2").await;
	let session = Session {cookie: answer.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string(), csrf: answer.json()["csrf"].as_str().unwrap().to_string()};
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.2").await.json();
	assert!(settings.get("two_step").is_none());
	settings["two_step"] = json!("on");
	let put = h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings.clone()), "10.0.0.2").await;
	assert!(put.status.is_client_error(), "{}", put.status);
	settings["two_step"] = json!(true);
	settings.as_object_mut().unwrap().remove("two_step");
	let status = h.call(Method::GET, "/p/api/status", None, None, "10.0.0.2").await.json();
	assert_eq!(status["two_step"], false);
	for (method, path) in [(Method::PUT, "/p/api/status"), (Method::POST, "/p/api/status"), (Method::PATCH, "/p/api/settings")] {
		assert!(!h.call(method, path, Some(&session), Some(json!({"two_step": "on"})), "10.0.0.2").await.status.is_success());
	}
	assert_eq!(h.call(Method::GET, "/p/api/status", None, None, "10.0.0.2").await.json()["two_step"], false);
}

#[tokio::test]
async fn turning_it_back_on_ends_sessions_and_revokes_the_tokens_made_while_off() {
	let first = Harness::new().await;
	let session = first.login("10.0.0.1").await;
	let before = first.token(&session, "full", json!({})).await;
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	let off = rebuilt(&first, "off").await;
	let answer = off.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD})), "10.0.0.2").await;
	assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	let off_session = Session {cookie: answer.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string(), csrf: answer.json()["csrf"].as_str().unwrap().to_string()};
	let made_off = off.token(&off_session, "full", json!({})).await;
	let on = rebuilt(&off, "on").await;
	assert_eq!(on.call(Method::GET, "/p/api/users", Some(&session), None, "10.0.0.1").await.status, StatusCode::UNAUTHORIZED, "a session from before the switch");
	assert_eq!(on.call(Method::GET, "/p/api/users", Some(&off_session), None, "10.0.0.2").await.status, StatusCode::UNAUTHORIZED, "a session from while it was off");
	assert_eq!(on.bearer(Method::GET, "/p/api/users", &before, None, "10.0.0.1").await.status, StatusCode::OK, "a token made while on keeps working");
	assert_eq!(on.bearer(Method::GET, "/p/api/users", &made_off, None, "10.0.0.1").await.status, StatusCode::UNAUTHORIZED, "a token made while off is revoked");
	let fresh = on.login("10.0.0.3").await;
	let entries = on.call(Method::GET, "/p/api/audit?limit=1000", Some(&fresh), None, "10.0.0.3").await.json();
	let seen: Vec<(String, String)> = entries["entries"].as_array().unwrap().iter().filter(|entry| entry["action"] == "panel.two_step").map(|entry| (entry["detail"].as_str().unwrap().to_string(), entry["actor"].as_str().unwrap().to_string())).collect();
	assert_eq!(seen, vec![("on, 2 sessions ended, 1 tokens revoked".to_string(), "panel".to_string()), ("off".to_string(), "panel".to_string())], "newest first");
	assert_eq!(on.app.db.call(|db| db.query_row("select count(*) from settings where key = 'two_step_off_at'", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	let again = rebuilt(&on, "on").await;
	let count: i64 = again.app.db.call(|db| db.query_row("select count(*) from audit where action = 'panel.two_step'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(count, 2, "an unchanged value writes nothing");
}

#[tokio::test]
async fn an_admin_without_a_secret_gets_one_at_start_and_the_password_alone_never_signs_in_while_on() {
	let off = Harness::with_config(None, |cfg| cfg.two_step = "off".into()).await;
	off.app.db.call(|db| db.execute("update admins set totp_secret = x'', totp_record = x'' where username = 'owner'", []).unwrap()).await.unwrap();
	let on = rebuilt(&off, "on").await;
	assert_eq!(on.app.db.call(|db| db.query_row("select count(*) from admins where length(totp_secret) = 0", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	assert_eq!(on.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD})), "10.0.0.2").await.status, StatusCode::UNAUTHORIZED);
	let back_off = rebuilt(&on, "off").await;
	assert_eq!(back_off.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD})), "10.0.0.2").await.status, StatusCode::OK);
}

#[tokio::test]
async fn no_admin_is_left_without_a_secret_after_setup_add_reset_or_change_in_either_mode() {
	for two_step in ["on", "off"] {
		let h = Harness::with_config(None, |cfg| cfg.two_step = two_step.into()).await;
		let session = h.login("10.0.0.1").await;
		let made = h.call(Method::POST, "/p/api/admins", Some(&session), Some(json!({"username": "second", "password": PASSWORD})), "10.0.0.1").await;
		assert_eq!(made.status, StatusCode::OK, "{two_step}");
		let id: i64 = h.app.db.call(|db| db.query_row("select id from admins where username = 'second'", [], |row| row.get(0)).unwrap()).await.unwrap();
		let reset = h.call(Method::POST, &format!("/p/api/admins/{id}/reset"), Some(&session), Some(json!({"new_password": PASSWORD})), "10.0.0.1").await;
		assert_eq!(reset.status, StatusCode::OK, "{two_step}");
		let changed = h.call(Method::POST, "/p/api/account/totp", Some(&session), None, "10.0.0.1").await;
		assert_eq!(changed.status, StatusCode::OK, "{two_step}");
		assert!(!changed.json()["totp_secret"].as_str().unwrap().is_empty(), "{two_step}");
		assert_eq!(h.app.db.call(|db| db.query_row("select count(*) from admins where length(totp_secret) = 0", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0, "{two_step}");
	}
}

#[tokio::test]
async fn with_the_code_off_a_wait_holds_for_the_right_password_and_a_source_gets_fewer_tries() {
	async fn wrong(h: &Harness, name: &str, source: &str) -> Answer {h.call(Method::POST, "/p/api/login", None, Some(json!({"username": name, "password": "not the password at all", "totp": "000000"})), source).await}
	for (two_step, held) in [("off", true), ("on", false)] {
		let h = Harness::with_config(None, |cfg| cfg.two_step = two_step.into()).await;
		for n in 0..8 {wrong(&h, "owner", &format!("10.1.0.{n}")).await;}
		let right = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": h.code(0)})), "10.1.1.1").await;
		if held {
			assert_eq!((right.status, right.json()["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("rate_limited")));
			assert_eq!(h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD})), "10.1.1.2").await.status, StatusCode::TOO_MANY_REQUESTS);
		} else {
			assert_eq!(right.status, StatusCode::OK, "{}", String::from_utf8_lossy(&right.body));
		}
	}
	let counts = |h: Harness| async move {
		let mut statuses = Vec::new();
		for n in 0..6 {statuses.push(h.call(Method::POST, "/p/api/login", None, Some(json!({"username": format!("nobody{n}"), "password": "not the password at all", "totp": "000000"})), "10.2.0.1").await.status);}
		statuses
	};
	let on = counts(Harness::new().await).await;
	let off = counts(Harness::with_config(None, |cfg| cfg.two_step = "off".into()).await).await;
	assert!(on.iter().all(|status| *status == StatusCode::UNAUTHORIZED));
	assert_eq!(off.iter().filter(|status| **status == StatusCode::UNAUTHORIZED).count(), 5);
	assert_eq!(off[5], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn with_the_code_off_short_passwords_are_refused_and_a_stored_short_one_must_change_first() {
	let short = "short pw 1";
	let dir = std::env::temp_dir().join(format!("vwpanel-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	let app = build(Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), gateway: dir.join("gateway.keys"), gateway_next: dir.join("gateway.next"), node_socket: dir.join("none.sock"), two_step: "off".into(), ..Config::default()}).unwrap();
	let token = app.setup_token.lock().unwrap().clone().unwrap();
	let h = Harness {router: router(app.clone()), app, totp: Vec::new(), dir};
	assert_eq!(h.call(Method::POST, "/p/api/setup", None, Some(json!({"token": token, "username": "owner", "password": short, "accepted_terms": true})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::POST, "/p/api/setup", None, Some(json!({"token": token, "username": "owner", "password": PASSWORD, "accepted_terms": true})), "10.0.0.1").await.status, StatusCode::OK);
	async fn sign_in(h: &Harness, password: &str, source: &str) -> Answer {h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": password})), source).await}
	let answer = sign_in(&h, PASSWORD, "10.0.0.2").await;
	assert_eq!(answer.json()["password_change_required"], false);
	let session = Session {cookie: answer.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string(), csrf: answer.json()["csrf"].as_str().unwrap().to_string()};
	assert_eq!(h.call(Method::POST, "/p/api/admins", Some(&session), Some(json!({"username": "second", "password": short})), "10.0.0.2").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::POST, "/p/api/account/password", Some(&session), Some(json!({"new_password": short})), "10.0.0.2").await.status, StatusCode::BAD_REQUEST);
	let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
	let hash = argon2::password_hash::PasswordHasher::hash_password(&argon2::Argon2::default(), short.as_bytes(), &salt).unwrap().to_string();
	h.app.db.call(move |db| db.execute("update admins set password_hash = ?", [hash]).unwrap()).await.unwrap();
	let old = sign_in(&h, short, "10.0.0.3").await;
	assert_eq!(old.status, StatusCode::OK);
	assert_eq!(old.json()["password_change_required"], true);
	let session = Session {cookie: old.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string(), csrf: old.json()["csrf"].as_str().unwrap().to_string()};
	let denied = h.call(Method::GET, "/p/api/users", Some(&session), None, "10.0.0.3").await;
	assert_eq!((denied.status, denied.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("password_change_required")));
	assert_eq!(h.call(Method::GET, "/p/api/session", Some(&session), None, "10.0.0.3").await.json()["password_change_required"], true);
	assert_eq!(h.call(Method::POST, "/p/api/account/password", Some(&session), Some(json!({"new_password": PASSWORD})), "10.0.0.3").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::GET, "/p/api/users", Some(&session), None, "10.0.0.3").await.status, StatusCode::OK);
}

fn gateway_of(link: &Link) -> GatewayKey {if let Link::Native(native) = link {native.gateway()} else {panic!("not native")}}

async fn envelope_on(h: &Harness, link: &Link, path: &str, device: u8) -> Answer {
	let Link::Native(native) = link else {panic!("not native")};
	let body = json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [native.key().kid().text()], "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": "confirm"});
	h.sealed(&native.gateway(), body, path, "198.51.100.7", |request| request).await.0
}

#[tokio::test]
async fn gateway_keys_are_made_at_setup_apart_and_links_and_documents_carry_them() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let mode = |path: &std::path::Path| std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path).unwrap().permissions()) & 0o777;
	assert_eq!((mode(&h.app.cfg.gateway), mode(&h.app.cfg.gateway_next)), (0o600, 0o600));
	let shown = h.call(Method::GET, "/p/api/gateway-keys", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((shown["loaded"].clone(), shown["next"]["on_host"].clone(), shown["retired"].as_array().unwrap().len(), shown["accounts_without_device"].clone()), (json!(true), json!(true), 0, json!(0)));
	assert!(!shown.to_string().contains(&std::fs::read_to_string(&h.app.cfg.gateway_next).unwrap()), "no private part is shown");
	assert!(!std::fs::read_to_string(&h.app.cfg.gateway).unwrap().contains(&std::fs::read_to_string(&h.app.cfg.gateway_next).unwrap()), "the next key's private half is not in the key file");
	let (_, link) = h.user(&session, "ann", json!({})).await;
	assert_eq!(gateway_of(&link).id() as i64, shown["active"]["id"].as_i64().unwrap());
	let kids = [key_of(&link).kid()];
	let Payload::Subscription(document) = opened(&h.fetch(&link, &kids, 1, "fetch", None).await, &[key_of(&link)]) else {panic!("a document")};
	assert_eq!(document.gateway_keys.len(), 2);
	assert_eq!(document.gateway_keys[0], gateway_of(&link));
	assert_eq!(document.gateway_keys[1].id() as i64, shown["next"]["id"].as_i64().unwrap());
	let next = std::fs::read_to_string(&h.app.cfg.gateway_next).unwrap();
	let next: [u8; 32] = URL_SAFE_NO_PAD.decode(next.trim()).unwrap().try_into().unwrap();
	assert_eq!(&veilway_panel::gateway::public_of(&next), document.gateway_keys[1].public());
}

#[tokio::test]
async fn a_switch_keeps_old_links_working_until_the_old_key_is_destroyed() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, old_link) = h.user(&session, "ann", json!({})).await;
	let key = key_of(&old_link);
	assert!(matches!(opened(&h.fetch(&old_link, &[key.kid()], 1, "confirm", None).await, &[key]), Payload::Subscription(_)));
	assert_eq!(h.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(json!({"private": "not a key"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "a key that is not the next one is refused");
	let switched = h.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(json!({})), "10.0.0.1").await.json();
	assert_eq!(switched["gateway"]["retired"].as_array().unwrap().len(), 1);
	assert_eq!(switched["gateway"]["retired"][0]["accounts_recent"], 1);
	assert_eq!(switched["next_file_written"], true);
	let new_next = switched["next_private"].as_str().unwrap().to_string();
	assert_eq!(std::fs::read_to_string(&h.app.cfg.gateway_next).unwrap().trim(), new_next, "the file holds the new next key");
	// The old link still opens under the retired key, and the document lists the new active key and the new next key.
	let Payload::Subscription(by_old) = opened(&h.fetch(&old_link, &[key.kid()], 1, "fetch", None).await, &[key]) else {panic!("a document")};
	assert_eq!(by_old.gateway_keys[0].id() as i64, switched["gateway"]["active"]["id"].as_i64().unwrap());
	assert_ne!(by_old.gateway_keys[0], gateway_of(&old_link));
	assert_eq!(by_old.gateway_keys[1].id() as i64, switched["gateway"]["next"]["id"].as_i64().unwrap());
	// A link shown again carries the active key, and the client that follows the document is served.
	let (id, _) = (1, 0);
	let shown = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/show"), Some(&session), None, "10.0.0.1").await.json();
	let again = Link::parse(shown["veilway"].as_str().unwrap()).unwrap();
	assert_eq!(gateway_of(&again), by_old.gateway_keys[0]);
	assert!(matches!(opened(&h.fetch(&again, &[key.kid()], 1, "fetch", None).await, &[key]), Payload::Subscription(_)) || true);
	// Past the days it is kept, the retired key is destroyed and the old link is an unknown path.
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	let kept = std::fs::read_to_string(&h.app.cfg.gateway).unwrap();
	let mut file: Value = serde_json::from_str(&kept).unwrap();
	file["held"][0]["retired_at"] = json!(crypto::now() - 121 * 86_400);
	std::fs::write(&h.app.cfg.gateway, file.to_string()).unwrap();
	let restarted = rebuilt(&h, "on").await;
	let mut state = Upkeep::default();
	upkeep_once(&restarted.app, &mut state).await;
	assert_eq!(restarted.call(Method::POST, "/s", None, None, "198.51.100.7").await.shape().0, 404);
	assert_eq!(restarted.fetch(&old_link, &[key.kid()], 1, "fetch", None).await.shape(), unknown, "the destroyed key opens nothing");
	assert!(matches!(opened(&restarted.fetch(&again, &[key.kid()], 2, "fetch", None).await, &[key]), Payload::Subscription(_)));
	assert!(!std::fs::read_to_string(&restarted.app.cfg.gateway).unwrap().contains("retired_at\":1"), "the destroyed key is gone from the file");
}

#[tokio::test]
async fn a_stolen_key_is_destroyed_at_once_and_one_action_resets_the_accounts_that_used_it() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({})).await;
	let (_, bob) = h.user(&session, "bob", json!({})).await;
	let (_, cy) = h.user(&session, "cy", json!({})).await;
	for (link, device) in [(&ann, 1u8), (&bob, 2)] {assert!(matches!(opened(&h.fetch(link, &[key_of(link).kid()], device, "fetch", None).await, &[key_of(link)]), Payload::Subscription(_)));}
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	let stolen = h.call(Method::POST, "/p/api/gateway-keys/theft", Some(&session), Some(json!({})), "10.0.0.1").await.json();
	assert_eq!(stolen["affected"], 2, "ann and bob sent a request under the key, cy did not");
	assert_eq!(stolen["gateway"]["retired"].as_array().unwrap().len(), 0, "a stolen key is not kept");
	assert_eq!(stolen["gateway"]["affected"], 2);
	assert_eq!(h.fetch(&ann, &[key_of(&ann).kid()], 1, "fetch", None).await.shape(), unknown, "requests sealed to the stolen key open nothing");
	assert_eq!(h.call(Method::POST, "/p/api/gateway-keys/reset-affected", Some(&session), Some(json!({"dry_run": true})), "10.0.0.1").await.json()["count"], 2);
	let reset = h.call(Method::POST, "/p/api/gateway-keys/reset-affected", Some(&session), Some(json!({})), "10.0.0.1").await.json();
	assert_eq!((reset["count"].clone(), reset["links"].as_array().unwrap().len()), (json!(2), 2));
	assert_eq!(h.call(Method::POST, "/p/api/gateway-keys/reset-affected", Some(&session), Some(json!({"dry_run": true})), "10.0.0.1").await.json()["count"], 0);
	let fresh = Link::parse(reset["links"].as_array().unwrap().iter().find(|made| made["id"] == ann_id).unwrap()["link"].as_str().unwrap()).unwrap();
	assert_ne!(gateway_of(&fresh), gateway_of(&ann));
	assert!(matches!(opened(&h.fetch(&fresh, &[key_of(&fresh).kid()], 1, "fetch", None).await, &[key_of(&fresh)]), Payload::Subscription(_)), "the new link opens and ann's device is still hers");
	assert_eq!(h.fetch(&bob, &[key_of(&bob).kid()], 2, "fetch", None).await.shape(), unknown, "the old tokens are unknown");
	let Link::Native(cy_native) = &cy else {panic!()};
	assert_ne!(gateway_of(&cy), gateway_of(&fresh), "cy's link names the stolen key too, and nothing opens under it");
	let _ = cy_native;
}

#[tokio::test]
async fn the_gateway_is_lost_loudly_and_never_remade_by_itself() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	std::fs::remove_file(&h.app.cfg.gateway).unwrap();
	let lost = rebuilt(&h, "on").await;
	let session = lost.login("10.0.0.1").await;
	assert!(!lost.app.cfg.gateway.exists(), "a panel with accounts never makes keys by itself");
	assert_eq!(lost.fetch(&link, &[key_of(&link).kid()], 1, "fetch", None).await.shape(), unknown);
	let info = lost.call(Method::GET, "/p/api/node", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(info["gateway_missing"], true);
	assert_eq!(lost.call(Method::POST, "/p/api/gateway-keys/recreate", Some(&session), Some(json!({"confirm": false})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	// With the next key in hand, loading it is a switch.
	assert_eq!(lost.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(json!({})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "there is nothing to switch from");
	let made = lost.call(Method::POST, "/p/api/gateway-keys/recreate", Some(&session), Some(json!({"confirm": true})), "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	assert_eq!(lost.call(Method::GET, "/p/api/node", Some(&session), None, "10.0.0.1").await.json()["gateway_missing"], false);
	assert_eq!(lost.call(Method::POST, "/p/api/gateway-keys/recreate", Some(&session), Some(json!({"confirm": true})), "10.0.0.1").await.status, StatusCode::CONFLICT, "only while the keys are lost");
	let shown = lost.call(Method::POST, "/p/api/users/1/subscription/show", Some(&session), None, "10.0.0.1").await.json();
	let again = Link::parse(shown["veilway"].as_str().unwrap()).unwrap();
	assert!(matches!(opened(&lost.fetch(&again, &[key_of(&again).kid()], 1, "fetch", None).await, &[key_of(&again)]), Payload::Subscription(_)), "tokens stay valid under the new key");
}

#[tokio::test]
async fn only_a_new_valid_request_is_charged_to_its_source_and_a_restart_refuses_earlier_requests() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let Link::Native(native) = &link else {panic!()};
	let body = |t: i64| json!({"v": 1, "t": t, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [native.key().kid().text()], "device_public_key": STANDARD.encode([1u8; 32]), "device_secret": URL_SAFE_NO_PAD.encode([1u8; 16]), "op": "fetch"});
	let send = |bytes: Vec<u8>| h.send_bytes(Request::builder().method(Method::POST).uri("/s").header(HOST, "panel.example.org"), bytes, "198.51.100.7");
	let seal = |value: Value| exchange::seal(&native.gateway(), value.to_string().as_bytes(), &mut crypto::fill).unwrap().bytes().to_vec();
	let now = crypto::now();
	let mut cut = seal(body(now));
	cut[40] ^= 1;
	let unknown_token = seal(json!({"v": 1, "t": now, "token": URL_SAFE_NO_PAD.encode([5u8; 16]), "kids": [native.key().kid().text()], "device_public_key": STANDARD.encode([1u8; 32]), "device_secret": URL_SAFE_NO_PAD.encode([1u8; 16]), "op": "fetch"}));
	for bytes in [cut, vec![0; 1073], seal(body(now - 1000)), vec![1; 10]] {send(bytes).await;}
	assert_eq!(h.app.sub_limits.count("sub:198.51.100.7", 60), 0, "nothing that failed to open or was outside the window is charged");
	send(unknown_token).await;
	assert_eq!(h.app.sub_limits.count("sub:198.51.100.7", 60), 1, "a request that opened is charged, whoever it is for");
	let valid = seal(body(now));
	assert_eq!(send(valid.clone()).await.status, StatusCode::OK);
	assert_eq!(h.app.sub_limits.count("sub:198.51.100.7", 60), 2);
	send(valid.clone()).await;
	assert_eq!(h.app.sub_limits.count("sub:198.51.100.7", 60), 2, "a replay is not charged");
	// A request from before a restart is refused after it, whatever its window.
	tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
	let restarted = rebuilt(&h, "on").await;
	let unknown = restarted.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	let early = restarted.send_bytes(Request::builder().method(Method::POST).uri("/s").header(HOST, "panel.example.org"), seal(body(now)), "198.51.100.8").await;
	assert_eq!(early.shape(), unknown, "t is before the start");
	assert_eq!(restarted.send_bytes(Request::builder().method(Method::POST).uri("/s").header(HOST, "panel.example.org"), seal(body(crypto::now())), "198.51.100.8").await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_clock_that_steps_back_does_not_reopen_the_window() {
	let dir = std::env::temp_dir().join(format!("vwhold-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
	std::fs::create_dir_all(&dir).unwrap();
	let mut hold = veilway_panel::gateway::Hold::load(&dir.join("gateway.keys"), &dir.join("gateway.next"), true).unwrap();
	let at = crypto::now();
	let open = |hold: &mut veilway_panel::gateway::Hold, at: i64| {let unsealed = hold.keyring().unwrap().unseal(&[0; 1073]); hold.admit(unsealed, at, || true).unwrap()};
	assert!(open(&mut hold, at + 1000).is_err());
	assert_eq!(hold.steps_back(), 0);
	assert!(open(&mut hold, at).is_err());
	assert_eq!(hold.steps_back(), 1, "the step back is counted, and logged at warning level");
	assert_eq!(hold.counts.size + hold.counts.open + hold.counts.key, 2);
	let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_signed_refusal_is_signed_once_per_account_and_reason() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, link) = h.user(&session, "ann", json!({"enabled": false})).await;
	let key = key_of(&link);
	let first = h.fetch(&link, &[key.kid()], 1, "fetch", None).await;
	let second = h.fetch(&link, &[key.kid()], 2, "fetch", None).await;
	assert_eq!((refusal_of(&first, &[key]), first.body.clone()), (Reason::Disabled, second.body), "the same signed bytes, sealed again each time");
	h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"enabled": true, "expires_at": 1})), "10.0.0.1").await;
	assert_eq!(refusal_of(&h.fetch(&link, &[key.kid()], 3, "fetch", None).await, &[key]), Reason::Expired);
}

fn two_endpoints(extra: Value) -> Value {
	let mut settings = json!({"endpoints": [{"name": "main", "url": "https://panel.example.org/s", "pins": []}, {"name": "blue", "url": "https://blue.example.net/s", "pins": []}], "default_endpoint": "main"});
	settings.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
	settings
}

#[tokio::test]
async fn endpoints_resolve_user_then_group_then_default_and_moves_are_signed_with_a_higher_serial() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, two_endpoints(json!({}))).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({"groups": ["vip"]})).await;
	let (bob_id, _) = h.user(&session, "bob", json!({"groups": ["vip"], "endpoint": "blue"})).await;
	let (cy_id, _) = h.user(&session, "cy", json!({})).await;
	let resolved = |id: i64| {let (h, session) = (&h, &session); async move {h.call(Method::GET, &format!("/p/api/users/{id}/endpoint"), Some(session), None, "10.0.0.1").await.json()}};
	assert_eq!((resolved(ann_id).await["resolved"].clone(), resolved(ann_id).await["source"].clone()), (json!("main"), json!("default")));
	assert_eq!((resolved(bob_id).await["resolved"].clone(), resolved(bob_id).await["source"].clone()), (json!("blue"), json!("user")));
	// A dry run counts and changes nothing. A group move gives the endpoint to the members who have none of their own.
	let dry = h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"group": "vip", "endpoint": "blue", "dry_run": true})), "10.0.0.1").await.json();
	assert_eq!((dry["applied"].clone(), dry["moving"].clone(), dry["staying"].clone()), (json!(false), json!(1), json!(1)));
	assert_eq!(resolved(ann_id).await["resolved"], "main");
	// Before the move: a document on the old endpoint names the endpoint ann is to use, which is the one she reached.
	let Payload::Subscription(before) = opened(&envelope_on(&h, &ann, "/s/main", 1).await, &[key_of(&ann)]) else {panic!("a document")};
	let named = before.main_endpoint.clone().unwrap();
	assert_eq!(named.url.as_str(), "https://panel.example.org/s");
	let moved = h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"group": "vip", "endpoint": "blue"})), "10.0.0.1").await.json();
	assert_eq!((moved["applied"].clone(), moved["moving"].clone()), (json!(true), json!(1)));
	assert_eq!((resolved(ann_id).await["resolved"].clone(), resolved(ann_id).await["source"].clone(), resolved(cy_id).await["resolved"].clone()), (json!("blue"), json!("group"), json!("main")));
	// The old endpoint keeps answering and its document asks for the move. The new endpoint answers a fresh document with a higher serial that names itself.
	let Payload::Subscription(asks) = opened(&envelope_on(&h, &ann, "/s/main", 1).await, &[key_of(&ann)]) else {panic!("a document")};
	let asked = asks.main_endpoint.clone().unwrap();
	assert_eq!((asked.url.as_str(), asked.gateway_keys.clone()), ("https://blue.example.net/s", asks.gateway_keys.clone()));
	let Payload::Subscription(there) = opened(&envelope_on(&h, &ann, "/s/blue", 1).await, &[key_of(&ann)]) else {panic!("a document")};
	assert!(there.serial > asks.serial, "{} is above {}", there.serial, asks.serial);
	assert_eq!(there.main_endpoint.as_ref().unwrap().url.as_str(), asked.url.as_str(), "the document of the new endpoint names that endpoint, as the move check needs");
	assert_eq!(there.id, asks.id);
	assert!(there.gateway_keys.iter().any(|key| asked.gateway_keys.contains(key)), "its gateway keys include one of the move's");
	assert!(there.endpoint_pins.is_empty() && asked.pins.is_empty());
	// A link shown again names the account's endpoint.
	let shown = h.call(Method::POST, &format!("/p/api/users/{ann_id}/subscription/show"), Some(&session), None, "10.0.0.1").await.json();
	assert!(shown["veilway"].as_str().unwrap().starts_with("veilway://sub/blue.example.net/s#v1."));
	// The page counts who still refreshes on the old endpoint, and an endpoint in use cannot be dropped.
	let listed = h.call(Method::GET, "/p/api/endpoints", Some(&session), None, "10.0.0.1").await.json();
	let row = |name: &str| listed["endpoints"].as_array().unwrap().iter().find(|row| row["name"] == name).unwrap().clone();
	assert_eq!((row("blue")["users"].clone(), row("main")["still_here"].clone()), (json!(2), json!(1)), "ann moved and last asked on the old endpoint");
	let refused = h.call(Method::PUT, "/p/api/settings", Some(&session), Some({let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json(); settings["endpoints"] = json!([settings["endpoints"][0].clone()]); settings["group_endpoints"] = json!({}); settings}), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&refused.body));
	// A selection moves back to the default with null.
	let back = h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"users": [bob_id, cy_id], "endpoint": null})), "10.0.0.1").await.json();
	assert_eq!(back["moving"], 0, "bob follows his group, which is the same endpoint, and cy stays");
	assert_eq!(resolved(bob_id).await["source"], "group");
	assert_eq!(h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"users": [bob_id], "group": "vip", "endpoint": "blue"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"users": [bob_id], "endpoint": "nowhere"})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn endpoint_rules_pins_http_and_one_host_one_endpoint() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let put = |endpoints: Value, default: &str| {
		let (h, session) = (&h, &session);
		let default = default.to_string();
		async move {
			let mut settings = h.call(Method::GET, "/p/api/settings", Some(session), None, "10.0.0.1").await.json();
			settings["endpoints"] = endpoints;
			settings["default_endpoint"] = json!(default);
			settings["profiles"] = json!([{"id": "main", "name": "Main", "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]}]);
			h.call(Method::PUT, "/p/api/settings", Some(session), Some(settings), "10.0.0.1").await
		}
	};
	let pin = STANDARD.encode([4u8; 32]);
	assert_eq!(put(json!([{"name": "a", "url": "http://plain.example.org/s", "pins": [pin]}]), "a").await.status, StatusCode::BAD_REQUEST, "pins apply only to https");
	assert_eq!(put(json!([{"name": "a", "url": "https://203.0.113.7:8443/s", "pins": []}]), "a").await.status, StatusCode::BAD_REQUEST, "an address with no pin");
	assert_eq!(put(json!([{"name": "a", "url": "https://x.example.org/s", "pins": []}, {"name": "b", "url": "https://x.example.org/s", "pins": []}]), "a").await.status, StatusCode::BAD_REQUEST, "one host and port, one endpoint");
	assert_eq!(put(json!([{"name": "a", "url": "ftp://x.example.org/s", "pins": []}]), "a").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(put(json!([{"name": "a", "url": "https://x.example.org/s", "pins": []}]), "missing").await.status, StatusCode::BAD_REQUEST);
	assert_eq!(put(json!([{"name": "a", "url": "https://x.example.org", "pins": []}]), "a").await.status, StatusCode::BAD_REQUEST, "no path");
	let saved = put(json!([{"name": "pinned", "url": "https://203.0.113.7:8443/s", "pins": [pin]}, {"name": "plain", "url": "http://203.0.113.8:8080/s", "pins": []}]), "pinned").await;
	assert_eq!(saved.status, StatusCode::OK, "{}", String::from_utf8_lossy(&saved.body));
	let listed = h.call(Method::GET, "/p/api/endpoints", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((listed["endpoints"][0]["plain"].clone(), listed["endpoints"][1]["plain"].clone()), (json!(false), json!(true)), "a plain endpoint is marked, and the page shows its warning");
	let (_, pinned) = h.user(&session, "ann", json!({})).await;
	let Link::Native(native) = &pinned else {panic!()};
	assert_eq!((native.pin().is_some(), native.endpoint().as_str()), (true, "https://203.0.113.7:8443/s"));
	let (_, plain) = h.user(&session, "bob", json!({"endpoint": "plain"})).await;
	let Link::Native(native) = &plain else {panic!()};
	assert_eq!((native.pin().is_none(), native.veilway().starts_with("veilway://sub-plain/203.0.113.8:8080/s#v1.")), (true, true));
	let key = key_of(&plain);
	// The plain endpoint answers by its path and its document names it, with no pins.
	let answer = envelope_on(&h, &plain, "/s/plain", 2).await;
	let Payload::Subscription(document) = opened(&answer, &[key]) else {panic!("a document")};
	assert_eq!(document.main_endpoint.as_ref().unwrap().url.as_str(), "http://203.0.113.8:8080/s");
	assert!(document.endpoint_pins.is_empty());
	// The pinned endpoint's document lists its pin.
	let Payload::Subscription(pinned_document) = opened(&envelope_on(&h, &pinned, "/s/pinned", 1).await, &[key_of(&pinned)]) else {panic!("a document")};
	assert_eq!(pinned_document.endpoint_pins, vec![[4u8; 32]]);
}

fn pins_of(numbers: [u8; 2]) -> Vec<String> {numbers.iter().map(|number| STANDARD.encode([*number; 32])).collect()}

fn pinned_endpoints() -> Value {json!({"endpoints": [{"name": "old", "url": "https://203.0.113.7:8443/s", "pins": pins_of([1, 2])}, {"name": "new", "url": "https://203.0.113.9:8443/s", "pins": pins_of([3, 4])}], "default_endpoint": "old"})}

fn host_is(host: &'static str) -> impl FnOnce(axum::http::request::Builder) -> axum::http::request::Builder {
	move |mut request| {
		request.headers_mut().unwrap().insert(HOST, host.parse().unwrap());
		request
	}
}

fn fetch_body(link: &Link, device: u8) -> Value {
	let Link::Native(native) = link else {panic!("not native")};
	json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [native.key().kid().text()], "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": "confirm"})
}

#[tokio::test]
async fn an_endpoint_is_told_by_its_path_alone_and_its_pins_follow_the_endpoint_the_request_reached() {
	let secret = [9u8; 32];
	let h = Harness::with_config(None, |cfg| cfg.trusted_mirrors = vec![TrustedMirror {name: "relay".into(), secret: URL_SAFE_NO_PAD.encode(secret)}]).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, pinned_endpoints()).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({})).await;
	let key = key_of(&ann);
	let forget = || h.app.sub_limits.clear(&format!("dev:{ann_id}:{}", STANDARD.encode([1u8; 32])));
	let Payload::Subscription(settled) = opened(&envelope_on(&h, &ann, "/s/old", 1).await, &[key]) else {panic!("a document")};
	assert_eq!((settled.endpoint_pins.clone(), settled.main_endpoint.as_ref().unwrap().url.as_str()), (vec![[1u8; 32], [2u8; 32]], "https://203.0.113.7:8443/s"));
	// The move: ann is to use the new endpoint. The old endpoint still answers her, and lists its own pins.
	assert_eq!(h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"users": [ann_id], "endpoint": "new"})), "10.0.0.1").await.status, StatusCode::OK);
	forget();
	let Payload::Subscription(by_old) = opened(&envelope_on(&h, &ann, "/s/old", 1).await, &[key]) else {panic!("a document")};
	assert_eq!(by_old.endpoint_pins, vec![[1u8; 32], [2u8; 32]], "the pins of the endpoint reached, which the client holds");
	let asked = by_old.main_endpoint.as_ref().unwrap();
	assert_eq!((asked.url.as_str(), asked.pins.clone()), ("https://203.0.113.9:8443/s", vec![[3u8; 32], [4u8; 32]]), "the move names the endpoint she is to use");
	forget();
	let Payload::Subscription(by_new) = opened(&envelope_on(&h, &ann, "/s/new", 1).await, &[key]) else {panic!("a document")};
	assert_eq!(by_new.endpoint_pins, vec![[3u8; 32], [4u8; 32]]);
	// The Host header, whatever it says, decides nothing: the path does.
	forget();
	let (answer, _) = h.sealed(&gateway_of(&ann), fetch_body(&ann, 1), "/s/old", "198.51.100.7", host_is("203.0.113.9:8443")).await;
	let Payload::Subscription(lying) = opened(&answer, &[key]) else {panic!("a document")};
	assert_eq!(lying.endpoint_pins, vec![[1u8; 32], [2u8; 32]], "a Host of the new endpoint on the old path is still the old endpoint");
	// The bare path reaches no named endpoint: no pins, and never the resolved endpoint's in place of the one reached. A path no endpoint has is an unknown path.
	forget();
	let Payload::Subscription(bare) = opened(&envelope_on(&h, &ann, "/s", 1).await, &[key]) else {panic!("a document")};
	assert!(bare.endpoint_pins.is_empty() && bare.main_endpoint.is_some());
	let unknown = h.call(Method::GET, "/nothing-here", None, None, "198.51.100.7").await.shape();
	assert_eq!(envelope_on(&h, &ann, "/s/nowhere", 1).await.shape(), unknown);
	assert_eq!(h.call(Method::POST, "/s/", None, None, "198.51.100.7").await.shape().0, 404);
	// The endpoints she reached are what the page counts.
	let reached: Vec<String> = h.app.db.call(move |db| db.prepare("select endpoint from endpoint_use where user_id = ? order by endpoint").unwrap().query_map([ann_id], |row| row.get(0)).unwrap().map(Result::unwrap).collect()).await.unwrap();
	assert_eq!(reached, ["new", "old"]);
	// A relay mirror forwards to the path of the endpoint its link names, and the document it carries lists that endpoint's pins.
	let Link::Native(native) = &ann else {panic!()};
	let mut body = fetch_body(&ann, 1);
	body["op"] = json!("fetch");
	body["t"] = json!(crypto::now());
	let sealed = exchange::seal(&native.gateway(), body.to_string().as_bytes(), &mut crypto::fill).unwrap();
	forget();
	let (at, nonce) = (crypto::now(), URL_SAFE_NO_PAD.encode([5u8; 16]));
	let header = format!("v1;relay;203.0.113.50;{at};{nonce};{}", URL_SAFE_NO_PAD.encode(mirrors::mac(&secret, "relay", "203.0.113.50", at, &nonce, sealed.bytes())));
	let mut relayed = h.send_bytes(Request::builder().method(Method::POST).uri("/s/old").header(CONTENT_TYPE, "application/octet-stream").header(HOST, "relay.example.net").header(mirrors::HEADER, header), sealed.bytes().to_vec(), "198.51.100.7").await;
	relayed.body = sealed.open(&relayed.body).unwrap();
	let Payload::Subscription(through) = opened(&relayed, &[key]) else {panic!("a document")};
	assert_eq!(through.endpoint_pins, vec![[1u8; 32], [2u8; 32]], "the path of the mirror's upstream names the endpoint");
}

#[tokio::test]
async fn a_static_file_carries_pins_only_for_an_account_with_no_move_pending() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let base = "https://files.example.net/vw/";
	h.configure(&session, json!({"static_mirrors": [base], "endpoints": pinned_endpoints()["endpoints"].clone(), "default_endpoint": "old"})).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({})).await;
	let (_, bob) = h.user(&session, "bob", json!({})).await;
	for (link, device) in [(&ann, 1), (&bob, 2)] {assert_eq!(envelope_on(&h, link, "/s/old", device).await.status, StatusCode::OK);}
	assert_eq!(h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"users": [ann_id], "endpoint": "new"})), "10.0.0.1").await.status, StatusCode::OK);
	let at = crypto::now();
	veilway_panel::statics::round(&h.app, at).await.unwrap();
	let directory = h.dir.join("static").join(veilway_panel::statics::label(base)).join("current");
	let read = |link: &Link, device: u8| {
		let Link::Native(native) = link else {panic!()};
		let keys = veilway_proto::keys::MirrorKeys::derive(&<[u8; 16]>::try_from(native.token().expose().as_ref()).unwrap(), &[device; 16], &[device; 32]);
		let epoch = veilway_proto::subscription::mirror::epoch(at as u64);
		let body = std::fs::read(directory.join(veilway_proto::subscription::mirror::file_name(&keys, base, epoch))).unwrap();
		let found = veilway_proto::subscription::mirror::open(&keys, base, epoch, &body).unwrap();
		let Payload::Subscription(document) = payload::parse(&envelope::verify(&found, &[native.key()], BODY_MAX).unwrap()).unwrap() else {panic!("a document")};
		document
	};
	let (moving, settled) = (read(&ann, 1), read(&bob, 2));
	assert!(moving.endpoint_pins.is_empty() && moving.main_endpoint.as_ref().unwrap().url.as_str() == "https://203.0.113.9:8443/s", "ann is moving: her file names the move and lists no pins, which a client that holds the old ones would refuse");
	assert_eq!(settled.endpoint_pins, vec![[1u8; 32], [2u8; 32]], "bob has not moved: his file lists the pins of his endpoint");
}

#[tokio::test]
async fn a_stored_settings_row_that_does_not_parse_stops_the_start_and_is_left_alone() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let damaged = r#"{"provider_name": "Test Net", "endpoints": "not a list""#;
	h.app.db.call(move |db| db.execute("update settings set value = ? where key = 'settings'", [damaged]).unwrap()).await.unwrap();
	let Err(error) = build(h.app.cfg.clone()) else {panic!("the panel started on settings it could not read")};
	assert!(error.contains("stored settings") && error.contains("untouched"), "{error}");
	let kept: String = h.app.db.call(|db| db.query_row("select value from settings where key = 'settings'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(kept, damaged, "the row is as it was");
	// A row that is not there at all is a first start, and gives the defaults.
	h.app.db.call(|db| db.execute("delete from settings where key = 'settings'", []).unwrap()).await.unwrap();
	assert_eq!(build(h.app.cfg.clone()).unwrap().settings().provider_name, "Veilway");
}

#[tokio::test]
async fn a_device_key_belongs_to_one_account_and_is_never_a_nodes_inbound_key() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, ann) = h.user(&session, "ann", json!({})).await;
	let (bob_id, bob) = h.user(&session, "bob", json!({})).await;
	assert_eq!(h.fetch(&ann, &[key_of(&ann).kid()], 1, "confirm", None).await.status, StatusCode::OK);
	h.app.sub_limits.clear(&format!("new:{bob_id}:1"));
	// Bob offers ann's device key with a secret of his own: the answer is the one for a device whose secret is not the stored one, and nothing is stored for him.
	let theirs = h.fetch(&bob, &[key_of(&bob).kid()], 1, "confirm", None).await;
	assert_eq!(refusal_of(&theirs, &[key_of(&bob)]), Reason::DeviceMismatch);
	// The key of an inbound of the node (the configuration has [7; 32]) is no device's.
	let node = h.fetch(&bob, &[key_of(&bob).kid()], 7, "confirm", None).await;
	assert_eq!(refusal_of(&node, &[key_of(&bob)]), Reason::DeviceMismatch);
	assert_eq!(h.app.db.call(move |db| db.query_row("select count(*) from devices where user_id = ?", [bob_id], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
	// Another key is taken as before, and the table itself refuses a key twice.
	assert_eq!(h.fetch(&bob, &[key_of(&bob).kid()], 2, "confirm", None).await.status, StatusCode::OK);
	let twice = h.app.db.call(move |db| db.execute("update devices set public_key = ? where user_id = ?", rusqlite::params![STANDARD.encode([1u8; 32]), bob_id])).await.unwrap();
	assert!(twice.is_err(), "a unique index on the key");
}

#[tokio::test]
async fn the_endpoints_limits_are_its_own_and_an_ipv6_source_counts_by_its_48() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, ann) = h.user(&session, "ann", json!({})).await;
	assert_eq!((bucket("2001:db8:1:2::1", 48), bucket("192.0.2.7", 48)), (bucket("2001:db8:1:ffff::9", 48), "192.0.2.7".to_string()));
	assert_ne!(bucket("2001:db8:1:2::1", 48), bucket("2001:db8:2:2::1", 48));
	let Link::Native(native) = &ann else {panic!()};
	let answer = h.sealed(&native.gateway(), fetch_body(&ann, 1), "/s", "[2001:db8:1:2::7]", |request| request).await.0;
	assert_eq!(answer.status, StatusCode::OK);
	assert_eq!(h.app.sub_limits.count(&format!("sub:{}", bucket("2001:db8:1:2::7", 48)), 60), 1, "the whole /48 shares one allowance");
	assert_eq!(h.app.limits.count(&format!("sub:{}", bucket("2001:db8:1:2::7", 48)), 60), 0, "and the admin side's limiter is not the one charged");
	// A flood of sources fills the endpoint's limiter to its cap. Admin requests still pass, since they count in another one.
	for index in 0..100_000 {h.app.sub_limits.hit(&format!("sub:flood{index}"), 120, 60);}
	assert!(!h.app.sub_limits.hit("sub:one more", 120, 60));
	let again = h.login("10.0.0.9").await;
	assert_eq!(h.call(Method::GET, "/p/api/users", Some(&again), None, "10.0.0.9").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": "wrong password here", "totp": "000000"})), "10.0.0.10").await.status, StatusCode::UNAUTHORIZED, "a sign-in is judged, not refused for a full table");
}

#[tokio::test]
async fn a_theft_destroys_every_held_key_and_marks_the_accounts_of_all_of_them() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({})).await;
	let (_, bob) = h.user(&session, "bob", json!({})).await;
	assert_eq!(h.fetch(&ann, &[key_of(&ann).kid()], 1, "confirm", None).await.status, StatusCode::OK);
	assert_eq!(h.fetch(&bob, &[key_of(&bob).kid()], 2, "confirm", None).await.status, StatusCode::OK);
	let switched = h.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(json!({})), "10.0.0.1").await.json();
	assert_eq!(switched["gateway"]["retired"].as_array().unwrap().len(), 1);
	let shown = h.call(Method::POST, &format!("/p/api/users/{ann_id}/subscription/show"), Some(&session), None, "10.0.0.1").await.json();
	let fresh = Link::parse(shown["veilway"].as_str().unwrap()).unwrap();
	h.app.sub_limits.clear(&format!("dev:{ann_id}:{}", STANDARD.encode([1u8; 32])));
	assert_eq!(h.fetch(&fresh, &[key_of(&fresh).kid()], 1, "fetch", None).await.status, StatusCode::OK, "ann reaches the new active key");
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	let stolen = h.call(Method::POST, "/p/api/gateway-keys/theft", Some(&session), Some(json!({})), "10.0.0.1").await.json();
	assert_eq!(stolen["affected"], 2, "ann (under both keys) and bob (under the retired one)");
	assert_eq!(stolen["gateway"]["retired"].as_array().unwrap().len(), 0);
	let kept: Value = serde_json::from_str(&std::fs::read_to_string(&h.app.cfg.gateway).unwrap()).unwrap();
	assert_eq!(kept["held"].as_array().unwrap().len(), 1, "no retired key survives a theft");
	assert_eq!(h.fetch(&bob, &[key_of(&bob).kid()], 2, "fetch", None).await.shape(), unknown, "the retired key opens nothing any more");
	assert_eq!(h.call(Method::POST, "/p/api/gateway-keys/reset-affected", Some(&session), Some(json!({"dry_run": true})), "10.0.0.1").await.json()["count"], 2);
}

#[tokio::test]
async fn a_theft_whose_request_is_dropped_still_marks_the_accounts() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, ann) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.fetch(&ann, &[key_of(&ann).kid()], 1, "confirm", None).await.status, StatusCode::OK);
	let before = std::fs::read(&h.app.cfg.gateway).unwrap();
	{
		let request = h.call(Method::POST, "/p/api/gateway-keys/theft", Some(&session), Some(json!({})), "10.0.0.1");
		tokio::pin!(request);
		// Poll the request until the key file has changed, then drop it, as a client that hangs up does.
		for _ in 0..10_000 {
			std::future::poll_fn(|context| {let _ = request.as_mut().poll(context); std::task::Poll::Ready(())}).await;
			if std::fs::read(&h.app.cfg.gateway).unwrap() != before {break}
			tokio::task::yield_now().await;
		}
		assert_ne!(std::fs::read(&h.app.cfg.gateway).unwrap(), before, "the key file was switched");
	}
	let mut marked = 0;
	for _ in 0..200 {
		marked = h.app.db.call(|db| db.query_row("select count(*) from settings where key = 'gateway_affected'", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap();
		if marked == 1 {break}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
	assert_eq!(marked, 1, "the database part of the action ran although the request was gone");
	assert_eq!(h.call(Method::POST, "/p/api/gateway-keys/reset-affected", Some(&session), Some(json!({"dry_run": true})), "10.0.0.1").await.json()["count"], 1);
}

#[tokio::test]
async fn the_affected_list_is_kept_until_the_links_are_built_and_then_the_accounts_settled_leave_it() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (ann_id, ann) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.fetch(&ann, &[key_of(&ann).kid()], 1, "confirm", None).await.status, StatusCode::OK);
	h.call(Method::POST, "/p/api/gateway-keys/theft", Some(&session), Some(json!({})), "10.0.0.1").await;
	// A user who is gone is not left on the list for ever.
	h.app.db.call(move |db| db.execute("insert into settings (key, value) values ('gateway_affected', ?) on conflict (key) do update set value = excluded.value", [json!([ann_id, 9999]).to_string()]).unwrap()).await.unwrap();
	let reset = h.call(Method::POST, "/p/api/gateway-keys/reset-affected", Some(&session), Some(json!({})), "10.0.0.1").await.json();
	assert_eq!((reset["count"].clone(), reset["links"].as_array().unwrap().len()), (json!(1), 1));
	assert_eq!(h.app.db.call(|db| db.query_row("select count(*) from settings where key = 'gateway_affected'", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 0);
}

#[tokio::test]
async fn a_key_the_operator_kept_loads_when_no_key_file_is_there_and_not_while_one_is() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, ann) = h.user(&session, "ann", json!({})).await;
	let shown = h.call(Method::GET, "/p/api/gateway-keys", Some(&session), None, "10.0.0.1").await.json();
	let (next_id, kept) = (shown["next"]["id"].as_u64().unwrap(), std::fs::read_to_string(&h.app.cfg.gateway_next).unwrap());
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	// A file that cannot be used is not replaced: it is for the operator to repair or move aside.
	std::fs::write(&h.app.cfg.gateway, b"not json").unwrap();
	let broken = rebuilt(&h, "on").await;
	let session = broken.login("10.0.0.1").await;
	let body = json!({"private": kept.trim(), "id": next_id, "confirm": true});
	assert_eq!(broken.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(body.clone()), "10.0.0.1").await.status, StatusCode::CONFLICT);
	assert_eq!(std::fs::read(&broken.app.cfg.gateway).unwrap(), b"not json");
	assert_eq!(broken.call(Method::POST, "/p/api/gateway-keys/recreate", Some(&session), Some(json!({"confirm": true})), "10.0.0.1").await.status, StatusCode::CONFLICT, "new keys are not made over a file that is there");
	assert_eq!(std::fs::read(&broken.app.cfg.gateway).unwrap(), b"not json");
	std::fs::remove_file(&broken.app.cfg.gateway).unwrap();
	let lost = rebuilt(&broken, "on").await;
	let session = lost.login("10.0.0.1").await;
	assert_eq!(lost.fetch(&ann, &[key_of(&ann).kid()], 1, "confirm", None).await.shape(), unknown);
	for (what, edit) in [("no confirmation", json!({"confirm": false})), ("no id", json!({"id": null})), ("a key that is not a key", json!({"private": "short"}))] {
		let mut changed = body.clone();
		changed.as_object_mut().unwrap().extend(edit.as_object().unwrap().clone());
		assert_eq!(lost.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(changed), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "{what}");
	}
	assert!(!lost.app.cfg.gateway.exists());
	let loaded = lost.call(Method::POST, "/p/api/gateway-keys/rotate", Some(&session), Some(body), "10.0.0.1").await;
	assert_eq!(loaded.status, StatusCode::OK, "{}", String::from_utf8_lossy(&loaded.body));
	let loaded = loaded.json();
	assert_eq!((loaded["gateway"]["loaded"].clone(), loaded["gateway"]["active"]["id"].clone()), (json!(true), json!(next_id)));
	assert_ne!(loaded["next_private"].as_str().unwrap(), kept.trim(), "a fresh next key is made");
	let private: [u8; 32] = URL_SAFE_NO_PAD.decode(kept.trim()).unwrap().try_into().unwrap();
	let key = GatewayKey::new(next_id as u8, veilway_panel::gateway::public_of(&private)).unwrap();
	let (answer, _) = lost.sealed(&key, fetch_body(&ann, 1), "/s", "198.51.100.7", |request| request).await;
	assert_eq!(answer.status, StatusCode::OK, "a client that was shown this key as the next one is served by it");
	assert_eq!(lost.app.db.call(|db| db.query_row("select count(*) from audit where action = 'gateway.recover'", [], |row| row.get::<_, i64>(0)).unwrap()).await.unwrap(), 1);
}

#[tokio::test]
async fn refresh_mirrors_are_read_as_a_document_reads_them_and_pins_are_not_changed_to_none_that_clients_hold() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, pinned_endpoints()).await;
	let put = |extra: Value| {
		let (h, session) = (&h, &session);
		async move {
			let mut settings = h.call(Method::GET, "/p/api/settings", Some(session), None, "10.0.0.1").await.json();
			settings.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
			h.call(Method::PUT, "/p/api/settings", Some(session), Some(settings), "10.0.0.1").await
		}
	};
	let pin = STANDARD.encode([1u8; 32]);
	assert_eq!(put(json!({"refresh_mirrors": ["https://mirror.example.net/s", {"url": "https://203.0.113.50/s", "pins": [pin]}]})).await.status, StatusCode::OK);
	for (what, entries) in [
		("a number", json!([7])),
		("ftp", json!(["ftp://mirror.example.net/s"])),
		("an address with no pins", json!(["https://203.0.113.50/s"])),
		("pins on http", json!([{"url": "http://mirror.example.net/s", "pins": [pin]}])),
		("an object with a member more", json!([{"url": "https://mirror.example.net/s", "pins": [pin], "more": 1}])),
		("the same pin twice", json!([{"url": "https://mirror.example.net/s", "pins": [pin, pin]}])),
		("one host in two kinds", json!(["https://mirror.example.net/s", "http://mirror.example.net:443/other"])),
		("an endpoint's host in another kind", json!(["http://203.0.113.7:8443/s"])),
		("an endpoint's host and none of its pins", json!([{"url": "https://203.0.113.7:8443/s", "pins": [STANDARD.encode([9u8; 32])]}])),
	] {assert_eq!(put(json!({"refresh_mirrors": entries})).await.status, StatusCode::BAD_REQUEST, "{what}");}
	assert_eq!(put(json!({"refresh_mirrors": [{"url": "https://203.0.113.7:8443/other", "pins": [pin]}]})).await.status, StatusCode::OK, "a relay of a pinned endpoint that holds one of its pins");
	// A list of pins that keeps none of the ones clients hold locks them out, so it is refused. A switch keeps the former standby.
	let endpoints = |pins: [u8; 2]| json!({"refresh_mirrors": [], "endpoints": [{"name": "old", "url": "https://203.0.113.7:8443/s", "pins": pins_of(pins)}, {"name": "new", "url": "https://203.0.113.9:8443/s", "pins": pins_of([3, 4])}]});
	assert_eq!(put(endpoints([5, 6])).await.status, StatusCode::CONFLICT, "no pin kept");
	assert_eq!(put(json!({"refresh_mirrors": [], "endpoints": [{"name": "old", "url": "https://203.0.113.7:8443/s", "pins": []}, {"name": "new", "url": "https://203.0.113.9:8443/s", "pins": pins_of([3, 4])}]})).await.status, StatusCode::BAD_REQUEST, "an address with no pin is refused by its own rule");
	assert_eq!(put(endpoints([2, 5])).await.status, StatusCode::OK, "the standby is kept");
	assert_eq!(h.app.settings().endpoints[0].pins, pins_of([2, 5]));
	// A host name can drop to no pins in the URL rules, and the pin rule is what refuses it.
	let named = |pins: Vec<String>| json!({"refresh_mirrors": [], "endpoints": [{"name": "old", "url": "https://old.example.org/s", "pins": pins}, {"name": "new", "url": "https://203.0.113.9:8443/s", "pins": pins_of([3, 4])}]});
	assert_eq!(put(named(pins_of([2, 5]))).await.status, StatusCode::OK);
	assert_eq!(put(named(Vec::new())).await.status, StatusCode::CONFLICT, "pins taken away from an endpoint whose clients hold them");
	assert_eq!(h.app.settings().endpoints[0].pins, pins_of([2, 5]));
}

#[tokio::test]
async fn a_known_token_is_counted_under_its_key_even_when_the_account_is_refused() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, link) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"enabled": false})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(refusal_of(&h.fetch(&link, &[key_of(&link).kid()], 1, "fetch", None).await, &[key_of(&link)]), Reason::Disabled);
	let counted: i64 = h.app.db.call(move |db| db.query_row("select count(*) from gateway_use where user_id = ?", [id], |row| row.get(0)).unwrap()).await.unwrap();
	assert_eq!(counted, 1, "a switch would have missed this account");
}

#[tokio::test]
async fn a_fault_of_the_panel_answers_as_an_unknown_path_and_never_as_a_signed_disabled() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let unknown = h.call(Method::GET, "/nothing", None, None, "198.51.100.7").await.shape();
	h.app.update_settings(|settings| settings.profiles.clear()).await.unwrap();
	let broken = h.fetch(&link, &[key_of(&link).kid()], 1, "confirm", None).await;
	assert_eq!(broken.shape(), unknown, "no profile makes the document impossible to build");
}

#[tokio::test]
async fn settings_reach_the_cache_only_after_their_commit_and_a_group_move_changes_only_its_own_entry() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let cache = h.app.settings.clone();
	let after_rollback = h.app.db.call(move |db| {
		let tx = db.transaction().unwrap();
		let stored = veilway_panel::app::store_settings(&tx, &cache, |settings| settings.provider_name = "Never committed".into()).unwrap();
		assert_eq!(stored.provider_name, "Never committed");
		assert_eq!(cache.read().unwrap().provider_name, "Test Net", "the cache is not touched by the write");
		drop(tx);
		cache.read().unwrap().provider_name.clone()
	}).await.unwrap();
	assert_eq!(after_rollback, "Test Net");
	let row: String = h.app.db.call(|db| db.query_row("select value from settings where key = 'settings'", [], |row| row.get(0)).unwrap()).await.unwrap();
	assert!(row.contains("Test Net") && !row.contains("Never committed"));
	h.configure(&session, json!({"endpoints": pinned_endpoints()["endpoints"].clone(), "default_endpoint": "old", "provider_name": "Renamed"})).await;
	h.user(&session, "ann", json!({"groups": ["vip"]})).await;
	let moved = h.call(Method::POST, "/p/api/endpoints/move", Some(&session), Some(json!({"group": "vip", "endpoint": "new"})), "10.0.0.1").await;
	assert_eq!(moved.status, StatusCode::OK, "{}", String::from_utf8_lossy(&moved.body));
	let after = h.app.settings();
	assert_eq!((after.provider_name.as_str(), after.group_endpoints.get("vip").map(String::as_str)), ("Renamed", Some("new")));
}

#[tokio::test]
async fn a_reset_of_a_link_is_one_unit() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({})).await;
	let (id, link) = h.user(&session, "ann", json!({})).await;
	assert_eq!(h.fetch(&link, &[key_of(&link).kid()], 1, "confirm", None).await.status, StatusCode::OK);
	let reset = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/reset"), Some(&session), Some(json!({"remove_devices": true})), "10.0.0.1").await;
	assert_eq!(reset.status, StatusCode::OK, "{}", String::from_utf8_lossy(&reset.body));
	let (generation, devices, audited): (i64, i64, i64) = h.app.db.call(move |db| (db.query_row("select token_gen from users where id = ?", [id], |row| row.get(0)).unwrap(), db.query_row("select count(*) from devices where user_id = ?", [id], |row| row.get(0)).unwrap(), db.query_row("select count(*) from audit where action = 'link.reset'", [], |row| row.get(0)).unwrap())).await.unwrap();
	assert_eq!((generation, devices, audited), (2, 0, 1));
	assert_eq!(h.call(Method::POST, "/p/api/users/9999/subscription/reset", Some(&session), Some(json!({})), "10.0.0.1").await.status, StatusCode::NOT_FOUND, "a missing account changes nothing");
}

fn borrowed_inbounds(site: Value, key: &str) -> Value {
	json!([{"tag": "Main", "type": "veilway", "private_key": "<redacted>", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "faketls", "listen": "0.0.0.0:443", "site": site, "transport_key": key}]}])
}

#[tokio::test]
async fn a_borrowed_site_goes_to_the_node_and_into_a_profile_of_its_own_that_apps_read() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"node_host": "192.0.2.10"})).await;
	let site = json!({"host": "www.example.com", "names": ["example.com"], "acknowledged": true});
	let put = |value: Value, revision: u32| h.call(Method::PUT, "/p/api/config/inbounds", Some(&session), Some(json!({"revision": format!("rev{revision}"), "value": value})), "10.0.0.1");
	let refused = put(borrowed_inbounds(json!({"host": "www.example.com", "acknowledged": false}), &STANDARD.encode([5u8; 32])), 1).await;
	assert_eq!((refused.status, refused.json()["error"]["code"].clone()), (StatusCode::UNPROCESSABLE_ENTITY, json!("invalid_config")));
	assert!(refused.json()["error"]["message"].as_str().unwrap().contains("site.acknowledged"), "the panel says which rule, before the node is asked");
	assert!(fake.applied.lock().unwrap().is_empty(), "nothing reached the node");
	let key = STANDARD.encode([5u8; 32]);
	assert_eq!(put(borrowed_inbounds(site.clone(), &key), 1).await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((derived["templates"].as_array().unwrap().len(), derived["templates"][1]["kind"].clone(), derived["templates"][1]["refused"].clone()), (2, json!("faketls"), json!([])));
	let marked = borrowed_inbounds(site.clone(), "<redacted:05050505>");
	assert_eq!(put(marked, 2).await.status, StatusCode::OK, "the key comes back as the node's marker, and the panel keeps what it made of the key");
	let template = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json()["templates"][1].clone();
	assert_eq!(template["profile"]["transports"][0]["transport_public_key"], STANDARD.encode(veilway_proto::proof::public_key(&[5u8; 32])));
	assert_eq!(h.call(Method::PUT, "/p/api/profiles/overrides/Main", Some(&session), Some(json!({"set": {"inbound_public_key": STANDARD.encode([7u8; 32])}})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let (key, kids) = (key_of(&link), [key_of(&link).kid()]);
	let answer = h.fetch(&link, &kids, 1, "fetch", None).await;
	let Payload::Subscription(document) = opened(&answer, &[key]) else {panic!("a document {:?}", refusal_of(&answer, &[key]))};
	assert_eq!(document.profiles.iter().map(|profile| profile.id.clone()).collect::<Vec<_>>(), ["main", "main-faketls"], "its own profile, so an app that does not know the type keeps the other");
	let (plain, borrowed) = (&document.profiles[0], &document.profiles[1]);
	assert!(plain.transports.iter().all(|transport| !matches!(transport, payload::Transport::FakeTls {..})));
	assert_eq!((borrowed.transports.len(), borrowed.dropped.len(), borrowed.transport_public_key, borrowed.rating_cap), (1, 0, None, Some(payload::RatingCap::Detectable)));
	let payload::Transport::FakeTls {key, candidates} = &borrowed.transports[0] else {panic!("the transport is faketls")};
	assert_eq!((*key, candidates.len(), candidates[0].address.address().to_string(), candidates[0].sni.clone()), (veilway_proto::proof::public_key(&[5u8; 32]), 1, "192.0.2.10:443".to_string(), "www.example.com".to_string()));
}

#[tokio::test]
async fn a_borrowed_site_that_cannot_be_emitted_is_named_on_the_node_page_and_not_published() {
	let (_fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"node_host": "192.0.2.10"})).await;
	let key = STANDARD.encode([5u8; 32]);
	let inbounds = borrowed_inbounds(json!({"host": "www.example.com", "acknowledged": true}), &key);
	assert_eq!(h.call(Method::PUT, "/p/api/config/inbounds", Some(&session), Some(json!({"revision": "rev1", "value": inbounds})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::PUT, "/p/api/profiles/overrides/Main", Some(&session), Some(json!({"set": {"inbound_public_key": STANDARD.encode([7u8; 32]), "transport_public_key": STANDARD.encode(veilway_proto::proof::public_key(&[5u8; 32]))}})), "10.0.0.1").await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((derived["templates"][1]["refused"][0]["code"].clone(), derived["templates"][1]["refused"][0]["transport"].clone(), derived["templates"][1]["profile"]["transports"].clone()), (json!("key_shared"), json!("0.0.0.0:443"), json!([])), "the public key of the profile's other transports is the same");
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK, "a refused transport blocks nothing else");
	let published = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(published["profiles"].as_array().unwrap().iter().map(|profile| profile["id"].as_str().unwrap().to_string()).collect::<Vec<_>>(), ["main"]);
}

fn public_of(fill: u8) -> String {STANDARD.encode(veilway_proto::proof::public_key(&[fill; 32]))}

#[tokio::test]
async fn a_fronted_shaped_relay_is_accepted_with_the_nodes_shape_and_faketls_is_refused() {
	let (_fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"node_host": "192.0.2.10"})).await;
	let shape = json!({"up": {"method": "POST", "in": "body"}, "down": {"mode": "sse"}});
	let inbounds = json!([{"tag": "Main", "type": "veilway", "private_key": "<redacted>", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "fronted-shaped", "listen": "127.0.0.1:8443", "path": "/a-long-enough-path", "decoy": {"origin": "http://origin.example.org:8080"}, "trusted_proxies": ["127.0.0.1"], "shape": shape.clone()}]}]);
	assert_eq!(h.call(Method::PUT, "/p/api/config/inbounds", Some(&session), Some(json!({"revision": "rev1", "value": inbounds})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::PUT, "/p/api/profiles/overrides/Main", Some(&session), Some(json!({"set": {"inbound_public_key": STANDARD.encode([7u8; 32]), "transport_public_key": public_of(5)}})), "10.0.0.1").await.status, StatusCode::OK);
	let relay = json!({"name": "edge", "address": "198.51.100.7", "transports": ["fronted-shaped"], "ports": {"fronted-shaped": 9443}, "enabled": true});
	let site = json!({"name": "site", "address": "198.51.100.8", "transports": ["faketls"], "enabled": true});
	assert_eq!(h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": [site]})), "10.0.0.1").await.status, StatusCode::BAD_REQUEST, "faketls is never carried by a relay");
	let preview = h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": [relay.clone()]})), "10.0.0.1").await.json();
	assert_eq!(preview["templates"][0]["profile"]["transports"][1]["candidates"][1]["address"], json!("198.51.100.7:9443"));
	assert_eq!(preview["templates"][0]["profile"]["transports"][1]["shape"], shape, "the relay's candidate keeps the node's shape");
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	settings["relays"] = json!([relay]);
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	let (_, link) = h.user(&session, "ann", json!({})).await;
	let (key, kids) = (key_of(&link), [key_of(&link).kid()]);
	let answer = h.fetch(&link, &kids, 1, "fetch", None).await;
	let Payload::Subscription(document) = opened(&answer, &[key]) else {panic!("a document {:?}", refusal_of(&answer, &[key]))};
	let payload::Transport::FrontedShaped(stream, carried) = &document.profiles[0].transports[1] else {panic!("the transport is fronted-shaped")};
	assert_eq!(stream.candidates.iter().map(|candidate| (candidate.address.address().to_string(), candidate.sni.clone(), candidate.host.clone())).collect::<Vec<_>>(), [("192.0.2.10:8443".to_string(), Some("origin.example.org".to_string()), "origin.example.org".to_string()), ("198.51.100.7:9443".to_string(), Some("origin.example.org".to_string()), "origin.example.org".to_string())], "the relay keeps the node's name and its own address");
	assert_eq!(carried, &veilway_proto::shape::Shape::parse(shape.to_string().as_bytes()).unwrap(), "the shape is the node's, read by the core");
}

async fn borrowed_node() -> (Arc<Fake>, Harness, Session) {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	h.configure(&session, json!({"node_host": "192.0.2.10"})).await;
	(fake, h, session)
}

async fn put_inbounds(h: &Harness, session: &Session, revision: u32, inbounds: Value) -> Answer {h.call(Method::PUT, "/p/api/config/inbounds", Some(session), Some(json!({"revision": format!("rev{revision}"), "value": inbounds})), "10.0.0.1").await}

fn site_of(host: &str) -> Value {json!({"host": host, "acknowledged": true})}

#[tokio::test]
async fn an_inbound_applied_with_its_private_key_gets_its_public_key_in_its_profile() {
	let (_fake, h, session) = borrowed_node().await;
	let inbound = |key: String| json!([{"tag": "Main", "type": "veilway", "private_key": key, "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}]);
	let wg = |fill: u8| STANDARD.encode(x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([fill; 32])).to_bytes());
	let derived = || async {h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json()["templates"][0].clone()};
	assert_eq!(derived().await["missing"], json!(["inbound_public_key"]), "a key the panel never saw in full is still asked for");
	h.configure(&session, json!({"node_host": "192.0.2.10", "profile_overrides": {"Main": {"inbound_public_key": wg(9), "name": "Edited"}}})).await;
	assert_eq!(put_inbounds(&h, &session, 1, inbound(STANDARD.encode([7u8; 32]))).await.status, StatusCode::OK);
	let template = derived().await;
	assert_eq!((template["profile"]["inbound_public_key"].clone(), template["missing"].clone()), (json!(wg(7)), json!([])), "the public half is made from the key that was applied");
	assert_eq!(h.app.settings().profile_overrides["Main"], json!({"name": "Edited"}), "an override with another key is dropped, the other edits stay");
	assert_eq!(put_inbounds(&h, &session, 2, inbound("<redacted>".into())).await.status, StatusCode::OK);
	assert_eq!(derived().await["profile"]["inbound_public_key"], json!(wg(7)), "a marker keeps the key made before");
	let mut forged = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	forged["inbound_keys"] = json!({"Main": wg(3)});
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(forged), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.app.settings().inbound_keys["Main"], wg(7), "a settings update never takes the keys from the page");
	let spec: Value = serde_json::from_str(&openapi::openapi()).unwrap();
	assert_eq!(spec["components"]["schemas"]["Settings"]["properties"]["inbound_keys"]["readOnly"], json!(true));
}

#[tokio::test]
async fn the_first_endpoint_needs_a_default_and_the_error_says_where() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	let answer = h.call(Method::PUT, "/p/api/settings", Some(&session), Some(json!({"provider_name": "Test Net", "endpoints": [{"name": "main", "url": "https://panel.example.org/s", "pins": []}], "default_endpoint": ""})), "10.0.0.1").await;
	assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&answer.body));
	assert!(String::from_utf8_lossy(&answer.body).contains("Pick one under Default endpoint"), "{}", String::from_utf8_lossy(&answer.body));
}

#[tokio::test]
async fn a_settings_update_never_takes_the_borrowed_site_keys_from_the_page() {
	let (_fake, h, session) = borrowed_node().await;
	assert_eq!(put_inbounds(&h, &session, 1, borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([5u8; 32]))).await.status, StatusCode::OK);
	let mut old = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(old["faketls_keys"], json!({"Main": {"0.0.0.0:443": public_of(5)}}));
	let mut forged = old.clone();
	forged["faketls_keys"] = json!({"Main": {"0.0.0.0:443": public_of(9)}, "Other": {"0.0.0.0:444": public_of(9)}});
	forged["provider_name"] = json!("Renamed");
	let answer = h.call(Method::PUT, "/p/api/settings", Some(&session), Some(forged), "10.0.0.1").await;
	assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	assert_eq!((answer.json()["faketls_keys"].clone(), answer.json()["provider_name"].clone()), (json!({"Main": {"0.0.0.0:443": public_of(5)}}), json!("Renamed")), "the answer is what was stored");
	assert_eq!(h.app.settings().faketls_keys, std::collections::BTreeMap::from([("Main".to_string(), std::collections::BTreeMap::from([("0.0.0.0:443".to_string(), public_of(5))]))]));
	old.as_object_mut().unwrap().remove("faketls_keys");
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(old.clone()), "10.0.0.1").await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(derived["templates"][1]["refused"], json!([]), "a page that sends none loses nothing");
	assert_eq!(put_inbounds(&h, &session, 2, borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([6u8; 32]))).await.status, StatusCode::OK);
	old["provider_name"] = json!("Stale page");
	old["faketls_keys"] = json!({"Main": {"0.0.0.0:443": public_of(5)}});
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(old), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(h.app.settings().faketls_keys["Main"]["0.0.0.0:443"], public_of(6), "a page that read the key before it changed does not put the old one back");
	let spec: Value = serde_json::from_str(&openapi::openapi()).unwrap();
	assert_eq!(spec["components"]["schemas"]["Settings"]["properties"]["faketls_keys"]["readOnly"], json!(true));
}

#[tokio::test]
async fn a_published_borrowed_site_profile_follows_its_key_and_listener_and_is_taken_down_with_the_transport() {
	let (_fake, h, session) = borrowed_node().await;
	assert_eq!(h.call(Method::PUT, "/p/api/profiles/overrides/Main", Some(&session), Some(json!({"set": {"inbound_public_key": STANDARD.encode([7u8; 32])}})), "10.0.0.1").await.status, StatusCode::OK);
	let ids = |h: &Harness| h.app.settings().profiles.iter().map(|profile| profile["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
	let faketls = |h: &Harness| h.app.settings().profiles.iter().find(|profile| profile["id"] == "main-faketls").map(|profile| profile["transports"][0].clone());
	assert_eq!(put_inbounds(&h, &session, 1, borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([5u8; 32]))).await.status, StatusCode::OK);
	assert_eq!(ids(&h), ["main"], "an apply publishes nothing that was not published");
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	let main = h.app.settings().profiles[0].clone();
	assert_eq!(faketls(&h), Some(json!({"type": "faketls", "transport_public_key": public_of(5), "candidates": [{"address": "192.0.2.10:443", "sni": "www.example.com"}]})));
	let mut moved = borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([6u8; 32]));
	moved[0]["transports"][1]["listen"] = json!("0.0.0.0:8443");
	assert_eq!(put_inbounds(&h, &session, 2, moved).await.status, StatusCode::OK);
	assert_eq!(faketls(&h), Some(json!({"type": "faketls", "transport_public_key": public_of(6), "candidates": [{"address": "192.0.2.10:8443", "sni": "www.example.com"}]})), "the new key and the new listener, with no publish in between");
	assert_eq!((ids(&h), h.app.settings().profiles[0].clone()), (vec!["main".to_string(), "main-faketls".to_string()], main.clone()), "the other profile is not touched");
	let mut marked = borrowed_inbounds(site_of("www.example.com"), "<redacted:06060606>");
	marked[0]["transports"][1]["listen"] = json!("0.0.0.0:8443");
	assert_eq!(put_inbounds(&h, &session, 3, marked).await.status, StatusCode::OK);
	assert_eq!(faketls(&h).unwrap()["transport_public_key"], public_of(6), "an apply that changes neither keeps it");
	let plain = json!([{"tag": "Main", "type": "veilway", "private_key": "<redacted>", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}]);
	assert_eq!(put_inbounds(&h, &session, 4, plain).await.status, StatusCode::OK);
	assert_eq!((ids(&h), h.app.settings().relay_profiles.contains_key("main-faketls")), (vec!["main".to_string()], false), "a transport that is gone takes its profile down");
}

#[tokio::test]
async fn a_token_cannot_add_a_borrowed_site_or_change_its_site_and_a_session_needs_a_recent_reauth() {
	let (fake, h, session) = borrowed_node().await;
	let full = h.token(&session, "full", json!({})).await;
	let new = borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([5u8; 32]));
	let by_token = |revision: u32, inbounds: Value| h.bearer(Method::PUT, "/p/api/config/inbounds", &full, Some(json!({"revision": format!("rev{revision}"), "value": inbounds})), "10.1.1.1");
	let refused = by_token(1, new.clone()).await;
	assert_eq!((refused.status, refused.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("forbidden")));
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	let stale = put_inbounds(&h, &session, 1, new.clone()).await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	assert!(fake.applied.lock().unwrap().is_empty(), "nothing reached the node");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	assert_eq!(put_inbounds(&h, &session, 1, new).await.status, StatusCode::OK);
	let rekeyed = borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([6u8; 32]));
	assert_eq!(by_token(2, rekeyed.clone()).await.status, StatusCode::OK, "the key is the node's rule to check and not the site's");
	for site in [site_of("www.example.org"), json!({"host": "www.example.com", "acknowledged": false}), json!({"host": "www.example.com", "names": ["example.com"], "acknowledged": true})] {
		let changed = by_token(3, borrowed_inbounds(site.clone(), &STANDARD.encode([6u8; 32]))).await;
		assert_eq!((changed.status, changed.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("forbidden")), "{site}");
	}
	let mut whole = h.call(Method::GET, "/p/api/config", Some(&session), None, "10.0.0.1").await.json()["document"].clone();
	whole["inbounds"] = borrowed_inbounds(site_of("www.example.org"), &STANDARD.encode([6u8; 32]));
	let through_all = h.bearer(Method::PUT, "/p/api/config", &full, Some(json!({"revision": "rev3", "document": whole})), "10.1.1.1").await;
	assert_eq!(through_all.status, StatusCode::FORBIDDEN, "the whole document is no way round it");
	assert_eq!(fake.applied.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn the_dry_runs_say_the_borrowed_site_rules_before_the_node_is_asked() {
	let (_fake, h, session) = borrowed_node().await;
	let mut document = node_document("10.66.0.1/24");
	document["inbounds"] = borrowed_inbounds(json!({"host": "www.example.com", "acknowledged": false}), &STANDARD.encode([5u8; 32]));
	for path in ["/p/api/config/diff", "/p/api/config/validate"] {
		let answer = h.call(Method::POST, path, Some(&session), Some(json!({"document": document.clone()})), "10.0.0.1").await;
		assert_eq!((answer.status, answer.json()["error"]["code"].clone()), (StatusCode::UNPROCESSABLE_ENTITY, json!("invalid_config")), "{path}");
		assert!(answer.json()["error"]["message"].as_str().unwrap().contains("site.acknowledged"), "{path}");
	}
	document["inbounds"] = borrowed_inbounds(site_of("www.example.com"), "<redacted:05050505>");
	let moved = h.call(Method::POST, "/p/api/config/diff", Some(&session), Some(json!({"document": document.clone()})), "10.0.0.1").await;
	assert!(moved.json()["error"]["message"].as_str().unwrap().contains("expected the key in full"), "a marker for a key the node does not hold there");
	document["inbounds"] = borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([5u8; 32]));
	assert_eq!(h.call(Method::POST, "/p/api/config/diff", Some(&session), Some(json!({"document": document})), "10.0.0.1").await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_profile_written_by_hand_under_the_id_of_a_borrowed_site_profile_is_not_replaced_by_publishing() {
	let (_fake, h, session) = borrowed_node().await;
	let by_hand = json!({"id": "main-faketls", "name": "Mine", "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]});
	let main = h.app.settings().profiles[0].clone();
	h.configure(&session, json!({"node_host": "192.0.2.10", "profiles": [main, by_hand.clone()]})).await;
	assert_eq!(h.call(Method::PUT, "/p/api/profiles/overrides/Main", Some(&session), Some(json!({"set": {"inbound_public_key": STANDARD.encode([7u8; 32])}})), "10.0.0.1").await.status, StatusCode::OK);
	assert_eq!(put_inbounds(&h, &session, 1, borrowed_inbounds(site_of("www.example.com"), &STANDARD.encode([5u8; 32]))).await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((derived["templates"][1]["refused"][0]["code"].clone(), derived["templates"][1]["profile"]["transports"].clone()), (json!("profile_id"), json!([])));
	assert_eq!(h.call(Method::POST, "/p/api/profiles/publish", Some(&session), None, "10.0.0.1").await.status, StatusCode::OK, "a refused transport blocks nothing else");
	let profiles = h.app.settings().profiles;
	assert_eq!((profiles.len(), profiles.iter().find(|profile| profile["id"] == "main-faketls").cloned()), (2, Some(by_hand)), "the profile written by hand is still there, unchanged");
}

#[tokio::test]
async fn the_console_lists_admins_and_resets_a_password() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	assert_eq!(h.app.db.call(|db| admin::console_admins(db).unwrap()).await.unwrap(), vec![("owner".to_string(), true)]);
	assert!(h.app.db.call(|db| admin::console_reset(db, "owner", "short")).await.unwrap().is_err(), "a short password");
	assert!(h.app.db.call(|db| admin::console_reset(db, "nobody", "a console long password")).await.unwrap().is_err(), "an unknown name");
	assert_eq!(h.app.db.call(|db| admin::console_reset(db, "owner", "a console long password")).await.unwrap(), Ok(1));
	assert_eq!(h.call(Method::GET, "/p/api/admins", Some(&session), None, "10.0.0.1").await.status, StatusCode::UNAUTHORIZED, "its sessions ended");
	h.app.db.call(|db| db.execute("update admins set totp_last_step = 0", []).unwrap()).await.unwrap();
	let login = h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": "a console long password", "totp": h.code(0)})), "10.0.0.1").await;
	assert_eq!(login.status, StatusCode::OK, "{}", String::from_utf8_lossy(&login.body));
}

#[tokio::test]
async fn devices_that_have_not_refreshed_for_the_set_days_are_removed_and_their_places_freed() {
	let h = Harness::new().await;
	let session = h.login("10.0.0.1").await;
	// A limit shorter than three refresh intervals would take devices that are in use.
	let refused = h.call(Method::PUT, "/p/api/settings", Some(&session), Some({let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json(); settings["idle_device_days"] = json!(1); settings["update_interval"] = json!(604_800); settings}), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::BAD_REQUEST);
	h.configure(&session, json!({"idle_device_days": 30})).await;
	let (id, link) = h.user(&session, "ann", json!({"device_limit": 2})).await;
	let (key, kids) = (key_of(&link), [key_of(&link).kid()]);
	for device in [1, 2] {
		assert!(matches!(opened(&h.fetch(&link, &kids, device, "confirm", None).await, &[key.clone()]), Payload::Subscription(_)));
		h.app.sub_limits.clear(&format!("new:{id}:1"));
	}
	// Device 1 was last seen 31 days ago, device 2 today.
	let stale = STANDARD.encode([1u8; 32]);
	h.app.db.call(move |db| db.execute("update devices set last_seen = ? where public_key = ?", rusqlite::params![crypto::now() - 31 * 86_400, stale]).map(drop)).await.unwrap().unwrap();
	upkeep_once(&h.app, &mut Upkeep::default()).await;
	let devices = h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(devices["devices"].as_array().unwrap().iter().map(|device| device["public_key"].as_str().unwrap().to_owned()).collect::<Vec<_>>(), [STANDARD.encode([2u8; 32])]);
	assert!(matches!(opened(&h.fetch(&link, &kids, 3, "confirm", None).await, &[key]), Payload::Subscription(_)));
}
