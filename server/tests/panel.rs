use axum::{body::Body, extract::{ConnectInfo, State}, http::{header::{CONTENT_TYPE, COOKIE, HOST, ORIGIN, SET_COOKIE}, HeaderMap, Method, Request, StatusCode}, routing::{get, post}, Json, Router};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{net::SocketAddr, path::PathBuf, sync::{atomic::Ordering, Arc, Mutex}};
use tower::ServiceExt;
use veilway_panel::{app::{bucket, App, Limiter, Signing}, build, config::{Config, TrustedMirror}, crypto, mirrors, openapi, router, upkeep_once, Upkeep};
use veilway_proto::subscription::{envelope::{self, Kid}, link::Link, payload::{self, Payload, Reason}, Tag, BODY_MAX};

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
		let mut cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), node_socket: socket.unwrap_or(dir.join("none.sock")), ..Config::default()};
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
	async fn send(&self, request: axum::http::request::Builder, body: Option<Value>, source: &str) -> Answer {
		let mut request = request.body(Body::from(body.map(|body| body.to_string()).unwrap_or_default())).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>(format!("{source}:5000").parse().unwrap()));
		let response = self.router.clone().oneshot(request).await.unwrap();
		let (parts, body) = response.into_parts();
		Answer {status: parts.status, headers: parts.headers, body: body.collect().await.unwrap().to_bytes().to_vec()}
	}
	fn code(&self, offset: i64) -> String {format!("{:06}", crypto::totp_at(&self.totp, (crypto::now() / 30 + offset) as u64))}
	async fn login(&self, source: &str) -> Session {
		// Time passing between two logins is simulated by forgetting the last used code.
		self.app.db.lock().execute("update admins set totp_last_step = 0", []).unwrap();
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
		let mut settings = json!({"provider_name": "Test Net", "endpoint_url": "https://panel.example.org/s", "endpoint_pins": [], "pool_v4": "10.66.0.0/24", "default_device_limit": 3, "show_links_once": false, "update_interval": 3600, "document_days": 14, "refresh_mirrors": [],
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
	async fn fetch(&self, link: &Link, kids: &[Kid], device: u8, op: &str, name: Option<&str>) -> Answer {
		let Link::Native(native) = link else {panic!("not native")};
		let mut body = json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": kids.iter().map(|kid| kid.text()).collect::<Vec<_>>(), "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": op});
		if let Some(name) = name {body["device_name"] = json!(name);}
		self.send(Request::builder().method(Method::POST).uri("/s").header(CONTENT_TYPE, "application/json").header(HOST, "panel.example.org"), Some(body), "198.51.100.7").await
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
	let cookie_line = h.app.db.lock().query_row("select count(*) from sessions", [], |row| row.get::<_, i64>(0)).unwrap();
	assert_eq!(cookie_line, 1);
	// Cookie attributes come from the login answer.
	h.app.db.lock().execute("update admins set totp_last_step = 0", []).unwrap();
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
	h.app.db.lock().execute("update admins set totp_last_step = 0", []).unwrap();
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
		for (method, path, body) in [(Method::POST, "/p/api/tokens", Some(json!({"name": "x", "scope": "full"}))), (Method::GET, "/p/api/tokens", None), (Method::GET, "/p/api/signing-keys", None), (Method::POST, "/p/api/signing-keys/rotate", None), (Method::GET, "/p/api/admins", None), (Method::GET, "/p/api/sessions", None), (Method::POST, "/p/api/users/1/subscription/show", None), (Method::POST, "/p/api/account/password", Some(json!({"new_password": "another long password"})))] {
			assert_eq!(h.bearer(method.clone(), path, token, body, src).await.status, StatusCode::FORBIDDEN, "{method} {path}");
		}
	}
	let bound = h.token(&session, "full", json!({"allowed_sources": ["192.0.2.1"]})).await;
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &bound, None, "192.0.2.1").await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &bound, None, "192.0.2.2").await.status, StatusCode::UNAUTHORIZED);
	h.app.db.lock().execute("update api_tokens set expires_at = 1 where name = 'read'", []).unwrap();
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &read, None, src).await.status, StatusCode::UNAUTHORIZED);
	let id = h.call(Method::GET, "/p/api/tokens", Some(&session), None, src).await.json()["tokens"].as_array().unwrap().iter().find(|token| token["name"] == "users").unwrap()["id"].as_i64().unwrap();
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/tokens/{id}"), Some(&session), None, src).await.status, StatusCode::OK);
	assert_eq!(h.bearer(Method::GET, "/p/api/users", &users, None, src).await.status, StatusCode::UNAUTHORIZED);
	// A token that is stored only as a hash: the plain text is nowhere in the database.
	let stored: i64 = h.app.db.lock().query_row("select count(*) from api_tokens where token_hash = ?", [crypto::sha256(full.as_bytes()).as_slice()], |row| row.get(0)).unwrap();
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
	let mut bodies: Vec<(Method, Body)> = vec![
		(Method::GET, Body::empty()), (Method::PUT, Body::from("{}")), (Method::POST, Body::empty()), (Method::POST, Body::from("not json")), (Method::POST, Body::from("[1,2]")), (Method::POST, Body::from("null")),
		(Method::POST, Body::from(valid_shape(&other_token).to_string())), (Method::POST, Body::from(valid_shape("short").to_string())), (Method::POST, Body::from("x".repeat(5000))),
		(Method::POST, Body::from(json!({"token": 5}).to_string())), (Method::POST, Body::from(json!({"v": 1}).to_string())),
	];
	let mut extra = valid_shape(&other_token);
	extra["extra"] = json!(1);
	bodies.push((Method::POST, Body::from(extra.to_string())));
	for (method, body) in bodies {
		let mut request = Request::builder().method(method.clone()).uri("/s").header(HOST, "panel.example.org").body(body).unwrap();
		request.extensions_mut().insert(ConnectInfo::<SocketAddr>("198.51.100.7:1".parse().unwrap()));
		let response = h.router.clone().oneshot(request).await.unwrap();
		let (parts, body) = response.into_parts();
		let answer = Answer {status: parts.status, headers: parts.headers, body: body.collect().await.unwrap().to_bytes().to_vec()};
		assert_eq!(answer.shape(), unknown.shape(), "{method} was not answered like an unknown path");
	}
	// A valid token with a malformed request is a signed refusal and not the 404.
	let mut bad = valid_shape(&token);
	bad["extra"] = json!(1);
	let answer = h.send(Request::builder().method(Method::POST).uri("/s").header(HOST, "panel.example.org"), Some(bad), "198.51.100.7").await;
	assert_eq!(refusal_of(&answer, &[key_of(&link)]), Reason::BadRequest);
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
		h.send(Request::builder().method(Method::POST).uri("/s").header(HOST, "panel.example.org"), Some(body), "198.51.100.7").await
	};
	assert_eq!(refusal_of(&mismatch, &[key]), Reason::DeviceMismatch);
	h.app.limits.clear(&format!("new:{id}:1"));
	// A second device fits, a third does not, and a pending place can be released.
	assert!(matches!(opened(&h.fetch(&link, &kids, 2, "fetch", None).await, &[key]), Payload::Subscription(_)));
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 3, "fetch", None).await, &[key]), Reason::DeviceLimit);
	assert_eq!(refusal_of(&h.fetch(&link, &kids, 2, "release", None).await, &[key]), Reason::Released);
	assert_eq!(h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json()["devices"].as_array().unwrap().len(), 1);
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
	h.app.db.lock().execute("update sessions set reauth_at = 0", []).unwrap();
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
	let (lookup, copy): (Vec<u8>, Vec<u8>) = h.app.db.lock().query_row("select token_lookup, token_copy from users where id = ?", [id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
	assert_eq!((lookup.len(), copy.len()), (32, 44));
	let keys = h.app.keys.as_ref().unwrap();
	assert!(keys.open_copy(&[0; 16], &copy).is_none());
	// "Show links once": copies go, and a link can no longer be shown.
	h.app.db.lock().execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap();
	h.configure(&session, json!({"show_links_once": true})).await;
	assert_eq!(h.call(Method::POST, &format!("/p/api/users/{id}/subscription/show"), Some(&session), None, "10.0.0.1").await.status, StatusCode::GONE);
	let audit = h.call(Method::GET, "/p/api/audit?limit=1000", Some(&session), None, "10.0.0.1").await;
	assert!(audit.body.windows(10).all(|window| window != b"veilway://"), "no link in the audit log");
	assert!(std::fs::metadata(&h.app.cfg.keys).map(|meta| std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777 == 0o600).unwrap());
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
	let cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), node_socket: dir.join("none.sock"), ..Config::default()};
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
	let detail: String = h.app.db.lock().query_row("select detail from audit where action = 'setup'", [], |row| row.get(0)).unwrap();
	assert_eq!(detail, "first admin created, terms 2026-10-16 accepted");
	let kept: String = h.app.db.lock().query_row("select value from settings where key = 'terms_accepted'", [], |row| row.get(0)).unwrap();
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
	let urls: Vec<&str> = document.support.iter().map(|support| support.url.as_str()).collect();
	assert_eq!(urls, ["https://terms.example.org/terms", "https://example.org/privacy"]);
	let persian = Tag::read("fa").unwrap();
	assert_eq!(document.support[0].label.pick(&[persian.clone()]), ("شرایط استفاده", Some(&persian)));
	assert_eq!(document.support[1].label.as_str(), "Privacy policy");
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
	let logged: i64 = h.app.db.lock().query_row("select count(*) from audit where source = '203.0.113.5' and action = 'login.failed'", [], |row| row.get(0)).unwrap();
	assert_eq!(logged, 1);
	let same_host = h.send(Request::builder().method(Method::POST).uri("/p/api/users").header(HOST, "panel.test").header(ORIGIN, "https://panel.test").header(COOKIE, &session.cookie).header("x-csrf-token", &session.csrf).header(CONTENT_TYPE, "application/json"), Some(json!({"name": "zed"})), "10.0.0.1").await;
	assert_eq!(same_host.status, StatusCode::OK);
}

#[tokio::test]
async fn failed_logins_name_only_accounts_that_exist() {
	let h = Harness::new().await;
	h.call(Method::POST, "/p/api/login", None, Some(json!({"username": "ghost", "password": "nope nope nope", "totp": "000000"})), "10.0.0.2").await;
	let names: Vec<String> = h.app.db.lock().prepare("select actor from audit where action = 'login.failed'").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
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
	assert_eq!(bucket("2001:db8:1:2::1"), bucket("2001:db8:1:2:ffff::9"));
	assert_ne!(bucket("2001:db8:1:2::1"), bucket("2001:db8:1:3::1"));
	assert_eq!(bucket("192.0.2.7"), "192.0.2.7");
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
				Json(json!({"revision": format!("rev{generation}"), "generation": generation, "document": fake.document.lock().unwrap().clone()}))
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
	for (section, wrong) in [("notices", json!({})), ("links", json!({})), ("dns", json!([])), ("log", json!([]))] {
		assert_eq!(h.bearer(Method::PUT, &format!("/p/api/config/{section}"), &full, Some(json!({"revision": "rev1", "value": wrong})), "10.1.1.1").await.status, StatusCode::BAD_REQUEST, "{section}");
	}
	let mut revision = 1;
	for (section, value) in [("notices", json!([{"severity": "warning", "text": "Maintenance on Friday from 02:00 UTC"}])), ("dns", json!({"servers": ["9.9.9.9:53"], "hijack": false})), ("log", json!({"level": "warn", "destinations": false})), ("links", json!([])), ("replay", json!({"cache": 4096}))] {
		let applied = h.call(Method::PUT, &format!("/p/api/config/{section}"), Some(&session), Some(json!({"revision": format!("rev{revision}"), "value": value})), "10.0.0.1").await;
		assert_eq!(applied.status, StatusCode::OK, "{section}: {}", String::from_utf8_lossy(&applied.body));
		revision += 1;
		assert_eq!(fake.applied.lock().unwrap().last().unwrap()[section], value, "{section}");
	}
	assert_eq!(h.call(Method::GET, "/p/api/config/notices", Some(&session), None, "10.0.0.1").await.json()["value"][0]["severity"], "warning");
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
async fn guarded_sections_need_a_recent_reauth_and_no_token_and_null_removes_optional_ones() {
	let (fake, socket) = Fake::start(node_document("10.66.0.1/24")).await;
	let h = Harness::with_socket(Some(socket)).await;
	let session = h.login("10.0.0.1").await;
	let full = h.token(&session, "full", json!({})).await;
	assert_eq!(h.bearer(Method::PUT, "/p/api/config/log", &full, Some(json!({"revision": "rev1", "value": {"level": "warn"}})), "10.1.1.1").await.status, StatusCode::FORBIDDEN, "a token never changes log");
	h.app.db.lock().execute("update sessions set reauth_at = 0", []).unwrap();
	let stale = h.call(Method::PUT, "/p/api/config/log", Some(&session), Some(json!({"revision": "rev1", "value": {"level": "warn"}})), "10.0.0.1").await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	h.app.db.lock().execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap();
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
	h.app.db.lock().execute("update sessions set reauth_at = 0", []).unwrap();
	assert_eq!(h.call(Method::PUT, "/p/api/config", Some(&session), Some(json!({"revision": "rev5", "document": document.clone()})), "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.lock().execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap();
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
	let refused = h.call(Method::POST, "/p/api/profiles/preview", Some(&session), Some(json!({"relays": [{"name": "edge", "address": "relay.example.org", "enabled": true}]})), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::BAD_REQUEST);
	let mut settings = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	settings["relays"] = relays;
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings.clone()), "10.0.0.1").await.status, StatusCode::OK);
	let derived = h.call(Method::GET, "/p/api/profiles/derived", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!(derived["templates"][0]["profile"]["transports"][1]["endpoints"], json!(["198.51.100.7:4000", "192.0.2.10:51821"]));
	settings["relays"][0]["address"] = json!("127.0.0.1");
	assert_eq!(h.call(Method::PUT, "/p/api/settings", Some(&session), Some(settings), "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
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
	assert_eq!(h.call(Method::GET, "/p/api/stats/usage?kind=nothing", Some(&session), None, "10.0.0.1").await.status, StatusCode::BAD_REQUEST);
	h.app.db.lock().execute("update usage_buckets set at = at - 2 * 86400 where res = 60", []).unwrap();
	veilway_panel::stats::prune(&h.app.db.lock(), crypto::now());
	let left: i64 = h.app.db.lock().query_row("select count(*) from usage_buckets where res = 60", [], |row| row.get(0)).unwrap();
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
	let restore = |file: String, passphrase: &'static str| json!({"file": file, "passphrase": passphrase});
	let wrong = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(file.clone(), "another long passphrase")), "10.0.0.1").await;
	assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{}", String::from_utf8_lossy(&wrong.body));
	let garbage = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(STANDARD.encode([1u8; 300]), "a long enough passphrase")), "10.0.0.1").await;
	assert_eq!(garbage.status, StatusCode::BAD_REQUEST);
	let newer = h.dir.join("newer.db");
	h.app.db.lock().execute("vacuum into ?", [newer.to_string_lossy().to_string()]).unwrap();
	rusqlite::Connection::open(&newer).unwrap().pragma_update(None, "user_version", 99).unwrap();
	let content = veilway_panel::backup::pack([&std::fs::read(&newer).unwrap(), &std::fs::read(&h.app.cfg.keys).unwrap(), &std::fs::read(&h.app.cfg.signing).unwrap()]);
	let refused = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(STANDARD.encode(veilway_panel::backup::seal("a long enough passphrase", &content).unwrap()), "a long enough passphrase")), "10.0.0.1").await;
	assert_eq!(refused.status, StatusCode::BAD_REQUEST);
	assert!(refused.json()["error"]["message"].as_str().unwrap().contains("newer"));
	assert!(h.app.db.lock().query_row("select count(*) from users where name = 'late'", [], |row| row.get::<_, i64>(0)).unwrap() == 1);
	let done = h.call(Method::POST, "/p/api/backup/restore", Some(&session), Some(restore(file, "a long enough passphrase")), "10.0.0.1").await;
	assert_eq!(done.status, StatusCode::OK, "{}", String::from_utf8_lossy(&done.body));
	tokio::time::timeout(std::time::Duration::from_secs(2), h.app.restart.notified()).await.expect("the server is told to restart");
	assert!(h.app.restoring.load(Ordering::SeqCst));
	assert_eq!(h.call(Method::POST, "/p/api/users", Some(&session), Some(json!({"name": "after"})), "10.0.0.1").await.status, StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(h.call(Method::GET, "/p/api/status", None, None, "10.0.0.1").await.status, StatusCode::OK);
	let saved = h.dir.join(done.json()["saved_as"].as_str().unwrap());
	assert!(saved.join("panel.db").exists() && saved.join("panel.keys").exists() && saved.join("signing.keys").exists());
	let reopened = build(h.app.cfg.clone()).unwrap();
	let names: Vec<String> = reopened.db.lock().prepare("select name from users").unwrap().query_map([], |row| row.get(0)).unwrap().map(Result::unwrap).collect();
	assert_eq!(names, ["alice"]);
	assert_eq!(reopened.db.lock().query_row("select count(*) from sessions", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
	assert!(reopened.db.lock().query_row("select count(*) from audit where action = 'backup.restore'", [], |row| row.get::<_, i64>(0)).unwrap() >= 1);
	assert!(reopened.keys.is_some());
	assert_eq!(reopened.db.lock().query_row("select count(*) from api_tokens where revoked_at is null", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
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
	h.app.update.lock().unwrap().found = Some(veilway_panel::updater::Found {version: "9.9.9".into(), notes_url: "https://github.com/veilway-project/veilway-panel/releases/tag/v9.9.9".into()});
	assert_eq!(h.bearer(Method::POST, "/p/api/update/request", &full, None, "10.1.1.1").await.status, StatusCode::FORBIDDEN);
	h.app.db.lock().execute("update sessions set reauth_at = 0", []).unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.lock().execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap();
	std::fs::write(h.app.cfg.update_request.with_extension("tmp"), b"stale").unwrap();
	let made = h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await;
	assert_eq!(made.status, StatusCode::OK, "{}", String::from_utf8_lossy(&made.body));
	assert_eq!(std::fs::read(&h.app.cfg.update_request).unwrap(), b"panel");
	assert!(!h.app.cfg.update_request.with_extension("tmp").exists());
	assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&h.app.cfg.update_request).unwrap().permissions()) & 0o777, 0o600);
	assert_eq!(h.call(Method::GET, "/p/api/update", Some(&session), None, "10.0.0.1").await.json()["updating"], true);
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT);
	let audit: i64 = h.app.db.lock().query_row("select count(*) from audit where action = 'update.request' and detail = 'from ' || ? || ' to 9.9.9'", [veilway_panel::updater::CURRENT], |row| row.get(0)).unwrap();
	assert_eq!(audit, 1);
	std::fs::remove_dir_all(folder).unwrap();
	h.app.update.lock().unwrap().requested_at = None;
	assert_eq!(h.call(Method::POST, "/p/api/update/request", Some(&session), None, "10.0.0.1").await.status, StatusCode::CONFLICT);
	assert_eq!(h.call(Method::GET, "/p/api/update", Some(&session), None, "10.0.0.1").await.json()["can_update"], false);
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
	h.app.db.lock().execute("vacuum into ?", [staged(&cfg.database).to_string_lossy().to_string()]).unwrap();
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
	h.app.db.lock().execute("insert into settings (key, value) values ('filler', randomblob(30000000))", []).unwrap();
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
	h.app.db.lock().execute("update sessions set reauth_at = 0", []).unwrap();
	let stale = h.call(Method::POST, &format!("/p/api/admins/{second_id}/reset"), Some(&session), Some(json!({"new_password": "a third long password"})), "10.0.0.1").await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	let token = {
		h.app.db.lock().execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap();
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
	assert_eq!(h.app.db.lock().query_row("select count(*) from sessions where admin_id = ?", [second_id], |row| row.get::<_, i64>(0)).unwrap(), 0);
	h.app.db.lock().execute("update audit set at = at - 100 where action = 'login'", []).unwrap();
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
	h.app.db.lock().execute("update sessions set reauth_at = 0", []).unwrap();
	let stale = h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8391, "new_server_key": true})), "10.0.0.1").await;
	assert_eq!((stale.status, stale.json()["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("reauth_required")));
	h.app.db.lock().execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap();
	*fake.document.lock().unwrap() = {let mut document = applied.clone(); document["invalid"] = json!(true); document};
	assert_eq!(h.call(Method::PATCH, &path("vless1"), Some(&session), Some(json!({"port": 9444, "cert": "/a", "key": "/b", "host": "other.example.org"})), "10.0.0.1").await.status, StatusCode::UNPROCESSABLE_ENTITY, "the node refuses");
	assert_eq!(h.call(Method::GET, "/p/api/xray", Some(&session), None, "10.0.0.1").await.json()["inbounds"][0]["own_host"], "edge.example.org", "a refused edit leaves the host as it was");
	let stored = |tag: &str| h.app.db.lock().query_row("select server_key from xray_inbounds where tag = ?", [tag], |row| row.get::<_, Vec<u8>>(0)).unwrap();
	let (kept, reached) = (stored("ss"), fake.applied.lock().unwrap().len());
	assert_eq!(h.call(Method::PATCH, &path("ss"), Some(&session), Some(json!({"port": 8392, "new_server_key": true})), "10.0.0.1").await.status, StatusCode::UNPROCESSABLE_ENTITY, "the node refuses a new key");
	assert_eq!((stored("ss") == kept, fake.applied.lock().unwrap().len() == reached), (true, true), "a refused new key is in neither the panel nor the node");
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
	let body = |device: u8| json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [kids[0].text()], "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": "fetch"});
	let header = |name: &str, address: &str, at: i64, nonce: &str, secret: &[u8]| format!("v1;{name};{address};{at};{nonce};{}", URL_SAFE_NO_PAD.encode(mirrors::mac(secret, name, address, at, nonce, body(1).to_string().as_bytes())));
	let send = |value: Option<String>, device: u8| {
		let mut request = Request::builder().method(Method::POST).uri("/s").header(CONTENT_TYPE, "application/json").header(HOST, "panel.example.org");
		if let Some(value) = value {request = request.header(mirrors::HEADER, value);}
		h.send(request, Some(body(device)), "198.51.100.7")
	};
	let unknown = h.send(Request::builder().method(Method::GET).uri("/nothing-here").header(HOST, "panel.example.org"), None, "198.51.100.7").await.shape();
	let (now, nonce) = (crypto::now(), |n: u8| URL_SAFE_NO_PAD.encode([n; 16]));
	let valid = header("relay", "203.0.113.9", now, &nonce(1), &secret);
	let answer = send(Some(valid.clone()), 1).await;
	assert_eq!(answer.headers.get(CONTENT_TYPE).unwrap(), "application/jose", "a document and a refusal are both signed answers");
	assert!(matches!(opened(&answer, &[key]), Payload::Subscription(_)));
	assert_eq!(h.app.limits.count("sub:203.0.113.9", 60), 1, "the forwarded address is the source");
	assert_eq!(h.app.limits.count("sub:198.51.100.7", 60), 0);
	assert_eq!(send(Some(valid), 1).await.shape(), unknown, "a replayed header");
	assert_eq!(send(Some(header("relay", "203.0.113.9", now - 120, &nonce(2), &secret)), 1).await.shape(), unknown, "a stale header");
	assert_eq!(send(Some(header("relay", "203.0.113.9", now + 120, &nonce(3), &secret)), 1).await.shape(), unknown, "a header from the future");
	assert_eq!(send(Some(header("other", "203.0.113.9", now, &nonce(4), &secret)), 1).await.shape(), unknown, "an unknown mirror");
	assert_eq!(send(Some(header("relay", "203.0.113.9", now, &nonce(5), &[1; 32])), 1).await.shape(), unknown, "a bad mac");
	assert_eq!(send(Some(header("relay", "not an address", now, &nonce(6), &secret)), 1).await.shape(), unknown, "a bad address");
	assert_eq!(send(Some("v1;relay".into()), 1).await.shape(), unknown, "a short header");
	assert_eq!(send(Some(header("relay", "203.0.113.9", now, &nonce(7), &secret)), 2).await.shape(), unknown, "a body the mirror did not sign");
	for _ in 0..120 {h.app.limits.hit("sub:203.0.113.9", 120, 60);}
	assert_eq!(send(Some(header("relay", "203.0.113.9", now, &nonce(8), &secret)), 1).await.shape(), unknown, "a source over its limit");
	h.app.limits.clear("sub:203.0.113.9");
	assert!(matches!(opened(&send(Some(header("relay", "203.0.113.9", now, &nonce(8), &secret)), 1).await, &[key]), Payload::Subscription(_)), "a refused header takes no nonce");
	assert!(matches!(opened(&send(None, 1).await, &[key]), Payload::Subscription(_)), "no header is an ordinary request");
	assert_eq!(h.app.limits.count("sub:198.51.100.7", 60), 1);
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
	let send = |value: String| h.send(Request::builder().method(Method::POST).uri("/s").header(CONTENT_TYPE, "application/json").header(HOST, "panel.example.org").header(mirrors::HEADER, value), Some(json!({})), "198.51.100.7");
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
	assert_eq!(off.app.db.lock().query_row("select count(*) from admins where length(totp_secret) = 0", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
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
	assert_eq!(on.app.db.lock().query_row("select count(*) from settings where key = 'two_step_off_at'", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
	let again = rebuilt(&on, "on").await;
	let count: i64 = again.app.db.lock().query_row("select count(*) from audit where action = 'panel.two_step'", [], |row| row.get(0)).unwrap();
	assert_eq!(count, 2, "an unchanged value writes nothing");
}

#[tokio::test]
async fn an_admin_without_a_secret_gets_one_at_start_and_the_password_alone_never_signs_in_while_on() {
	let off = Harness::with_config(None, |cfg| cfg.two_step = "off".into()).await;
	off.app.db.lock().execute("update admins set totp_secret = x'', totp_record = x'' where username = 'owner'", []).unwrap();
	let on = rebuilt(&off, "on").await;
	assert_eq!(on.app.db.lock().query_row("select count(*) from admins where length(totp_secret) = 0", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
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
		let id: i64 = h.app.db.lock().query_row("select id from admins where username = 'second'", [], |row| row.get(0)).unwrap();
		let reset = h.call(Method::POST, &format!("/p/api/admins/{id}/reset"), Some(&session), Some(json!({"new_password": PASSWORD})), "10.0.0.1").await;
		assert_eq!(reset.status, StatusCode::OK, "{two_step}");
		let changed = h.call(Method::POST, "/p/api/account/totp", Some(&session), None, "10.0.0.1").await;
		assert_eq!(changed.status, StatusCode::OK, "{two_step}");
		assert!(!changed.json()["totp_secret"].as_str().unwrap().is_empty(), "{two_step}");
		assert_eq!(h.app.db.lock().query_row("select count(*) from admins where length(totp_secret) = 0", [], |row| row.get::<_, i64>(0)).unwrap(), 0, "{two_step}");
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
	let app = build(Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), node_socket: dir.join("none.sock"), two_step: "off".into(), ..Config::default()}).unwrap();
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
	h.app.db.lock().execute("update admins set password_hash = ?", [hash]).unwrap();
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
