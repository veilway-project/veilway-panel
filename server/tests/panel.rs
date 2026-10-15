use axum::{body::Body, extract::ConnectInfo, http::{header::{CONTENT_TYPE, COOKIE, HOST, ORIGIN, SET_COOKIE}, HeaderMap, Method, Request, StatusCode}, routing::{get, post}, Json, Router};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{net::SocketAddr, path::PathBuf, sync::{atomic::Ordering, Arc, Mutex}};
use tower::ServiceExt;
use veilway_panel::{app::{bucket, App, Limiter, Signing}, build, config::Config, crypto, openapi, router, upkeep_once, Upkeep};
use veilway_proto::subscription::{envelope::{self, Kid}, link::Link, payload::{self, Payload, Reason}, BODY_MAX};

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
		let answer = harness.call(Method::POST, "/p/api/setup", None, Some(json!({"token": token, "username": "owner", "password": PASSWORD})), "10.0.0.1").await;
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
async fn web_pages_load_without_a_session() {
	let h = Harness::new().await;
	let page = h.call(Method::GET, "/p/", None, None, "10.0.0.1").await;
	assert_eq!((page.status, page.headers.get("x-robots-tag").map(|value| value.to_str().unwrap().to_string())), (StatusCode::OK, Some("noindex".to_string())));
	assert_eq!(h.call(Method::GET, "/p", None, None, "10.0.0.1").await.status, StatusCode::OK);
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
