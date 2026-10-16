//! Static mirrors, the publisher's side: the keys a request leaves behind, what a round writes, the swap, refusals, the settings and the specification's vectors.
use axum::{body::Body, extract::ConnectInfo, http::{header::{CONTENT_TYPE, COOKIE, HOST, SET_COOKIE}, HeaderMap, Method, Request, StatusCode}, Router};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::{collections::HashSet, fs, net::SocketAddr, path::{Path, PathBuf}, sync::Arc};
use tower::ServiceExt;
use veilway_panel::{app::App, build, config::Config, crypto, router, statics};
use veilway_proto::{keys::MirrorKeys, subscription::{envelope, link::Link, mirror, payload::{self, Payload, Reason}, BODY_MAX}, NoRandom};

const PASSWORD: &str = "correct horse battery";
const BASE: &str = "https://files.example.net/vw/";
const RAW: &str = "https://raw.githubusercontent.com/owner/repo/main/f/";

struct Harness {app: Arc<App>, router: Router, totp: Vec<u8>, dir: PathBuf}

struct Session {cookie: String, csrf: String}

struct Answer {status: StatusCode, headers: HeaderMap, body: Vec<u8>}

impl Answer {
	fn json(&self) -> Value {serde_json::from_slice(&self.body).unwrap_or_else(|_| panic!("not JSON ({}): {}", self.status, String::from_utf8_lossy(&self.body)))}
}

impl Harness {
	async fn new() -> Self {
		let dir = std::env::temp_dir().join(format!("vwstatic-{}", URL_SAFE_NO_PAD.encode(crypto::random::<9>())));
		fs::create_dir_all(&dir).unwrap();
		let cfg = Config {prefix: "/p".into(), sub_path: "/s".into(), database: dir.join("panel.db"), keys: dir.join("panel.keys"), signing: dir.join("signing.keys"), node_socket: dir.join("none.sock"), ..Config::default()};
		let app = build(cfg).unwrap();
		let mut harness = Self {router: router(app.clone()), app, totp: Vec::new(), dir};
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
	async fn login(&self) -> Session {
		let code = format!("{:06}", crypto::totp_at(&self.totp, (crypto::now() / 30) as u64));
		let answer = self.call(Method::POST, "/p/api/login", None, Some(json!({"username": "owner", "password": PASSWORD, "totp": code})), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
		let cookie = answer.headers.get(SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
		Session {cookie, csrf: answer.json()["csrf"].as_str().unwrap().to_string()}
	}
	fn settings(extra: Value) -> Value {
		let mut settings = json!({"provider_name": "Test Net", "endpoint_url": "https://panel.example.org/s", "endpoint_pins": [], "pool_v4": "10.66.0.0/24", "default_device_limit": 3, "show_links_once": false, "update_interval": 3600, "document_days": 14, "refresh_mirrors": [],
			"profiles": [{"id": "main", "name": "Main", "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]}]});
		settings.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		settings
	}
	async fn put(&self, session: &Session, extra: Value) -> Answer {self.call(Method::PUT, "/p/api/settings", Some(session), Some(Self::settings(extra)), "10.0.0.1").await}
	async fn configure(&self, session: &Session, extra: Value) {
		let answer = self.put(session, extra).await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
	}
	async fn user(&self, session: &Session, name: &str) -> (i64, Link) {
		let answer = self.call(Method::POST, "/p/api/users", Some(session), Some(json!({"name": name})), "10.0.0.1").await;
		assert_eq!(answer.status, StatusCode::OK, "{}", String::from_utf8_lossy(&answer.body));
		let created = answer.json();
		(created["user"]["id"].as_i64().unwrap(), Link::parse(created["link"]["veilway"].as_str().unwrap()).unwrap())
	}
	async fn fetch(&self, link: &Link, device: u8, op: &str) -> Answer {
		let Link::Native(native) = link else {panic!("not native")};
		let kid = native.key().kid();
		let body = json!({"v": 1, "token": URL_SAFE_NO_PAD.encode(native.token().expose()), "kids": [kid.text()], "device_public_key": STANDARD.encode([device; 32]), "device_secret": URL_SAFE_NO_PAD.encode([device; 16]), "op": op});
		self.send(Request::builder().method(Method::POST).uri("/s").header(CONTENT_TYPE, "application/json").header(HOST, "panel.example.org"), Some(body), "198.51.100.7").await
	}
	fn forget_limits(&self, id: i64, device: u8) {self.app.limits.clear(&format!("dev:{id}:{}", STANDARD.encode([device; 32])));}
	fn root(&self, base: &str) -> PathBuf {self.dir.join("static").join(statics::label(base))}
	fn current(&self, base: &str) -> PathBuf {self.root(base).join("current")}
}

impl Drop for Harness {
	fn drop(&mut self) {let _ = fs::remove_dir_all(&self.dir);}
}

fn native(link: &Link) -> &veilway_proto::subscription::link::Native {if let Link::Native(native) = link {native} else {panic!("not native")}}

fn derived(link: &Link, device: u8) -> MirrorKeys {MirrorKeys::derive(&<[u8; 16]>::try_from(native(link).token().expose().as_ref()).unwrap(), &[device; 16], &[device; 32])}

fn read(directory: &Path, keys: &MirrorKeys, base: &str, epoch: u64, link: &Link) -> Payload {
	let body = fs::read(directory.join(mirror::file_name(keys, base, epoch))).unwrap();
	let envelope = mirror::open(keys, base, epoch, &body).unwrap();
	payload::parse(&envelope::verify(&envelope, &[native(link).key()], BODY_MAX).unwrap()).unwrap()
}

fn names(directory: &Path) -> HashSet<String> {fs::read_dir(directory).unwrap().flatten().map(|entry| entry.file_name().to_string_lossy().to_string()).collect()}

fn document(payload: Payload) -> Box<payload::Subscription> {match payload {Payload::Subscription(document) => document, Payload::Refusal(_) => panic!("a refusal, not a document")}}

async fn enrolled(h: &Harness, session: &Session, devices: &[u8]) -> (i64, Link) {
	h.configure(session, json!({"static_mirrors": [BASE, RAW]})).await;
	let (id, link) = h.user(session, "ann").await;
	for device in devices {
		h.app.limits.clear(&format!("new:{id}:1"));
		assert_eq!(h.fetch(&link, *device, "confirm").await.status, StatusCode::OK);
	}
	(id, link)
}

#[tokio::test]
async fn keys_are_stored_sealed_on_the_request_of_a_confirmed_device_and_of_no_other() {
	let h = Harness::new().await;
	let session = h.login().await;
	h.configure(&session, json!({})).await;
	let (id, link) = h.user(&session, "ann").await;
	let stored = |device: u8| h.app.db.call(move |db| db.query_row("select mirror_name, mirror_key, mirror_gen from devices where public_key = ?", [STANDARD.encode([device; 32])], |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, Option<i64>>(2)?))).unwrap());
	assert_eq!(h.fetch(&link, 1, "fetch").await.status, StatusCode::OK);
	assert_eq!(stored(1).await.unwrap(), (None, None, None), "a pending device has none");
	assert_eq!(h.fetch(&link, 1, "confirm").await.status, StatusCode::OK);
	let (Some(name), Some(key), Some(generation)) = stored(1).await.unwrap() else {panic!("a confirmed device has keys")};
	assert_eq!(generation, 1);
	let (record, keys) = (h.app.db.call(move |db| db.query_row("select record_id from users where id = ?", [id], |row| row.get::<_, Vec<u8>>(0)).unwrap()).await.unwrap(), h.app.keys.as_ref().unwrap());
	let record: [u8; 16] = record.try_into().unwrap();
	let derived = derived(&link, 1);
	let (expected_name, expected_key) = derived.expose();
	let open = |label: &[u8], device: u8, sealed: &[u8]| keys.open_secret(&record, [label, &[device; 32][..]].concat(), sealed);
	assert_eq!(open(b"mirror_name", 1, &name).as_deref(), Some(&expected_name[..]));
	assert_eq!(open(b"mirror_key", 1, &key).as_deref(), Some(&expected_key[..]));
	assert!(open(b"mirror_name", 2, &name).is_none() && open(b"mirror_key", 1, &name).is_none(), "a key moved to another device's row or another purpose does not open");
	assert!(!name.windows(32).any(|window| window == expected_name) && !key.windows(32).any(|window| window == expected_key), "nothing is stored in the clear");
	assert!(derived.id(5, BASE) != MirrorKeys::derive(&[9; 16], &[1; 16], &[1; 32]).id(5, BASE));
}

#[tokio::test]
async fn a_round_writes_a_sealed_file_per_confirmed_device_and_period_and_decoys_of_one_size() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (id, link) = enrolled(&h, &session, &[1, 2]).await;
	h.app.limits.clear(&format!("new:{id}:1"));
	assert_eq!(h.fetch(&link, 3, "fetch").await.status, StatusCode::OK, "a pending device");
	let at = crypto::now();
	statics::round(&h.app, at).await.unwrap();
	let epochs = mirror::live(at as u64);
	let (one, two) = (derived(&link, 1), derived(&link, 2));
	for base in [BASE, RAW] {
		let current = h.current(base);
		let found = names(&current);
		let real: HashSet<String> = epochs.iter().flat_map(|epoch| [mirror::file_name(&one, base, *epoch), mirror::file_name(&two, base, *epoch)]).collect();
		assert!(real.is_subset(&found), "the names are the specification's");
		let lengths: HashSet<u64> = found.iter().map(|name| fs::metadata(current.join(name)).unwrap().len()).collect();
		assert_eq!(lengths.len(), 1, "one size per folder, decoys included");
		let mut largest = 0;
		for epoch in &epochs {
			for (keys, device) in [(&one, 1u8), (&two, 2)] {
				let body = fs::read(current.join(mirror::file_name(keys, base, *epoch))).unwrap();
				largest = largest.max(mirror::open(keys, base, *epoch, &body).unwrap().len());
				let found = document(read(&current, keys, base, *epoch, &link));
				assert!(found.usage.is_none(), "a static document carries no usage");
				assert_eq!(found.static_mirrors.iter().map(|url| url.as_str().to_string()).collect::<Vec<_>>(), vec![BASE.to_string(), RAW.to_string()]);
				assert_eq!(found.devices.iter().filter(|other| other.this).count(), 1, "device {device}");
				assert!(found.devices.iter().any(|other| other.pending), "the document is what the endpoint would answer");
			}
		}
		assert_eq!(*lengths.iter().next().unwrap() as usize, mirror::size_for(largest).unwrap());
		let decoys = found.len() - real.len();
		assert!((32 * epochs.len()..=64 * epochs.len()).contains(&decoys), "{decoys} decoys for {} periods", epochs.len());
		assert!(found.difference(&real).all(|name| name.len() == 36 && name.ends_with(".bin") && name[..32].bytes().all(|byte| byte.is_ascii_hexdigit())) && found.iter().all(|name| name != "current"));
		assert!(!found.iter().any(|name| name.contains(&STANDARD.encode([3u8; 32]))));
	}
	assert!(names(&h.root(BASE)).contains("current"));
	let pending = derived(&link, 3);
	assert!(!h.current(BASE).join(mirror::file_name(&pending, BASE, epochs[0])).exists(), "a pending device has no file");
	assert!(id > 0);
}

#[tokio::test]
async fn a_round_is_put_in_place_in_one_step_and_every_file_is_written_again() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (_, link) = enrolled(&h, &session, &[1]).await;
	let at = mirror::start(3000) + 3 * 86_400;
	statics::round(&h.app, at as i64).await.unwrap();
	let root = h.root(BASE);
	let first = fs::read_link(root.join("current")).unwrap();
	let keys = derived(&link, 1);
	let file = mirror::file_name(&keys, BASE, 3000);
	let before = fs::read(root.join("current").join(&file)).unwrap();
	let decoy = names(&root.join("current")).into_iter().find(|name| *name != file).unwrap();
	let decoy_before = fs::read(root.join("current").join(&decoy)).unwrap();
	statics::round(&h.app, at as i64 + 21_600).await.unwrap();
	let second = fs::read_link(root.join("current")).unwrap();
	assert_ne!(first, second);
	assert!(root.join(&first).is_dir() && root.join(&second).is_dir(), "the last round stays for a copy that is under way");
	assert_ne!(before, fs::read(root.join("current").join(&file)).unwrap(), "same name, new salt, new bytes");
	assert_eq!(before.len(), fs::read(root.join("current").join(&file)).unwrap().len());
	if let Ok(now) = fs::read(root.join("current").join(&decoy)) {assert_ne!(decoy_before, now, "a decoy is written again too")}
	statics::round(&h.app, at as i64 + 43_200).await.unwrap();
	assert!(!root.join(&first).exists() && root.join(fs::read_link(root.join("current")).unwrap()).is_dir(), "old rounds go");
	assert!(!fs::read_dir(&root).unwrap().flatten().any(|entry| entry.file_name() == "current.new"));
}

#[tokio::test]
async fn a_disabled_or_expired_account_gets_the_signed_refusal_and_nothing_else() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (id, link) = enrolled(&h, &session, &[1]).await;
	let at = crypto::now();
	let epoch = mirror::epoch(at as u64);
	let (keys, current) = (derived(&link, 1), h.current(BASE));
	for (patch, reason) in [(json!({"enabled": false}), Reason::Disabled), (json!({"enabled": true, "expires_at": 1}), Reason::Expired)] {
		assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(patch), "10.0.0.1").await.status, StatusCode::OK);
		statics::round(&h.app, at).await.unwrap();
		match read(&current, &keys, BASE, epoch, &link) {Payload::Refusal(refusal) => assert_eq!(refusal.reason, reason), Payload::Subscription(_) => panic!("a document for an account that is off")}
	}
	assert_eq!(h.call(Method::PATCH, &format!("/p/api/users/{id}"), Some(&session), Some(json!({"expires_at": null})), "10.0.0.1").await.status, StatusCode::OK);
	statics::round(&h.app, at).await.unwrap();
	assert!(matches!(read(&current, &keys, BASE, epoch, &link), Payload::Subscription(_)));
}

#[tokio::test]
async fn a_reset_a_removed_device_and_a_removed_base_url_take_their_files_away_in_the_next_round() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (id, link) = enrolled(&h, &session, &[1, 2]).await;
	let at = crypto::now();
	let epoch = mirror::epoch(at as u64);
	statics::round(&h.app, at).await.unwrap();
	let (one, two) = (derived(&link, 1), derived(&link, 2));
	let exists = |keys: &MirrorKeys| h.current(BASE).join(mirror::file_name(keys, BASE, epoch)).exists();
	assert!(exists(&one) && exists(&two));
	let devices = h.call(Method::GET, &format!("/p/api/users/{id}/devices"), Some(&session), None, "10.0.0.1").await.json();
	let first = devices["devices"].as_array().unwrap().iter().find(|device| device["public_key"] == STANDARD.encode([2u8; 32])).unwrap()["id"].as_i64().unwrap();
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/users/{id}/devices/{first}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	assert!(exists(&two), "not at once");
	statics::round(&h.app, at + 1).await.unwrap();
	assert!(exists(&one) && !exists(&two));
	let reset = h.call(Method::POST, &format!("/p/api/users/{id}/subscription/reset"), Some(&session), Some(json!({"remove_devices": false})), "10.0.0.1").await;
	assert_eq!(reset.status, StatusCode::OK);
	let fresh = Link::parse(reset.json()["link"]["veilway"].as_str().unwrap()).unwrap();
	statics::round(&h.app, at + 2).await.unwrap();
	assert!(!exists(&one), "the old token's keys name nothing");
	h.forget_limits(id, 1);
	assert_eq!(h.fetch(&fresh, 1, "fetch").await.status, StatusCode::OK);
	statics::round(&h.app, at + 3).await.unwrap();
	assert!(h.current(BASE).join(mirror::file_name(&derived(&fresh, 1), BASE, epoch)).exists() && !exists(&one), "the new token's files appear after the device's first request with it");
	h.configure(&session, json!({"static_mirrors": [RAW]})).await;
	statics::round(&h.app, at + 4).await.unwrap();
	assert!(!h.root(BASE).exists() && h.current(RAW).exists());
	assert_eq!(h.call(Method::DELETE, &format!("/p/api/users/{id}"), Some(&session), None, "10.0.0.1").await.status, StatusCode::OK);
	statics::round(&h.app, at + 5).await.unwrap();
	assert!(!h.current(RAW).join(mirror::file_name(&derived(&fresh, 1), RAW, epoch)).exists());
}

#[tokio::test]
async fn nothing_is_published_or_deleted_without_the_key_file() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (_, _) = enrolled(&h, &session, &[1]).await;
	let at = crypto::now();
	statics::round(&h.app, at).await.unwrap();
	let before = (fs::read_link(h.current(BASE)).unwrap(), names(&h.root(BASE)));
	let cfg = h.app.cfg.clone();
	fs::remove_file(&cfg.keys).unwrap();
	let broken = build(cfg).unwrap();
	assert!(broken.keys.is_none());
	let error = statics::round(&broken, at + 1).await.unwrap_err();
	assert!(error.contains("key file"), "{error}");
	assert_eq!((fs::read_link(h.current(BASE)).unwrap(), names(&h.root(BASE))), before);
}

#[tokio::test]
async fn decoys_stay_in_their_range_and_are_born_and_die_apart() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (_, link) = enrolled(&h, &session, &[1, 2]).await;
	let at = (mirror::start(3000) + 3 * 86_400) as i64;
	let real: HashSet<String> = [derived(&link, 1), derived(&link, 2)].iter().map(|keys| mirror::file_name(keys, BASE, 3000)).collect();
	let (mut before, mut counts, mut born_alone, mut died_alone) = (HashSet::new(), Vec::new(), false, false);
	for round in 0..80 {
		statics::round(&h.app, at + round).await.unwrap();
		let now: HashSet<String> = names(&h.current(BASE)).difference(&real).cloned().collect();
		assert!((32..=64).contains(&now.len()), "{} decoys", now.len());
		if round > 0 {
			let (born, died) = (now.difference(&before).count(), before.difference(&now).count());
			assert!(born <= 1 && died <= 2, "{born} born, {died} died");
			born_alone |= born == 1 && died == 0;
			died_alone |= died >= 1 && born == 0;
		}
		counts.push(now.len());
		before = now;
	}
	assert!(born_alone && died_alone, "births and deaths are not paired: {counts:?}");
}

#[tokio::test]
async fn a_folder_grows_at_once_and_shrinks_only_after_eight_calm_rounds() {
	let h = Harness::new().await;
	let session = h.login().await;
	let big = |size: usize| json!({"static_mirrors": [BASE], "profiles": [{"id": "main", "name": "Main", "type": "veilway", "inbound_public_key": STANDARD.encode([7u8; 32]), "gateways": ["10.66.0.1"], "mtu": 1420, "transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}], "note": "x".repeat(size)}]});
	h.configure(&session, big(10_000)).await;
	let (_, link) = h.user(&session, "ann").await;
	assert_eq!(h.fetch(&link, 1, "confirm").await.status, StatusCode::OK);
	let at = crypto::now();
	let size = |round: i64| {
		let directory = h.current(BASE);
		let name = names(&directory).into_iter().next().unwrap();
		(round, fs::metadata(directory.join(name)).unwrap().len())
	};
	statics::round(&h.app, at).await.unwrap();
	assert_eq!(size(0).1, 36_979);
	h.configure(&session, big(10)).await;
	for round in 1..=8 {
		statics::round(&h.app, at + round).await.unwrap();
		assert_eq!(size(round), (round, 36_979), "the smaller size has held for {round} rounds");
	}
	statics::round(&h.app, at + 9).await.unwrap();
	assert_eq!(size(9), (9, 9_413));
	h.configure(&session, big(10_000)).await;
	statics::round(&h.app, at + 10).await.unwrap();
	assert_eq!(size(10), (10, 36_979), "a larger need moves every file in that round");
}

#[tokio::test]
async fn the_endpoint_and_the_publisher_never_sign_one_serial_twice_for_a_device() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (id, link) = enrolled(&h, &session, &[1]).await;
	let at = crypto::now();
	let (keys, current, epoch) = (derived(&link, 1), h.current(BASE), mirror::epoch(at as u64));
	let mut serials = Vec::new();
	for _ in 0..3 {
		h.forget_limits(id, 1);
		let answer = h.fetch(&link, 1, "fetch").await;
		serials.push(document(payload::parse(&envelope::verify(&answer.body, &[native(&link).key()], BODY_MAX).unwrap()).unwrap()).serial);
		statics::round(&h.app, at).await.unwrap();
		serials.push(document(read(&current, &keys, BASE, epoch, &link)).serial);
	}
	assert!(serials.windows(2).all(|pair| pair[0] < pair[1]), "{serials:?}");
	let live = mirror::live(at as u64);
	statics::round(&h.app, at).await.unwrap();
	let across: HashSet<u64> = live.iter().map(|epoch| document(read(&current, &keys, BASE, *epoch, &link)).serial).collect();
	assert_eq!(across.len(), 1, "one body, one serial, in every period's file of a round");
}

#[tokio::test]
async fn the_settings_refuse_what_a_base_url_may_not_be() {
	let h = Harness::new().await;
	let session = h.login().await;
	let refused = |extra: Value| async {let answer = h.put(&session, extra).await; (answer.status, answer.json()["error"]["message"].as_str().unwrap_or_default().to_string())};
	for bad in ["http://files.example.net/vw/", "https://files.example.net/vw", "https://192.0.2.7/vw/", "https://[2001:db8::1]/vw/", "https://user@files.example.net/vw/", "https://files.example.net/vw/?x=1", "https://files.example.net/vw/#x", "https://files.example.net/../vw/", "https://files.example.net/a%2fb/", "https://Files.Example.net/vw/", "https://panel.example.org/mirror/", "https://panel.example.org:443/mirror/", &format!("https://files.example.net/{}/", "a".repeat(220))] {
		assert_eq!(refused(json!({"static_mirrors": [bad]})).await.0, StatusCode::BAD_REQUEST, "{bad}");
	}
	assert_eq!(refused(json!({"static_mirrors": [BASE, BASE]})).await.0, StatusCode::BAD_REQUEST, "twice");
	assert_eq!(refused(json!({"static_mirrors": ["https://a.example.net/", "https://b.example.net/", "https://c.example.net/", "https://d.example.net/", "https://e.example.net/"]})).await.0, StatusCode::BAD_REQUEST, "five");
	assert_eq!(refused(json!({"static_mirrors": ["https://relay.example.net/x/"], "refresh_mirrors": ["https://relay.example.net/sub"]})).await.0, StatusCode::BAD_REQUEST, "the host of a relay mirror");
	assert_eq!(refused(json!({"static_mirrors": ["https://relay.example.net/x/"], "refresh_mirrors": [{"url": "https://relay.example.net/sub", "pins": []}]})).await.0, StatusCode::BAD_REQUEST, "the host of a relay mirror with pins");
	for hours in [0, 13] {assert_eq!(refused(json!({"static_interval": hours})).await.0, StatusCode::BAD_REQUEST, "{hours} hours")}
	assert_eq!(refused(json!({"static_mirrors": ["https://files.example.net:8443/vw/", "https://files.example.net/vw/"], "static_interval": 12})).await.0, StatusCode::OK, "another port is another host");
	let saved = h.call(Method::GET, "/p/api/settings", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((saved["static_interval"].clone(), saved["static_mirrors"].as_array().unwrap().len()), (json!(12), 2));
	assert_eq!(h.put(&session, json!({})).await.json()["static_interval"], 6, "the default interval is six hours");
}

#[tokio::test]
async fn the_status_names_the_folders_and_the_zip_needs_a_recent_confirmation() {
	let h = Harness::new().await;
	let session = h.login().await;
	let (_, _) = enrolled(&h, &session, &[1, 2]).await;
	let before = h.call(Method::GET, "/p/api/static", Some(&session), None, "10.0.0.1").await.json();
	assert_eq!((before["folders"].as_array().unwrap().len(), before["folders"][0]["files"].clone(), before["last_round"].clone()), (2, Value::Null, Value::Null));
	assert_eq!((before["folders"][0]["shared_host"].clone(), before["folders"][1]["shared_host"].clone()), (json!(false), json!(true)));
	let at = crypto::now();
	statics::round(&h.app, at).await.unwrap();
	let after = h.call(Method::GET, "/p/api/static", Some(&session), None, "10.0.0.1").await.json();
	let folder = &after["folders"][0];
	let found = names(&h.current(BASE));
	assert_eq!((folder["files"].as_u64().unwrap() as usize, folder["size"].clone(), after["last_round"].clone(), after["error"].clone()), (found.len(), json!(9413), json!(at), Value::Null));
	assert!(folder["sync"].as_array().unwrap().iter().all(|hint| hint["command"].as_str().unwrap().contains(&h.current(BASE).display().to_string())));
	assert!(!after.to_string().contains("decoy") && !after.to_string().contains("real"), "which files are real is never shown");
	let label = statics::label(BASE);
	h.app.db.call(|db| db.execute("update sessions set reauth_at = 0", []).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, &format!("/p/api/static/{label}/zip"), Some(&session), None, "10.0.0.1").await.json()["error"]["code"], "reauth_required");
	h.app.db.call(|db| db.execute("update sessions set reauth_at = ?", [crypto::now()]).unwrap()).await.unwrap();
	assert_eq!(h.call(Method::POST, "/p/api/static/nothing/zip", Some(&session), None, "10.0.0.1").await.status, StatusCode::NOT_FOUND);
	let zipped = h.call(Method::POST, &format!("/p/api/static/{label}/zip"), Some(&session), None, "10.0.0.1").await.json();
	let bytes = STANDARD.decode(zipped["file"].as_str().unwrap()).unwrap();
	assert_eq!(&bytes[..4], b"PK\x03\x04");
	assert_eq!(u16::from_le_bytes(bytes[bytes.len() - 14..bytes.len() - 12].try_into().unwrap()) as usize, found.len());
	assert_eq!(&bytes[bytes.len() - 22..bytes.len() - 18], b"PK\x05\x06");
}

#[tokio::test]
async fn a_round_is_due_when_the_interval_ends_a_base_url_comes_or_goes_and_a_failure_waits() {
	let h = Harness::new().await;
	let session = h.login().await;
	let at = crypto::now();
	assert!(!statics::due(&h.app, at).await, "nothing is listed");
	let (_, _) = enrolled(&h, &session, &[1]).await;
	assert!(statics::due(&h.app, at).await);
	statics::round(&h.app, at).await.unwrap();
	assert!(!statics::due(&h.app, at + 3600 * 5).await && statics::due(&h.app, at + 3600 * 6).await);
	h.configure(&session, json!({"static_mirrors": [BASE, RAW, "https://c.example.net/x/"]})).await;
	assert!(statics::due(&h.app, at + 3600).await, "a new base URL is written without waiting for the interval");
	h.configure(&session, json!({"static_mirrors": [BASE, RAW, "https://c.example.net/x/"], "profiles": []})).await;
	assert!(statics::round(&h.app, at + 3600).await.is_err(), "a document cannot be made without a profile");
	assert!(!statics::due(&h.app, at + 3600 + 10).await && statics::due(&h.app, at + 3600 + 301).await, "a failed round waits a few minutes");
	let shown = h.call(Method::GET, "/p/api/static", Some(&session), None, "10.0.0.1").await.json();
	assert!(shown["error"].as_str().unwrap().contains("profile"));
}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

#[test]
fn the_specifications_vectors_are_reproduced() {
	let keys = MirrorKeys::derive(&std::array::from_fn(|i| 1 + i as u8), &std::array::from_fn(|i| 0x21 + i as u8), &std::array::from_fn(|i| 0x41 + i as u8));
	let (name, key) = keys.expose();
	assert_eq!(hex(name), "e51da8f1ac5e86f8e82d38263a9be4d9e5475244df049ccc8d883f76fdb485c4");
	assert_eq!(hex(key), "b8ff922d98c7e74b613574b516f1b36aa7ed924c2ad698ddfb9661e52ab62278");
	let url = "https://files.example.net/vw/";
	assert_eq!(hex(&keys.id(2000, url)), "41061aa1ae12d729f9dd2f2d5f715408");
	assert_eq!(mirror::file_name(&keys, url, 2000), "41061aa1ae12d729f9dd2f2d5f715408.bin");
	assert_eq!(hex(&keys.id(2001, url)), "4e83a838a81e0da8089cde74f331fac2");
	assert_eq!(hex(&keys.id(2000, "https://files.example.net/vx/")), "95641ef2aeed852ee6b08ce9e5799da6");
	let mut fixed = |bytes: &mut [u8]| -> Result<(), NoRandom> {for (index, byte) in bytes.iter_mut().enumerate() {*byte = 0x80 + index as u8}; Ok(())};
	let file = mirror::seal(&keys, url, 2000, 9_413, b"veilway static mirror test vector", &mut fixed).unwrap();
	assert_eq!(hex(&file[..48]), "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f6698f3e5d7ee42a2fc67ad5a1154bbfb");
	assert_eq!(hex(&file[file.len() - 16..]), "f297f77add1830549d7d8d6715fe435e");
	assert_eq!(hex(&crypto::sha256(&file)), "863389c734cb351fa2456037c58716e7d40cc6cfd6be326f242a56f6fdb829a1");
}
