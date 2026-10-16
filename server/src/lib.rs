//! The Veilway panel server: admin login and API, users and devices, subscription links and the public endpoint.
pub mod admin;
pub mod app;
pub mod auth;
pub mod backup;
pub mod config;
pub mod crypto;
pub mod db;
pub mod http;
pub mod links;
pub mod nodecfg;
pub mod node;
pub mod openapi;
pub mod routes;
pub mod stats;
pub mod subs;
pub mod updater;
pub mod users;
pub mod web;
pub mod xray;

use app::{App, Limiter, Settings, Signing};
use axum::{extract::{Request, State}, http::{StatusCode, header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS}, HeaderName, HeaderValue, Method}, middleware::{self, Next}, response::{IntoResponse, Response}, routing::{any, get}, Router};
use auth::{Access, Guard};
use config::Config;
use http::Failure;
use std::{collections::HashMap, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex}, time::Duration};

/// Opens the database and the key files. The first start with no accounts makes the keys and prints a setup token.
pub fn build(cfg: Config) -> Result<Arc<App>, String> {
	if backup::marker(&cfg).exists() {
		backup::complete(&cfg).map_err(|error| format!("a restore was cut short and could not be finished: {error}"))?;
		tracing::info!("finished a restore that was cut short");
	}
	let db = db::Db::open(&cfg.database).map_err(|error| format!("{}: {error}", cfg.database.display()))?;
	let accounts: i64 = db.lock().query_row("select (select count(*) from users) + (select count(*) from admins)", [], |row| row.get(0)).map_err(|error| error.to_string())?;
	let keys = match (cfg.keys.exists(), accounts) {
		(true, _) => crypto::Keys::load(&cfg.keys).map_err(|error| tracing::error!("the key file {} cannot be used: {error}", cfg.keys.display())).ok(),
		(false, 0) => Some(crypto::Keys::create(&cfg.keys).map_err(|error| format!("{}: {error}", cfg.keys.display()))?),
		(false, _) => None,
	};
	let signing = Signing::load(&cfg.signing)?;
	let not_found = db.lock().query_row("select value from settings where key = 'settings'", [], |row| row.get::<_, String>(0)).ok().and_then(|text| serde_json::from_str::<Settings>(&text).ok()).and_then(|settings| settings.not_found);
	let setup_needed = db.lock().query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0)).map_err(|error| error.to_string())? == 0;
	let two_step = if cfg.two_step_on() {"on"} else {"off"};
	if !cfg.two_step_on() {tracing::warn!("with two-step sign-in off, a stored password cannot be checked for length: an admin whose password is shorter than 12 characters is found at their next sign-in and must change it before anything else works")}
	if !cfg.two_step_on() {tracing::warn!("two-step sign-in is OFF (two_step is \"off\" in the panel's config file): anyone with an admin password can sign in. Use this for demos only")}
	{
		let db = db.lock();
		let last = db.query_row("select value from settings where key = 'two_step'", [], |row| row.get::<_, String>(0)).unwrap_or_else(|_| "on".into());
		if last != two_step {db::audit(&db, "panel", "config", "panel.two_step", "panel", two_step)}
		let _ = db.execute("insert into settings (key, value) values ('two_step', ?) on conflict (key) do update set value = excluded.value", [two_step]);
	}
	let token = setup_needed.then(|| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, crypto::random::<20>()));
	if let Some(token) = &token {println!("Setup token (one time): {token}\nPOST it with a username and password to {}/api/setup", cfg.prefix);}
	Ok(Arc::new(App {cfg, db, keys, signing: Mutex::new(signing), limits: Limiter::default(), setup_token: Mutex::new(token), node_lock: tokio::sync::Mutex::new(()), last_sync: Mutex::new(None), dirty: AtomicBool::new(false), not_found_page: Mutex::new(not_found), live: Mutex::new(None), restart: tokio::sync::Notify::new(), restoring: AtomicBool::new(false), start_id: base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, crypto::random::<8>()), update: Mutex::new(Default::default()), pairing: Mutex::new(links::Pairing::default())}))
}

/// What the upkeep loop remembers between passes.
#[derive(Default)]
pub struct Upkeep {pub cleaned_at: i64, pub retry_at: i64, pub wait: i64, pub polled_at: i64}

/// Runs upkeep every few seconds. The clean-up is hourly; a failed node push is retried, waiting twice as long each time up to ten minutes.
pub fn spawn_upkeep(app: Arc<App>) {
	tokio::spawn(async move {
		let mut state = Upkeep::default();
		loop {
			upkeep_once(&app, &mut state).await;
			tokio::time::sleep(Duration::from_secs(5)).await;
		}
	});
}

pub async fn upkeep_once(app: &Arc<App>, state: &mut Upkeep) {
	if app.restoring.load(Ordering::Relaxed) {return}
	let at = crypto::now();
	if at - state.cleaned_at >= 3600 {
		state.cleaned_at = at;
		let db = app.db.lock();
		let _ = db.execute("delete from sessions where last_seen < ? or created < ?", [at - auth::IDLE, at - auth::ABSOLUTE]);
		let _ = subs::expire_pending(&db, at);
		stats::prune(&db, at);
		drop(db);
		if let Err(error) = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).prune() {tracing::error!("the signing keys could not be pruned: {error}")}
		if app.keys.is_none() {tracing::error!("the key file is missing: the subscription endpoint answers every request as an unknown path and no secret can be opened")}
	}
	if at - state.polled_at >= stats::POLL {
		state.polled_at = at;
		stats::poll(app).await;
	}
	if app.dirty.load(Ordering::Relaxed) && at >= state.retry_at {
		state.wait = if node::sync(app).await.is_ok() {0} else {(state.wait * 2).clamp(5, 600)};
		state.retry_at = at + state.wait;
	}
}

/// While a restore swaps the files nothing may change, so anything but a read is refused.
async fn restoring(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
	if app.restoring.load(Ordering::Relaxed) && !matches!(*request.method(), Method::GET | Method::HEAD) {return Failure::new(StatusCode::SERVICE_UNAVAILABLE, "restoring", "The panel is restoring a backup and restarting. Try again in a moment.").into_response()}
	next.run(request).await
}

async fn headers(request: Request, next: Next) -> Response {
	let mut response = next.run(request).await;
	let map = response.headers_mut();
	map.entry(CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
	map.entry(CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
	map.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
	map.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
	map.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
	map.insert(HeaderName::from_static("x-robots-tag"), HeaderValue::from_static("noindex"));
	response
}

pub fn router(app: Arc<App>) -> Router {
	let mut schemas = schemars::generate::SchemaSettings::draft2020_12().into_generator();
	let (base, mut access, mut api) = (format!("{}/api", app.cfg.prefix), HashMap::new(), Router::new());
	for route in routes::routes(&mut schemas) {
		let path = format!("{base}{}", route.path);
		access.insert((route.method.clone(), path.clone()), route.access);
		api = api.route(&path, route.handler);
	}
	// The web app is served without a session, since its login page is what a logged-out browser needs.
	let pages = [app.cfg.prefix.clone(), format!("{}/", app.cfg.prefix), format!("{}/{{*path}}", app.cfg.prefix)];
	for page in &pages {for method in [Method::GET, Method::HEAD] {access.insert((method, page.clone()), Access::Public);}}
	let guard = Arc::new(Guard {app: app.clone(), access});
	let admin = api.route(&pages[0], get(web::slash)).route(&pages[1], get(web::index)).route(&pages[2], get(web::asset)).route_layer(middleware::from_fn_with_state(guard, auth::guard)).method_not_allowed_fallback(routes::not_found).layer(middleware::from_fn(headers));
	Router::new().merge(admin).route(&app.cfg.sub_path, any(subs::endpoint)).route("/robots.txt", get(web::robots)).fallback(routes::not_found).layer(middleware::from_fn_with_state(app.clone(), restoring)).with_state(app)
}
