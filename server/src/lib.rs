//! The Veilway panel server: admin login and API, users and devices, subscription links and the public endpoint.
pub mod admin;
pub mod app;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod http;
pub mod node;
pub mod openapi;
pub mod routes;
pub mod subs;
pub mod users;
pub mod web;

use app::{App, Limiter, Signing};
use axum::{extract::Request, http::{header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS}, HeaderValue}, middleware::{self, Next}, response::Response, routing::{any, get}, Router};
use auth::Guard;
use config::Config;
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};

/// Opens the database and the key files. The first start with no accounts makes the keys and prints a setup token.
pub fn build(cfg: Config) -> Result<Arc<App>, String> {
	let db = db::Db::open(&cfg.database).map_err(|error| format!("{}: {error}", cfg.database.display()))?;
	let accounts: i64 = db.lock().query_row("select (select count(*) from users) + (select count(*) from admins)", [], |row| row.get(0)).map_err(|error| error.to_string())?;
	let keys = match (cfg.keys.exists(), accounts) {
		(true, _) => crypto::Keys::load(&cfg.keys).map_err(|error| tracing::error!("the key file {} cannot be used: {error}", cfg.keys.display())).ok(),
		(false, 0) => Some(crypto::Keys::create(&cfg.keys).map_err(|error| format!("{}: {error}", cfg.keys.display()))?),
		(false, _) => None,
	};
	let signing = Signing::load(&cfg.signing)?;
	let setup_needed = db.lock().query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0)).map_err(|error| error.to_string())? == 0;
	let token = setup_needed.then(|| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, crypto::random::<20>()));
	if let Some(token) = &token {println!("Setup token (one time): {token}\nPOST it with a username and password to {}/api/setup", cfg.prefix);}
	Ok(Arc::new(App {cfg, db, keys, signing: Mutex::new(signing), limits: Limiter::default(), setup_token: Mutex::new(token), node_lock: tokio::sync::Mutex::new(()), last_sync: Mutex::new(None)}))
}

/// Ends old sessions and says so loudly, once an hour, when the panel has accounts and no key file.
pub fn spawn_upkeep(app: Arc<App>) {
	tokio::spawn(async move {
		loop {
			let _ = app.db.lock().execute("delete from sessions where last_seen < ? or created < ?", [crypto::now() - auth::IDLE, crypto::now() - auth::ABSOLUTE]);
			if app.keys.is_none() {tracing::error!("the key file is missing: the subscription endpoint answers every request as an unknown path and no secret can be opened")}
			tokio::time::sleep(Duration::from_secs(3600)).await;
		}
	});
}

async fn headers(request: Request, next: Next) -> Response {
	let mut response = next.run(request).await;
	let map = response.headers_mut();
	map.entry(CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
	map.entry(CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
	map.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
	map.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
	map.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
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
	let guard = Arc::new(Guard {app: app.clone(), access});
	let admin = api.route(&app.cfg.prefix, get(web::index)).route(&format!("{}/", app.cfg.prefix), get(web::index)).route(&format!("{}/{{*path}}", app.cfg.prefix), get(web::asset)).route_layer(middleware::from_fn_with_state(guard, auth::guard)).layer(middleware::from_fn(headers));
	Router::new().merge(admin).route(&app.cfg.sub_path, any(subs::endpoint)).fallback(routes::not_found).with_state(app)
}
