//! The Veilway panel server: admin login and API, users and devices, subscription links and the public endpoint.
pub mod admin;
pub mod app;
pub mod auth;
pub mod backup;
pub mod borrowed;
pub mod config;
pub mod crypto;
pub mod db;
pub mod endpoints;
pub mod gateway;
pub mod http;
pub mod links;
pub mod mirrors;
pub mod names;
pub mod nodecfg;
pub mod node;
pub mod nodes;
pub mod openapi;
pub mod routes;
pub mod stats;
pub mod statics;
pub mod subs;
pub mod updater;
pub mod usage;
pub mod upstreams;
pub mod users;
pub mod via;
pub mod web;
pub mod xray;

use app::{App, Limiter, NodeState, Settings, Signing, LOCAL};
use axum::{extract::{Request, State}, http::{StatusCode, header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS}, HeaderName, HeaderValue, Method}, middleware::{self, Next}, response::{IntoResponse, Response}, routing::{any, get}, Router};
use auth::{Access, Guard};
use config::Config;
use http::Failure;
use rusqlite::OptionalExtension;
use std::{collections::{HashMap, HashSet}, sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, RwLock}, time::Duration};

/// Opens the database and the key files. The first start with no accounts makes the keys and prints a setup token.
pub fn build(cfg: Config) -> Result<Arc<App>, String> {
	if backup::marker(&cfg).exists() {
		backup::complete(&cfg).map_err(|error| format!("a restore was cut short and could not be finished: {error}"))?;
		tracing::info!("finished a restore that was cut short");
	}
	let db = db::Db::open(&cfg.database).map_err(|error| format!("{}: {error}", cfg.database.display()))?;
	let (accounts, stored, admins) = db.blocking(|connection| -> rusqlite::Result<(i64, Option<String>, i64)> {
		let accounts = connection.query_row("select (select count(*) from users) + (select count(*) from admins)", [], |row| row.get(0))?;
		let stored = connection.query_row("select value from settings where key = 'settings'", [], |row| row.get::<_, String>(0)).optional()?;
		Ok((accounts, stored, connection.query_row("select count(*) from admins", [], |row| row.get(0))?))
	}).map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	// A row that does not parse is never turned into the defaults: the next save would write them over it and drop the profiles, endpoints and relays it held. The row is left as it is for the operator to read or restore.
	let mut settings: Settings = stored.map(|text| serde_json::from_str(&text).map_err(|error| format!("the stored settings in {} cannot be read ({error}); the row 'settings' of the table 'settings' is left untouched. Restore a backup, or fix the row by hand with the panel stopped", cfg.database.display()))).transpose()?.unwrap_or_default();
	settings.migrate();
	let keys = match (cfg.keys.exists(), accounts) {
		(true, _) => crypto::Keys::load(&cfg.keys).map_err(|error| tracing::error!("the key file {} cannot be used: {error}", cfg.keys.display())).ok(),
		(false, 0) => Some(crypto::Keys::create(&cfg.keys).map_err(|error| format!("{}: {error}", cfg.keys.display()))?),
		(false, _) => None,
	};
	let signing = Signing::load(&cfg.signing)?;
	let gateway = gateway::Hold::load(&cfg.gateway, &cfg.gateway_next, accounts == 0)?;
	if !gateway.loaded() && accounts > 0 {tracing::error!("no gateway key can be read ({}): the subscription endpoint answers every request as an unknown path", cfg.gateway.display())}
	let lookups = Arc::new(RwLock::new(HashMap::new()));
	let table = lookups.clone();
	let not_found = settings.not_found.clone();
	let setup_needed = admins == 0;
	let two_step = if cfg.two_step_on() {"on"} else {"off"};
	if !cfg.two_step_on() {tracing::warn!("with two-step sign-in off, a stored password cannot be checked for length: an admin whose password is shorter than 12 characters is found at their next sign-in and must change it before anything else works")}
	if !cfg.two_step_on() {tracing::warn!("two-step sign-in is OFF (two_step is \"off\" in the panel's config file): anyone with an admin password can sign in. Use this for demos only")}
	let keys = db.blocking(move |connection| {
		let last = connection.query_row("select value from settings where key = 'two_step'", [], |row| row.get::<_, String>(0)).unwrap_or_else(|_| "on".into());
		if last != two_step && two_step == "on" {
			let since: i64 = connection.query_row("select value from settings where key = 'two_step_off_at'", [], |row| row.get::<_, String>(0)).ok().and_then(|text| text.parse().ok()).unwrap_or(0);
			let ended = connection.execute("delete from sessions", []).unwrap_or(0);
			// Without a recorded time for going off, every token counts as made while it was off.
			let revoked = connection.execute("update api_tokens set revoked_at = ? where created >= ? and revoked_at is null", rusqlite::params![crypto::now(), since]).unwrap_or(0);
			let _ = connection.execute("delete from settings where key = 'two_step_off_at'", []);
			db::audit(connection, "panel", "config", "panel.two_step", "panel", &format!("on, {ended} sessions ended, {revoked} tokens revoked"));
		}
		if last != two_step && two_step == "off" {
			let _ = connection.execute("insert into settings (key, value) values ('two_step_off_at', ?) on conflict (key) do update set value = excluded.value", [crypto::now().to_string()]);
			db::audit(connection, "panel", "config", "panel.two_step", "panel", "off");
		}
		let _ = connection.execute("insert into settings (key, value) values ('two_step', ?) on conflict (key) do update set value = excluded.value", [two_step]);
		if let Some(keys) = &keys {admin::complete_secrets(connection, keys)}
		app::load_lookups(connection, &table);
		keys
	}).map_err(|error| error.to_string())?;
	let nodes: Vec<i64> = db.blocking(|connection| connection.prepare("select id from nodes order by id").and_then(|mut statement| statement.query_map([], |row| row.get(0))?.collect())).map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let token = setup_needed.then(|| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, crypto::random::<20>()));
	if let Some(token) = &token {println!("Setup token (one time): {token}\nPOST it with a username and password to {}/api/setup", cfg.prefix);}
	Ok(Arc::new(App {cfg, db, keys, signing: Mutex::new(signing), gateway: Mutex::new(gateway), lookups, refusals: Mutex::new(HashMap::new()), names: Default::default(), limits: Limiter::default(), sub_limits: Limiter::default(), setup_token: Mutex::new(token), node_states: Mutex::new(nodes.into_iter().map(|id| (id, Arc::new(NodeState {dirty: Arc::new(AtomicBool::new(true)), ..Default::default()}))).collect()), settings: Arc::new(RwLock::new(settings)), not_found_page: Mutex::new(not_found), live: Mutex::new(None), restart: tokio::sync::Notify::new(), restoring: AtomicBool::new(false), start_id: base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, crypto::random::<8>()), update: Mutex::new(Default::default()), pairing: Mutex::new(links::Pairing::default()), previews: Mutex::new(upstreams::Previews::default()), mirrors_seen: Default::default(), publishing: tokio::sync::Mutex::new(())}))
}

/// What the upkeep loop remembers between passes.
#[derive(Default)]
pub struct Upkeep {pub cleaned_at: i64, pub polled_at: i64, pub nodes: HashMap<i64, Retry>, pub read_at: HashMap<i64, i64>}

/// When a node whose push failed is tried again, and how long the wait before it was.
#[derive(Default)]
pub struct Retry {pub retry_at: i64, pub wait: i64}

/// Runs upkeep every few seconds. The clean-up is hourly; a failed node push is retried, waiting twice as long each time up to ten minutes, for each node on its own.
pub fn spawn_upkeep(app: Arc<App>) {
	tokio::spawn(async move {
		let mut state = Upkeep::default();
		loop {
			let pass = tokio::spawn({let app = app.clone(); async move {let mut state = state; upkeep_once(&app, &mut state).await; state}});
			state = match pass.await {Ok(state) => state, Err(error) => {tracing::error!("an upkeep pass failed and runs again in a few seconds: {error}"); Upkeep::default()}};
			tokio::time::sleep(Duration::from_secs(5)).await;
		}
	});
}

pub async fn upkeep_once(app: &Arc<App>, state: &mut Upkeep) {
	if app.restoring.load(Ordering::Relaxed) {return}
	let at = crypto::now();
	if at - state.cleaned_at >= 3600 {
		state.cleaned_at = at;
		let idle = app.settings().idle_device_days;
		match app.db.call(move |db| {
			let _ = db.execute("delete from sessions where last_seen < ? or created < ?", [at - auth::IDLE, at - auth::ABSOLUTE]);
			let _ = subs::expire_pending(db, at);
			stats::prune(db, at);
			subs::forget_idle(db, at, idle)
		}).await {
			Ok(Ok(gone)) if gone > 0 => {
				tracing::info!("{gone} devices that had not refreshed for {idle} days were removed");
				for node in app.nodes() {app.node(node).dirty.store(true, Ordering::Relaxed);}
			}
			Ok(Err(error)) => tracing::warn!("idle devices could not be removed: {error}"),
			Ok(_) => {}
			Err(_) => tracing::warn!("the database clean-up did not run: the database cannot take the call"),
		}
		if let Err(error) = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).prune() {tracing::error!("the signing keys could not be pruned: {error}")}
		let days = app.settings().gateway_retired_days;
		let (pruned, loaded, due) = {
			let mut hold = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
			(hold.prune(days), hold.loaded(), hold.active().is_some_and(|key| at - key.created > gateway::REMIND_AFTER))
		};
		match pruned {
			Ok(gone) if !gone.is_empty() => {
				tracing::info!("retired gateway keys destroyed: {gone:?}");
				let _ = app.db.call(move |db| for id in gone {let _ = db.execute("delete from gateway_use where key_id = ?", [id]);}).await;
			}
			Ok(_) => {}
			Err(error) => tracing::error!("the retired gateway keys could not be pruned: {error}"),
		}
		if !loaded {tracing::error!("no gateway key can be read: the subscription endpoint answers every request as an unknown path. Load the next key, or make new gateway keys in the panel")}
		if due {tracing::warn!("the active gateway key is more than 180 days old: load the next key")}
		nodecfg::rotate_keys(app, at).await;
		if app.keys.is_none() {tracing::error!("the key file is missing: the subscription endpoint answers every request as an unknown path and no secret can be opened")}
	}
	if at - state.polled_at >= stats::POLL {
		state.polled_at = at;
		stats::poll(app, LOCAL).await;
	}
	if statics::due(app, at).await {
		if let Err(error) = statics::round(app, at).await {tracing::warn!("static mirrors: no round was published: {error}")}
	}
	let up = if app.nodes().len() > 1 {nodes::up(app).await} else {HashSet::from([LOCAL.0])};
	usage::round(app, &mut state.read_at, &up).await;
	// Every node that is due is pushed to at once, so one that is slow or down holds nothing up. One that is not up keeps its flag and is pushed to when its link is up again.
	let mut pushes = tokio::task::JoinSet::new();
	for node in app.nodes().into_iter().filter(|node| up.contains(&node.0)) {
		let retry = state.nodes.entry(node.0).or_default();
		if app.node(node).dirty.load(Ordering::Relaxed) && at >= retry.retry_at {
			let held = app.clone();
			pushes.spawn(async move {(node, node::sync(&held, node).await.is_ok())});
		}
	}
	while let Some(done) = pushes.join_next().await {
		let Ok((node, worked)) = done else {continue};
		let retry = state.nodes.entry(node.0).or_default();
		retry.wait = if worked {0} else {(retry.wait * 2).clamp(5, 600)};
		retry.retry_at = at + retry.wait;
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
	Router::new().merge(admin).route(&app.cfg.sub_path, any(subs::endpoint)).route(&format!("{}/{{*endpoint}}", app.cfg.sub_path), any(subs::endpoint)).route("/robots.txt", get(web::robots)).fallback(routes::not_found).layer(middleware::from_fn_with_state(app.clone(), restoring)).with_state(app)
}
