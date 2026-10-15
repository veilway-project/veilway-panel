//! The guard in front of every admin route: host and origin checks, rate limits, API tokens, sessions, CSRF and re-authentication.
use crate::{app::App, crypto::{self, now}, db::audit, http::{Ctx, Failure}};
use axum::{extract::{ConnectInfo, MatchedPath, Request, State}, http::{header::{AUTHORIZATION, COOKIE, HOST, ORIGIN, USER_AGENT}, Method, StatusCode}, middleware::Next, response::{IntoResponse, Response}};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, OptionalExtension};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

pub const COOKIE_NAME: &str = "vw_session";
pub const IDLE: i64 = 1800;
pub const ABSOLUTE: i64 = 12 * 3600;
pub const REAUTH: i64 = 300;
pub const TOKEN_PREFIX: &str = "vwp_";

/// What a route asks of its caller.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
	/// Nobody is logged in yet.
	Public,
	/// Any admin session, or any token that is allowed to read.
	Read,
	/// A session, or a token of scope users or full.
	Users,
	/// A session, or a token of scope full.
	Full,
	/// A session only: a token never reaches this.
	Admin,
	/// A session that logged in again in the last five minutes.
	AdminReauth,
}

impl Access {
	pub fn word(self) -> &'static str {
		match self {Access::Public => "public", Access::Read => "read", Access::Users => "users", Access::Full => "full", Access::Admin => "session", Access::AdminReauth => "session-reauth"}
	}
}

pub struct Guard {pub app: Arc<App>, pub access: HashMap<(Method, String), Access>}

fn source(app: &App, request: &Request) -> String {
	let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip().to_string()).unwrap_or_else(|| "unknown".into());
	if !app.cfg.trusted_proxies.contains(&peer) {return peer}
	request.headers().get("x-forwarded-for").and_then(|value| value.to_str().ok()).and_then(|value| value.rsplit(',').next()).map(|last| last.trim().to_string()).filter(|last| last.parse::<std::net::IpAddr>().is_ok()).unwrap_or(peer)
}

fn refuse(status: StatusCode, code: &'static str, message: &str) -> Response {Failure::new(status, code, message).into_response()}

pub fn cookie_value(request: &Request, name: &str) -> Option<String> {
	request.headers().get_all(COOKIE).iter().filter_map(|value| value.to_str().ok()).flat_map(|value| value.split(';')).find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('=')).map(str::to_string)
}

pub async fn guard(State(guard): State<Arc<Guard>>, mut request: Request, next: Next) -> Response {
	let app = &guard.app;
	let source = source(app, &request);
	let method = request.method().clone();
	let path = request.extensions().get::<MatchedPath>().map(|matched| matched.as_str().to_string()).unwrap_or_default();
	let access = guard.access.get(&(method.clone(), path.clone())).copied().unwrap_or(Access::Admin);
	let host = request.headers().get(HOST).and_then(|value| value.to_str().ok()).unwrap_or("").to_string();
	// A panel bound to localhost is a target for a page open in the admin's browser, through DNS rebinding or a cross-site request.
	if !app.cfg.allowed_hosts.is_empty() && !app.cfg.allowed_hosts.contains(&host) {return app.not_found()}
	let changes = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
	if changes {
		if let Some(origin) = request.headers().get(ORIGIN) {
			let authority = origin.to_str().ok().and_then(|origin| origin.split_once("://")).map(|(_, rest)| rest);
			if authority != Some(host.as_str()) {return refuse(StatusCode::FORBIDDEN, "bad_origin", "The request comes from another origin.")}
		}
	}
	if !app.limits.hit(&format!("src:{source}"), 600, 60) {return refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many requests from this address.")}
	let bearer = request.headers().get(AUTHORIZATION).and_then(|value| value.to_str().ok()).and_then(|value| value.strip_prefix("Bearer ")).map(str::to_string);
	let agent = request.headers().get(USER_AGENT).and_then(|value| value.to_str().ok()).unwrap_or("").chars().take(200).collect::<String>();
	if access == Access::Public {
		request.extensions_mut().insert(Ctx {actor: "anonymous".into(), admin_id: 0, token_id: None, session_id: None, source});
		request.extensions_mut().insert(Agent(agent));
		return next.run(request).await;
	}
	if let Some(bearer) = bearer {
		let hash = crypto::sha256(bearer.as_bytes());
		let found = app.db.lock().query_row("select t.id, t.name, t.scope, t.expires_at, t.sources, t.revoked_at, a.id from api_tokens t join admins a on a.id = t.admin_id where t.token_hash = ?", [hash.as_slice()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<i64>>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, i64>(6)?))).optional().unwrap_or(None);
		let Some((id, name, scope, expires, sources, revoked, admin_id)) = found else {return refuse(StatusCode::UNAUTHORIZED, "unauthorized", "The token is not valid.")};
		let allowed: Vec<String> = serde_json::from_str(&sources).unwrap_or_default();
		if revoked.is_some() || expires.is_some_and(|at| at <= now()) || (!allowed.is_empty() && !allowed.contains(&source)) {return refuse(StatusCode::UNAUTHORIZED, "unauthorized", "The token is not valid.")}
		if !app.limits.hit(&format!("tok:{id}"), 120, 60) {return refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "This token is over its limit.")}
		let permitted = match access {
			Access::Public | Access::Read => true,
			Access::Users => scope == "users" || scope == "full",
			Access::Full => scope == "full",
			Access::Admin | Access::AdminReauth => false,
		} && (scope != "read" || !changes);
		let actor = format!("token:{name}");
		if !permitted {
			audit(&app.db.lock(), &actor, &source, "api.denied", &format!("{method} {path}"), &format!("scope {scope}"));
			return refuse(StatusCode::FORBIDDEN, "forbidden", "This token's scope does not allow that.");
		}
		let _ = app.db.lock().execute("update api_tokens set last_used = ? where id = ?", params![now(), id]);
		request.extensions_mut().insert(Ctx {actor: actor.clone(), admin_id, token_id: Some(id), session_id: None, source: source.clone()});
		let response = next.run(request).await;
		audit(&app.db.lock(), &actor, &source, "api.call", &format!("{method} {path}"), &format!("status {}", response.status().as_u16()));
		return response;
	}
	let Some(cookie) = cookie_value(&request, COOKIE_NAME) else {return refuse(StatusCode::UNAUTHORIZED, "unauthorized", "Log in first.")};
	let Some(raw) = URL_SAFE_NO_PAD.decode(&cookie).ok().filter(|raw| raw.len() == 32) else {return refuse(StatusCode::UNAUTHORIZED, "unauthorized", "Log in first.")};
	let hash = crypto::sha256(&raw);
	let found = app.db.lock().query_row("select s.id, s.csrf, s.created, s.last_seen, s.reauth_at, a.id, a.username from sessions s join admins a on a.id = s.admin_id where s.token_hash = ?", [hash.as_slice()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?, row.get::<_, String>(6)?))).optional().unwrap_or(None);
	let Some((id, csrf, created, seen, reauth_at, admin_id, username)) = found else {return refuse(StatusCode::UNAUTHORIZED, "unauthorized", "Log in first.")};
	let at = now();
	if at - seen > IDLE || at - created > ABSOLUTE {
		let _ = app.db.lock().execute("delete from sessions where id = ?", [&id]);
		return refuse(StatusCode::UNAUTHORIZED, "unauthorized", "The session has expired.");
	}
	if changes && !request.headers().get("x-csrf-token").and_then(|value| value.to_str().ok()).is_some_and(|sent| crypto::equal(sent.as_bytes(), csrf.as_bytes())) {return refuse(StatusCode::FORBIDDEN, "csrf", "The CSRF token is missing or wrong.")}
	if access == Access::AdminReauth && at - reauth_at > REAUTH {return refuse(StatusCode::FORBIDDEN, "reauth_required", "Confirm your password and code again first.")}
	let _ = app.db.lock().execute("update sessions set last_seen = ? where id = ?", params![at, id]);
	request.extensions_mut().insert(Ctx {actor: format!("admin:{username}"), admin_id, token_id: None, session_id: Some(id), source});
	request.extensions_mut().insert(Agent(agent));
	next.run(request).await
}

#[derive(Clone)]
pub struct Agent(pub String);
