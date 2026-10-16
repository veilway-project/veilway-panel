//! Admin accounts: setup, login, TOTP, sessions, API tokens, the audit log, settings, signing keys and the node.
use crate::{app::{bucket, App, Settings, SigningEntry}, auth::{Agent, COOKIE_NAME, TOKEN_PREFIX}, crypto::{self, now}, db::audit, http::{json, ok, Body, Ctx, Failure}, node};
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use axum::{extract::{Path, Query, State}, http::{header::SET_COOKIE, HeaderName, HeaderValue, StatusCode}, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use data_encoding::BASE32_NOPAD;
use ipnet::{IpNet, Ipv4Net};
use rusqlite::{params, OptionalExtension};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

const LOGIN_PER_SOURCE: (usize, i64) = (10, 900);
/// Wrong tries count against an account for an hour. From the fifth on, the wait before the next answer doubles, up to 15 minutes.
const FAILS_WINDOW: i64 = 3600;
const DELAY_AFTER: usize = 5;
/// Argon2 is memory-hard, so the checks that run at once are capped.
static ARGON: Semaphore = Semaphore::const_new(4);

fn hash_blocking(password: &str) -> Result<String, Failure> {
	let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
	Argon2::default().hash_password(password.as_bytes(), &salt).map(|hash| hash.to_string()).map_err(Failure::internal)
}

async fn hash_password(password: String) -> Result<String, Failure> {
	let _permit = ARGON.acquire().await.map_err(Failure::internal)?;
	tokio::task::spawn_blocking(move || hash_blocking(&password)).await.map_err(Failure::internal)?
}

async fn check_password(hash: String, password: String) -> bool {
	let Ok(_permit) = ARGON.acquire().await else {return false};
	tokio::task::spawn_blocking(move || PasswordHash::new(&hash).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())).await.unwrap_or(false)
}

/// What a login that fails checks against, so an unknown name costs the same time as a known one.
fn dummy() -> &'static str {
	static DUMMY: OnceLock<String> = OnceLock::new();
	DUMMY.get_or_init(|| hash_blocking("not a password anyone has").unwrap_or_default())
}

fn password_ok(password: &str) -> Result<(), Failure> {
	if password.chars().count() < 12 || password.len() > 256 {Err(Failure::bad("A password is 12 to 256 characters."))} else {Ok(())}
}

fn username_ok(name: &str) -> Result<(), Failure> {
	if (3..=32).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)) {Ok(())} else {Err(Failure::bad("A username is 3 to 32 characters of a-z, 0-9, dot, dash and underscore."))}
}

fn wrong() -> Failure {Failure::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "Wrong username, password or code.")}

#[derive(Serialize, JsonSchema)]
pub struct Status {pub setup_needed: bool, /// Different on every start of the server.
	pub start_id: String}

pub async fn status(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	ok(&Status {setup_needed: app.db.lock().query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0))? == 0, start_id: app.start_id.clone()})
}

#[derive(Serialize, JsonSchema)]
pub struct TotpEnrolled {
	/// Base32, for an authenticator app. Shown once.
	pub totp_secret: String, pub otpauth: String,
}

fn new_totp(app: &App, name: &str) -> Result<(Vec<u8>, Vec<u8>, TotpEnrolled), Failure> {
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	let (secret, record) = (crypto::random::<20>(), crypto::random::<16>());
	let text = BASE32_NOPAD.encode(&secret);
	Ok((keys.seal_secret(&record, "totp", &secret), record.to_vec(), TotpEnrolled {otpauth: format!("otpauth://totp/Veilway:{name}?secret={text}&issuer=Veilway"), totp_secret: text}))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Setup {pub token: String, pub username: String, pub password: String}

pub async fn setup(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Setup>) -> Result<Response, Failure> {
	if !app.limits.hit(&format!("setup:{}", bucket(&ctx.source)), 5, 900) {return Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many tries."))}
	let expected = app.setup_token.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
	if !expected.is_some_and(|expected| crypto::equal(expected.as_bytes(), input.token.as_bytes())) {return Err(Failure::new(StatusCode::FORBIDDEN, "bad_setup_token", "The setup token is wrong, or setup is done."))}
	username_ok(&input.username)?;
	password_ok(&input.password)?;
	let hash = hash_password(input.password.clone()).await?;
	let (sealed, record, shown) = new_totp(&app, &input.username)?;
	{
		let db = app.db.lock();
		if db.query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0))? > 0 {return Err(Failure::conflict("Setup is done."))}
		db.execute("insert into admins (username, password_hash, totp_secret, totp_record, created) values (?, ?, ?, ?, ?)", params![input.username, hash, sealed, record, now()])?;
		audit(&db, &format!("admin:{}", input.username), &ctx.source, "setup", "admin", "first admin created");
	}
	*app.setup_token.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
	ok(&shown)
}

struct AdminRow {id: i64, username: String, hash: String, secret: Vec<u8>, record: Vec<u8>, last_step: i64}

fn admin_by(app: &App, column: &str, value: rusqlite::types::Value) -> Option<AdminRow> {
	app.db.lock().query_row(&format!("select id, username, password_hash, totp_secret, totp_record, totp_last_step from admins where {column} = ?"), [value], |row| Ok(AdminRow {id: row.get(0)?, username: row.get(1)?, hash: row.get(2)?, secret: row.get(3)?, record: row.get(4)?, last_step: row.get(5)?})).optional().unwrap_or(None)
}

/// Seconds an account still waits after its wrong tries. None before the fifth in an hour, then 1, 2, 4 and so on up to 15 minutes.
fn wait_left(app: &App, name: &str) -> i64 {
	let key = format!("acct:{name}");
	let fails = app.limits.count(&key, FAILS_WINDOW);
	match app.limits.last(&key) {
		Some(last) if fails >= DELAY_AFTER => ((1_i64 << (fails - DELAY_AFTER).min(10)).min(900) - (now() - last)).max(0),
		_ => 0,
	}
}

/// The actor an audit line names for a login. The typed name is written only when that account exists, so the log holds no guesses.
fn actor_of(app: &App, name: &str) -> String {
	let known = app.db.lock().query_row("select 1 from admins where username = ?", [name], |_| Ok(())).is_ok();
	if known {format!("admin:{name}")} else {"unknown".into()}
}

/// Password and a TOTP code that was not used before. A wrong try counts against the account, and while the account is waiting a wrong try gets a "wait" answer. A right one passes whatever the wait.
async fn verify(app: &App, admin: Option<AdminRow>, name: &str, password: &str, code: &str) -> Result<AdminRow, Failure> {
	let waiting = wait_left(app, name) > 0;
	let good = check_password(admin.as_ref().map_or_else(|| dummy().to_string(), |admin| admin.hash.clone()), password.to_string()).await;
	let step = admin.as_ref().and_then(|admin| {
		let record: [u8; 16] = admin.record.clone().try_into().ok()?;
		let secret = app.keys.as_ref()?.open_secret(&record, "totp", &admin.secret)?;
		crypto::totp_check(&secret, code, now()).filter(|step| *step > admin.last_step)
	});
	// The step is claimed in the same statement that checks it, so two requests with one code cannot both pass.
	let claimed = match (good, step, &admin) {
		(true, Some(step), Some(admin)) => app.db.lock().execute("update admins set totp_last_step = ? where id = ? and totp_last_step < ?", params![step, admin.id, step]).unwrap_or(0) == 1,
		_ => false,
	};
	match admin {
		Some(admin) if claimed => {
			app.limits.clear(&format!("acct:{name}"));
			Ok(admin)
		}
		_ => {
			app.limits.hit(&format!("acct:{name}"), usize::MAX, FAILS_WINDOW);
			if waiting {Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many tries. Wait a while."))} else {Err(wrong())}
		}
	}
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Login {pub username: String, pub password: String, pub totp: String}

#[derive(Serialize, JsonSchema)]
pub struct LoggedIn {pub username: String, pub session_id: String, pub csrf: String}

pub async fn login(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Extension(agent): Extension<Agent>, Body(input): Body<Login>) -> Result<Response, Failure> {
	if !app.limits.hit(&format!("login:{}", bucket(&ctx.source)), LOGIN_PER_SOURCE.0, LOGIN_PER_SOURCE.1) {
		let actor = actor_of(&app, &input.username);
		audit(&app.db.lock(), &actor, &ctx.source, "login.limited", "admin", "");
		return Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many tries. Wait a while."));
	}
	let admin = admin_by(&app, "username", input.username.clone().into());
	let admin = match verify(&app, admin, &input.username, &input.password, &input.totp).await {
		Ok(admin) => admin,
		Err(error) => {
			let actor = actor_of(&app, &input.username);
			audit(&app.db.lock(), &actor, &ctx.source, "login.failed", "admin", "");
			return Err(error);
		}
	};
	let (raw, id, csrf) = (crypto::random::<32>(), hex(&crypto::random::<8>()), URL_SAFE_NO_PAD.encode(crypto::random::<32>()));
	{
		let db = app.db.lock();
		db.execute("insert into sessions (id, admin_id, token_hash, csrf, created, last_seen, reauth_at, source, agent) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", params![id, admin.id, crypto::sha256(&raw).as_slice(), csrf, now(), now(), now(), ctx.source, agent.0])?;
		audit(&db, &format!("admin:{}", admin.username), &ctx.source, "login", "admin", &id);
	}
	let cookie = format!("{COOKIE_NAME}={}; Path={}; HttpOnly; SameSite=Strict; Max-Age={}{}", URL_SAFE_NO_PAD.encode(raw), app.cfg.prefix, crate::auth::ABSOLUTE, if app.cfg.secure_cookies {"; Secure"} else {""});
	let mut response = json(StatusCode::OK, &LoggedIn {username: admin.username, session_id: id, csrf});
	response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie).map_err(Failure::internal)?);
	Ok(response)
}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

#[derive(Serialize, JsonSchema)]
pub struct Done {pub ok: bool}

pub async fn logout(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	if let Some(id) = &ctx.session_id {
		let db = app.db.lock();
		db.execute("delete from sessions where id = ?", [id])?;
		audit(&db, &ctx.actor, &ctx.source, "logout", "admin", id);
	}
	let mut response = json(StatusCode::OK, &Done {ok: true});
	response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&format!("{COOKIE_NAME}=; Path={}; HttpOnly; SameSite=Strict; Max-Age=0", app.cfg.prefix)).map_err(Failure::internal)?);
	Ok(response)
}

#[derive(Serialize, JsonSchema)]
pub struct SessionInfo {pub username: String, pub session_id: String, pub csrf: String, pub reauth_until: i64}

pub async fn session(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let id = ctx.session_id.ok_or_else(|| Failure::bad("This call is for a login session."))?;
	let (csrf, reauth): (String, i64) = app.db.lock().query_row("select csrf, reauth_at from sessions where id = ?", [&id], |row| Ok((row.get(0)?, row.get(1)?)))?;
	ok(&SessionInfo {username: ctx.actor.trim_start_matches("admin:").to_string(), session_id: id, csrf, reauth_until: reauth + crate::auth::REAUTH})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reauth {pub password: String, pub totp: String}

pub async fn reauth(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Reauth>) -> Result<Response, Failure> {
	let name = ctx.actor.trim_start_matches("admin:").to_string();
	verify(&app, admin_by(&app, "id", ctx.admin_id.into()), &name, &input.password, &input.totp).await?;
	let id = ctx.session_id.clone().ok_or_else(|| Failure::bad("This call is for a login session."))?;
	let db = app.db.lock();
	db.execute("update sessions set reauth_at = ? where id = ?", params![now(), id])?;
	audit(&db, &ctx.actor, &ctx.source, "reauth", "admin", &id);
	ok(&Done {ok: true})
}

#[derive(Serialize, JsonSchema)]
pub struct SessionRow {pub id: String, pub created: i64, pub last_seen: i64, pub source: String, pub agent: String, pub current: bool}

#[derive(Serialize, JsonSchema)]
pub struct SessionsOut {pub sessions: Vec<SessionRow>}

pub async fn sessions(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let db = app.db.lock();
	let mut statement = db.prepare("select id, created, last_seen, source, agent from sessions where admin_id = ? order by created desc")?;
	let sessions = statement.query_map([ctx.admin_id], |row| Ok(SessionRow {id: row.get(0)?, created: row.get(1)?, last_seen: row.get(2)?, source: row.get(3)?, agent: row.get(4)?, current: false}))?.collect::<Result<Vec<_>, _>>()?;
	ok(&SessionsOut {sessions: sessions.into_iter().map(|session| SessionRow {current: ctx.session_id.as_deref() == Some(session.id.as_str()), ..session}).collect()})
}

pub async fn revoke_session(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>) -> Result<Response, Failure> {
	let db = app.db.lock();
	if db.execute("delete from sessions where id = ? and admin_id = ?", params![id, ctx.admin_id])? == 0 {return Err(Failure::missing("session"))}
	audit(&db, &ctx.actor, &ctx.source, "session.revoke", "session", &id);
	ok(&Done {ok: true})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewPassword {pub new_password: String}

/// Every other session of the admin ends when the password or the TOTP secret changes.
pub async fn change_password(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<NewPassword>) -> Result<Response, Failure> {
	password_ok(&input.new_password)?;
	let hash = hash_password(input.new_password.clone()).await?;
	let db = app.db.lock();
	db.execute("update admins set password_hash = ? where id = ?", params![hash, ctx.admin_id])?;
	db.execute("delete from sessions where admin_id = ? and id != ?", params![ctx.admin_id, ctx.session_id.clone().unwrap_or_default()])?;
	audit(&db, &ctx.actor, &ctx.source, "account.password", "admin", "");
	ok(&Done {ok: true})
}

pub async fn change_totp(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let (sealed, record, shown) = new_totp(&app, ctx.actor.trim_start_matches("admin:"))?;
	let db = app.db.lock();
	db.execute("update admins set totp_secret = ?, totp_record = ?, totp_last_step = 0 where id = ?", params![sealed, record, ctx.admin_id])?;
	db.execute("delete from sessions where admin_id = ? and id != ?", params![ctx.admin_id, ctx.session_id.clone().unwrap_or_default()])?;
	audit(&db, &ctx.actor, &ctx.source, "account.totp", "admin", "");
	ok(&shown)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewAdmin {pub username: String, pub password: String}

pub async fn create_admin(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<NewAdmin>) -> Result<Response, Failure> {
	username_ok(&input.username)?;
	password_ok(&input.password)?;
	let hash = hash_password(input.password.clone()).await?;
	let (sealed, record, shown) = new_totp(&app, &input.username)?;
	let db = app.db.lock();
	db.execute("insert into admins (username, password_hash, totp_secret, totp_record, created) values (?, ?, ?, ?, ?)", params![input.username, hash, sealed, record, now()])?;
	audit(&db, &ctx.actor, &ctx.source, "admin.create", &input.username, "");
	ok(&shown)
}

#[derive(Serialize, JsonSchema)]
pub struct AdminRowOut {pub id: i64, pub username: String, pub created: i64}

#[derive(Serialize, JsonSchema)]
pub struct AdminsOut {pub admins: Vec<AdminRowOut>}

pub async fn admins(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let db = app.db.lock();
	let mut statement = db.prepare("select id, username, created from admins order by id")?;
	let admins = statement.query_map([], |row| Ok(AdminRowOut {id: row.get(0)?, username: row.get(1)?, created: row.get(2)?}))?.collect::<Result<_, _>>()?;
	ok(&AdminsOut {admins})
}

pub async fn remove_admin(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	if id == ctx.admin_id {return Err(Failure::conflict("An admin cannot remove themselves."))}
	let db = app.db.lock();
	if db.execute("delete from admins where id = ?", [id])? == 0 {return Err(Failure::missing("admin"))}
	audit(&db, &ctx.actor, &ctx.source, "admin.remove", &format!("admin:{id}"), "");
	ok(&Done {ok: true})
}

#[derive(Deserialize, JsonSchema)]
pub struct AuditQuery {pub limit: Option<i64>, pub before: Option<i64>}

#[derive(Serialize, JsonSchema)]
pub struct AuditRow {pub id: i64, pub at: i64, pub actor: String, pub source: String, pub action: String, pub target: String, pub detail: String}

#[derive(Serialize, JsonSchema)]
pub struct AuditOut {pub entries: Vec<AuditRow>}

pub async fn audit_log(State(app): State<Arc<App>>, Query(query): Query<AuditQuery>) -> Result<Response, Failure> {
	let db = app.db.lock();
	let mut statement = db.prepare("select id, at, actor, source, action, target, detail from audit where id < ? order by id desc limit ?")?;
	let entries = statement.query_map(params![query.before.unwrap_or(i64::MAX), query.limit.unwrap_or(100).clamp(1, 1000)], |row| Ok(AuditRow {id: row.get(0)?, at: row.get(1)?, actor: row.get(2)?, source: row.get(3)?, action: row.get(4)?, target: row.get(5)?, detail: row.get(6)?}))?.collect::<Result<_, _>>()?;
	ok(&AuditOut {entries})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewToken {
	pub name: String,
	/// "read" (reads only), "users" (users, devices and links) or "full" (everything an API token may do).
	pub scope: String,
	/// Unix seconds.
	pub expires_at: Option<i64>,
	/// Source addresses the token works from. Empty means any.
	#[serde(default)] pub allowed_sources: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct TokenCreated {pub id: i64, pub name: String, pub scope: String,
	/// Shown once. Only its hash is stored.
	pub token: String}

pub async fn create_token(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<NewToken>) -> Result<Response, Failure> {
	if !["read", "users", "full"].contains(&input.scope.as_str()) {return Err(Failure::bad("scope is read, users or full."))}
	if input.name.is_empty() || input.name.chars().count() > 64 || input.expires_at.is_some_and(|at| at <= now()) || input.allowed_sources.len() > 32 || input.allowed_sources.iter().any(|source| source.parse::<IpNet>().is_err() && source.parse::<std::net::IpAddr>().is_err()) {return Err(Failure::bad("A token has a name of 1 to 64 characters, an expiry in the future and at most 32 source addresses or networks."))}
	let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(crypto::random::<32>()));
	let db = app.db.lock();
	db.execute("insert into api_tokens (admin_id, name, scope, token_hash, prefix, expires_at, sources, created) values (?, ?, ?, ?, ?, ?, ?, ?)", params![ctx.admin_id, input.name, input.scope, crypto::sha256(token.as_bytes()).as_slice(), &token[..TOKEN_PREFIX.len() + 4], input.expires_at, serde_json::to_string(&input.allowed_sources).unwrap_or_default(), now()])?;
	let id = db.last_insert_rowid();
	audit(&db, &ctx.actor, &ctx.source, "token.create", &format!("token:{id}"), &format!("{} ({})", input.name, input.scope));
	ok(&TokenCreated {id, name: input.name, scope: input.scope, token})
}

#[derive(Serialize, JsonSchema)]
pub struct TokenRow {pub id: i64, pub name: String, pub scope: String, pub prefix: String, pub expires_at: Option<i64>, pub allowed_sources: Vec<String>, pub created: i64, pub last_used: Option<i64>, pub revoked_at: Option<i64>}

#[derive(Serialize, JsonSchema)]
pub struct TokensOut {pub tokens: Vec<TokenRow>}

pub async fn tokens(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let db = app.db.lock();
	let mut statement = db.prepare("select id, name, scope, prefix, expires_at, sources, created, last_used, revoked_at from api_tokens where admin_id = ? order by id")?;
	let tokens = statement.query_map([ctx.admin_id], |row| Ok(TokenRow {id: row.get(0)?, name: row.get(1)?, scope: row.get(2)?, prefix: row.get(3)?, expires_at: row.get(4)?, allowed_sources: serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default(), created: row.get(6)?, last_used: row.get(7)?, revoked_at: row.get(8)?}))?.collect::<Result<_, _>>()?;
	ok(&TokensOut {tokens})
}

pub async fn revoke_token(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let db = app.db.lock();
	if db.execute("update api_tokens set revoked_at = ? where id = ? and admin_id = ? and revoked_at is null", params![now(), id, ctx.admin_id])? == 0 {return Err(Failure::missing("token"))}
	audit(&db, &ctx.actor, &ctx.source, "token.revoke", &format!("token:{id}"), "");
	ok(&Done {ok: true})
}

pub async fn get_settings(State(app): State<Arc<App>>) -> Result<Response, Failure> {ok(&app.settings())}

pub async fn put_settings(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Settings>) -> Result<Response, Failure> {
	if input.pool_v4.parse::<Ipv4Net>().map_or(true, |pool| pool.prefix_len() < 16 || pool.prefix_len() > 30) {return Err(Failure::bad("pool_v4 is an IPv4 network from /16 to /30."))}
	if !input.endpoint_url.is_empty() && !(input.endpoint_url.starts_with("https://") && input.endpoint_url.len() <= 256 && !input.endpoint_url.contains('#')) {return Err(Failure::bad("endpoint_url is an https URL of at most 256 characters, without a fragment."))}
	if input.endpoint_pins.len() > 2 || input.endpoint_pins.iter().any(|pin| STANDARD.decode(pin).map_or(true, |bytes| bytes.len() != 32)) {return Err(Failure::bad("endpoint_pins is at most two SHA-256 pins in standard base64."))}
	if !(900..=604_800).contains(&input.update_interval) || !(1..=90).contains(&input.document_days) || input.provider_name.is_empty() || input.provider_name.chars().count() > 64 {return Err(Failure::bad("update_interval is 900 to 604800, document_days is 1 to 90 and provider_name is 1 to 64 characters."))}
	if input.profiles.len() > 64 || input.profiles.iter().any(|profile| !profile.is_object() || profile.get("device").is_some()) || input.refresh_mirrors.len() > 4 {return Err(Failure::bad("profiles are at most 64 objects without a device, and refresh_mirrors at most 4."))}
	if let Some(page) = &input.not_found {
		if !(200..=599).contains(&page.status) || page.headers.len() > 16 || page.body.len() > 65_536 || page.headers.iter().any(|(name, value)| HeaderName::try_from(name.as_str()).is_err() || HeaderValue::from_str(value).is_err()) {return Err(Failure::bad("not_found is a status from 200 to 599, at most 16 valid headers and a body of at most 64 KB."))}
	}
	let before = app.settings();
	app.save_settings(&input);
	*app.not_found_page.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = input.not_found.clone();
	let db = app.db.lock();
	if input.show_links_once && !before.show_links_once {db.execute("update users set token_copy = null", [])?;}
	audit(&db, &ctx.actor, &ctx.source, "settings.update", "settings", if before.profiles != input.profiles {"profiles changed"} else {""});
	drop(db);
	ok(&input)
}

#[derive(Serialize, JsonSchema)]
pub struct KeyOut {pub kid: String, pub fingerprint: String, pub public_key: String, pub state: String, pub created: i64, pub retired_at: Option<i64>}

#[derive(Serialize, JsonSchema)]
pub struct KeysOut {pub keys: Vec<KeyOut>}

fn keys_out(app: &App) -> KeysOut {
	let held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	KeysOut {keys: held.entries.iter().map(|entry| KeyOut {kid: entry.proto().kid().text(), fingerprint: entry.proto().fingerprint().to_string(), public_key: STANDARD.encode(entry.public()), state: if entry.retired_at.is_some() {"retired"} else {"current"}.into(), created: entry.created, retired_at: entry.retired_at}).collect()}
}

pub async fn signing_keys(State(app): State<Arc<App>>) -> Result<Response, Failure> {ok(&keys_out(&app))}

/// Starts an overlap: a second current key, both listed in every document from now on. The old one still signs for clients that hold only it.
pub async fn rotate_signing(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	{
		let mut held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if held.current().len() != 1 {return Err(Failure::conflict("A rotation is already under way. Finish it first."))}
		held.entries.push(SigningEntry {seed: URL_SAFE_NO_PAD.encode(crypto::random::<32>()), created: now(), retired_at: None});
		held.save().map_err(Failure::internal)?;
	}
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "signing.rotate", "signing", "overlap started");
	ok(&keys_out(&app))
}

/// Ends the overlap: the older current key is retired. It is kept for 365 days to sign the refusal that tells a client to get a new link.
pub async fn finish_signing(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	{
		let mut held = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if held.current().len() != 2 {return Err(Failure::conflict("There is no rotation to finish."))}
		let oldest = held.entries.iter().position(|entry| entry.retired_at.is_none()).unwrap_or(0);
		held.entries[oldest].retired_at = Some(now());
		held.save().map_err(Failure::internal)?;
	}
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "signing.finish", "signing", "old key retired");
	ok(&keys_out(&app))
}

#[derive(Serialize, JsonSchema)]
pub struct NodeInfo {pub reachable: bool, pub status: Option<Value>, pub last_sync: Option<String>, pub keys_missing: bool}

pub async fn node_info(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let status = match node::request(&app.cfg.node_socket, "GET", "/v1/status", None, None).await {Ok((200, body)) => serde_json::from_slice(&body).ok(), _ => None};
	ok(&NodeInfo {reachable: status.is_some(), status, last_sync: app.last_sync.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone(), keys_missing: app.keys.is_none()})
}

pub async fn node_sync(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "node.sync", "node", "");
	ok(&crate::users::push(&app).await)
}
