//! Admin accounts: setup, login, TOTP, sessions, API tokens, the audit log, settings, signing keys and the node.
use crate::{app::{bucket, publish_settings, store_settings, App, Settings, SigningEntry}, auth::{Agent, COOKIE_NAME, TOKEN_PREFIX}, crypto::{self, now, Keys}, db::audit, http::{json, ok, Body, Ctx, Failure}, node};
use veilway_proto::subscription::{Url, URL_MAX};
use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use axum::{extract::{Path, Query, State}, http::{header::SET_COOKIE, HeaderName, HeaderValue, StatusCode}, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use data_encoding::BASE32_NOPAD;
use ipnet::{IpNet, Ipv4Net};
use rusqlite::{params, Connection, OptionalExtension};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

const LOGIN_PER_SOURCE: (usize, i64) = (10, 900);
/// While the code is off the password is the only factor, so a source gets fewer tries.
const LOGIN_PER_SOURCE_OFF: (usize, i64) = (5, 900);
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
pub struct Status {pub setup_needed: bool,
	/// False when the panel's config file turns the authenticator code off. Read-only: no route changes it.
	pub two_step: bool,
	/// Different on every start of the server.
	pub start_id: String}

pub async fn status(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	ok(&Status {two_step: app.cfg.two_step_on(), setup_needed: app.db.call(|db| db.query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0))).await?? == 0, start_id: app.start_id.clone()})
}

#[derive(Serialize, JsonSchema)]
pub struct TotpEnrolled {
	/// Base32, for an authenticator app. Shown once, whatever two-step sign-in is set to.
	pub totp_secret: String, pub otpauth: String,
}

/// A new secret, made whatever two-step sign-in is set to, so that no account is left without one.
fn new_totp(app: &App, name: &str) -> Result<(Vec<u8>, Vec<u8>, TotpEnrolled), Failure> {
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	let (secret, record) = (crypto::random::<20>(), crypto::random::<16>());
	let text = BASE32_NOPAD.encode(&secret);
	Ok((keys.seal_secret(&record, "totp", &secret), record.to_vec(), TotpEnrolled {otpauth: format!("otpauth://totp/Veilway:{name}?secret={text}&issuer=Veilway"), totp_secret: text}))
}

/// Gives a secret to each admin that has none, which only an account made while two-step sign-in was off can lack. Nobody has seen that secret, so the admin changes it under Account while the code is off, which shows it, or another admin resets the account under Admins.
pub fn complete_secrets(db: &Connection, keys: &Keys) {
	let Ok(mut statement) = db.prepare("select id, username from admins where length(totp_secret) = 0") else {return};
	let missing: Vec<(i64, String)> = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).map(|rows| rows.filter_map(Result::ok).collect()).unwrap_or_default();
	for (id, name) in missing {
		let (secret, record) = (crypto::random::<20>(), crypto::random::<16>());
		let _ = db.execute("update admins set totp_secret = ?, totp_record = ?, totp_last_step = 0 where id = ?", params![keys.seal_secret(&record, "totp", &secret), record.to_vec(), id]);
		tracing::warn!("admin {name} had no authenticator secret, from a time when two-step sign-in was off, so one was made that nobody has seen. Change the authenticator under Account while two-step sign-in is off, or have another admin reset the account under Admins");
	}
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Setup {pub token: String, pub username: String, pub password: String, #[serde(default)] pub accepted_terms: bool}

/// The version of the Veilway terms the operator accepts at setup, kept with the acceptance.
const TERMS_VERSION: &str = "2026-10-16";

pub async fn setup(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Setup>) -> Result<Response, Failure> {
	if !app.limits.hit(&format!("setup:{}", bucket(&ctx.source, 64)), 5, 900) {return Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many tries."))}
	let expected = app.setup_token.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
	if !expected.is_some_and(|expected| crypto::equal(expected.as_bytes(), input.token.as_bytes())) {return Err(Failure::new(StatusCode::FORBIDDEN, "bad_setup_token", "The setup token is wrong, or setup is done."))}
	if !input.accepted_terms {return Err(Failure::bad("Accept the Veilway terms to set up the panel."))}
	username_ok(&input.username)?;
	password_ok(&input.password)?;
	let hash = hash_password(input.password.clone()).await?;
	let (sealed, record, shown) = new_totp(&app, &input.username)?;
	app.db.call(move |db| -> Result<(), Failure> {
		if db.query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0))? > 0 {return Err(Failure::conflict("Setup is done."))}
		db.execute("insert into admins (username, password_hash, totp_secret, totp_record, created) values (?, ?, ?, ?, ?)", params![input.username, hash, sealed, record, now()])?;
		db.execute("insert or replace into settings (key, value) values ('terms_accepted', ?)", [serde_json::json!({"version": TERMS_VERSION, "accepted_at": now()}).to_string()])?;
		audit(db, &format!("admin:{}", input.username), &ctx.source, "setup", "admin", &format!("first admin created, terms {TERMS_VERSION} accepted"));
		Ok(())
	}).await??;
	*app.setup_token.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
	ok(&shown)
}

struct AdminRow {id: i64, username: String, hash: String, secret: Vec<u8>, record: Vec<u8>, last_step: i64}

async fn admin_by(app: &App, column: &str, value: rusqlite::types::Value) -> Result<Option<AdminRow>, Failure> {
	let sql = format!("select id, username, password_hash, totp_secret, totp_record, totp_last_step from admins where {column} = ?");
	app.db.call(move |db| db.query_row(&sql, [value], |row| Ok(AdminRow {id: row.get(0)?, username: row.get(1)?, hash: row.get(2)?, secret: row.get(3)?, record: row.get(4)?, last_step: row.get(5)?})).optional().unwrap_or(None)).await.map_err(Failure::from)
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
async fn actor_of(app: &App, name: &str) -> String {
	let lookup = name.to_string();
	let known = app.db.call(move |db| db.query_row("select 1 from admins where username = ?", [lookup], |_| Ok(())).is_ok()).await.unwrap_or(false);
	if known {format!("admin:{name}")} else {"unknown".into()}
}

/// Password and a TOTP code that was not used before. A wrong try counts against the account, and while the account is waiting a wrong try gets a "wait" answer. With the code on, a right one passes whatever the wait, so an attacker who guesses wrong cannot lock the admin out.
/// With two-step sign-in off the password is the only factor, so the wait holds for a right password too and the password is not even checked during it: otherwise the wait would only slow down guessing and never stop it. The tradeoff is that an attacker can keep the admin waiting by guessing wrong, up to 15 minutes at a time. That is acceptable only in this mode, which is for demos where nothing is at stake, and never with the code on.
async fn verify(app: &App, admin: Option<AdminRow>, name: &str, password: &str, code: &str) -> Result<AdminRow, Failure> {
	let waiting = wait_left(app, name) > 0;
	if waiting && !app.cfg.two_step_on() {return Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many tries. Wait a while."))}
	let good = check_password(admin.as_ref().map_or_else(|| dummy().to_string(), |admin| admin.hash.clone()), password.to_string()).await;
	let need_code = app.cfg.two_step_on();
	let step = admin.as_ref().filter(|_| need_code).and_then(|admin| {
		let record: [u8; 16] = admin.record.clone().try_into().ok()?;
		let secret = app.keys.as_ref()?.open_secret(&record, "totp", &admin.secret)?;
		crypto::totp_check(&secret, code, now()).filter(|step| *step > admin.last_step)
	});
	// The step is claimed in the same statement that checks it, so two requests with one code cannot both pass.
	let claimed = match (good, step, &admin) {
		(true, Some(step), Some(admin)) => {
			let id = admin.id;
			app.db.call(move |db| db.execute("update admins set totp_last_step = ? where id = ? and totp_last_step < ?", params![step, id, step]).unwrap_or(0)).await.unwrap_or(0) == 1
		}
		(true, None, Some(_)) => !need_code,
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
pub struct Login {pub username: String, pub password: String,
	/// Not read while two-step sign-in is off.
	#[serde(default)]
	pub totp: String}

#[derive(Serialize, JsonSchema)]
pub struct LoggedIn {pub username: String, pub session_id: String, pub csrf: String,
	/// True when two-step sign-in is off and this admin's password is shorter than 12 characters: only the password change works until it is done.
	pub password_change_required: bool}

pub async fn login(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Extension(agent): Extension<Agent>, Body(input): Body<Login>) -> Result<Response, Failure> {
	let per_source = if app.cfg.two_step_on() {LOGIN_PER_SOURCE} else {LOGIN_PER_SOURCE_OFF};
	if !app.limits.hit(&format!("login:{}", bucket(&ctx.source, 64)), per_source.0, per_source.1) {
		let actor = actor_of(&app, &input.username).await;
		app.db.audit(&actor, &ctx.source, "login.limited", "admin", "").await;
		return Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many tries. Wait a while."));
	}
	let admin = admin_by(&app, "username", input.username.clone().into()).await?;
	let admin = match verify(&app, admin, &input.username, &input.password, &input.totp).await {
		Ok(admin) => admin,
		Err(error) => {
			let actor = actor_of(&app, &input.username).await;
			app.db.audit(&actor, &ctx.source, "login.failed", "admin", "").await;
			return Err(error);
		}
	};
	// A stored password cannot be measured, so one shorter than the rule (from before it) is found here, while the code is off, and must be changed before anything else works.
	let short = !app.cfg.two_step_on() && input.password.chars().count() < 12;
	if short {
		let key = format!("short_password:{}", admin.id);
		let _ = app.db.call(move |db| db.execute("insert into settings (key, value) values (?, '1') on conflict (key) do nothing", [key])).await;
	}
	let (raw, id, csrf) = (crypto::random::<32>(), hex(&crypto::random::<8>()), URL_SAFE_NO_PAD.encode(crypto::random::<32>()));
	let (entry, shown_csrf, token_hash, actor, admin_id) = (id.clone(), csrf.clone(), crypto::sha256(&raw), format!("admin:{}", admin.username), admin.id);
	app.db.call(move |db| -> Result<(), rusqlite::Error> {
		db.execute("insert into sessions (id, admin_id, token_hash, csrf, created, last_seen, reauth_at, source, agent) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", params![entry, admin_id, token_hash.as_slice(), shown_csrf, now(), now(), now(), ctx.source, agent.0])?;
		audit(db, &actor, &ctx.source, "login", &format!("admin:{admin_id}"), &entry);
		Ok(())
	}).await??;
	let cookie = format!("{COOKIE_NAME}={}; Path={}; HttpOnly; SameSite=Strict; Max-Age={}{}", URL_SAFE_NO_PAD.encode(raw), app.cfg.prefix, crate::auth::ABSOLUTE, if app.cfg.secure_cookies {"; Secure"} else {""});
	let mut response = json(StatusCode::OK, &LoggedIn {password_change_required: short, username: admin.username, session_id: id, csrf});
	response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie).map_err(Failure::internal)?);
	Ok(response)
}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

#[derive(Serialize, JsonSchema)]
pub struct Done {pub ok: bool}

pub async fn logout(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	if let Some(id) = &ctx.session_id {
		let id = id.clone();
		app.db.call(move |db| -> Result<(), rusqlite::Error> {
			db.execute("delete from sessions where id = ?", [&id])?;
			audit(db, &ctx.actor, &ctx.source, "logout", "admin", &id);
			Ok(())
		}).await??;
	}
	let mut response = json(StatusCode::OK, &Done {ok: true});
	response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&format!("{COOKIE_NAME}=; Path={}; HttpOnly; SameSite=Strict; Max-Age=0", app.cfg.prefix)).map_err(Failure::internal)?);
	Ok(response)
}

#[derive(Serialize, JsonSchema)]
pub struct SessionInfo {pub username: String, pub session_id: String, pub csrf: String, pub reauth_until: i64,
	/// True when two-step sign-in is off and this admin's password is shorter than 12 characters: only the password change works until it is done.
	pub password_change_required: bool}

pub async fn session(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let id = ctx.session_id.ok_or_else(|| Failure::bad("This call is for a login session."))?;
	let lookup = id.clone();
	let (csrf, reauth): (String, i64) = app.db.call(move |db| db.query_row("select csrf, reauth_at from sessions where id = ?", [lookup], |row| Ok((row.get(0)?, row.get(1)?)))).await??;
	ok(&SessionInfo {username: ctx.actor.trim_start_matches("admin:").to_string(), session_id: id, csrf, reauth_until: reauth + crate::auth::REAUTH, password_change_required: !app.cfg.two_step_on() && crate::auth::short_password(&app, ctx.admin_id).await?})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reauth {pub password: String,
	/// Not read while two-step sign-in is off.
	#[serde(default)]
	pub totp: String}

pub async fn reauth(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Reauth>) -> Result<Response, Failure> {
	let name = ctx.actor.trim_start_matches("admin:").to_string();
	verify(&app, admin_by(&app, "id", ctx.admin_id.into()).await?, &name, &input.password, &input.totp).await?;
	let id = ctx.session_id.clone().ok_or_else(|| Failure::bad("This call is for a login session."))?;
	app.db.call(move |db| -> Result<(), rusqlite::Error> {
		db.execute("update sessions set reauth_at = ? where id = ?", params![now(), id])?;
		audit(db, &ctx.actor, &ctx.source, "reauth", "admin", &id);
		Ok(())
	}).await??;
	ok(&Done {ok: true})
}

#[derive(Serialize, JsonSchema)]
pub struct SessionRow {pub id: String, pub created: i64, pub last_seen: i64, pub source: String, pub agent: String, pub current: bool}

#[derive(Serialize, JsonSchema)]
pub struct SessionsOut {pub sessions: Vec<SessionRow>}

pub async fn sessions(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let admin_id = ctx.admin_id;
	let sessions = app.db.call(move |db| -> Result<Vec<SessionRow>, rusqlite::Error> {
		let mut statement = db.prepare("select id, created, last_seen, source, agent from sessions where admin_id = ? order by created desc")?;
		let sessions = statement.query_map([admin_id], |row| Ok(SessionRow {id: row.get(0)?, created: row.get(1)?, last_seen: row.get(2)?, source: row.get(3)?, agent: row.get(4)?, current: false}))?.collect::<Result<Vec<_>, _>>()?;
		Ok(sessions)
	}).await??;
	ok(&SessionsOut {sessions: sessions.into_iter().map(|session| SessionRow {current: ctx.session_id.as_deref() == Some(session.id.as_str()), ..session}).collect()})
}

pub async fn revoke_session(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>) -> Result<Response, Failure> {
	app.db.call(move |db| -> Result<(), Failure> {
		if db.execute("delete from sessions where id = ? and admin_id = ?", params![id, ctx.admin_id])? == 0 {return Err(Failure::missing("session"))}
		audit(db, &ctx.actor, &ctx.source, "session.revoke", "session", &id);
		Ok(())
	}).await??;
	ok(&Done {ok: true})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewPassword {pub new_password: String}

/// Every other session of the admin ends when the password or the TOTP secret changes.
pub async fn change_password(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<NewPassword>) -> Result<Response, Failure> {
	password_ok(&input.new_password)?;
	let hash = hash_password(input.new_password.clone()).await?;
	app.db.call(move |db| -> Result<(), rusqlite::Error> {
		db.execute("update admins set password_hash = ? where id = ?", params![hash, ctx.admin_id])?;
		db.execute("delete from settings where key = ?", [format!("short_password:{}", ctx.admin_id)])?;
		db.execute("delete from sessions where admin_id = ? and id != ?", params![ctx.admin_id, ctx.session_id.clone().unwrap_or_default()])?;
		audit(db, &ctx.actor, &ctx.source, "account.password", "admin", "");
		Ok(())
	}).await??;
	ok(&Done {ok: true})
}

pub async fn change_totp(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let (sealed, record, shown) = new_totp(&app, ctx.actor.trim_start_matches("admin:"))?;
	app.db.call(move |db| -> Result<(), rusqlite::Error> {
		db.execute("update admins set totp_secret = ?, totp_record = ?, totp_last_step = 0 where id = ?", params![sealed, record, ctx.admin_id])?;
		db.execute("delete from sessions where admin_id = ? and id != ?", params![ctx.admin_id, ctx.session_id.clone().unwrap_or_default()])?;
		audit(db, &ctx.actor, &ctx.source, "account.totp", "admin", "");
		Ok(())
	}).await??;
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
	app.db.call(move |db| -> Result<(), rusqlite::Error> {
		db.execute("insert into admins (username, password_hash, totp_secret, totp_record, created) values (?, ?, ?, ?, ?)", params![input.username, hash, sealed, record, now()])?;
		audit(db, &ctx.actor, &ctx.source, "admin.create", &input.username, "");
		Ok(())
	}).await??;
	ok(&shown)
}

#[derive(Serialize, JsonSchema)]
pub struct AdminRowOut {pub id: i64, pub username: String, pub created: i64,
	/// The last login, from the audit log. None when the log holds none.
	pub last_login: Option<i64>,
	/// Whether a code from the current TOTP secret has been used, which says the admin set up their authenticator. False after a reset until the next login.
	pub totp_used: bool,
	/// The admin who asks.
	pub you: bool}

#[derive(Serialize, JsonSchema)]
pub struct AdminsOut {pub admins: Vec<AdminRowOut>}

pub async fn admins(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let admins = app.db.call(move |db| -> Result<Vec<AdminRowOut>, rusqlite::Error> {
		let mut statement = db.prepare("select a.id, a.username, a.created, (select max(at) from audit where action = 'login' and at >= a.created and (target = 'admin:' || a.id or (target = 'admin' and actor = 'admin:' || a.username))), a.totp_last_step > 0 from admins a order by a.id")?;
		let admins = statement.query_map([], |row| Ok(AdminRowOut {id: row.get(0)?, username: row.get(1)?, created: row.get(2)?, last_login: row.get(3)?, totp_used: row.get(4)?, you: row.get::<_, i64>(0)? == ctx.admin_id}))?.collect::<Result<_, _>>()?;
		Ok(admins)
	}).await??;
	ok(&AdminsOut {admins})
}

/// Another admin's account. Yourself and the last admin are never removed, so the panel always keeps one admin who can sign in. Their sessions and API tokens go with the account.
pub async fn remove_admin(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	if id == ctx.admin_id {return Err(Failure::conflict("An admin cannot remove themselves."))}
	app.db.call(move |db| -> Result<(), Failure> {
		let name: String = db.query_row("select username from admins where id = ?", [id], |row| row.get(0)).optional()?.ok_or_else(|| Failure::missing("admin"))?;
		if db.query_row("select count(*) from admins", [], |row| row.get::<_, i64>(0))? <= 1 {return Err(Failure::conflict("The last admin cannot be removed."))}
		if db.execute("delete from admins where id = ? and username = ?", params![id, name])? == 0 {return Err(Failure::missing("admin"))}
		db.execute("delete from settings where key = ?", [format!("short_password:{id}")])?;
		audit(db, &ctx.actor, &ctx.source, "admin.remove", &format!("admin:{name}"), "");
		Ok(())
	}).await??;
	ok(&Done {ok: true})
}

/// Gives another admin a new password and a new TOTP secret, shown once, and ends every session of theirs. For an admin who lost their authenticator or whose account is in doubt; an admin changes their own through the account routes.
pub async fn reset_admin(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<NewPassword>) -> Result<Response, Failure> {
	if id == ctx.admin_id {return Err(Failure::conflict("Change your own password and code on the account page."))}
	password_ok(&input.new_password)?;
	let name: String = app.db.call(move |db| db.query_row("select username from admins where id = ?", [id], |row| row.get(0)).optional()).await??.ok_or_else(|| Failure::missing("admin"))?;
	let hash = hash_password(input.new_password.clone()).await?;
	let (sealed, record, shown) = new_totp(&app, &name)?;
	app.db.call(move |db| -> Result<(), Failure> {
		if db.execute("update admins set password_hash = ?, totp_secret = ?, totp_record = ?, totp_last_step = 0 where id = ? and username = ?", params![hash, sealed, record, id, name])? == 0 {return Err(Failure::missing("admin"))}
		db.execute("delete from settings where key = ?", [format!("short_password:{id}")])?;
		let ended = db.execute("delete from sessions where admin_id = ?", [id])?;
		let revoked = db.execute("update api_tokens set revoked_at = ? where admin_id = ? and revoked_at is null", params![now(), id])?;
		audit(db, &ctx.actor, &ctx.source, "admin.reset", &format!("admin:{name}"), &format!("password and code replaced, {ended} sessions ended, {revoked} tokens revoked"));
		Ok(())
	}).await??;
	ok(&shown)
}

/// The usernames, for an operator on the server's console who lost track of theirs, and whether each has used a code from its authenticator.
pub fn console_admins(db: &Connection) -> rusqlite::Result<Vec<(String, bool)>> {
	let mut statement = db.prepare("select username, totp_last_step > 0 from admins order by id")?;
	let admins = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect();
	admins
}

/// A new password set from the server's console, for an operator locked out of the panel. Every session of the admin ends; the authenticator secret and the API tokens stay.
pub fn console_reset(db: &Connection, name: &str, password: &str) -> Result<usize, String> {
	password_ok(password).map_err(|failure| failure.message)?;
	let hash = hash_blocking(password).map_err(|failure| failure.message)?;
	let id: i64 = db.query_row("select id from admins where username = ?", [name], |row| row.get(0)).optional().map_err(|error| error.to_string())?.ok_or_else(|| format!("no admin is called {name}"))?;
	db.execute("update admins set password_hash = ? where id = ?", params![hash, id]).map_err(|error| error.to_string())?;
	db.execute("delete from settings where key = ?", [format!("short_password:{id}")]).map_err(|error| error.to_string())?;
	let ended = db.execute("delete from sessions where admin_id = ?", [id]).map_err(|error| error.to_string())?;
	audit(db, "console", "console", "admin.reset", &format!("admin:{name}"), &format!("password replaced from the server console, {ended} sessions ended"));
	Ok(ended)
}

#[derive(Deserialize, JsonSchema)]
pub struct AuditQuery {pub limit: Option<i64>, pub before: Option<i64>}

#[derive(Serialize, JsonSchema)]
pub struct AuditRow {pub id: i64, pub at: i64, pub actor: String, pub source: String, pub action: String, pub target: String, pub detail: String}

#[derive(Serialize, JsonSchema)]
pub struct AuditOut {pub entries: Vec<AuditRow>}

pub async fn audit_log(State(app): State<Arc<App>>, Query(query): Query<AuditQuery>) -> Result<Response, Failure> {
	let entries = app.db.call(move |db| -> Result<Vec<AuditRow>, rusqlite::Error> {
		let mut statement = db.prepare("select id, at, actor, source, action, target, detail from audit where id < ? order by id desc limit ?")?;
		let entries = statement.query_map(params![query.before.unwrap_or(i64::MAX), query.limit.unwrap_or(100).clamp(1, 1000)], |row| Ok(AuditRow {id: row.get(0)?, at: row.get(1)?, actor: row.get(2)?, source: row.get(3)?, action: row.get(4)?, target: row.get(5)?, detail: row.get(6)?}))?.collect::<Result<_, _>>()?;
		Ok(entries)
	}).await??;
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
	let (name, scope, token_hash, prefix, sources, expires_at) = (input.name.clone(), input.scope.clone(), crypto::sha256(token.as_bytes()), token[..TOKEN_PREFIX.len() + 4].to_string(), serde_json::to_string(&input.allowed_sources).unwrap_or_default(), input.expires_at);
	let id = app.db.call(move |db| -> Result<i64, rusqlite::Error> {
		db.execute("insert into api_tokens (admin_id, name, scope, token_hash, prefix, expires_at, sources, created) values (?, ?, ?, ?, ?, ?, ?, ?)", params![ctx.admin_id, name, scope, token_hash.as_slice(), prefix, expires_at, sources, now()])?;
		let id = db.last_insert_rowid();
		audit(db, &ctx.actor, &ctx.source, "token.create", &format!("token:{id}"), &format!("{name} ({scope})"));
		Ok(id)
	}).await??;
	ok(&TokenCreated {id, name: input.name, scope: input.scope, token})
}

#[derive(Serialize, JsonSchema)]
pub struct TokenRow {pub id: i64, pub name: String, pub scope: String, pub prefix: String, pub expires_at: Option<i64>, pub allowed_sources: Vec<String>, pub created: i64, pub last_used: Option<i64>, pub revoked_at: Option<i64>}

#[derive(Serialize, JsonSchema)]
pub struct TokensOut {pub tokens: Vec<TokenRow>}

pub async fn tokens(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let tokens = app.db.call(move |db| -> Result<Vec<TokenRow>, rusqlite::Error> {
		let mut statement = db.prepare("select id, name, scope, prefix, expires_at, sources, created, last_used, revoked_at from api_tokens where admin_id = ? order by id")?;
		let tokens = statement.query_map([ctx.admin_id], |row| Ok(TokenRow {id: row.get(0)?, name: row.get(1)?, scope: row.get(2)?, prefix: row.get(3)?, expires_at: row.get(4)?, allowed_sources: serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default(), created: row.get(6)?, last_used: row.get(7)?, revoked_at: row.get(8)?}))?.collect::<Result<_, _>>()?;
		Ok(tokens)
	}).await??;
	ok(&TokensOut {tokens})
}

pub async fn revoke_token(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	app.db.call(move |db| -> Result<(), Failure> {
		if db.execute("update api_tokens set revoked_at = ? where id = ? and admin_id = ? and revoked_at is null", params![now(), id, ctx.admin_id])? == 0 {return Err(Failure::missing("token"))}
		audit(db, &ctx.actor, &ctx.source, "token.revoke", &format!("token:{id}"), "");
		Ok(())
	}).await??;
	ok(&Done {ok: true})
}

pub async fn get_settings(State(app): State<Arc<App>>) -> Result<Response, Failure> {ok(&app.settings())}

pub async fn put_settings(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Settings>) -> Result<Response, Failure> {
	if [&input.terms_url, &input.privacy_url].iter().any(|url| !url.is_empty() && Url::parse(url, URL_MAX, true, true).is_none()) {return Err(Failure::bad("terms_url and privacy_url are https URLs of at most 512 characters, or empty."))}
	if input.pool_v4.parse::<Ipv4Net>().map_or(true, |pool| pool.prefix_len() < 16 || pool.prefix_len() > 30) {return Err(Failure::bad("pool_v4 is an IPv4 network from /16 to /30."))}
	crate::endpoints::validate(&input).map_err(Failure::bad)?;
	if !(900..=604_800).contains(&input.update_interval) || !(1..=90).contains(&input.document_days) || input.provider_name.is_empty() || input.provider_name.chars().count() > 64 {return Err(Failure::bad("update_interval is 900 to 604800, document_days is 1 to 90 and provider_name is 1 to 64 characters."))}
	// An app refreshes once every `update_interval` at best, so a limit shorter than three of them would take devices that are in use.
	if input.idle_device_days > 365 || (input.idle_device_days > 0 && i64::from(input.idle_device_days) * 86_400 < 3 * i64::from(input.update_interval)) {return Err(Failure::bad("idle_device_days is 0, or 1 to 365 and at least three refresh intervals."))}
	if input.new_device_minutes > 1440 {return Err(Failure::bad("new_device_minutes is 0 to 1440."))}
	if !(7..=30).contains(&input.transport_key_days) {return Err(Failure::bad("transport_key_days is 7 to 30."))}
	if input.profiles.len() > 64 || input.profiles.iter().any(|profile| !profile.is_object() || profile.get("device").is_some()) || input.refresh_mirrors.len() > 4 {return Err(Failure::bad("profiles are at most 64 objects without a device, and refresh_mirrors at most 4."))}
	if input.profile_overrides.values().any(|edits| edits.as_object().is_some_and(crate::nodecfg::plain_written)) {return Err(Failure::bad("An override of transports may not hold a ws-plain transport."))}
	crate::statics::check(&input).map_err(Failure::bad)?;
	if let Some(page) = &input.not_found {
		if !(200..=599).contains(&page.status) || page.headers.len() > 16 || page.body.len() > 65_536 || page.headers.iter().any(|(name, value)| HeaderName::try_from(name.as_str()).is_err() || HeaderValue::from_str(value).is_err()) {return Err(Failure::bad("not_found is a status from 200 to 599, at most 16 valid headers and a body of at most 64 KB."))}
	}
	let (cache, saved) = (app.settings.clone(), input.clone());
	let (detail, stored) = app.db.call(move |db| -> Result<(&'static str, Settings), Failure> {
		let mut saved = saved;
		let tx = db.transaction()?;
		let before = cache.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
		// The public halves of the borrowed-site keys are the server's: a page that read them earlier would write an old copy back over what an apply made since.
		saved.faketls_keys = before.faketls_keys.clone();
		saved.inbound_keys = before.inbound_keys.clone();
		saved.transport_keys = before.transport_keys.clone();
		saved.transport_clocks = before.transport_clocks.clone();
		// A form loaded before a rotation may carry a key the node no longer accepts, or soon will not.
		crate::nodecfg::retarget(&mut saved.profiles, &crate::nodecfg::stale_keys(&before));
		crate::endpoints::in_use(&tx, &saved).map_err(Failure::conflict)?;
		let known: Vec<i64> = tx.prepare("select id from users")?.query_map([], |row| row.get(0))?.collect::<Result<_, _>>()?;
		if let Some(id) = saved.relays.iter().flat_map(|relay| relay.users.iter().copied()).find(|id| !known.contains(id)) {return Err(Failure::bad(format!("A relay names the account {id}, which does not exist. Take it off the relay first.")))}
		// A client accepts a list of pins only when it holds one of them, so a change that keeps none of the pins of an endpoint locks out every client that holds them. A switch to a standby keeps it: the former standby is in the new list.
		if let Some(endpoint) = saved.endpoints.iter().find(|endpoint| before.named(&endpoint.name).is_some_and(|old| !old.pins.is_empty() && !old.pins.iter().any(|pin| endpoint.pins.contains(pin)))) {return Err(Failure::conflict(format!("The pins of {} keep none of its current pins, so the apps that hold them would refuse every document. Keep one of the current pins in the list (a switch keeps the standby), or add the endpoint under another name and move the accounts to it.", endpoint.name)))}
		if saved.show_links_once && !before.show_links_once {tx.execute("update users set token_copy = null", [])?;}
		let detail = if before.profiles != saved.profiles {"profiles changed"} else {""};
		let stored = store_settings(&tx, &cache, move |settings| *settings = saved).map_err(Failure::internal)?;
		tx.commit()?;
		publish_settings(&cache, stored.clone());
		Ok((detail, stored))
	}).await??;
	*app.not_found_page.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = input.not_found.clone();
	app.db.audit(&ctx.actor, &ctx.source, "settings.update", "settings", detail).await;
	ok(&stored)
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
	app.db.audit(&ctx.actor, &ctx.source, "signing.rotate", "signing", "overlap started").await;
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
	app.db.audit(&ctx.actor, &ctx.source, "signing.finish", "signing", "old key retired").await;
	ok(&keys_out(&app))
}

#[derive(Serialize, JsonSchema)]
pub struct NodeInfo {pub reachable: bool, pub status: Option<Value>, pub last_sync: Option<String>, pub keys_missing: bool,
	/// True while no gateway key can be read: the subscription endpoint answers every request as an unknown path.
	pub gateway_missing: bool,
	/// The active gateway key is older than 180 days: time to load the next key.
	pub gateway_switch_due: bool,
	/// Whether the system reports its clock as synchronized, null when it cannot tell. A panel whose clock is off by more than a day writes static mirror names that no client asks for.
	pub clock_synchronized: Option<bool>}

pub async fn node_info(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let status = match node::request(&app.cfg.node_socket, "GET", "/v1/status", None, None).await {Ok((200, body)) => serde_json::from_slice(&body).ok(), _ => None};
	let (gateway_missing, gateway_switch_due) = {let hold = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner()); (!hold.loaded(), hold.active().is_some_and(|key| now() - key.created > crate::gateway::REMIND_AFTER))};
	ok(&NodeInfo {reachable: status.is_some(), status, last_sync: app.last_sync.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone(), keys_missing: app.keys.is_none(), gateway_missing, gateway_switch_due, clock_synchronized: crate::statics::clock_synchronized()})
}

pub async fn node_sync(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	app.db.audit(&ctx.actor, &ctx.source, "node.sync", "node", "").await;
	ok(&crate::users::push(&app).await)
}
