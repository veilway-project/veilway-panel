//! The SQLite file: schema, the connection and the audit log.
use crate::crypto::now;
use rusqlite::{params, Connection};
use std::{path::Path, sync::{Arc, Mutex, MutexGuard}};

const SCHEMA: &str = "
create table if not exists admins (id integer primary key, username text not null unique, password_hash text not null, totp_secret blob not null, totp_record blob not null, totp_last_step integer not null default 0, created integer not null);
create table if not exists sessions (id text primary key, admin_id integer not null references admins(id) on delete cascade, token_hash blob not null unique, csrf text not null, created integer not null, last_seen integer not null, reauth_at integer not null default 0, source text not null, agent text not null);
create table if not exists api_tokens (id integer primary key, admin_id integer not null references admins(id) on delete cascade, name text not null, scope text not null, token_hash blob not null unique, prefix text not null, expires_at integer, sources text not null, created integer not null, last_used integer, revoked_at integer);
create table if not exists audit (id integer primary key, at integer not null, actor text not null, source text not null, action text not null, target text not null, detail text not null);
create table if not exists settings (key text primary key, value text not null);
create table if not exists users (id integer primary key, name text not null unique, enabled integer not null default 1, groups text not null default '[]', exits text not null default '\"all\"', quota_bytes integer, quota_period text, expires_at integer, device_limit integer not null, note text not null default '', created integer not null, record_id blob not null, sub_id text not null unique, token_lookup blob not null unique, token_copy blob, token_gen integer not null default 1, token_created integer not null);
create table if not exists devices (id integer primary key, user_id integer not null references users(id) on delete cascade, name text not null, public_key text not null, secret_hash blob not null, address text not null unique, transport_secret blob not null, private_key blob, state text not null, token_gen integer not null, created integer not null, confirmed_at integer, last_seen integer, unique (user_id, public_key));
";

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
	pub fn open(path: &Path) -> rusqlite::Result<Self> {
		let connection = Connection::open(path)?;
		connection.execute_batch("pragma journal_mode=wal; pragma foreign_keys=on; pragma busy_timeout=5000;")?;
		connection.execute_batch(SCHEMA)?;
		Ok(Self(Arc::new(Mutex::new(connection))))
	}
	/// Held for the length of one query or one short transaction and never across an await.
	pub fn lock(&self) -> MutexGuard<'_, Connection> {self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())}
}

/// One line of the audit log. `detail` never holds a secret: a link, a token, a key or a password.
pub fn audit(connection: &Connection, actor: &str, source: &str, action: &str, target: &str, detail: &str) {
	if let Err(error) = connection.execute("insert into audit (at, actor, source, action, target, detail) values (?, ?, ?, ?, ?, ?)", params![now(), actor, source, action, target, detail]) {tracing::error!("the audit log could not be written: {error}")}
}
