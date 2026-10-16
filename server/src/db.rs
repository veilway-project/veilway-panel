//! The SQLite file: schema, migrations, the thread that owns the connection and the audit log.
use crate::crypto::now;
use rusqlite::{params, Connection};
use std::{fmt, panic::{catch_unwind, AssertUnwindSafe}, path::Path, sync::mpsc, thread};

/// The layout of a fresh file, which is the layout of `SCHEMA_VERSION`. Keep it in step with `MIGRATIONS`.
const SCHEMA: &str = "
create table admins (id integer primary key, username text not null unique, password_hash text not null, totp_secret blob not null, totp_record blob not null, totp_last_step integer not null default 0, created integer not null);
create table sessions (id text primary key, admin_id integer not null references admins(id) on delete cascade, token_hash blob not null unique, csrf text not null, created integer not null, last_seen integer not null, reauth_at integer not null default 0, source text not null, agent text not null);
create table api_tokens (id integer primary key, admin_id integer not null references admins(id) on delete cascade, name text not null, scope text not null, token_hash blob not null unique, prefix text not null, expires_at integer, sources text not null, created integer not null, last_used integer, revoked_at integer);
create table audit (id integer primary key, at integer not null, actor text not null, source text not null, action text not null, target text not null, detail text not null);
create table settings (key text primary key, value text not null);
create table users (id integer primary key, name text not null unique, enabled integer not null default 1, groups text not null default '[]', exits text not null default '\"all\"', default_exit text, quota_bytes integer, quota_period text, expires_at integer, device_limit integer not null, note text not null default '', created integer not null, record_id blob not null, sub_id text not null unique, token_lookup blob not null unique, token_copy blob, token_gen integer not null default 1, token_created integer not null, endpoint text);
create table usage_buckets (res integer not null, at integer not null, kind text not null, name text not null, up integer not null default 0, down integer not null default 0, peak_up integer not null default 0, peak_down integer not null default 0, primary key (res, at, kind, name)) without rowid;
create table counters (kind text not null, name text not null, up integer not null, down integer not null, primary key (kind, name)) without rowid;
create table devices (id integer primary key, user_id integer not null references users(id) on delete cascade, name text not null, public_key text not null, secret_hash blob not null, address text not null unique, transport_secret blob not null, private_key blob, state text not null, token_gen integer not null, created integer not null, confirmed_at integer, last_seen integer, mirror_name blob, mirror_key blob, mirror_gen integer, last_serial integer not null default 0);
create unique index devices_public_key on devices (public_key);
create table xray_inbounds (tag text primary key, protocol text not null, host text not null default '', created integer not null, server_key blob);
create table xray_clients (tag text not null references xray_inbounds(tag) on delete cascade, user_id integer not null references users(id) on delete cascade, secret blob not null, primary key (tag, user_id)) without rowid;
create table gateway_use (key_id integer not null, user_id integer not null references users(id) on delete cascade, first_at integer not null, last_at integer not null, primary key (key_id, user_id)) without rowid;
create table endpoint_use (endpoint text not null, user_id integer not null references users(id) on delete cascade, last_at integer not null, primary key (endpoint, user_id)) without rowid;
";

/// Steps from one version to the next, applied in order to a file older than the code. Entry `n` takes a file from version `n + 1` to `n + 2`. To add one, append its SQL here, update `SCHEMA` to the new layout (a fresh file gets `SCHEMA` directly) and never edit a step that has shipped. Each step runs in its own transaction together with its version bump.
pub const MIGRATIONS: &[&str] = &[];
/// The version this code writes, kept in the file's `user_version`. A file with a higher number was made by a newer panel and is refused, at start-up and in a restore.
pub const SCHEMA_VERSION: i64 = 1 + MIGRATIONS.len() as i64;
/// Calls waiting for the database thread. A call past this is refused at once, so a burst cannot grow the queue without bound.
const QUEUE: usize = 1024;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// The database could not take a call: its queue is full, its thread stopped, or the call panicked.
#[derive(Debug)]
pub struct Unavailable;

impl fmt::Display for Unavailable {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {write!(f, "the database cannot take the call right now")}
}

/// Handle to the database thread, which owns the only connection. Jobs run one at a time, in the order they were queued.
#[derive(Clone)]
pub struct Db(mpsc::SyncSender<Job>);

/// Brings the file up to the newest version in `migrations`. A fresh file gets `SCHEMA` and its version in one transaction. An older file gets each step it lacks in its own transaction, so a failed step leaves the version of the last step that worked.
pub fn migrate(connection: &mut Connection, migrations: &[&str]) -> Result<(), String> {
	let found: i64 = connection.query_row("pragma user_version", [], |row| row.get(0)).map_err(|error| error.to_string())?;
	let latest = 1 + migrations.len() as i64;
	if found < 0 {return Err(format!("the database has a negative version ({found}), which no panel writes"))}
	if found > latest {return Err(format!("the database was made by a newer panel (version {found}, this panel writes version {latest})"))}
	if found == 0 {
		let objects: i64 = connection.query_row("select count(*) from sqlite_master", [], |row| row.get(0)).map_err(|error| error.to_string())?;
		if objects > 0 {return Err("the database is not empty and has no version, so it is not a panel database".into())}
		return apply(connection, SCHEMA, latest)
	}
	for (step, sql) in migrations.iter().enumerate().skip(found as usize - 1) {apply(connection, sql, step as i64 + 2)?}
	Ok(())
}

/// One step with foreign keys off while it runs, since a table rebuild needs that. The check after it refuses a step that leaves a reference to nothing.
fn apply(connection: &mut Connection, sql: &str, version: i64) -> Result<(), String> {
	connection.pragma_update(None, "foreign_keys", false).map_err(|error| error.to_string())?;
	let result = step(connection, sql, version);
	connection.pragma_update(None, "foreign_keys", true).map_err(|error| error.to_string())?;
	result
}

fn step(connection: &mut Connection, sql: &str, version: i64) -> Result<(), String> {
	let transaction = connection.transaction().map_err(|error| error.to_string())?;
	transaction.execute_batch(sql).map_err(|error| format!("the database could not move to version {version}: {error}"))?;
	if transaction.prepare("pragma foreign_key_check").and_then(|mut check| check.exists([])).map_err(|error| error.to_string())? {return Err(format!("version {version} leaves a row that points at nothing"))}
	transaction.pragma_update(None, "user_version", version).map_err(|error| error.to_string())?;
	transaction.commit().map_err(|error| error.to_string())
}

impl Db {
	pub fn open(path: &Path) -> Result<Self, String> {
		let mut connection = Connection::open(path).map_err(|error| error.to_string())?;
		connection.execute_batch("pragma journal_mode=wal; pragma foreign_keys=on; pragma busy_timeout=5000;").map_err(|error| error.to_string())?;
		let found: i64 = connection.query_row("pragma user_version", [], |row| row.get(0)).map_err(|error| error.to_string())?;
		if found > 0 && found < SCHEMA_VERSION {
			let copy = format!("{}.version-{found}", path.display());
			let _ = std::fs::remove_file(&copy);
			connection.execute("vacuum into ?", [&copy]).map_err(|error| format!("the database could not be copied before its migration: {error}"))?;
		}
		migrate(&mut connection, MIGRATIONS)?;
		let (jobs, queue) = mpsc::sync_channel::<Job>(QUEUE);
		thread::Builder::new().name("panel-db".into()).spawn(move || {
			for job in queue {
				if catch_unwind(AssertUnwindSafe(|| job(&mut connection))).is_err() {tracing::error!("a database call panicked")}
			}
		}).map_err(|error| error.to_string())?;
		Ok(Self(jobs))
	}
	/// The way in from async code. Nothing is locked on an async worker and no guard is held across an await: the job is queued on the thread that owns the connection and its answer is awaited. A full queue refuses the call at once. A job whose caller has already gone is skipped, so an abandoned request writes nothing; a job that has started finishes, and its flags are set inside it.
	pub async fn call<T: Send + 'static>(&self, f: impl FnOnce(&mut Connection) -> T + Send + 'static) -> Result<T, Unavailable> {
		let (answer, reply) = tokio::sync::oneshot::channel();
		self.0.try_send(Box::new(move |connection: &mut Connection| {if !answer.is_closed() {let _ = answer.send(f(connection));}})).map_err(|_| Unavailable)?;
		reply.await.map_err(|_| Unavailable)
	}
	/// For code off the async workers: start-up, a spawn_blocking task, a test. It blocks the calling thread until the job has run, and waits for queue space rather than refusing.
	pub fn blocking<T: Send + 'static>(&self, f: impl FnOnce(&mut Connection) -> T + Send + 'static) -> Result<T, Unavailable> {
		let (answer, reply) = mpsc::sync_channel(1);
		self.0.send(Box::new(move |connection: &mut Connection| {let _ = answer.send(f(connection));})).map_err(|_| Unavailable)?;
		reply.recv().map_err(|_| Unavailable)
	}
	pub async fn audit(&self, actor: &str, source: &str, action: &str, target: &str, detail: &str) {
		let (actor, source, action, target, detail) = (actor.to_owned(), source.to_owned(), action.to_owned(), target.to_owned(), detail.to_owned());
		if self.call(move |connection| audit(connection, &actor, &source, &action, &target, &detail)).await.is_err() {tracing::error!("the audit log could not be written: the database cannot take the call")}
	}
}

/// One line of the audit log. `detail` never holds a secret: a link, a token, a key or a password.
pub fn audit(connection: &Connection, actor: &str, source: &str, action: &str, target: &str, detail: &str) {
	if let Err(error) = connection.execute("insert into audit (at, actor, source, action, target, detail) values (?, ?, ?, ?, ?, ?)", params![now(), actor, source, action, target, detail]) {tracing::error!("the audit log could not be written: {error}")}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

	fn version(connection: &Connection) -> i64 {connection.query_row("pragma user_version", [], |row| row.get(0)).unwrap()}

	fn memory() -> Connection {Connection::open_in_memory().unwrap()}

	fn open_temp(name: &str) -> Db {
		let dir = std::env::temp_dir().join(format!("vwdb-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		Db::open(&dir.join("panel.db")).unwrap()
	}

	#[test]
	fn a_fresh_database_gets_the_schema_and_version_1() {
		let mut connection = memory();
		migrate(&mut connection, MIGRATIONS).unwrap();
		assert_eq!(SCHEMA_VERSION, 1);
		assert_eq!(version(&connection), 1);
		assert_eq!(connection.query_row("select count(*) from sqlite_master where type = 'table'", [], |row| row.get::<_, i64>(0)).unwrap(), 13);
	}

	#[test]
	fn a_migrated_file_has_the_schema_of_a_fresh_one() {
		let (mut fresh, mut migrated) = (memory(), memory());
		migrate(&mut fresh, MIGRATIONS).unwrap();
		migrate(&mut migrated, &[]).unwrap();
		migrate(&mut migrated, MIGRATIONS).unwrap();
		let dump = |connection: &Connection| connection.prepare("select sql from sqlite_master where sql is not null order by name").unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
		assert_eq!(dump(&migrated), dump(&fresh));
	}

	#[test]
	fn a_migration_step_runs_once_and_in_order() {
		let mut connection = memory();
		migrate(&mut connection, &[]).unwrap();
		let steps = ["create table log (step integer not null)", "insert into log values (1)", "insert into log select step + 1 from log"];
		migrate(&mut connection, &steps).unwrap();
		migrate(&mut connection, &steps).unwrap();
		assert_eq!(version(&connection), 4);
		assert_eq!(connection.query_row("select count(*) from log", [], |row| row.get::<_, i64>(0)).unwrap(), 2);
		assert_eq!(connection.query_row("select max(step) from log", [], |row| row.get::<_, i64>(0)).unwrap(), 2);
	}

	#[test]
	fn a_failing_step_stops_start_up_and_keeps_the_version_of_the_last_good_step() {
		let mut connection = memory();
		migrate(&mut connection, &[]).unwrap();
		let error = migrate(&mut connection, &["create table ok (id integer)", "this is not sql"]).unwrap_err();
		assert!(error.contains("version 3"), "{error}");
		assert_eq!(version(&connection), 2);
		assert_eq!(connection.query_row("select count(*) from sqlite_master where name = 'ok'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
	}

	#[test]
	fn a_step_that_leaves_a_dangling_reference_is_refused() {
		let mut connection = memory();
		migrate(&mut connection, &[]).unwrap();
		let error = migrate(&mut connection, &["create table parent (id integer primary key); create table child (parent integer references parent(id)); insert into child values (1);"]).unwrap_err();
		assert!(error.contains("points at nothing"), "{error}");
		assert_eq!(version(&connection), 1);
	}

	#[test]
	fn a_newer_or_negative_file_is_refused_and_left_alone() {
		let mut connection = memory();
		migrate(&mut connection, &[]).unwrap();
		connection.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
		assert!(migrate(&mut connection, MIGRATIONS).unwrap_err().contains("newer panel"));
		assert_eq!(version(&connection), SCHEMA_VERSION + 1);
		connection.pragma_update(None, "user_version", -1).unwrap();
		assert!(migrate(&mut connection, MIGRATIONS).unwrap_err().contains("negative"));
	}

	#[test]
	fn a_file_with_tables_and_no_version_is_refused() {
		let mut connection = memory();
		connection.execute_batch("create table other (id integer)").unwrap();
		assert!(migrate(&mut connection, MIGRATIONS).unwrap_err().contains("not empty"));
		assert_eq!(version(&connection), 0);
	}

	#[tokio::test]
	async fn a_panicking_call_is_an_error_and_the_thread_keeps_going() {
		let db = open_temp("panic");
		assert!(db.call(|_| -> i64 {panic!("the job fails")}).await.is_err());
		assert_eq!(db.call(|_| 7).await.unwrap(), 7);
	}

	#[tokio::test]
	async fn a_job_that_started_finishes_and_sets_its_flag_after_the_caller_is_gone() {
		let db = open_temp("started");
		let flag = Arc::new(AtomicBool::new(false));
		let (started_tx, started_rx) = mpsc::channel::<()>();
		let (go_tx, go_rx) = mpsc::channel::<()>();
		let done = flag.clone();
		let caller = tokio::spawn({let db = db.clone(); async move {db.call(move |_| {started_tx.send(()).unwrap(); go_rx.recv().unwrap(); done.store(true, Ordering::SeqCst)}).await}});
		tokio::task::spawn_blocking(move || started_rx.recv().unwrap()).await.unwrap();
		caller.abort();
		go_tx.send(()).unwrap();
		db.blocking(|_| ()).unwrap();
		assert!(flag.load(Ordering::SeqCst));
	}
}
