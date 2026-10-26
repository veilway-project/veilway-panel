//! The SQLite file: schema, migrations, the thread that owns the connection and the audit log.
use crate::crypto::now;
use rusqlite::{params, Connection};
use std::{fmt, fs, os::unix::fs::OpenOptionsExt, panic::{catch_unwind, AssertUnwindSafe}, path::{Path, PathBuf}, sync::mpsc, thread};

/// The layout of a fresh file, which is the layout of `SCHEMA_VERSION`. Keep it in step with `MIGRATIONS`.
const SCHEMA: &str = "
create table admins (id integer primary key, username text not null unique, password_hash text not null, totp_secret blob not null, totp_record blob not null, totp_last_step integer not null default 0, created integer not null);
create table sessions (id text primary key, admin_id integer not null references admins(id) on delete cascade, token_hash blob not null unique, csrf text not null, created integer not null, last_seen integer not null, reauth_at integer not null default 0, source text not null, agent text not null);
create table api_tokens (id integer primary key, admin_id integer not null references admins(id) on delete cascade, name text not null, scope text not null, token_hash blob not null unique, prefix text not null, expires_at integer, sources text not null, created integer not null, last_used integer, revoked_at integer);
create table audit (id integer primary key, at integer not null, actor text not null, source text not null, action text not null, target text not null, detail text not null);
create table settings (key text primary key, value text not null);
create table users (id integer primary key, name text not null unique, enabled integer not null default 1, groups text not null default '[]', exits text not null default '\"all\"', default_exit text, quota_bytes integer, quota_period text, expires_at integer, device_limit integer not null, note text not null default '', created integer not null, record_id blob not null, sub_id text not null unique, token_lookup blob not null unique, token_copy blob, token_gen integer not null default 1, token_created integer not null, endpoint text, proxy_password blob, nodes text not null default '\"all\"', cut_until integer, profile_order text);
create table usage_buckets (res integer not null, at integer not null, kind text not null, name text not null, up integer not null default 0, down integer not null default 0, peak_up integer not null default 0, peak_down integer not null default 0, primary key (res, at, kind, name)) without rowid;
create table counters (kind text not null, name text not null, up integer not null, down integer not null, primary key (kind, name)) without rowid;
create table devices (id integer primary key, user_id integer not null references users(id) on delete cascade, name text not null, public_key text not null, secret_hash blob not null, transport_secret blob not null, private_key blob, state text not null, token_gen integer not null, created integer not null, confirmed_at integer, last_seen integer, mirror_name blob, mirror_key blob, mirror_gen integer, last_serial integer not null default 0);
create unique index devices_public_key on devices (public_key);
create table nodes (id integer primary key, uid blob not null unique, name text not null unique, slug text not null unique, link_id text, place integer not null default 0, pool_v4 text not null, settings text not null default '{}', wanted_rev integer not null default 0, applied_rev integer not null default 0, config_rev text, last_seen integer, last_error text, version text, counted integer not null default 1, max_rate integer, created integer not null, link_tag text, emptied integer not null default 0, relays text not null default '[]');
create table device_addresses (node_id integer not null references nodes(id) on delete cascade, device_id integer not null references devices(id) on delete cascade, address text not null, added_rev integer not null default 0, primary key (node_id, device_id), unique (node_id, address)) without rowid;
create table node_usage (node_id integer not null references nodes(id) on delete cascade, user_id integer not null references users(id) on delete cascade, period_start integer not null, used_bytes integer not null, up_bytes integer not null default 0, down_bytes integer not null default 0, banked_bytes integer not null default 0, reported_at integer not null, primary key (node_id, user_id)) without rowid;
create table node_resets (node_id integer not null references nodes(id) on delete cascade, user_id integer not null references users(id) on delete cascade, totals integer not null default 0, wanted_at integer not null, primary key (node_id, user_id)) without rowid;
create table xray_inbounds (tag text primary key, protocol text not null, host text not null default '', created integer not null, server_key blob);
create table xray_clients (tag text not null references xray_inbounds(tag) on delete cascade, user_id integer not null references users(id) on delete cascade, secret blob not null, primary key (tag, user_id)) without rowid;
create table gateway_use (key_id integer not null, user_id integer not null references users(id) on delete cascade, first_at integer not null, last_at integer not null, primary key (key_id, user_id)) without rowid;
create table endpoint_use (endpoint text not null, user_id integer not null references users(id) on delete cascade, last_at integer not null, primary key (endpoint, user_id)) without rowid;
insert into nodes (id, uid, name, slug, pool_v4, created) values (1, randomblob(16), 'Node 1', 'node-1', '10.66.0.0/16', cast(strftime('%s', 'now') as integer));
";

/// Steps from one version to the next, applied in order to a file older than the code. Entry `n` takes a file from version `n + 1` to `n + 2`. To add one, append its SQL here, update `SCHEMA` to the new layout (a fresh file gets `SCHEMA` directly) and never edit a step that has shipped. Each step runs in its own transaction together with its version bump.
/// Entry 1 makes node 1, the node on the panel's own socket, out of today's single node: its pool is the setting `pool_v4`, and every device keeps its address as the address it has at node 1. `devices` is rebuilt without `address`. The step is one transaction, so a failure leaves the file as it was.
/// Entry 3 records in `nodes.emptied` that a remote node was emptied before its link was taken out of node 1, so a removal that failed there is retried without asking the node again.
/// Entry 4 keeps the relays of a remote node in `nodes.relays`, as the list that node 1 keeps in its settings.
/// Entry 5 gives a user their own order of the profiles, a JSON list of profile ids, or null to follow the global order of the settings.
pub const MIGRATIONS: &[&str] = &["alter table users add column proxy_password blob", NODES, SEVERAL, "alter table nodes add column emptied integer not null default 0", "alter table nodes add column relays text not null default '[]'", "alter table users add column profile_order text"];

const NODES: &str = "create table if not exists nodes (id integer primary key, uid blob not null unique, name text not null unique, slug text not null unique, link_id text, place integer not null default 0, pool_v4 text not null, settings text not null default '{}', wanted_rev integer not null default 0, applied_rev integer not null default 0, config_rev text, last_seen integer, last_error text, version text, counted integer not null default 1, max_rate integer, created integer not null);
insert or ignore into nodes (id, uid, name, slug, pool_v4, created) values (1, randomblob(16), 'Node 1', 'node-1', coalesce((select json_extract(value, '$.pool_v4') from settings where key = 'settings'), '10.66.0.0/16'), cast(strftime('%s', 'now') as integer));
create table if not exists device_addresses (node_id integer not null references nodes(id) on delete cascade, device_id integer not null references devices(id) on delete cascade, address text not null, added_rev integer not null default 0, primary key (node_id, device_id), unique (node_id, address)) without rowid;
insert or ignore into device_addresses (node_id, device_id, address) select 1, id, address from devices;
create table devices_next (id integer primary key, user_id integer not null references users(id) on delete cascade, name text not null, public_key text not null, secret_hash blob not null, transport_secret blob not null, private_key blob, state text not null, token_gen integer not null, created integer not null, confirmed_at integer, last_seen integer, mirror_name blob, mirror_key blob, mirror_gen integer, last_serial integer not null default 0);
insert into devices_next select id, user_id, name, public_key, secret_hash, transport_secret, private_key, state, token_gen, created, confirmed_at, last_seen, mirror_name, mirror_key, mirror_gen, last_serial from devices;
drop table devices;
alter table devices_next rename to devices;
create unique index devices_public_key on devices (public_key);";
/// Entry 2 is what several nodes need: a node is reached through the link of node 1 named by `link_tag`, a user has the nodes they may use and the time a quota cut lasts until, and what each node counted for each user and the usage resets that still have to reach a node are kept per node.
const SEVERAL: &str = "alter table users add column nodes text not null default '\"all\"';
alter table users add column cut_until integer;
alter table nodes add column link_tag text;
create table node_usage (node_id integer not null references nodes(id) on delete cascade, user_id integer not null references users(id) on delete cascade, period_start integer not null, used_bytes integer not null, up_bytes integer not null default 0, down_bytes integer not null default 0, banked_bytes integer not null default 0, reported_at integer not null, primary key (node_id, user_id)) without rowid;
create table node_resets (node_id integer not null references nodes(id) on delete cascade, user_id integer not null references users(id) on delete cascade, totals integer not null default 0, wanted_at integer not null, primary key (node_id, user_id)) without rowid;";
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
			// The copy is the undo of the upgrade, made before any step runs. It is created first, owner-only, and VACUUM INTO fills it from this connection, so the write-ahead log is in it.
			let copy = format!("{}.before-schema-{found}-to-{SCHEMA_VERSION}-{}", path.display(), now());
			let refuse = |error: String| format!("the database could not be copied to {copy} before its migration to version {SCHEMA_VERSION}, so it was not migrated: {error}");
			fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&copy).map_err(|error| refuse(error.to_string()))?;
			if let Err(error) = connection.execute("vacuum into ?", [&copy]) {
				let _ = fs::remove_file(&copy);
				return Err(refuse(error.to_string()));
			}
			tracing::info!("the database was copied to {copy} before its migration from version {found} to {SCHEMA_VERSION}");
			let prefix = format!("{}.before-schema-", path.file_name().unwrap_or_default().to_string_lossy());
			let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
			let mut copies: Vec<(i64, PathBuf)> = fs::read_dir(dir).into_iter().flatten().filter_map(Result::ok).filter_map(|entry| Some((entry.file_name().to_str()?.strip_prefix(&prefix)?.rsplit('-').next()?.parse::<i64>().ok()?, entry.path()))).collect();
			copies.sort_by(|a, b| b.0.cmp(&a.0));
			for (_, old) in copies.iter().skip(3) {if let Err(error) = fs::remove_file(old) {tracing::warn!("the old copy {} could not be removed: {error}", old.display())}}
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
	use std::{os::unix::fs::PermissionsExt, sync::{atomic::{AtomicBool, Ordering}, Arc}};

	/// The layout of version 2, the last one with a single node.
	const SCHEMA_V2: &str = include_str!("../tests/golden/schema_v2.sql");

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
		assert_eq!(SCHEMA_VERSION, 7);
		assert_eq!(version(&connection), 7);
		assert_eq!(connection.query_row("select count(*) from sqlite_master where type = 'table'", [], |row| row.get::<_, i64>(0)).unwrap(), 17);
		assert_eq!(connection.query_row("select id, name, pool_v4 from nodes", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))).unwrap(), (1, "Node 1".into(), "10.66.0.0/16".into()));
	}

	#[test]
	fn a_migrated_file_has_the_schema_of_a_fresh_one() {
		let (mut fresh, mut migrated) = (memory(), memory());
		migrate(&mut fresh, MIGRATIONS).unwrap();
		migrated.execute_batch(&SCHEMA_V2.replace(", proxy_password blob", "")).unwrap();
		migrated.pragma_update(None, "user_version", 1).unwrap();
		migrate(&mut migrated, MIGRATIONS).unwrap();
		// A renamed table is stored with its name in quotes.
		let dump = |connection: &Connection| connection.prepare("select sql from sqlite_master where sql is not null order by name").unwrap().query_map([], |row| row.get::<_, String>(0).map(|sql| sql.replace('"', ""))).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
		assert_eq!(dump(&migrated), dump(&fresh));
	}

	#[test]
	fn the_move_to_nodes_makes_node_1_of_the_one_node_and_keeps_every_address() {
		let mut connection = memory();
		connection.execute_batch(SCHEMA_V2).unwrap();
		connection.pragma_update(None, "user_version", 2).unwrap();
		connection.execute("insert into settings (key, value) values ('settings', '{\"pool_v4\": \"10.7.0.0/24\"}')", []).unwrap();
		connection.execute("insert into users (id, name, device_limit, created, record_id, sub_id, token_lookup, token_created) values (1, 'a', 3, 1, x'00', 's', x'01', 1)", []).unwrap();
		for (id, address) in [(1, "10.7.0.2"), (2, "10.7.0.9")] {connection.execute("insert into devices (id, user_id, name, public_key, secret_hash, address, transport_secret, state, token_gen, created) values (?, 1, 'd', ?, x'00', ?, x'00', 'enrolled', 1, 1)", params![id, format!("key{id}"), address]).unwrap();}
		migrate(&mut connection, MIGRATIONS).unwrap();
		assert_eq!(version(&connection), 7);
		assert_eq!(connection.query_row("select id, pool_v4, link_id, place, counted from nodes", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?))).unwrap(), (1, "10.7.0.0/24".into(), None, 0, 1));
		let addresses: Vec<(i64, i64, String)> = connection.prepare("select node_id, device_id, address from device_addresses order by device_id").unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<Result<_, _>>().unwrap();
		assert_eq!(addresses, vec![(1, 1, "10.7.0.2".to_string()), (1, 2, "10.7.0.9".to_string())]);
		assert_eq!(connection.query_row("select profile_order from users", [], |row| row.get::<_, Option<String>>(0)).unwrap(), None, "a user from before follows the global profile order");
		assert_eq!(connection.query_row("select count(*) from pragma_table_info('devices') where name = 'address'", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
		assert_eq!(connection.query_row("select count(*), min(public_key) from devices", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))).unwrap(), (2, "key1".into()));
		connection.execute("delete from devices where id = 1", []).unwrap();
		assert_eq!(connection.query_row("select count(*) from device_addresses", [], |row| row.get::<_, i64>(0)).unwrap(), 1, "an address goes with its device");
		migrate(&mut connection, MIGRATIONS).unwrap();
		assert_eq!(connection.query_row("select count(*) from nodes", [], |row| row.get::<_, i64>(0)).unwrap(), 1, "a second run changes nothing");
	}

	#[test]
	fn a_file_without_settings_gets_the_default_pool_at_node_1() {
		let mut connection = memory();
		connection.execute_batch(SCHEMA_V2).unwrap();
		connection.pragma_update(None, "user_version", 2).unwrap();
		migrate(&mut connection, MIGRATIONS).unwrap();
		assert_eq!(connection.query_row("select pool_v4 from nodes where id = 1", [], |row| row.get::<_, String>(0)).unwrap(), "10.66.0.0/16");
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

	/// A database file of the layout of version 2, as an older panel left it, in a directory of its own named after the test.
	fn version_2(name: &str) -> (PathBuf, PathBuf) {
		let dir = std::env::temp_dir().join(format!("vwdb-{name}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let path = dir.join("panel.db");
		let connection = Connection::open(&path).unwrap();
		connection.execute_batch(SCHEMA_V2).unwrap();
		connection.pragma_update(None, "user_version", 2).unwrap();
		(dir, path)
	}

	/// The copies made before a migration in `dir`, sorted by name.
	fn copies(dir: &Path) -> Vec<PathBuf> {
		let mut found: Vec<PathBuf> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.to_string_lossy().contains(".before-schema-")).collect();
		found.sort();
		found
	}

	#[test]
	fn a_migration_copies_the_database_first_and_the_copy_is_the_old_version() {
		let (dir, path) = version_2("copy-first");
		let _db = Db::open(&path).unwrap();
		let made = copies(&dir);
		assert_eq!(made.len(), 1, "{made:?}");
		assert!(made[0].to_string_lossy().contains(&format!("panel.db.before-schema-2-to-{SCHEMA_VERSION}-")), "{made:?}");
		let copy = Connection::open(&made[0]).unwrap();
		assert_eq!(version(&copy), 2);
		assert_eq!(copy.query_row("select count(*) from sqlite_master where name = 'nodes'", [], |row| row.get::<_, i64>(0)).unwrap(), 0, "the copy has the layout of version 2");
		assert_eq!(fs::metadata(&made[0]).unwrap().permissions().mode() & 0o777, 0o600);
	}

	#[test]
	fn a_second_start_makes_no_copy() {
		let (dir, path) = version_2("copy-second");
		let _first = Db::open(&path).unwrap();
		let _second = Db::open(&path).unwrap();
		assert_eq!(copies(&dir).len(), 1, "a file at the newest version is not copied again");
	}

	#[test]
	fn the_copies_are_capped_at_the_three_newest() {
		let (dir, path) = version_2("copy-cap");
		for stamp in [1000, 2000, 3000, 4000] {fs::write(dir.join(format!("panel.db.before-schema-2-to-{SCHEMA_VERSION}-{stamp}")), b"").unwrap()}
		let _db = Db::open(&path).unwrap();
		let stamps: Vec<i64> = copies(&dir).iter().map(|copy| copy.to_string_lossy().rsplit('-').next().unwrap().parse().unwrap()).collect();
		assert_eq!(stamps.len(), 3, "{stamps:?}");
		assert!(stamps.iter().all(|stamp| *stamp >= 3000), "the two oldest are removed: {stamps:?}");
	}

	#[test]
	fn a_fresh_database_makes_no_copy() {
		let dir = std::env::temp_dir().join(format!("vwdb-copy-fresh-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let _db = Db::open(&dir.join("panel.db")).unwrap();
		assert!(copies(&dir).is_empty());
	}

	#[test]
	fn a_copy_that_cannot_be_made_refuses_the_migration() {
		let dir = std::env::temp_dir().join(format!("vwdb-copy-refused-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let path = dir.join(format!("{}.db", "a".repeat(240)));
		let connection = Connection::open(&path).unwrap();
		connection.execute_batch(SCHEMA_V2).unwrap();
		connection.pragma_update(None, "user_version", 2).unwrap();
		drop(connection);
		let error = Db::open(&path).err().unwrap();
		assert!(error.contains("could not be copied"), "{error}");
		assert_eq!(version(&Connection::open(&path).unwrap()), 2, "the file is left at its version");
	}
}
