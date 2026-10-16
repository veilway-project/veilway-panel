//! Backup and restore: one file with a snapshot of the database, the sealed-secret keys and the signing keys, encrypted with a passphrase.
//!
//! Layout (`.vwbackup`), all numbers big-endian:
//! `magic "VWPBACKP"` (8) | `format version` (1) | `argon2id memory in KiB` (4) | `passes` (4) | `lanes` (4) | `salt` (16) | `nonce` (12) | ChaCha20-Poly1305 of the content with a 16 byte tag.
//! The first 49 bytes are the header and are the AAD. The content is three sections, each a 4 byte length and the bytes: database, `panel.keys`, signing keys.
use crate::{app::{App, SigningEntry}, config::Config, crypto::{self, now}, db::{audit, migrate, MIGRATIONS}, http::{ok, Body, Ctx, Failure}};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::{extract::{FromRequestParts, State}, http::request::Parts, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use rusqlite::Connection;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fs::{self, File}, io, os::unix::fs::PermissionsExt, path::{Path, PathBuf}, sync::{atomic::Ordering, Arc}};
use time::OffsetDateTime;
use tokio::sync::{Semaphore, SemaphorePermit};

const MAGIC: &[u8; 8] = b"VWPBACKP";
const FORMAT: u8 = 1;
const HEADER: usize = 49;
/// Memory in KiB, passes and lanes of a new file. A file's own are read back from its header, up to `COST_MAX`.
const COST: (u32, u32, u32) = (65_536, 3, 1);
const COST_MAX: (u32, u32, u32) = (262_144, 10, 16);
/// Largest backup file, and so the largest restore: the content is read into memory.
pub const FILE_MAX: usize = 32 << 20;
/// The JSON body of a restore: the file in base64 and a passphrase.
pub const BODY_MAX: usize = FILE_MAX.div_ceil(3) * 4 + 4096;
pub const PASSPHRASE_MIN: usize = 12;
const PASSPHRASE_MAX: usize = 1024;
/// One backup or restore at a time: each holds the content in memory and runs a memory-hard hash.
static BUSY: Semaphore = Semaphore::const_new(1);
/// How many `pre-restore-*` folders are kept.
const KEPT: usize = 3;

/// Taken before the body is read, so a second backup or restore is refused without reading its file.
pub struct Turn {_permit: SemaphorePermit<'static>}

impl FromRequestParts<Arc<App>> for Turn {
	type Rejection = Failure;
	async fn from_request_parts(_: &mut Parts, _: &Arc<App>) -> Result<Self, Failure> {BUSY.try_acquire().map(|permit| Turn {_permit: permit}).map_err(|_| Failure::conflict("Another backup or restore is running."))}
}

pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
	let mut name = path.as_os_str().to_owned();
	name.push(suffix);
	PathBuf::from(name)
}

/// Its existence says a restore has staged all three files and must be finished. It is written last, after the staged files are complete and synced, and removed last.
pub fn marker(cfg: &Config) -> PathBuf {with_suffix(&cfg.database, ".restore-pending")}

fn sync_dirs(cfg: &Config) -> io::Result<()> {
	for path in [&cfg.database, &cfg.keys, &cfg.signing] {File::open(path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;}
	Ok(())
}

/// Puts the staged files in place, the database first. It runs again at start-up when a restore was cut short: every staged file is complete once the marker exists, so finishing is the only direction a restore goes.
pub fn complete(cfg: &Config) -> io::Result<()> {
	let staged = with_suffix(&cfg.database, ".restore");
	if staged.exists() {
		for suffix in ["-wal", "-shm"] {let _ = fs::remove_file(with_suffix(&cfg.database, suffix));}
		fs::rename(&staged, &cfg.database)?;
	}
	for target in [&cfg.keys, &cfg.signing] {
		let staged = with_suffix(target, ".restore");
		if staged.exists() {fs::rename(&staged, target)?}
	}
	sync_dirs(cfg)?;
	fs::remove_file(marker(cfg))?;
	sync_dirs(cfg)
}

fn derive(passphrase: &str, salt: &[u8], (memory, passes, lanes): (u32, u32, u32)) -> Result<[u8; 32], String> {
	let mut key = [0u8; 32];
	Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(memory, passes, lanes, Some(32)).map_err(|error| error.to_string())?).hash_password_into(passphrase.as_bytes(), salt, &mut key).map_err(|error| error.to_string())?;
	Ok(key)
}

/// Encrypts `content` under a key made from the passphrase.
pub fn seal(passphrase: &str, content: &[u8]) -> Result<Vec<u8>, String> {
	let (salt, nonce): ([u8; 16], [u8; 12]) = (crypto::random(), crypto::random());
	let mut file = [MAGIC.as_slice(), &[FORMAT], &COST.0.to_be_bytes(), &COST.1.to_be_bytes(), &COST.2.to_be_bytes(), &salt, &nonce].concat();
	let key = derive(passphrase, &salt, COST)?;
	let mut body = content.to_vec();
	LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("32 byte key")).seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(file.as_slice()), &mut body).map_err(|_| "The backup could not be encrypted.".to_string())?;
	file.extend(body);
	Ok(file)
}

/// Checks the header, then decrypts and authenticates the whole file in place. Nothing in it is read before that has passed.
pub fn open(passphrase: &str, mut file: Vec<u8>) -> Result<Vec<u8>, String> {
	if file.len() > FILE_MAX {return Err("The file is too large to be a backup of this panel.".into())}
	if file.len() < HEADER + 16 || &file[..8] != MAGIC {return Err("This is not a Veilway panel backup.".into())}
	if file[8] > FORMAT {return Err("This backup was made by a newer panel. Update this panel first.".into())}
	if file[8] != FORMAT {return Err("This backup has a format this panel does not know.".into())}
	let header: [u8; HEADER] = file[..HEADER].try_into().expect("the header");
	let number = |at: usize| u32::from_be_bytes(header[at..at + 4].try_into().expect("4 bytes"));
	let cost = (number(9), number(13), number(17));
	if cost.0 > COST_MAX.0 || cost.1 > COST_MAX.1 || cost.2 > COST_MAX.2 {return Err("The backup asks for more work to open than this panel allows.".into())}
	let key = derive(passphrase, &header[21..37], cost).map_err(|_| "The backup's header is not valid.".to_string())?;
	file.drain(..HEADER);
	let length = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("32 byte key")).open_in_place(Nonce::try_assume_unique_for_key(&header[37..49]).expect("12 bytes"), Aad::from(&header[..]), &mut file).map_err(|_| "Wrong passphrase, or the file is damaged.".to_string())?.len();
	file.truncate(length);
	Ok(file)
}

pub fn pack(sections: [&[u8]; 3]) -> Vec<u8> {sections.iter().flat_map(|section| (section.len() as u32).to_be_bytes().into_iter().chain(section.iter().copied())).collect()}

pub fn unpack(content: &[u8]) -> Result<[Vec<u8>; 3], String> {
	let (mut rest, mut sections) = (content, Vec::new());
	for _ in 0..3 {
		let length = rest.get(..4).map(|bytes| u32::from_be_bytes(bytes.try_into().expect("4 bytes")) as usize).ok_or("The backup's content is cut short.")?;
		sections.push(rest.get(4..4 + length).ok_or("The backup's content is cut short.")?.to_vec());
		rest = &rest[4 + length..];
	}
	if !rest.is_empty() {return Err("The backup has data it should not have.".into())}
	Ok(sections.try_into().expect("three sections"))
}

/// What stops a staged database from replacing the live one, or None. Its migrations run here, on the staged copy, so a backup this panel cannot migrate is refused before the swap.
fn staged_refusal(staged: &mut Connection, migrations: &[&str]) -> rusqlite::Result<Option<String>> {
	if staged.query_row("pragma integrity_check", [], |row| row.get::<_, String>(0))? != "ok" {return Ok(Some("The database in the backup is damaged.".into()))}
	if staged.query_row("pragma user_version", [], |row| row.get::<_, i64>(0))? > 1 + migrations.len() as i64 {return Ok(Some("This backup was made by a newer panel. Update this panel first.".into()))}
	if staged.query_row("select count(*) from sqlite_master where type = 'table' and name in ('admins', 'sessions', 'users', 'settings')", [], |row| row.get::<_, i64>(0))? != 4 {return Ok(Some("The database in the backup is not a panel database.".into()))}
	Ok(migrate(staged, migrations).err().map(|error| format!("The database in the backup cannot be moved to this panel's version: {error}")))
}

#[derive(Deserialize, JsonSchema)]
pub struct DownloadIn {
	/// At least 12 characters. It cannot be recovered: a backup without it is useless.
	pub passphrase: String,
}

#[derive(Serialize, JsonSchema)]
pub struct Downloaded {
	pub filename: String,
	/// The encrypted file, standard base64.
	pub file: String,
}

fn passphrase_ok(passphrase: &str) -> Result<(), Failure> {
	if passphrase.chars().count() < PASSPHRASE_MIN {return Err(Failure::bad(format!("The passphrase needs at least {PASSPHRASE_MIN} characters.")))}
	if passphrase.len() > PASSPHRASE_MAX {return Err(Failure::bad("The passphrase is too long."))}
	Ok(())
}

pub async fn download(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, _turn: Turn, Body(input): Body<DownloadIn>) -> Result<Response, Failure> {
	passphrase_ok(&input.passphrase)?;
	let (db, cfg) = (app.db.clone(), app.cfg.clone());
	let file = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, Failure> {
		let snapshot = cfg.database.with_extension("snapshot");
		let _ = fs::remove_file(&snapshot);
		crypto::write_private(&snapshot, &[], false).map_err(Failure::internal)?;
		let target = snapshot.to_string_lossy().to_string();
		let made = db.blocking(move |connection| connection.execute("vacuum into ?", [target]));
		let database = fs::read(&snapshot);
		let _ = fs::remove_file(&snapshot);
		made.map_err(Failure::internal)?.map_err(Failure::internal)?;
		let content = pack([&database.map_err(Failure::internal)?, &fs::read(&cfg.keys).map_err(Failure::internal)?, &fs::read(&cfg.signing).map_err(Failure::internal)?]);
		if content.len() + HEADER + 16 > FILE_MAX {return Err(Failure::conflict("The database is larger than a backup can hold."))}
		seal(&input.passphrase, &content).map_err(Failure::internal)
	}).await.map_err(Failure::internal)??;
	app.db.audit(&ctx.actor, &ctx.source, "backup.download", "panel", &format!("{} bytes", file.len())).await;
	let at = OffsetDateTime::from_unix_timestamp(now()).map_err(Failure::internal)?;
	ok(&Downloaded {filename: format!("veilway-panel-{:04}{:02}{:02}T{:02}{:02}{:02}Z.vwbackup", at.year(), u8::from(at.month()), at.day(), at.hour(), at.minute(), at.second()), file: STANDARD.encode(file)})
}

#[derive(Deserialize, JsonSchema)]
pub struct RestoreIn {
	/// The backup file, standard base64.
	pub file: String,
	pub passphrase: String,
}

#[derive(Serialize, JsonSchema)]
pub struct Restored {
	pub ok: bool,
	/// The folder in the data directory that holds the database and keys this restore replaced.
	pub saved_as: String,
}

pub async fn restore(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, _turn: Turn, Body(input): Body<RestoreIn, BODY_MAX>) -> Result<Response, Failure> {
	let worker = app.clone();
	let result = tokio::task::spawn_blocking(move || -> Result<String, Failure> {
		let (db, cfg) = (worker.db.clone(), worker.cfg.clone());
		let RestoreIn {file, passphrase} = input;
		let bytes = STANDARD.decode(&file).map_err(|_| Failure::bad("This is not a Veilway panel backup."))?;
		drop(file);
		let content = open(&passphrase, bytes).map_err(Failure::bad)?;
		let [database, keys, signing] = unpack(&content).map_err(Failure::bad)?;
		drop(content);
		if keys.len() != 96 {return Err(Failure::bad("The key file in the backup has the wrong length."))}
		if !serde_json::from_slice::<Vec<SigningEntry>>(&signing).is_ok_and(|entries| !entries.is_empty() && entries.iter().all(|entry| URL_SAFE_NO_PAD.decode(&entry.seed).is_ok_and(|seed| seed.len() == 32))) {return Err(Failure::bad("The signing keys in the backup cannot be read."))}
		let (new_database, new_keys, new_signing) = (with_suffix(&cfg.database, ".restore"), with_suffix(&cfg.keys, ".restore"), with_suffix(&cfg.signing, ".restore"));
		for (path, content) in [(&new_database, &database), (&new_keys, &keys), (&new_signing, &signing)] {
			let _ = fs::remove_file(path);
			crypto::write_private(path, content, false).map_err(Failure::internal)?;
		}
		drop(database);
		let refusal = (|| -> rusqlite::Result<Option<String>> {
			let mut staged = Connection::open(&new_database)?;
			staged.execute_batch("pragma trusted_schema=off")?;
			if let Some(message) = staged_refusal(&mut staged, MIGRATIONS)? {return Ok(Some(message))}
			staged.execute("delete from sessions", [])?;
			staged.execute("update api_tokens set revoked_at = ? where revoked_at is null", [now()])?;
			audit(&staged, &ctx.actor, &ctx.source, "backup.restore", "panel", "restored from a backup; every session ended and every API token was revoked");
			Ok(None)
		})().unwrap_or(Some("The database in the backup cannot be read.".into()));
		if let Some(message) = refusal {
			for path in [&new_database, &new_keys, &new_signing] {let _ = fs::remove_file(path);}
			return Err(Failure::bad(message));
		}
		// From here the panel refuses changes and its upkeep stops writing, until the process exits.
		worker.restoring.store(true, Ordering::SeqCst);
		let folder = format!("pre-restore-{}", now());
		let data = cfg.database.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
		let saved = data.join(&folder);
		fs::create_dir(&saved).map_err(Failure::internal)?;
		fs::set_permissions(&saved, fs::Permissions::from_mode(0o700)).map_err(Failure::internal)?;
		crypto::write_private(&saved.join("panel.db"), &[], false).map_err(Failure::internal)?;
		let (target, detail) = (saved.join("panel.db").to_string_lossy().to_string(), format!("restore started; the previous files are in {folder}"));
		db.blocking(move |live| {
			audit(live, &ctx.actor, &ctx.source, "backup.restore", "panel", &detail);
			live.execute("vacuum into ?", [target])
			}).map_err(Failure::internal)?.map_err(Failure::internal)?;
		fs::copy(&cfg.keys, saved.join("panel.keys")).map_err(Failure::internal)?;
		fs::copy(&cfg.signing, saved.join("signing.keys")).map_err(Failure::internal)?;
		crypto::write_private(&marker(&cfg), b"", false).map_err(Failure::internal)?;
		sync_dirs(&cfg).map_err(Failure::internal)?;
		complete(&cfg).map_err(Failure::internal)?;
		let mut old: Vec<(i64, PathBuf)> = fs::read_dir(&data).map_err(Failure::internal)?.filter_map(|entry| {
			let entry = entry.ok()?;
			Some((entry.file_name().to_str()?.strip_prefix("pre-restore-")?.parse().ok()?, entry.path())).filter(|(_, path)| entry.file_type().is_ok_and(|kind| kind.is_dir()) && !path.is_symlink())
		}).collect();
		old.sort();
		for (_, path) in old.iter().take(old.len().saturating_sub(KEPT)) {let _ = fs::remove_dir_all(path);}
		Ok(folder)
	}).await.map_err(Failure::internal)?;
	// A restore that failed before the marker changed nothing, so the panel goes on as it was.
	if result.is_err() && !marker(&app.cfg).exists() {app.restoring.store(false, Ordering::SeqCst)}
	let saved_as = result?;
	app.restart.notify_one();
	ok(&Restored {ok: true, saved_as})
}

#[cfg(test)]
mod tests {
	use super::*;

	const PASSPHRASE: &str = "a long enough passphrase";

	fn sample() -> Vec<u8> {pack([b"database bytes", &[7u8; 96], b"[]"])}

	#[test]
	fn a_backup_round_trips() {
		let file = seal(PASSPHRASE, &sample()).unwrap();
		assert_eq!(&file[..8], MAGIC);
		assert_eq!(file[8], FORMAT);
		let [database, keys, signing] = unpack(&open(PASSPHRASE, file.clone()).unwrap()).unwrap();
		assert_eq!((database.as_slice(), keys.len(), signing.as_slice()), (b"database bytes".as_slice(), 96, b"[]".as_slice()));
	}

	#[test]
	fn a_wrong_passphrase_or_a_changed_byte_opens_nothing() {
		let file = seal(PASSPHRASE, &sample()).unwrap();
		assert!(open("another long passphrase", file.clone()).is_err());
		for at in [0, 8, 10, 25, 40, HEADER, file.len() - 1] {
			let mut changed = file.clone();
			changed[at] ^= 1;
			assert!(open(PASSPHRASE, changed).is_err(), "byte {at}");
		}
	}

	#[test]
	fn a_cut_file_or_one_of_the_wrong_kind_is_refused() {
		let file = seal(PASSPHRASE, &sample()).unwrap();
		for length in [0, 8, HEADER, HEADER + 15, file.len() - 1] {assert!(open(PASSPHRASE, file[..length].to_vec()).is_err(), "{length} bytes")}
		assert!(open(PASSPHRASE, [file.as_slice(), b"x"].concat()).is_err());
		assert!(open(PASSPHRASE, vec![0u8; 200]).unwrap_err().contains("not a Veilway"));
	}

	#[test]
	fn a_newer_format_and_too_much_work_are_refused_before_any_hashing() {
		let mut file = seal(PASSPHRASE, &sample()).unwrap();
		file[8] = FORMAT + 1;
		assert!(open(PASSPHRASE, file.clone()).unwrap_err().contains("newer"));
		file[8] = FORMAT;
		file[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
		assert!(open(PASSPHRASE, file.clone()).unwrap_err().contains("more work"));
	}

	#[test]
	fn a_staged_database_is_migrated_or_refused_before_the_swap() {
		let mut staged = rusqlite::Connection::open_in_memory().unwrap();
		migrate(&mut staged, &[]).unwrap();
		assert!(staged_refusal(&mut staged, &["this is not sql"]).unwrap().unwrap().contains("cannot be moved"));
		assert_eq!(staged.query_row("pragma user_version", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
		assert_eq!(staged_refusal(&mut staged, &["create table extra (id integer)"]).unwrap(), None);
		assert_eq!(staged.query_row("pragma user_version", [], |row| row.get::<_, i64>(0)).unwrap(), 2);
	}

	#[test]
	fn an_oversize_file_is_refused() {assert!(open(PASSPHRASE, vec![0u8; FILE_MAX + 1]).unwrap_err().contains("too large"))}

	#[test]
	fn content_with_a_missing_or_extra_section_is_refused() {
		assert!(unpack(&sample()[..20]).is_err());
		assert!(unpack(&[sample(), vec![0]].concat()).is_err());
		assert!(unpack(&[0, 0, 0, 9, 1]).is_err());
	}
}
