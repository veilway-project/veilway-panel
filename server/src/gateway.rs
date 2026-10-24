//! The gateway keys: the X25519 keys every native subscription request is sealed to, their file, the gateway that opens requests with them, and the switch, theft and loss actions of the subscription format page, "Gateway keys".
use crate::{app::{App, LOCAL}, crypto::{self, now}, db::audit, http::{ok, Body, Ctx, Failure}, subs::USER_COLUMNS};
use axum::{extract::State, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use rusqlite::{params, OptionalExtension};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::{Path as FilePath, PathBuf}, sync::Arc};
use veilway_proto::subscription::exchange::{Gateway, GatewayKey, Keyring, Opened, Refusal, Unsealed};
use x25519_dalek::{PublicKey, StaticSecret};

const DAY: i64 = 86_400;
/// The panel reminds the operator to switch after this long.
pub const REMIND_AFTER: i64 = 180 * DAY;
/// Accounts that sent a request under a retired key are counted over this long.
const RECENT: i64 = 30 * DAY;

/// A key the panel holds the private half of: the active one, or a retired one that still opens requests.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Held {pub id: u8, pub private: String, pub created: i64, pub retired_at: Option<i64>}

/// The next key: only its public half is on this host, and its private half is the operator's to keep apart.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Upcoming {pub id: u8, pub public: String, pub created: i64}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyFile {pub held: Vec<Held>, pub next: Upcoming, pub last_id: u8}

impl KeyFile {
	/// Whether the file can open requests: an active key, every private half readable, no id twice.
	pub fn usable(&self) -> bool {self.held.iter().any(|key| key.retired_at.is_none()) && self.held.iter().all(|key| private_of(&key.private).is_some()) && self.held.iter().enumerate().all(|(place, key)| self.held[..place].iter().all(|earlier| earlier.id != key.id))}
}

/// How many requests each kind of refusal turned away since the start, and how many were served.
#[derive(Default, Serialize, JsonSchema, Clone, Debug)]
pub struct Counts {pub served: u64, pub size: u64, pub key: u64, pub open: u64, pub request: u64, pub window: u64, pub replay: u64, pub source: u64,
	/// Requests turned away because the gateway's memory of acted requests was full.
	pub full: u64}

pub fn public_of(private: &[u8; 32]) -> [u8; 32] {PublicKey::from(&StaticSecret::from(*private)).to_bytes()}

fn private_of(text: &str) -> Option<[u8; 32]> {URL_SAFE_NO_PAD.decode(text.trim()).ok()?.try_into().ok()}

fn made(id: u8) -> ([u8; 32], Upcoming) {
	let private = crypto::random::<32>();
	(private, Upcoming {id, public: URL_SAFE_NO_PAD.encode(public_of(&private)), created: now()})
}

/// The keys, the gateway built from the private ones, and the counters. `file` is None while the keys are lost or unreadable, and then no request is opened.
pub struct Hold {path: PathBuf, next_path: PathBuf, file: Option<KeyFile>, gateway: Option<Gateway>, pub counts: Counts, warned_steps: u64, full_logged: i64}

impl Hold {
	/// Reads the key file. Missing with `create` makes the first keys, which is setup: the next key's private half goes to its own file. Anything else that cannot be read leaves the keys lost, loudly, and never makes new ones.
	pub fn load(path: &FilePath, next_path: &FilePath, create: bool) -> Result<Self, String> {
		let mut hold = Self {path: path.to_path_buf(), next_path: next_path.to_path_buf(), file: None, gateway: None, counts: Counts::default(), warned_steps: 0, full_logged: 0};
		match fs::read(path) {
			Ok(bytes) => {
				let mode = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?.permissions().mode();
				hold.file = if mode & 0o077 != 0 {tracing::error!("{}: the gateway key file must be mode 600", path.display()); None} else {serde_json::from_slice::<KeyFile>(&bytes).map_err(|error| tracing::error!("{}: {error}", path.display())).ok().filter(KeyFile::usable)};
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
				let (private, active) = made(crypto::random::<1>()[0]);
				let (next_private, next) = made(active.id.wrapping_add(1));
				hold.file = Some(KeyFile {held: vec![Held {id: active.id, private: URL_SAFE_NO_PAD.encode(private), created: active.created, retired_at: None}], last_id: next.id, next});
				hold.save()?;
				crypto::write_private(next_path, URL_SAFE_NO_PAD.encode(next_private).as_bytes(), true).map_err(|error| format!("{}: {error}", next_path.display()))?;
			}
			Err(error) => tracing::error!("{}: {error}", path.display()),
		}
		hold.rebuild();
		Ok(hold)
	}
	pub fn save(&self) -> Result<(), String> {crypto::write_private(&self.path, &serde_json::to_vec(&self.file).unwrap_or_default(), true).map_err(|error| format!("{}: {error}", self.path.display()))}
	/// Builds the gateway again from the private keys held. Its replay memory starts empty, so it refuses any request from before this moment, as after a restart.
	fn rebuild(&mut self) {
		self.gateway = self.file.as_ref().and_then(|file| {
			let keys: Vec<(u8, [u8; 32])> = file.held.iter().filter_map(|key| Some((key.id, private_of(&key.private)?))).collect();
			Gateway::new(&keys, now().max(0) as u64, &mut crypto::fill).map_err(|error| tracing::error!("the gateway keys cannot be used: {error}")).ok()
		});
		self.warned_steps = 0;
	}
	pub fn loaded(&self) -> bool {self.gateway.is_some()}
	pub fn file(&self) -> Option<&KeyFile> {self.file.as_ref()}
	pub fn active(&self) -> Option<&Held> {self.file.as_ref()?.held.iter().find(|key| key.retired_at.is_none())}
	/// The keys a document lists: the active one, then the next. A link carries the first.
	pub fn listed(&self) -> Vec<GatewayKey> {
		let Some(file) = self.file.as_ref() else {return Vec::new()};
		let active = self.active().and_then(|key| GatewayKey::new(key.id, public_of(&private_of(&key.private)?)));
		let next = URL_SAFE_NO_PAD.decode(&file.next.public).ok().and_then(|bytes| GatewayKey::new(file.next.id, bytes.try_into().ok()?));
		active.into_iter().chain(next).collect()
	}
	/// The keys to open bodies with outside the lock on this hold. None while no key is held.
	pub fn keyring(&self) -> Option<Arc<Keyring>> {self.gateway.as_ref().map(Gateway::keyring)}
	/// Judges a body that `keyring` opened: the window, the memory and the source's limit. None while no key is held. The refusals are counted and nothing else is told of them.
	pub fn admit(&mut self, unsealed: Result<Unsealed, Refusal>, at: i64, charge: impl FnOnce() -> bool) -> Option<Result<Opened, Refusal>> {
		let gateway = self.gateway.as_mut()?;
		let result = unsealed.and_then(|unsealed| gateway.admit(unsealed, at.max(0) as u64, charge));
		if gateway.steps_back() > self.warned_steps {
			self.warned_steps = gateway.steps_back();
			tracing::warn!("the system clock stepped back ({} times since the gateway started): the request window did not move back with it", self.warned_steps);
		}
		match &result {
			Ok(_) => self.counts.served += 1,
			Err(Refusal::Size) => self.counts.size += 1,
			Err(Refusal::Key) => self.counts.key += 1,
			Err(Refusal::Open) => self.counts.open += 1,
			Err(Refusal::Request) => self.counts.request += 1,
			Err(Refusal::Window) => self.counts.window += 1,
			Err(Refusal::Replay) => self.counts.replay += 1,
			Err(Refusal::Source) => self.counts.source += 1,
			Err(Refusal::Full) => {
				self.counts.full += 1;
				if at - self.full_logged >= 60 {
					self.full_logged = at;
					tracing::warn!("the gateway's memory of acted requests is full ({} entries): new requests are answered as an unknown path until some expire. Either a flood of requests that open, or a burst the window will clear", gateway.remembered());
				}
			}
		}
		Some(result)
	}
	pub fn remembered(&self) -> usize {self.gateway.as_ref().map_or(0, Gateway::remembered)}
	pub fn steps_back(&self) -> u64 {self.gateway.as_ref().map_or(0, Gateway::steps_back)}
	/// "Each new key takes the id after that of the last key the panel made", skipping an id still held.
	fn next_id(file: &KeyFile) -> u8 {(1..=255u8).map(|step| file.last_id.wrapping_add(step)).find(|id| *id != file.next.id && file.held.iter().all(|key| key.id != *id)).unwrap_or(file.last_id.wrapping_add(1))}
	/// Loads the next key: it becomes active and the old active key is retired. With `destroy` every key held, retired ones too, is destroyed instead (the action for a theft: whoever took the file took them all). A new next key is made. Gives the ids of the keys that stopped opening requests (all of them when destroyed, else none) and the id of the old active one, and the new next key's private half, which is shown once. Nothing changes in memory unless the file is written.
	fn switch(&mut self, supplied: &[u8; 32], destroy: bool) -> Result<(Vec<u8>, u8, [u8; 32]), String> {
		let mut file = self.file.clone().ok_or("There are no gateway keys to switch.")?;
		if !crypto::equal(&public_of(supplied), &URL_SAFE_NO_PAD.decode(&file.next.public).unwrap_or_default()) {return Err("That is not the private half of the next key.".into())}
		let old = file.held.iter().position(|key| key.retired_at.is_none()).ok_or("There is no active key.")?;
		let (old_id, at) = (file.held[old].id, now());
		let gone = if destroy {file.held.drain(..).map(|key| key.id).collect()} else {file.held[old].retired_at = Some(at); Vec::new()};
		file.held.push(Held {id: file.next.id, private: URL_SAFE_NO_PAD.encode(supplied), created: at, retired_at: None});
		let id = Self::next_id(&file);
		let (private, next) = made(id);
		file.last_id = id;
		file.next = next;
		let before = self.file.replace(file);
		if let Err(error) = self.save() {
			self.file = before;
			return Err(error)
		}
		self.rebuild();
		Ok((gone, old_id, private))
	}
	/// Whether anything is at the path of the key file: a file that cannot be read still counts, so that no new keys are written over one an operator can repair.
	fn on_disk(&self) -> bool {!matches!(fs::symlink_metadata(&self.path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)}
	/// New active and next keys when none can be read. Every key held is dropped: the old links stop opening. Refused while the key file exists.
	fn recreate(&mut self) -> Result<[u8; 32], String> {
		if self.on_disk() {return Err(format!("{} exists but cannot be used. Fix its permissions (mode 600, owned by the panel's user) or its content, or move it aside, and then make new keys.", self.path.display()))}
		let (private, active) = made(crypto::random::<1>()[0]);
		let (next_private, next) = made(active.id.wrapping_add(1));
		self.file = Some(KeyFile {held: vec![Held {id: active.id, private: URL_SAFE_NO_PAD.encode(private), created: active.created, retired_at: None}], last_id: next.id, next});
		self.save()?;
		self.rebuild();
		Ok(next_private)
	}
	/// The operator's key, kept from the lost file, becomes the active one under the id it had. A new next key is made. Refused while the key file exists, as `recreate` is.
	fn recover(&mut self, supplied: &[u8; 32], id: u8) -> Result<[u8; 32], String> {
		if self.on_disk() {return Err(format!("{} exists but cannot be used. Fix its permissions or its content, or move it aside, and then load the key.", self.path.display()))}
		let (next_private, next) = made(id.wrapping_add(1));
		self.file = Some(KeyFile {held: vec![Held {id, private: URL_SAFE_NO_PAD.encode(supplied), created: now(), retired_at: None}], last_id: next.id, next});
		self.save()?;
		self.rebuild();
		Ok(next_private)
	}
	/// Destroys the retired keys past `days`. Gives their ids.
	pub fn prune(&mut self, days: u32) -> Result<Vec<u8>, String> {
		let Some(file) = self.file.as_mut() else {return Ok(Vec::new())};
		let at = now();
		let gone: Vec<u8> = file.held.iter().filter(|key| key.retired_at.is_some_and(|retired| at - retired >= i64::from(days) * DAY)).map(|key| key.id).collect();
		if gone.is_empty() {return Ok(gone)}
		file.held.retain(|key| !gone.contains(&key.id));
		self.save()?;
		self.rebuild();
		Ok(gone)
	}
	pub fn next_on_host(&self) -> bool {self.next_path.exists()}
	/// Writes the next key's private half to its file. Where the operator moves it from.
	fn write_next(&self, private: &[u8; 32]) -> bool {crypto::write_private(&self.next_path, URL_SAFE_NO_PAD.encode(private).as_bytes(), true).is_ok()}
}

#[derive(Serialize, JsonSchema)]
pub struct KeyView {
	pub id: u8,
	/// First 16 bytes of the SHA-256 of the key, as the apps show it.
	pub fingerprint: String,
	pub created: i64,
}

#[derive(Serialize, JsonSchema)]
pub struct RetiredView {
	pub id: u8, pub fingerprint: String, pub retired_at: i64, pub destroy_at: i64,
	/// Accounts that sent a request under this key in the last 30 days.
	pub accounts_recent: i64,
	/// Accounts that ever sent a request under it.
	pub accounts: i64,
}

#[derive(Serialize, JsonSchema)]
pub struct NextView {
	pub id: u8, pub fingerprint: String, pub created: i64,
	/// The file of the next key's private half is still on this host. Whoever takes the active key from the host takes the next one with it: move the file away.
	pub on_host: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct GatewayOut {
	/// False while the keys are lost or unreadable: the endpoint answers every request as an unknown path.
	pub loaded: bool,
	pub active: Option<KeyView>, pub next: Option<NextView>, pub retired: Vec<RetiredView>,
	pub retired_days: u32,
	/// The active key is older than 180 days.
	pub switch_due: bool,
	/// Accounts with no device yet: they hold a link made under some key and have not imported it.
	pub accounts_without_device: i64,
	/// Accounts that sent a request under a key stolen earlier and whose tokens are not reset yet.
	pub affected: i64,
	pub counts: Counts, pub remembered: usize, pub clock_steps: u64,
	/// Whether the system reports its clock as synchronized, null when it cannot tell. The gateway needs a synchronized clock.
	pub clock_synchronized: Option<bool>,
}

fn fingerprint(public: &[u8]) -> String {
	let digest = crypto::sha256(public);
	digest[..16].chunks(2).map(|pair| format!("{:02x}{:02x}", pair[0], pair[1])).collect::<Vec<_>>().join(" ")
}

fn held_fingerprint(key: &Held) -> String {fingerprint(&private_of(&key.private).map(|private| public_of(&private)).unwrap_or_default())}

fn affected_ids(connection: &rusqlite::Connection) -> Vec<i64> {connection.query_row("select value from settings where key = 'gateway_affected'", [], |row| row.get::<_, String>(0)).optional().ok().flatten().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()}

async fn view(app: &Arc<App>) -> Result<GatewayOut, Failure> {
	let (file, counts, remembered, steps, on_host, loaded) = {
		let hold = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		(hold.file().cloned(), hold.counts.clone(), hold.remembered(), hold.steps_back(), hold.next_on_host(), hold.loaded())
	};
	let (days, at) = (app.settings().gateway_retired_days, now());
	let ids: Vec<u8> = file.iter().flat_map(|file| file.held.iter().filter(|key| key.retired_at.is_some()).map(|key| key.id)).collect();
	let (recent, ever, without, affected) = app.db.call(move |db| -> rusqlite::Result<(Vec<i64>, Vec<i64>, i64, i64)> {
		let count = |id: u8, since: i64| db.query_row("select count(*) from gateway_use where key_id = ? and last_at >= ?", params![id, since], |row| row.get::<_, i64>(0));
		let (mut recent, mut ever) = (Vec::new(), Vec::new());
		for id in &ids {recent.push(count(*id, at - RECENT)?); ever.push(count(*id, 0)?);}
		Ok((recent, ever, db.query_row("select count(*) from users where not exists (select 1 from devices where devices.user_id = users.id)", [], |row| row.get(0))?, affected_ids(db).len() as i64))
	}).await??;
	let mut places = recent.into_iter().zip(ever);
	Ok(GatewayOut {
		loaded,
		active: file.as_ref().and_then(|file| file.held.iter().find(|key| key.retired_at.is_none())).map(|key| KeyView {id: key.id, fingerprint: held_fingerprint(key), created: key.created}),
		next: file.as_ref().map(|file| NextView {id: file.next.id, fingerprint: fingerprint(&URL_SAFE_NO_PAD.decode(&file.next.public).unwrap_or_default()), created: file.next.created, on_host}),
		retired: file.iter().flat_map(|file| file.held.iter().filter_map(|key| key.retired_at.map(|retired| (key, retired)))).map(|(key, retired)| {let (accounts_recent, accounts) = places.next().unwrap_or((0, 0)); RetiredView {id: key.id, fingerprint: held_fingerprint(key), retired_at: retired, destroy_at: retired + i64::from(days) * DAY, accounts_recent, accounts}}).collect(),
		retired_days: days,
		switch_due: file.as_ref().and_then(|file| file.held.iter().find(|key| key.retired_at.is_none())).is_some_and(|key| at - key.created > REMIND_AFTER),
		accounts_without_device: without, affected, counts, remembered, clock_steps: steps, clock_synchronized: crate::statics::clock_synchronized(),
	})
}

pub async fn get(State(app): State<Arc<App>>) -> Result<Response, Failure> {ok(&view(&app).await?)}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwitchIn {
	/// The private half of the next key, 43 characters of base64url. Left out, the panel reads it from its `gateway_next` file.
	pub private: Option<String>,
	/// Only while no key file is on this host: the id the supplied key had (the number the key carried in the links and documents, as the panel showed it before the file was lost). The key becomes the active one under that id.
	pub id: Option<u8>,
	/// Only while no key file is on this host: must be true. Loading a key from the operator's hands makes it the active key, so this is the explicit yes.
	#[serde(default)] pub confirm: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct Switched {
	pub gateway: GatewayOut,
	/// The private half of the new next key. Shown once: move it away from this host and keep it. The panel keeps no copy except the file named in its config, which it lists as still on the host until the file is moved.
	pub next_private: String,
	/// False when the file for the new next key could not be written, so the shown key is the only copy.
	pub next_file_written: bool,
	/// Accounts that sent a request under a stolen key (for a theft only): their tokens are to be reset.
	pub affected: i64,
}

/// The key file and the database move together here: the whole action runs as a task of its own, so a request that is dropped half way cannot leave a changed key file with the accounts of its destroyed keys not marked.
async fn switch(app: &Arc<App>, ctx: Ctx, input: SwitchIn, theft: bool) -> Result<Response, Failure> {
	let supplied = match &input.private {
		Some(text) => text.clone(),
		None => fs::read_to_string(&app.cfg.gateway_next).map_err(|_| Failure::bad("The private half of the next key was not given, and the file for it is not on this host. Paste the key you put away."))?,
	};
	let supplied = private_of(&supplied).ok_or_else(|| Failure::bad("The next key's private half is 43 characters of base64url."))?;
	let app = app.clone();
	tokio::spawn(async move {
		if !app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).loaded() {
			if input.private.is_none() {return Err(Failure::bad("There are no gateway keys to switch. Paste the private half of the key that was active, with its id."))}
			if !input.confirm {return Err(Failure::bad("confirm must be true: the key you paste becomes the active key."))}
			let id = input.id.ok_or_else(|| Failure::bad("id is needed: the number the key carried in the links, as the panel showed it."))?;
			let (next, written) = {
				let mut hold = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
				let next = hold.recover(&supplied, id).map_err(Failure::conflict)?;
				(next, hold.write_next(&next))
			};
			app.db.audit(&ctx.actor, &ctx.source, "gateway.recover", "gateway", &format!("a key supplied by the operator is the active key {id}")).await;
			return ok(&Switched {gateway: view(&app).await?, next_private: URL_SAFE_NO_PAD.encode(next), next_file_written: written, affected: 0})
		}
		let (gone, old, next, written, new_next_id) = {
			let mut hold = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
			let (gone, old, next) = hold.switch(&supplied, theft).map_err(Failure::bad)?;
			let (written, id) = (hold.write_next(&next), hold.file().map_or(0, |file| file.next.id));
			(gone, old, next, written, id)
		};
		let ids = if theft {gone} else {vec![old]};
		let affected = app.db.call(move |db| -> rusqlite::Result<i64> {
			let tx = db.transaction()?;
			let mut users = BTreeSet::new();
			for id in &ids {users.extend(tx.prepare("select user_id from gateway_use where key_id = ?")?.query_map([id], |row| row.get::<_, i64>(0))?.collect::<Result<Vec<_>, _>>()?);}
			if theft {
				let mut all = affected_ids(&tx);
				all.extend(&users);
				all.sort_unstable();
				all.dedup();
				tx.execute("insert into settings (key, value) values ('gateway_affected', ?) on conflict (key) do update set value = excluded.value", [serde_json::to_string(&all).unwrap_or_default()])?;
				for id in &ids {tx.execute("delete from gateway_use where key_id = ?", [id])?;}
			}
			tx.execute("delete from gateway_use where key_id = ?", [new_next_id])?;
			audit(&tx, &ctx.actor, &ctx.source, if theft {"gateway.theft"} else {"gateway.switch"}, "gateway", &format!("{} destroyed, {} accounts had sent a request under {}", if theft {format!("keys {ids:?}")} else {format!("none (key {old} retired)")}, users.len(), if theft {"them"} else {"it"}));
			tx.commit()?;
			Ok(users.len() as i64)
		}).await??;
		ok(&Switched {gateway: view(&app).await?, next_private: URL_SAFE_NO_PAD.encode(next), next_file_written: written, affected: if theft {affected} else {0}})
	}).await.map_err(Failure::internal)?
}

pub async fn rotate(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<SwitchIn>) -> Result<Response, Failure> {switch(&app, ctx, input, false).await}

pub async fn theft(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<SwitchIn>) -> Result<Response, Failure> {switch(&app, ctx, input, true).await}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResetIn {
	/// Only count the accounts and change nothing.
	#[serde(default)] pub dry_run: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct ResetLink {pub id: i64, pub name: String, pub link: Option<String>, pub error: Option<String>}

#[derive(Serialize, JsonSchema)]
pub struct Reset {
	pub applied: bool,
	/// Accounts whose token is reset, or would be.
	pub count: i64,
	/// The new links, when applied. A secret, shown once.
	pub links: Vec<ResetLink>,
	pub node: Option<crate::users::NodeState>,
}

/// One action for every account that sent a request under a stolen key: a new token and a new link each. Their devices stay. It runs as a task of its own, and the list of affected accounts is kept until the new links are built, so a dropped request cannot lose accounts whose token has not been reset, and no account is reset twice by the same action.
pub async fn reset_affected(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<ResetIn>) -> Result<Response, Failure> {
	if input.dry_run {return ok(&Reset {applied: false, count: app.db.call(|db| affected_ids(db).len() as i64).await?, links: Vec::new(), node: None})}
	if app.keys.is_none() {return Err(Failure::bad("The key file is missing, so no link can be made."))}
	tokio::spawn(async move {
		let (held, dirty) = (app.clone(), app.node(LOCAL).dirty.clone());
		let (made, settled) = app.db.call(move |db| -> rusqlite::Result<(Vec<(i64, String, [u8; 16])>, Vec<i64>)> {
			let keys = held.keys.as_ref().expect("checked before the job");
			let once = held.settings.read().unwrap_or_else(|poisoned| poisoned.into_inner()).show_links_once;
			let (mut done, mut settled, tx) = (Vec::new(), Vec::new(), db.transaction()?);
			for id in affected_ids(&tx) {
				settled.push(id);
				let Some((name, record)) = tx.query_row("select name, record_id from users where id = ?", [id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))).optional()? else {continue};
				let (token, record): ([u8; 16], [u8; 16]) = (crypto::random(), record.try_into().unwrap_or([0; 16]));
				let (lookup, copy) = (keys.token_lookup(&token), (!once).then(|| keys.seal_copy(&record, &token)));
				tx.execute("update users set token_lookup = ?, token_copy = ?, token_gen = token_gen + 1, token_created = ? where id = ?", params![lookup.as_slice(), copy, now(), id])?;
				tx.execute("delete from xray_clients where user_id = ?", [id])?;
				done.push((id, name, token));
			}
			audit(&tx, &ctx.actor, &ctx.source, "gateway.reset", "gateway", &format!("{} tokens reset after a stolen key", done.len()));
			tx.commit()?;
			crate::app::load_lookups(db, &held.lookups);
			dirty.store(true, std::sync::atomic::Ordering::Relaxed);
			Ok((done, settled))
		}).await??;
		let mut links = Vec::new();
		for (id, name, token) in &made {
			let made = app.db.call({let id = *id; move |db| db.query_row(&format!("select {USER_COLUMNS} from users where id = ?"), [id], crate::subs::UserRow::read)}).await?.map_err(Failure::from).and_then(|user| crate::users::view(&app, &user, token).map_err(Failure::bad));
			links.push(ResetLink {id: *id, name: name.clone(), link: made.as_ref().ok().map(|view| view.veilway.clone()), error: made.err().map(|error| error.message)});
		}
		// Only now are the accounts taken off the list, and only those this action settled: one marked by a theft meanwhile stays.
		app.db.call(move |db| {
			let rest: Vec<i64> = affected_ids(db).into_iter().filter(|id| !settled.contains(id)).collect();
			let result = if rest.is_empty() {db.execute("delete from settings where key = 'gateway_affected'", [])} else {db.execute("insert into settings (key, value) values ('gateway_affected', ?) on conflict (key) do update set value = excluded.value", [serde_json::to_string(&rest).unwrap_or_default()])};
			if let Err(error) = result {tracing::error!("the list of accounts of a stolen key could not be cleared: {error}")}
		}).await?;
		ok(&Reset {applied: true, count: made.len() as i64, links, node: Some(crate::users::push(&app).await)})
	}).await.map_err(Failure::internal)?
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecreateIn {
	/// Must be true: making new keys on a panel that has accounts means old links do not open at a first import, and clients learn the new key only from a newer document on a static mirror or from a link shown again.
	pub confirm: bool,
}

/// The explicit action for a lost key with no next key in hand. Only while the keys are lost.
pub async fn recreate(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<RecreateIn>) -> Result<Response, Failure> {
	if !input.confirm {return Err(Failure::bad("confirm must be true."))}
	let (next, written) = {
		let mut hold = app.gateway.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if hold.loaded() {return Err(Failure::conflict("The gateway keys are readable. Load the next key instead."))}
		let next = hold.recreate().map_err(Failure::conflict)?;
		(next, hold.write_next(&next))
	};
	app.db.call(|db| {db.execute("delete from gateway_use", []).ok(); db.execute("delete from settings where key = 'gateway_affected'", []).ok();}).await?;
	app.db.audit(&ctx.actor, &ctx.source, "gateway.recreate", "gateway", "new gateway keys made").await;
	ok(&Switched {gateway: view(&app).await?, next_private: URL_SAFE_NO_PAD.encode(next), next_file_written: written, affected: 0})
}

/// The standard base64 of a public key, as a document lists it.
pub fn listed(key: &GatewayKey) -> serde_json::Value {serde_json::json!({"id": key.id(), "key": STANDARD.encode(key.public())})}
