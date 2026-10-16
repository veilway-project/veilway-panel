//! Static mirrors, the publisher's side ("Static mirrors" on the subscription format page): the keys a request leaves behind, the rounds that write every device's sealed file and the decoys into a new directory, and what the admin pages show about them.
use crate::{app::{App, Settings, SigningEntry}, crypto::{self, now}, endpoints::RECENT, http::{ok, Ctx, Failure}, subs::{self, DeviceRow, Form, UserRow, DEVICE_COLUMNS, USER_COLUMNS}};
use axum::{extract::{Path as Route, State}, response::Response, Extension};
use base64::{engine::general_purpose::STANDARD, Engine};
use data_encoding::HEXLOWER;
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, HashMap, HashSet}, fs, os::unix::fs::symlink, path::{Path, PathBuf}, sync::Arc};
use veilway_proto::{keys::MirrorKeys, subscription::{mirror, Url}, uniform};

/// Host names that many unrelated sites share, with the folder in the path where TLS hides it. A `*` stands for one run of any characters. A base URL whose host is not here is one a censor can block at no cost to anyone else, and the panel says so.
const SHARED: [&str; 11] = ["raw.githubusercontent.com", "gitlab.com", "codeberg.org", "bitbucket.org", "raw.githack.com", "cdn.jsdelivr.net", "fastly.jsdelivr.net", "storage.googleapis.com", "s3.amazonaws.com", "s3.*.amazonaws.com", "s3.*.backblazeb2.com"];
/// A failed round is tried again after this many seconds, not on every pass of the upkeep.
const RETRY: i64 = 300;
/// "A folder moves to a smaller size only after 8 rounds in a row in which the smaller one held every envelope."
const CALM: u32 = 8;

/// Whether a host is on the list of shared names.
pub fn shared(host: &str) -> bool {
	SHARED.iter().any(|entry| match entry.split_once('*') {Some((head, tail)) => host.len() > head.len() + tail.len() && host.starts_with(head) && host.ends_with(tail), None => host == *entry})
}

/// The folder of a base URL: readable, safe as a file name, and apart from every other base URL's by a few digits of its hash.
pub fn label(base: &str) -> String {
	let readable: String = base.trim_start_matches("https://").trim_end_matches('/').chars().map(|found| if found.is_ascii_alphanumeric() || found == '.' || found == '-' {found.to_ascii_lowercase()} else {'_'}).take(80).collect();
	format!("{readable}-{}", HEXLOWER.encode(&crypto::sha256(base.as_bytes())[..3]))
}

/// What the settings may say about static mirrors. The rules are the page's for a base URL, plus: no host and port that the endpoint or a relay mirror already has.
pub fn check(input: &Settings) -> Result<(), String> {
	if !(1..=12).contains(&input.static_interval) {return Err("static_interval is 1 to 12 hours.".into())}
	if input.static_mirrors.len() > mirror::MIRRORS_MAX {return Err(format!("static_mirrors has at most {} entries.", mirror::MIRRORS_MAX))}
	let taken: Vec<String> = input.endpoints.iter().map(|endpoint| endpoint.url.as_str()).chain(input.refresh_mirrors.iter().filter_map(|entry| entry.as_str().or_else(|| entry.get("url").and_then(|url| url.as_str())))).filter_map(|text| Url::pinned(text, 1024, true, true)).map(|url| url.authority()).collect();
	let mut seen: Vec<Url> = Vec::new();
	for base in &input.static_mirrors {
		let url = Url::parse(base, mirror::BASE_MAX, false, false).filter(|_| base.ends_with('/')).ok_or_else(|| format!("{base} is not a base URL: it is https with a host name (no address), no user, query or fragment, at most {} characters, and a path that ends in /.", mirror::BASE_MAX))?;
		if taken.contains(&url.authority()) {return Err(format!("{base} has the host and port of the endpoint or a relay mirror. One host has one role."))}
		if seen.contains(&url) {return Err(format!("{base} is listed twice."))}
		seen.push(url);
	}
	Ok(())
}

/// Called with a request that carries the current token and the right secret, from a device that is enrolled: derives the device's two keys and stores them sealed under the panel's secret key, bound to the account and the device. Nothing here gives a way back to the token or the secret.
pub async fn remember(app: &App, user: &UserRow, device: &DeviceRow, token: &[u8; 16], secret: &[u8; 16]) {
	let Some(keys) = app.keys.as_ref() else {return};
	let Some(public) = STANDARD.decode(&device.public_key).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) else {return};
	let derived = MirrorKeys::derive(token, secret, &public);
	let (name, key) = derived.expose();
	let sealed = |label: &[u8], plain: &[u8; 32]| keys.seal_secret(&user.record_id, [label, &public[..]].concat(), plain);
	let (sealed_name, sealed_key, token_gen, id) = (sealed(b"mirror_name", name), sealed(b"mirror_key", key), user.token_gen, device.id);
	if let Err(error) = app.db.call(move |db| db.execute("update devices set mirror_name = ?, mirror_key = ?, mirror_gen = ? where id = ?", rusqlite::params![sealed_name, sealed_key, token_gen, id]).map_err(|error| error.to_string())).await.map_err(|error| error.to_string()).and_then(|result| result) {tracing::error!("the static mirror keys of a device could not be stored: {error}")}
}

/// Whether the system reports its clock as synchronized. None where it cannot tell: another system, or a container, whose clock the host keeps while the kernel's flag inside often reads unsynchronized.
pub fn clock_synchronized() -> Option<bool> {
	#[cfg(target_os = "linux")]
	{
		if ["/.dockerenv", "/run/.containerenv", "/run/systemd/container"].iter().any(|path| std::path::Path::new(path).exists()) {return None}
		// SAFETY: a zeroed timex with modes 0 is the read-only form of the call.
		let mut timex: libc::timex = unsafe {std::mem::zeroed()};
		match unsafe {libc::adjtimex(&mut timex)} {-1 => None, state => Some(state != libc::TIME_ERROR)}
	}
	#[cfg(not(target_os = "linux"))]
	{None}
}

/// What one folder keeps between rounds. `decoys` are the names of the decoys of each period, so that births and deaths go on from round to round.
#[derive(Serialize, Deserialize, Default, Clone)]
struct Folder {base: String, size: usize, calm: u32, calm_most: usize, files: usize, round: String, at: i64, decoys: BTreeMap<u64, Vec<String>>}

#[derive(Serialize, Deserialize, Default, Clone)]
struct Memory {last_round: i64, attempt: i64, error: Option<String>, folders: BTreeMap<String, Folder>}

/// No row, or one that does not parse, is a state that starts empty. A row that could not be read is an error, so that nobody saves an empty state over it.
async fn load(app: &App) -> Result<Memory, String> {
	let text = app.db.call(|db| db.query_row("select value from settings where key = 'static_state'", [], |row| row.get::<_, String>(0)).optional()).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	Ok(text.and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default())
}

async fn save(app: &App, state: &Memory) {
	let text = serde_json::to_string(state).unwrap_or_default();
	if let Err(error) = app.db.call(move |db| db.execute("insert into settings (key, value) values ('static_state', ?) on conflict (key) do update set value = excluded.value", [text]).map_err(|error| error.to_string())).await.map_err(|error| error.to_string()).and_then(|result| result) {tracing::warn!("the static mirror state could not be saved: {error}")}
}

fn root(app: &App) -> PathBuf {app.cfg.database.parent().unwrap_or(Path::new("")).join("static")}

/// Whether a round is due: the interval has passed, or a base URL came or went. A failed round waits a few minutes before the next try.
pub async fn due(app: &App, at: i64) -> bool {
	let settings = app.settings();
	let state = match load(app).await {Ok(state) => state, Err(error) => {tracing::warn!("the static mirror state could not be read, so no round starts: {error}"); return false}};
	if at - state.attempt < RETRY {return false}
	let wanted: Vec<String> = settings.static_mirrors.iter().map(|base| label(base)).collect();
	wanted.iter().any(|name| !state.folders.contains_key(name)) || state.folders.keys().any(|name| !wanted.contains(name)) || (!wanted.is_empty() && at - state.last_round >= i64::from(settings.static_interval) * 3600)
}

/// One round: every folder gets a new directory with every file rewritten, and then the `current` link is switched to it. On an error nothing is switched for the folder that failed, and the others keep what they have.
pub async fn round(app: &Arc<App>, at: i64) -> Result<(), String> {
	let _turn = app.publishing.lock().await;
	let mut next = load(app).await?;
	next.attempt = at;
	match publish(app, at, &mut next).await {
		Ok(()) => {
			next.last_round = at;
			next.error = None;
			save(app, &next).await;
			Ok(())
		}
		Err(error) => {
			next.error = Some(error.clone());
			save(app, &next).await;
			Err(error)
		}
	}
}

async fn publish(app: &App, at: i64, state: &mut Memory) -> Result<(), String> {
	let keys = app.keys.as_ref().ok_or("the key file is missing, so nothing is published and nothing is deleted")?;
	let (settings, root) = (app.settings(), root(app));
	let wanted: Vec<(String, &String)> = settings.static_mirrors.iter().map(|base| (label(base), base)).collect();
	for gone in state.folders.keys().filter(|name| !wanted.iter().any(|(label, _)| label == *name)).cloned().collect::<Vec<_>>() {
		let _ = fs::remove_dir_all(root.join(&gone));
		state.folders.remove(&gone);
	}
	if wanted.is_empty() {return Ok(())}
	let signing: Vec<SigningEntry> = app.signing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).current().into_iter().cloned().collect();
	// While two keys are current a static file is signed with the older one, which every client that refreshed since the overlap began holds.
	let signer = signing.first().ok_or("there is no signing key")?;
	// One job reads the users and every enrolled device with its mirror keys, so the loop below asks the database for nothing.
	let (users, mut held, seen) = app.db.call(move |db| -> rusqlite::Result<(Vec<UserRow>, HashMap<i64, Vec<(DeviceRow, (Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>))>>, Vec<(String, i64)>)> {
		let users = db.prepare(&format!("select {USER_COLUMNS} from users order by id"))?.query_map([], UserRow::read)?.collect::<rusqlite::Result<Vec<_>>>()?;
		let mut held: HashMap<i64, Vec<_>> = HashMap::new();
		let mut statement = db.prepare(&format!("select {DEVICE_COLUMNS}, mirror_name, mirror_key, mirror_gen from devices where state = 'enrolled' order by id"))?;
		for row in statement.query_map([], |row| Ok((DeviceRow::read(row)?, (row.get(13)?, row.get(14)?, row.get(15)?))))? {
			let (device, stored) = row?;
			held.entry(device.user_id).or_default().push((device, stored));
		}
		let seen = db.prepare("select endpoint, user_id from endpoint_use where last_at >= ?")?.query_map([at - RECENT], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
		Ok((users, held, seen))
	}).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	let mut devices: Vec<(MirrorKeys, Vec<u8>)> = Vec::new();
	for user in &users {
		let reason = if !user.enabled {Some("disabled")} else if user.expires_at.is_some_and(|expires| expires <= now()) {Some("expired")} else {None};
		for (device, (name, key, generation)) in held.remove(&user.id).unwrap_or_default() {
			let (Some(name), Some(key), Some(generation)) = (name, key, generation) else {continue};
			if generation != user.token_gen {continue}
			let public: [u8; 32] = STANDARD.decode(&device.public_key).ok().and_then(|bytes| bytes.try_into().ok()).ok_or("a device key is not 32 bytes")?;
			let open = |label: &[u8], sealed: &[u8]| keys.open_secret(&user.record_id, [label, &public[..]].concat(), sealed).and_then(|plain| <[u8; 32]>::try_from(plain).ok()).ok_or("a stored static mirror key does not open: the key file is not the one that sealed it, so nothing is published and nothing is deleted");
			let mirror_keys = MirrorKeys::restore(open(b"mirror_name", &name)?, open(b"mirror_key", &key)?);
			// A static file is fetched from no endpoint, so it carries the pins of the endpoint the account resolves to, as the client holds them once its move is done. An account that refreshed lately on another endpoint is still moving, and a client that holds the old endpoint's pins refuses a list of the new ones, so its file carries none, which changes nothing.
			let resolved = settings.resolve(user.endpoint.as_deref(), &serde_json::from_str::<Vec<String>>(&user.groups).unwrap_or_default()).map(|(found, _)| found);
			let moving = resolved.is_some_and(|resolved| seen.iter().any(|(endpoint, id)| *id == user.id && *endpoint != resolved.name));
			let text = match reason {Some(reason) => subs::refusal(signer, &user.sub_id, reason), None => subs::document(app, user, &device, &signing, signer, Form::Static, None, resolved.filter(|_| !moving)).await?};
			devices.push((mirror_keys, text.into_bytes()));
		}
	}
	let largest = devices.iter().map(|(_, envelope)| envelope.len()).max().unwrap_or(0);
	let needed = if largest == 0 {mirror::SIZES[0]} else {mirror::size_for(largest).ok_or("a document is larger than a static file can hold")?};
	let (wanted, folders): (Vec<(String, String)>, _) = (wanted.into_iter().map(|(name, base)| (name, base.clone())).collect(), state.folders.clone());
	// Blocking work, so it runs off the async workers: the sealed envelopes and the decoys of every folder go into a new directory, then `current` is switched.
	let (outcome, folders) = tokio::task::spawn_blocking(move || {
		let mut folders = folders;
		let outcome = (|| -> Result<(), String> {
			let epochs = mirror::live(at.max(0) as u64);
			for (name, base) in &wanted {
				let mut folder = folders.get(name).cloned().unwrap_or_default();
				folder.base = base.clone();
				if folder.size == 0 || needed > folder.size {
					folder.size = needed;
					folder.calm = 0;
					folder.calm_most = 0;
				} else if needed < folder.size {
					// The move comes in the round after the eighth one that the smaller size would have held.
					folder.calm_most = folder.calm_most.max(needed);
					if folder.calm >= CALM {
						folder.size = folder.calm_most;
						folder.calm = 0;
						folder.calm_most = 0;
					} else {folder.calm += 1;}
				} else {
					folder.calm = 0;
					folder.calm_most = 0;
				}
				folder.decoys.retain(|epoch, _| epochs.contains(epoch));
				let directory = root.join(&name);
				let mut round = format!("r{at}");
				while directory.join(&round).exists() {round.push('x');}
				fs::create_dir_all(directory.join(&round)).map_err(|error| format!("{}: {error}", directory.display()))?;
				let mut total = 0;
				for epoch in &epochs {
					let mut real = HashSet::new();
					for (mirror_keys, envelope) in &devices {
						let file = mirror::file_name(mirror_keys, base, *epoch);
						let sealed = mirror::seal(mirror_keys, base, *epoch, folder.size, envelope, &mut crypto::fill).map_err(|error| error.to_string())?;
						fs::write(directory.join(&round).join(&file), sealed).map_err(|error| error.to_string())?;
						real.insert(file);
					}
					let (low, high) = (32.max(real.len().div_ceil(4)) as u32, 64.max(real.len().div_ceil(2)) as u32);
					let first = !folder.decoys.contains_key(epoch);
					let decoys = folder.decoys.entry(*epoch).or_default();
					let fresh = |decoys: &Vec<String>| -> Result<String, String> {
						loop {
							let mut id = [0u8; 16];
							crypto::fill(&mut id).map_err(|error| error.to_string())?;
							let candidate = format!("{}.bin", HEXLOWER.encode(&id));
							if !decoys.contains(&candidate) && !real.contains(&candidate) {return Ok(candidate)}
						}
					};
					if first {
						for _ in 0..uniform(low, high, &mut crypto::fill).map_err(|error| error.to_string())? {decoys.push(fresh(decoys)?);}
					} else {
						// A birth and a death are drawn apart from each other, a quarter of the time each. The one that dies is chosen among those there were before the round.
						let (born, died) = (uniform(0, 3, &mut crypto::fill).map_err(|error| error.to_string())? == 0, uniform(0, 3, &mut crypto::fill).map_err(|error| error.to_string())? == 0);
						if died && !decoys.is_empty() {decoys.remove(uniform(0, decoys.len() as u32 - 1, &mut crypto::fill).map_err(|error| error.to_string())? as usize);}
						if born {decoys.push(fresh(decoys)?);}
						while decoys.len() < low as usize {decoys.push(fresh(decoys)?);}
						while decoys.len() > high as usize {decoys.remove(uniform(0, decoys.len() as u32 - 1, &mut crypto::fill).map_err(|error| error.to_string())? as usize);}
					}
					for decoy in decoys.iter() {
						let mut bytes = vec![0u8; folder.size];
						crypto::fill(&mut bytes).map_err(|error| error.to_string())?;
						fs::write(directory.join(&round).join(decoy), bytes).map_err(|error| error.to_string())?;
					}
					total += real.len() + decoys.len();
				}
				// A link switched by rename is one step: a copy that reads `current/` sees the old round or the new one, never half of one.
				let (link, pending) = (directory.join("current"), directory.join("current.new"));
				let _ = fs::remove_file(&pending);
				symlink(&round, &pending).and_then(|_| fs::rename(&pending, &link)).map_err(|error| format!("{}: {error}", link.display()))?;
				let previous = std::mem::replace(&mut folder.round, round.clone());
				for entry in fs::read_dir(&directory).map_err(|error| error.to_string())?.flatten() {
					let found = entry.file_name().to_string_lossy().to_string();
					if found.starts_with('r') && found != round && found != previous {let _ = fs::remove_dir_all(entry.path());}
				}
				(folder.files, folder.at) = (total, at);
				folders.insert(name.clone(), folder);
			}
			Ok(())
		})();
		(outcome, folders)
	}).await.map_err(|error| error.to_string())?;
	state.folders = folders;
	outcome
}

#[derive(Serialize, JsonSchema)]
pub struct SyncOut {pub tool: String, pub command: String}

#[derive(Serialize, JsonSchema)]
pub struct FolderOut {
	pub label: String,
	pub base_url: String,
	/// False when the host is not on the panel's list of shared host names: a censor that learns it can block it without blocking anything else.
	pub shared_host: bool,
	/// The folder to copy to the host: a link that is switched to each new round in one step.
	pub path: String,
	/// Files in the folder, real and decoy together. Null before the first round.
	pub files: Option<usize>,
	/// The size of every file of the folder, in bytes. Null before the first round.
	pub size: Option<usize>,
	/// When this folder was last written.
	pub written_at: Option<i64>,
	pub sync: Vec<SyncOut>,
}

#[derive(Serialize, JsonSchema)]
pub struct StaticOut {
	pub folders: Vec<FolderOut>,
	pub interval_hours: u32,
	pub last_round: Option<i64>,
	pub next_round: Option<i64>,
	/// Why the last round published nothing, if it failed.
	pub error: Option<String>,
}

pub async fn status(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (settings, state, root) = (app.settings(), load(&app).await.map_err(Failure::internal)?, root(&app));
	let folders = settings.static_mirrors.iter().map(|base| {
		let (name, kept) = (label(base), state.folders.get(&label(base)));
		let (path, remote) = (root.join(&name).join("current").display().to_string(), Url::parse(base, mirror::BASE_MAX, false, false).map(|url| (url.host().to_string(), base.trim_start_matches("https://").split_once('/').map_or(String::new(), |(_, path)| path.to_string()))));
		let (host, inside) = remote.unwrap_or_default();
		FolderOut {
			shared_host: shared(&host), files: kept.map(|folder| folder.files), size: kept.map(|folder| folder.size), written_at: kept.map(|folder| folder.at),
			sync: vec![
				SyncOut {tool: "rsync".into(), command: format!("rsync -rt --delete '{path}/' '<user>@<host>:<web root>/{inside}'")},
				SyncOut {tool: "rclone".into(), command: format!("rclone sync '{path}/' '<remote>:<bucket>/{inside}'")},
				SyncOut {tool: "git".into(), command: format!("rsync -rt --delete '{path}/' '<clone>/<folder>/' && git -C '<clone>' add -A && git -C '<clone>' commit -m publish && git -C '<clone>' push")},
			],
			label: name, base_url: base.clone(), path,
		}
	}).collect();
	let next = (!settings.static_mirrors.is_empty()).then(|| if state.last_round == 0 {now()} else {state.last_round + i64::from(settings.static_interval) * 3600});
	ok(&StaticOut {folders, interval_hours: settings.static_interval, last_round: (state.last_round > 0).then_some(state.last_round), next_round: next, error: state.error})
}

#[derive(Serialize, JsonSchema)]
pub struct Zipped {pub filename: String,
	/// The zip file, standard base64.
	pub file: String}

/// A zip file with the files stored as they are, in the order given. The files are sealed or random already, so compressing them would gain nothing, and the times are fixed so that no file carries the day it was written.
/// Refused past what a zip without the Zip64 extension can hold: 65,535 files, and offsets and sizes that fit 32 bits.
fn zip(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
	let total: u64 = files.iter().map(|(name, data)| 76 + 2 * name.len() as u64 + data.len() as u64).sum::<u64>() + 22;
	if files.len() > usize::from(u16::MAX) || total >= u64::from(u32::MAX) {return Err(format!("The folder holds {} files and about {} MB, more than a zip file without Zip64 can hold (65,535 files, 4 GB). Copy the folder with rsync, rclone or git instead.", files.len(), total / 1_000_000))}
	let table: Vec<u32> = (0..256u32).map(|mut value| {for _ in 0..8 {value = if value & 1 == 1 {0xedb8_8320 ^ (value >> 1)} else {value >> 1};} value}).collect();
	let (mut out, mut central) = (Vec::new(), Vec::new());
	for (name, data) in files {
		let crc = !data.iter().fold(!0u32, |state, byte| table[((state ^ u32::from(*byte)) & 0xff) as usize] ^ (state >> 8));
		let (size, length, offset) = (data.len() as u32, name.len() as u16, out.len() as u32);
		out.extend([&0x0403_4b50u32.to_le_bytes()[..], &20u16.to_le_bytes(), &0u16.to_le_bytes(), &0u16.to_le_bytes(), &0u16.to_le_bytes(), &0x21u16.to_le_bytes(), &crc.to_le_bytes(), &size.to_le_bytes(), &size.to_le_bytes(), &length.to_le_bytes(), &0u16.to_le_bytes(), name.as_bytes(), data].concat());
		central.extend([&0x0201_4b50u32.to_le_bytes()[..], &20u16.to_le_bytes(), &20u16.to_le_bytes(), &0u16.to_le_bytes(), &0u16.to_le_bytes(), &0u16.to_le_bytes(), &0x21u16.to_le_bytes(), &crc.to_le_bytes(), &size.to_le_bytes(), &size.to_le_bytes(), &length.to_le_bytes(), &[0u8; 12], &offset.to_le_bytes(), name.as_bytes()].concat());
	}
	let (count, start, length) = (files.len() as u16, out.len() as u32, central.len() as u32);
	out.extend(central);
	out.extend([&0x0605_4b50u32.to_le_bytes()[..], &0u32.to_le_bytes(), &count.to_le_bytes(), &count.to_le_bytes(), &length.to_le_bytes(), &start.to_le_bytes(), &0u16.to_le_bytes()].concat());
	Ok(out)
}

pub async fn download(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Route(name): Route<String>) -> Result<Response, Failure> {
	if !app.settings().static_mirrors.iter().any(|base| label(base) == name) {return Err(Failure::missing("static mirror folder"))}
	let current = root(&app).join(&name).join("current");
	let files = tokio::task::spawn_blocking(move || -> Result<Vec<(String, Vec<u8>)>, std::io::Error> {
		let mut files = fs::read_dir(&current)?.flatten().filter(|entry| entry.path().is_file()).map(|entry| Ok((entry.file_name().to_string_lossy().to_string(), fs::read(entry.path())?))).collect::<Result<Vec<_>, std::io::Error>>()?;
		files.sort();
		Ok(files)
	}).await.map_err(Failure::internal)?.map_err(|error| if error.kind() == std::io::ErrorKind::NotFound {Failure::conflict("No round has been published for this folder yet.")} else {Failure::internal(error)})?;
	let archive = zip(&files).map_err(Failure::conflict)?;
	app.db.audit(&ctx.actor, &ctx.source, "static.download", "static", &format!("{name}, {} files", files.len())).await;
	ok(&Zipped {filename: format!("{name}.zip"), file: STANDARD.encode(archive)})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_zip_has_the_crc_of_its_files() {
		let out = zip(&[("a.bin".into(), b"123456789".to_vec())]).unwrap();
		assert_eq!(&out[..4], b"PK\x03\x04");
		assert_eq!(u32::from_le_bytes(out[14..18].try_into().unwrap()), 0xcbf4_3926);
		assert_eq!(&out[out.len() - 22..out.len() - 18], b"PK\x05\x06");
	}

	#[test]
	fn a_zip_past_what_it_can_hold_is_refused() {
		let many: Vec<(String, Vec<u8>)> = (0..=usize::from(u16::MAX)).map(|number| (format!("{number}.bin"), Vec::new())).collect();
		assert!(zip(&many).unwrap_err().contains("65,535"));
		assert!(zip(&many[..usize::from(u16::MAX)]).is_ok());
	}

	#[test]
	fn a_label_is_a_safe_name_and_each_base_has_its_own() {
		let (one, two) = (label("https://files.example.net/vw/"), label("https://files.example.net/vx/"));
		assert_ne!(one, two);
		assert!(one.starts_with("files.example.net_vw-") && one.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)));
		assert!(label(&format!("https://x.example.net/{}/", "a".repeat(200))).len() < 100);
	}

	#[test]
	fn shared_names_match_exactly_or_by_their_wildcard() {
		for host in ["raw.githubusercontent.com", "s3.amazonaws.com", "s3.eu-west-1.amazonaws.com", "s3.us-west-004.backblazeb2.com"] {assert!(shared(host), "{host}")}
		for host in ["name.github.io", "files.example.net", "amazonaws.com", "s3..amazonaws.com", "mybucket.s3.amazonaws.com", "evil-raw.githubusercontent.com"] {assert!(!shared(host), "{host}")}
	}
}
