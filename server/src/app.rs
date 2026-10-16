//! The state every handler shares: configuration, database, keys, signing keys, limits and the settings.
use crate::{config::{Config, NotFound}, crypto::{self, now, Keys}, db::Db};
use axum::{body::Body, http::{HeaderName, HeaderValue, StatusCode}, response::Response};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::{HashMap, VecDeque}, fs, net::IpAddr, os::unix::fs::PermissionsExt, sync::{atomic::AtomicBool, Mutex}};

/// 365 days, then a retired signing key is destroyed.
pub const RETIRED_KEPT: i64 = 365 * 86_400;

/// Most keys the limiter holds. Past it, a key it does not hold yet is refused rather than stored.
const KEYS_MAX: usize = 100_000;

/// The key a source's limit counts under. An IPv6 address counts as its /64, since one host may hold many addresses.
pub fn bucket(source: &str) -> String {
	match source.parse::<IpAddr>() {
		Ok(IpAddr::V6(address)) => ipnet::Ipv6Net::new(address, 64).map_or(source.to_string(), |net| net.trunc().to_string()),
		_ => source.to_string(),
	}
}

/// A sliding window of hits per key. Kept in memory: a restart gives an attacker a fresh allowance, which the web server's own limits cover.
#[derive(Default)]
pub struct Limiter(Mutex<HashMap<String, VecDeque<i64>>>);

impl Limiter {
	/// Records a hit and says whether the key is still within `max` hits in `window` seconds.
	pub fn hit(&self, key: &str, max: usize, window: i64) -> bool {
		let (mut all, at) = (self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()), now());
		if all.len() >= KEYS_MAX {all.retain(|_, hits| hits.back().is_some_and(|last| at - last < 3600))}
		if all.len() >= KEYS_MAX && !all.contains_key(key) {return false}
		let hits = all.entry(key.to_string()).or_default();
		while hits.front().is_some_and(|first| at - first >= window) {hits.pop_front();}
		hits.push_back(at);
		hits.len() <= max
	}
	/// How many hits the key holds in the window, without recording one.
	pub fn count(&self, key: &str, window: i64) -> usize {
		let (all, at) = (self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()), now());
		all.get(key).map_or(0, |hits| hits.iter().filter(|hit| at - **hit < window).count())
	}
	/// When the key was last hit, if it was.
	pub fn last(&self, key: &str) -> Option<i64> {self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(key).and_then(|hits| hits.back().copied())}
	pub fn clear(&self, key: &str) {self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(key);}
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SigningEntry {pub seed: String, pub created: i64, pub retired_at: Option<i64>}

impl SigningEntry {
	pub fn pair(&self) -> Ed25519KeyPair {Ed25519KeyPair::from_seed_unchecked(&URL_SAFE_NO_PAD.decode(&self.seed).unwrap_or_default()).expect("a stored 32 byte seed")}
	pub fn public(&self) -> [u8; 32] {self.pair().public_key().as_ref().try_into().expect("32 bytes")}
	pub fn proto(&self) -> veilway_proto::subscription::envelope::SigningKey {veilway_proto::subscription::envelope::SigningKey::new(self.public()).expect("a generated key is not of small order")}
}

/// The signing keys, in a file of their own. A key is current until it is retired, and two are current during an overlap.
pub struct Signing {path: std::path::PathBuf, pub entries: Vec<SigningEntry>}

impl Signing {
	pub fn load(path: &std::path::Path) -> Result<Self, String> {
		let entries = match fs::read(path) {
			Ok(bytes) => {
				if fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?.permissions().mode() & 0o077 != 0 {return Err(format!("{}: the signing key file must be mode 600", path.display()))}
				serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => vec![SigningEntry {seed: URL_SAFE_NO_PAD.encode(crypto::random::<32>()), created: now(), retired_at: None}],
			Err(error) => return Err(format!("{}: {error}", path.display())),
		};
		let mut signing = Self {path: path.to_path_buf(), entries};
		signing.prune()?;
		Ok(signing)
	}
	/// Destroys retired keys past their year and saves what is left.
	pub fn prune(&mut self) -> Result<(), String> {
		self.entries.retain(|entry| entry.retired_at.is_none_or(|at| now() - at < RETIRED_KEPT));
		self.save()
	}
	pub fn save(&self) -> Result<(), String> {crypto::write_private(&self.path, &serde_json::to_vec(&self.entries).unwrap_or_default(), true).map_err(|error| format!("{}: {error}", self.path.display()))}
	pub fn current(&self) -> Vec<&SigningEntry> {self.entries.iter().filter(|entry| entry.retired_at.is_none()).collect()}
	pub fn retired(&self) -> Vec<&SigningEntry> {self.entries.iter().filter(|entry| entry.retired_at.is_some()).collect()}
}

/// What an operator sets once for the whole panel.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
	pub provider_name: String,
	/// The provider's own terms and privacy policy, put in every document as two `support` links. An `https` URL, or empty for none.
	pub terms_url: String,
	pub privacy_url: String,
	/// The public `https` URL of the subscription endpoint, with the path the web server forwards to the panel's `sub_path`. No fragment.
	pub endpoint_url: String,
	/// SHA-256 of the SubjectPublicKeyInfo of the endpoint's certificate, standard base64, when it has no certificate from an authority. The first is put in links. Empty for a chain-validated endpoint.
	pub endpoint_pins: Vec<String>,
	/// The address pool devices get their tunnel address from, an IPv4 network.
	pub pool_v4: String,
	pub default_device_limit: u16,
	/// Store no copy of a token: a link is shown at creation and reset, and never again.
	pub show_links_once: bool,
	pub update_interval: u32,
	pub document_days: u32,
	/// Other endpoints of the same subscription, put in every document as `refresh_urls`. A string, or an object with `url` and `pins`.
	pub refresh_mirrors: Vec<Value>,
	/// One profile per inbound, in the shape of "A profile" on the subscription format page, without `device`. The panel adds the device.
	pub profiles: Vec<Value>,
	/// Edits to the profiles derived from the node's inbounds, by inbound tag: an object whose members replace the derived ones.
	pub profile_overrides: serde_json::Map<String, Value>,
	/// The public host or address of this node, which the profiles' endpoints are made with.
	pub node_host: String,
	/// What the endpoint answers to a request it will not take, instead of the config file's. Null keeps the file's.
	pub not_found: Option<NotFound>,
	/// Forwarders in front of the node. Each one adds its address to the candidates of the transports it carries when profiles are derived.
	#[serde(deserialize_with = "crate::nodecfg::checked_relays")]
	pub relays: Vec<crate::nodecfg::Relay>,
}

impl Default for Settings {
	fn default() -> Self {
		Self {provider_name: "Veilway".into(), terms_url: String::new(), privacy_url: String::new(), endpoint_url: String::new(), endpoint_pins: Vec::new(), pool_v4: "10.66.0.0/16".into(), default_device_limit: 3, show_links_once: false, update_interval: 3600, document_days: 14, refresh_mirrors: Vec::new(), profiles: Vec::new(), profile_overrides: Default::default(), node_host: String::new(), not_found: None, relays: Vec::new()}
	}
}

pub struct App {
	pub cfg: Config,
	pub db: Db,
	/// None when accounts exist and the key file does not: the endpoint then answers like an unknown path and the panel says so.
	pub keys: Option<Keys>,
	pub signing: Mutex<Signing>,
	pub limits: Limiter,
	pub setup_token: Mutex<Option<String>>,
	/// One change of the node's config at a time.
	pub node_lock: tokio::sync::Mutex<()>,
	pub last_sync: Mutex<Option<String>>,
	/// Set when the node's config was not brought up to date, and cleared by the next push that works.
	pub dirty: AtomicBool,
	/// The settings' answer for unknown paths, kept here so a stranger's request never reads the database.
	pub not_found_page: Mutex<Option<NotFound>>,
	/// What the last poll of the node's stats saw.
	pub live: Mutex<Option<crate::stats::Live>>,
	pub update: Mutex<crate::updater::Known>,
	/// Set when a restore has begun: non-GET requests are refused and the upkeep stops writing, until the process exits.
	pub restoring: AtomicBool,
	/// Different on every start, so a page can tell that the server restarted.
	pub start_id: String,
	/// Notified after a restore has replaced the files: the server then stops and the service manager starts it on the new ones.
	pub restart: tokio::sync::Notify,
	/// Node link pairing, all in memory: an offer, its answer and the fingerprint wait here until the operator confirms, and a restart drops them.
	pub pairing: Mutex<crate::links::Pairing>,
	/// Nonces of the relay mirror headers that were accepted, so that a header seen once is not taken twice.
	pub mirrors_seen: crate::mirrors::Seen,
}

impl App {
	pub fn settings(&self) -> Settings {self.db.lock().query_row("select value from settings where key = 'settings'", [], |row| row.get::<_, String>(0)).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()}
	pub fn save_settings(&self, settings: &Settings) {let _ = self.db.lock().execute("insert into settings (key, value) values ('settings', ?) on conflict (key) do update set value = excluded.value", [serde_json::to_string(settings).unwrap_or_default()]);}
	/// The one answer for everything the panel does not serve: what the operator's web server says for a path it does not know.
	pub fn not_found(&self) -> Response {
		let page = self.not_found_page.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone().unwrap_or_else(|| self.cfg.not_found.clone());
		let mut response = Response::new(Body::from(page.body.clone()));
		*response.status_mut() = StatusCode::from_u16(page.status).unwrap_or(StatusCode::NOT_FOUND);
		for (name, value) in &page.headers {
			if let (Ok(name), Ok(value)) = (HeaderName::try_from(name.as_str()), HeaderValue::from_str(value)) {response.headers_mut().append(name, value);}
		}
		response
	}
	pub fn standard(bytes: &[u8]) -> String {STANDARD.encode(bytes)}
}
