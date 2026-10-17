//! The state every handler shares: configuration, database, keys, signing keys, limits and the settings.
use crate::{config::{Config, NotFound}, crypto::{self, now, Keys}, db::Db};
use axum::{body::Body, http::{HeaderName, HeaderValue, StatusCode}, response::Response};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use rusqlite::Connection;
use std::{collections::{BTreeMap, HashMap, VecDeque}, fs, net::IpAddr, os::unix::fs::PermissionsExt, sync::{atomic::AtomicBool, Arc, Mutex, RwLock}};

/// 365 days, then a retired signing key is destroyed.
pub const RETIRED_KEPT: i64 = 365 * 86_400;

/// Most keys the limiter holds. Past it, a key it does not hold yet is refused rather than stored.
const KEYS_MAX: usize = 100_000;

/// The key a source's limit counts under. An IPv6 address counts as its network of `prefix` bits, since one host may hold many addresses: /64 for the admin side, /48 for the subscription endpoint, where a provider's customer is given a /48 or less.
pub fn bucket(source: &str, prefix: u8) -> String {
	match source.parse::<IpAddr>() {
		Ok(IpAddr::V6(address)) => ipnet::Ipv6Net::new(address, prefix).map_or(source.to_string(), |net| net.trunc().to_string()),
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

/// One subscription endpoint the panel answers on and puts in links.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
	/// 1 to 64 characters of a-z, 0-9, dash and underscore.
	pub name: String,
	/// The public URL: `https`, or `http` for a plain endpoint, which hides nothing from the network (the exchange stays sealed). At most 256 characters, no fragment. The operator's web server forwards this host and path to the panel's `sub_path` followed by a slash and the name of the endpoint, and that path is how the panel knows which endpoint a request reached.
	pub url: String,
	/// SHA-256 of the SubjectPublicKeyInfo of the endpoint's certificate, standard base64, at most two. Required for a self-signed certificate (an IP address as host). Empty for a chain-validated or plain endpoint. `https` only.
	#[serde(default)]
	pub pins: Vec<String>,
}

/// What an operator sets once for the whole panel.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
	pub provider_name: String,
	/// The provider's own terms and privacy policy, put in every document as its `agreement`, which the apps ask users to accept. An `https` URL, or empty for none.
	pub terms_url: String,
	pub privacy_url: String,
	/// The named subscription endpoints, at most 16, each on its own host and port and each reached by its own path, the panel's `sub_path` and the endpoint's name. An account's links and documents use the endpoint resolved for it: its own, else the first of its groups that has one in `group_endpoints`, else the default.
	pub endpoints: Vec<Endpoint>,
	/// The name of the default endpoint. Empty only while there are no endpoints.
	pub default_endpoint: String,
	/// The endpoint of a group, by group name.
	pub group_endpoints: BTreeMap<String, String>,
	/// Days a retired gateway key keeps opening requests after a routine switch, 30 to 365.
	pub gateway_retired_days: u32,
	/// The address pool devices get their tunnel address from, an IPv4 network.
	pub pool_v4: String,
	pub default_device_limit: u16,
	/// Store no copy of a token: a link is shown at creation and reset, and never again.
	pub show_links_once: bool,
	pub update_interval: u32,
	pub document_days: u32,
	/// Other endpoints of the same subscription, put in every document as `refresh_urls`. A string, or an object with `url` and `pins`.
	pub refresh_mirrors: Vec<Value>,
	/// Base URLs of static mirrors, put in every document as `static_mirrors`: plain file hosting that holds each device's sealed document. `https`, a path ending in `/`, no pins and no IP literal, at most 4, and none shares host and port with the endpoint or a relay mirror.
	pub static_mirrors: Vec<String>,
	/// Hours between publishing rounds of the static mirrors, 1 to 12.
	pub static_interval: u32,
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
	/// The profiles derived from an inbound that carry the published relays reaching each account, by profile id and inbound tag. Written by publish.
	pub relay_profiles: BTreeMap<String, String>,
	/// The relays as they were when the profiles were published. A document carries the ones that reach its account.
	#[serde(deserialize_with = "crate::nodecfg::checked_relays")]
	pub published_relays: Vec<crate::nodecfg::Relay>,
}

impl Default for Settings {
	fn default() -> Self {
		Self {provider_name: "Veilway".into(), terms_url: String::new(), privacy_url: String::new(), endpoints: Vec::new(), default_endpoint: String::new(), group_endpoints: BTreeMap::new(), gateway_retired_days: 120, pool_v4: "10.66.0.0/16".into(), default_device_limit: 3, show_links_once: false, update_interval: 3600, document_days: 14, refresh_mirrors: Vec::new(), static_mirrors: Vec::new(), static_interval: 6, profiles: Vec::new(), profile_overrides: Default::default(), node_host: String::new(), not_found: None, relays: Vec::new(), relay_profiles: BTreeMap::new(), published_relays: Vec::new()}
	}
}

pub struct App {
	pub cfg: Config,
	pub db: Db,
	/// None when accounts exist and the key file does not: the endpoint then answers like an unknown path and the panel says so.
	pub keys: Option<Keys>,
	pub signing: Mutex<Signing>,
	/// The gateway keys and the gateway that opens requests: held together so a switch of keys and the replay memory change in one step. Never held across an await.
	pub gateway: Mutex<crate::gateway::Hold>,
	/// Token lookup value to user id, so that a request never reads the database for a token it does not know. Refreshed inside every job that writes a token.
	pub lookups: Arc<RwLock<HashMap<[u8; 32], i64>>>,
	/// The signed refusals made, by account, reason and signing key, reused while they are within their age.
	pub refusals: Mutex<HashMap<(i64, String, [u8; 8]), (i64, String)>>,
	pub limits: Limiter,
	/// The limits of the subscription endpoint, apart from `limits`: the keys a flood of requests makes there can fill this one and never lock an admin out.
	pub sub_limits: Limiter,
	pub setup_token: Mutex<Option<String>>,
	/// One change of the node's config at a time.
	pub node_lock: tokio::sync::Mutex<()>,
	pub last_sync: Mutex<Option<String>>,
	/// Set when the node's config was not brought up to date, and cleared by the next push that works.
	pub dirty: Arc<AtomicBool>,
	/// The settings as last stored. Written only inside a database job, together with the table, so the cache and the table move in step.
	pub settings: Arc<RwLock<Settings>>,
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
	/// One publishing round at a time.
	pub publishing: tokio::sync::Mutex<()>,
}

impl App {
	pub fn settings(&self) -> Settings {self.settings.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()}
	pub async fn update_settings(&self, change: impl FnOnce(&mut Settings) + Send + 'static) -> Result<(), String> {
		let cache = self.settings.clone();
		self.db.call(move |db| store_settings(db, &cache, change).map(|settings| publish_settings(&cache, settings))).await.map_err(|error| error.to_string())?
	}
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

/// Writes the settings a job changed and gives the new value. The cache is not touched: a caller with the write in a transaction calls `publish_settings` after the commit, so a failed commit leaves the cache as the table is.
pub fn store_settings(connection: &Connection, cache: &RwLock<Settings>, change: impl FnOnce(&mut Settings)) -> Result<Settings, String> {
	let mut settings = cache.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
	change(&mut settings);
	let text = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
	connection.execute("insert into settings (key, value) values ('settings', ?) on conflict (key) do update set value = excluded.value", [text]).map_err(|error| error.to_string())?;
	Ok(settings)
}

/// Puts committed settings in the cache. Only a job calls it, after the commit that wrote them.
pub fn publish_settings(cache: &RwLock<Settings>, settings: Settings) {*cache.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = settings}

/// Loads the token lookup table from the users. Called inside every job that writes a token or removes a user, so the table and the rows move together.
pub fn load_lookups(connection: &Connection, table: &RwLock<HashMap<[u8; 32], i64>>) {
	let rows = connection.prepare("select token_lookup, id from users").and_then(|mut statement| statement.query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))?.collect::<Result<Vec<_>, _>>());
	match rows {
		Ok(rows) => *table.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = rows.into_iter().filter_map(|(lookup, id)| Some((lookup.try_into().ok()?, id))).collect(),
		Err(error) => tracing::error!("the token lookup table could not be loaded: {error}"),
	}
}
