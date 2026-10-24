//! The state every handler shares: configuration, database, keys, signing keys, limits and the settings.
use crate::{config::{Config, NotFound}, crypto::{self, now, Keys}, db::Db};
use axum::{body::Body, http::{HeaderName, HeaderValue, StatusCode}, response::Response};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use rusqlite::{params, Connection};
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
	/// `hit` for a limit that only counts what it let through: a refused request is not recorded, so asking again early does not push the next allowed time further away. A key holds at most `max` times, and a full table drops its stalest key (nothing is kept past a day, the longest window used) instead of refusing a new one.
	pub fn admit(&self, key: &str, max: usize, window: i64) -> bool {self.admit_at(key, max, window, now())}
	/// `admit` at a given time, so that a test can slide the window without waiting.
	pub fn admit_at(&self, key: &str, max: usize, window: i64, at: i64) -> bool {
		let mut all = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if all.len() >= KEYS_MAX {all.retain(|_, hits| hits.back().is_some_and(|last| at - last < 86_400))}
		if all.len() >= KEYS_MAX && !all.contains_key(key) {
			let stalest = all.iter().min_by_key(|(_, hits)| hits.back().copied()).map(|(stale, _)| stale.clone());
			if let Some(stale) = stalest {all.remove(&stale);}
		}
		let hits = all.entry(key.to_string()).or_default();
		while hits.front().is_some_and(|first| at - first >= window) {hits.pop_front();}
		if hits.len() >= max {return false}
		hits.push_back(at);
		true
	}
	/// Gives back the one hit that `admit` recorded at `at` (give or take a second), for an enrollment that was cancelled. Other hits of the key stay.
	pub fn give_back(&self, key: &str, at: i64) {
		let mut all = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if let Some(hits) = all.get_mut(key) {
			if let Some(index) = (0..hits.len()).filter(|index| (hits[*index] - at).abs() <= 1).min_by_key(|index| (hits[*index] - at).abs()) {hits.remove(index);}
		}
	}
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

#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NoticeKind {Info, Warning}

/// A notice of the signed document: one line of plain text of at most 280 bytes, and the same line in other languages.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubNotice {
	pub severity: NoticeKind,
	/// The default text, shown when no translation fits the app's language.
	pub text: String,
	/// At most 8 translations by language tag (`fa`, `de`, `pt-BR`, `zh-Hans`), each as long as `text` may be.
	#[serde(default)]
	pub translations: BTreeMap<String, String>,
}

/// What an operator sets once for the whole panel.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
	pub provider_name: String,
	/// The provider's own terms and privacy policy, put in every document as its `agreement`, which the apps ask users to accept. An `https` URL, or empty for none.
	pub terms_url: String,
	pub privacy_url: String,
	/// Notices put in every document as `notices`, at most 4. Apps keep them from their last refresh and show them with no connection, which the notices a node sends over the tunnel cannot do. A notice with the same text as one the node sends is shown once.
	pub subscription_notices: Vec<SubNotice>,
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
	/// Devices that have not refreshed for this many days are removed, which frees their places: an app that was uninstalled, or a phone that was lost. 0 keeps them. A device whose key the panel made never refreshes and is never removed this way.
	pub idle_device_days: u32,
	/// How many new devices one subscription link may enroll in any window of `new_devices_window_minutes` minutes, 1 to 64, which slows down a leaked link. The device limit still holds. A large count with a short window comes close to no limit.
	pub new_devices: u32,
	/// The length of the window of `new_devices`, 1 to 1440 minutes. It slides: a device that enrolled leaves the count that many minutes later.
	pub new_devices_window_minutes: u32,
	/// Read only to carry an older setting over: the one wait in minutes between two new devices, now `new_devices` of 1 in a window of this length. It is never written and never in the schema; a value read is turned into the two new settings by `migrate`.
	#[serde(skip_serializing)]
	#[schemars(skip)]
	pub new_device_minutes: Option<u32>,
	/// Days the first transport key of a `veilway` inbound stays first before the panel makes a new one, 7 to 30 (a `ws-plain` transport's key at most 7). The node then holds the two keys, the old one second, and the old key keeps working for one more period of this length before it is destroyed.
	pub transport_key_days: u32,
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
	/// The IPv4 range of each `veilway` inbound, by inbound tag, as it was when the profiles were published. A document gives a device the address it has inside the range of the profile's inbound. Written by publish.
	pub inbound_ranges: BTreeMap<String, String>,
	/// The relays as they were when the profiles were published. A document carries the ones that reach its account.
	#[serde(deserialize_with = "crate::nodecfg::checked_relays")]
	pub published_relays: Vec<crate::nodecfg::Relay>,
	/// The public half of the key of each `faketls` transport, by inbound tag and listen address. The node shows a key only as a marker once it holds it, so the panel makes the public half when the key is applied in full. Owned by the server: read-only in the API, and a settings update keeps the stored value whatever it carries.
	#[schemars(extend("readOnly" = true))]
	pub faketls_keys: BTreeMap<String, BTreeMap<String, String>>,
	/// The public half of the key of each `veilway` inbound, by inbound tag, which its profile is made with. Made the same way as `faketls_keys`, and read-only in the API too.
	#[schemars(extend("readOnly" = true))]
	pub inbound_keys: BTreeMap<String, String>,
	/// The public half of the first transport key of each `veilway` inbound, by inbound tag, which its profile carries as `transport_public_key` for its `tls`, `ws` and `fronted` transports, and of each of its `ws-plain` transports (own keys), by tag, a newline and the path. Made the same way as `inbound_keys`.
	#[schemars(extend("readOnly" = true))]
	pub transport_keys: BTreeMap<String, String>,
	/// When the first transport key of each `veilway` inbound and of each `ws-plain` transport (named as in `transport_keys`) became first, the key held second, the keys destroyed and where its rotation stands. Owned by the server: read-only in the API.
	#[schemars(extend("readOnly" = true))]
	pub transport_clocks: BTreeMap<String, TransportClock>,
}

/// Where the rotation of one transport slot stands. A slot holds at most two keys, and a rotation puts the fresh one first and keeps the current one second, so the old key lives one more period.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct TransportClock {
	/// The public half of the first key when the clock started. A first key that differs was changed by hand, which restarts the clock.
	pub public: String,
	/// Unix time the key became first.
	pub since: i64,
	/// The public half of the key the node holds second, or empty when none is known. It is destroyed by the next rotation, so no profile may carry it.
	pub previous: String,
	/// Public halves of keys the node destroyed, newest last and at most 16. A settings form that was loaded before a rotation may bring one back, and it is rewritten to the current key.
	pub dropped: Vec<String>,
	/// The public half of the key a rotation is putting in force, written before the node is asked so that a rotation the node took is finished later.
	pub next: String,
	/// The node's marker of the key that was first when a rotation began. Markers last as long as the node's process. When the node took the rotation but its answer was lost, it holds that marker second, which tells the next pass to finish the rotation.
	pub old_marker: String,
	/// Unix time `next` was written, or 0 when no rotation waits. A rotation that is still not confirmed 2 days later is given up.
	pub started: i64,
}

impl TransportClock {
	/// Remembers keys the node destroyed, without repeats, at most 16.
	pub fn drop_keys(&mut self, gone: &[&str]) {
		for public in gone {if !public.is_empty() && !self.dropped.iter().any(|held| held == public) {self.dropped.push(public.to_string())}}
		let excess = self.dropped.len().saturating_sub(16);
		self.dropped.drain(..excess);
	}
}

impl Settings {
	/// Turns the retired `new_device_minutes` into the sliding window: 1 device per that many minutes, and 0 (no wait) into 64 per minute, the nearest to no limit. A value of 1, the old default, leaves the new defaults.
	pub fn migrate(&mut self) {
		match self.new_device_minutes.take() {
			Some(0) => (self.new_devices, self.new_devices_window_minutes) = (64, 1),
			Some(minutes) if minutes != 1 => (self.new_devices, self.new_devices_window_minutes) = (1, minutes.min(1440)),
			_ => {}
		}
	}
}

impl Default for Settings {
	fn default() -> Self {
		Self {provider_name: "Veilway".into(), terms_url: String::new(), privacy_url: String::new(), subscription_notices: Vec::new(), endpoints: Vec::new(), default_endpoint: String::new(), group_endpoints: BTreeMap::new(), gateway_retired_days: 120, pool_v4: "10.66.0.0/16".into(), default_device_limit: 3, show_links_once: false, update_interval: 3600, document_days: 14, idle_device_days: 0, new_devices: 3, new_devices_window_minutes: 60, new_device_minutes: None, transport_key_days: 30, refresh_mirrors: Vec::new(), static_mirrors: Vec::new(), static_interval: 6, profiles: Vec::new(), profile_overrides: Default::default(), node_host: String::new(), not_found: None, relays: Vec::new(), relay_profiles: BTreeMap::new(), inbound_ranges: BTreeMap::new(), published_relays: Vec::new(), faketls_keys: BTreeMap::new(), inbound_keys: BTreeMap::new(), transport_keys: BTreeMap::new(), transport_clocks: BTreeMap::new()}
	}
}

/// A node the panel manages, by its id in the `nodes` table. Every call to a node names one, so the calls need no change when more than one exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Node(pub i64);

/// Node 1: the node on the panel's own control socket, which is the whole of the panel's node until more are added.
pub const LOCAL: Node = Node(1);

/// The memory of one node: its lock, the flag that says its config is behind and the outcome of its last push.
#[derive(Default)]
pub struct NodeState {
	/// One change of the node's config at a time.
	pub lock: Arc<tokio::sync::Mutex<()>>,
	pub last_sync: Mutex<Option<String>>,
	/// Set when the node's config was not brought up to date, and cleared by the next push that works.
	pub dirty: Arc<AtomicBool>,
	/// Since when the link that reaches the node has not been up, while it is not.
	pub down_since: Mutex<Option<i64>>,
}

/// The dirty flags of every node, set together by a change to users or devices: a node's sync always carries the whole users list, so it does not matter which node a change belongs to.
#[derive(Clone)]
pub struct Dirty(Vec<Arc<AtomicBool>>);

impl Dirty {
	pub fn set(&self) {for flag in &self.0 {flag.store(true, std::sync::atomic::Ordering::Relaxed)}}
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
	/// The host names of the profiles and the addresses they last had.
	pub names: crate::names::Names,
	pub limits: Limiter,
	/// The limits of the subscription endpoint, apart from `limits`: the keys a flood of requests makes there can fill this one and never lock an admin out.
	pub sub_limits: Limiter,
	pub setup_token: Mutex<Option<String>>,
	/// What the panel keeps in memory for each node it manages, by node id. Read through `node` and `nodes`.
	pub node_states: Mutex<HashMap<i64, Arc<NodeState>>>,
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
	/// Fetches of another provider's subscription that wait for the operator, with the device made for each. In memory only: a restart drops them.
	pub previews: Mutex<crate::upstreams::Previews>,
	/// Nonces of the relay mirror headers that were accepted, so that a header seen once is not taken twice.
	pub mirrors_seen: crate::mirrors::Seen,
	/// One publishing round at a time.
	pub publishing: tokio::sync::Mutex<()>,
}

impl App {
	/// The state of a node, made empty the first time it is asked for.
	pub fn node(&self, node: Node) -> Arc<NodeState> {self.node_states.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(node.0).or_default().clone()}
	/// The nodes the panel manages, in id order.
	pub fn nodes(&self) -> Vec<Node> {
		let mut ids: Vec<i64> = self.node_states.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).keys().copied().collect();
		ids.sort();
		ids.into_iter().map(Node).collect()
	}
	/// The flags of all nodes at once, to be moved into a database job that changes users or devices.
	pub fn dirty_all(&self) -> Dirty {Dirty(self.node_states.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).values().map(|state| state.dirty.clone()).collect())}
	/// Starts keeping the memory of a node that was added, behind with its first push.
	pub fn add_node(&self, node: Node) {self.node_states.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(node.0, Arc::new(NodeState {dirty: Arc::new(AtomicBool::new(true)), ..Default::default()}));}
	/// Forgets a node that was removed.
	pub fn drop_node(&self, node: Node) {self.node_states.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&node.0);}
	/// The turn on a node's config: held while the panel reads it, changes it and pushes it.
	pub async fn turn(&self, node: Node) -> tokio::sync::OwnedMutexGuard<()> {self.node(node).lock.clone().lock_owned().await}
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
	// The pool of node 1 is what addresses are given from, and it is the setting that says so.
	connection.execute("update nodes set pool_v4 = ? where id = ?", params![settings.pool_v4, LOCAL.0]).map_err(|error| error.to_string())?;
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
