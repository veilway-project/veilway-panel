//! Finding out that a newer panel or node exists, and asking for it. The panel runs unprivileged and never updates itself: a request is a file with the word `panel`, `node` or `both` in a folder only the panel and root can write, which a root service on the host answers (see `veilway.sh`). Everything GitHub sends is untrusted.
use crate::{app::App, crypto::now, http::{ok, Body, Ctx, Failure}};
use axum::{extract::State, http::StatusCode, response::Response, Extension};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cmp::Ordering, fs::OpenOptions, io::{ErrorKind, Write}, os::unix::fs::OpenOptionsExt, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const HOST: &str = "api.github.com";
const PANEL_PATH: &str = "/repos/veilway-project/veilway-panel/releases/latest";
const PANEL_NOTES: &str = "https://github.com/veilway-project/veilway-panel/releases/tag/";
const NODE_PATH: &str = "/repos/veilway-project/veilway/releases/latest";
const NODE_NOTES: &str = "https://github.com/veilway-project/veilway/releases/tag/";
/// The release answer is a few KiB. Past this the body is dropped unread.
const BODY_MAX: usize = 262_144;
const TIMEOUT: Duration = Duration::from_secs(20);
const EVERY: Duration = Duration::from_secs(6 * 3600);
/// A failed check is tried again sooner than a good one.
const RETRY: Duration = Duration::from_secs(30 * 60);
/// How long a request stays "updating" without the panel coming back as another version.
const UPDATING: i64 = 20 * 60;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {Number(u64), Text(String)}

/// A version of the form `[v]MAJOR.MINOR.PATCH[-prerelease][+build]`, ordered the way semver orders them. Build metadata is checked and then ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {core: [u64; 3], pre: Vec<Ident>}

impl Version {
	pub fn parse(text: &str) -> Option<Self> {
		let text = text.strip_prefix('v').unwrap_or(text);
		if text.is_empty() || text.len() > 64 || !text.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte)) {return None}
		let (rest, build) = text.split_once('+').map_or((text, None), |(rest, build)| (rest, Some(build)));
		if build.is_some_and(|build| build.split('.').any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))) {return None}
		let (core, pre) = rest.split_once('-').map_or((rest, None), |(core, pre)| (core, Some(pre)));
		let numbers: Vec<u64> = core.split('.').map(|part| (!part.is_empty() && part.len() <= 9 && part.bytes().all(|byte| byte.is_ascii_digit()) && (part == "0" || !part.starts_with('0'))).then(|| part.parse().ok()).flatten()).collect::<Option<_>>()?;
		let pre = match pre {
			None => Vec::new(),
			Some(pre) => pre.split('.').map(|part| {
				if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {return None}
				if part.bytes().all(|byte| byte.is_ascii_digit()) {return (part == "0" || !part.starts_with('0')).then(|| part.parse().ok().map(Ident::Number)).flatten().filter(|_| part.len() <= 18)}
				Some(Ident::Text(part.to_string()))
			}).collect::<Option<_>>()?,
		};
		Some(Self {core: numbers.try_into().ok()?, pre})
	}
}

impl PartialOrd for Version {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {Some(self.cmp(other))}
}

impl Ord for Version {
	fn cmp(&self, other: &Self) -> Ordering {
		self.core.cmp(&other.core).then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
			(true, true) => Ordering::Equal,
			(true, false) => Ordering::Greater,
			(false, true) => Ordering::Less,
			_ => self.pre.cmp(&other.pre),
		})
	}
}

/// A published release: its version without the `v`, and the page that holds its notes.
#[derive(Clone, Debug)]
pub struct Found {pub version: String, pub notes_url: String}

/// The newest published release of the panel and of the node, as the last good checks found them, whether or not they are newer than what runs.
#[derive(Default)]
pub struct Known {pub found: Option<Found>, pub node_found: Option<Found>, pub checked_at: Option<i64>, pub requested_at: Option<i64>, pub requested: Option<Part>, pub node_from: Option<String>}

/// What an update request is for. The word is what the host script reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Part {Panel, Node, Both}

impl Part {
	fn word(self) -> &'static str {match self {Part::Panel => "panel", Part::Node => "node", Part::Both => "both"}}
}

/// The body of an update request.
#[derive(Deserialize, JsonSchema)]
pub struct Choice {pub part: Part}

/// The newest published release from its answer. The link is made here from the tag, since the answer's own links are not trusted. Drafts and pre-releases are nothing to offer.
fn release(body: &[u8], notes: &str) -> Result<Option<Found>, String> {
	let release: Value = serde_json::from_slice(body).map_err(|_| "the answer is not JSON".to_string())?;
	if release.get("draft").and_then(Value::as_bool).unwrap_or(false) || release.get("prerelease").and_then(Value::as_bool).unwrap_or(false) {return Ok(None)}
	let tag = release.get("tag_name").and_then(Value::as_str).ok_or("the answer has no tag")?;
	Version::parse(tag).ok_or("the tag is not a version")?;
	Ok(Some(Found {version: tag.strip_prefix('v').unwrap_or(tag).to_string(), notes_url: format!("{notes}{tag}")}))
}

/// The release when it is newer than `current`, the version this panel or the node runs. Nothing is offered while either version is unknown.
fn offered(found: Option<&Found>, current: Option<&str>) -> Option<Found> {
	let found = found?;
	(Version::parse(&found.version)? > Version::parse(current?)?).then(|| found.clone())
}

/// The node's version as its last poll saw it, when the node answered and the version parses.
fn node_version(app: &App) -> Option<String> {
	let live = app.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	live.as_ref().filter(|live| live.reachable).and_then(|live| live.health["version"].as_str()).filter(|version| Version::parse(version).is_some()).map(str::to_string)
}

/// The part an update request asks for. An empty body asks for the panel, as requests did before the node could be asked. Anything but an object with a known part is refused.
fn requested_part(body: &[u8]) -> Option<Part> {
	if body.is_empty() {return Some(Part::Panel)}
	serde_json::from_slice::<Value>(body).ok().filter(Value::is_object).and_then(|value| serde_json::from_value::<Choice>(value).ok()).map(|choice| choice.part)
}

/// The part a request writes, given what was asked and which parts have a newer release.
fn chosen(asked: Part, panel: bool, node: bool) -> Option<Part> {
	match (panel && asked != Part::Node, node && asked != Part::Panel) {
		(true, true) => Some(Part::Both),
		(true, false) => Some(Part::Panel),
		(false, true) => Some(Part::Node),
		(false, false) => None,
	}
}

fn connector() -> TlsConnector {
	let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	TlsConnector::from(Arc::new(rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().expect("the default protocol versions").with_root_certificates(roots).with_no_client_auth()))
}

async fn fetch(path: &str) -> Result<Vec<u8>, String> {
	let attempt = async {
		let tcp = TcpStream::connect((HOST, 443)).await.map_err(|error| error.to_string())?;
		let tls = connector().connect(ServerName::try_from(HOST).map_err(|error| error.to_string())?, tcp).await.map_err(|error| error.to_string())?;
		let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.map_err(|error| error.to_string())?;
		tokio::spawn(connection);
		let request = Request::builder().uri(path).header("host", HOST).header("user-agent", format!("veilway-panel/{CURRENT}")).header("accept", "application/vnd.github+json").body(Empty::<Bytes>::new()).map_err(|error| error.to_string())?;
		let response = sender.send_request(request).await.map_err(|error| error.to_string())?;
		if response.status() != StatusCode::OK {return Err(format!("GitHub answered {}", response.status().as_u16()))}
		Ok(Limited::new(response.into_body(), BODY_MAX).collect().await.map_err(|_| "the answer is larger than allowed or was cut".to_string())?.to_bytes().to_vec())
	};
	tokio::time::timeout(TIMEOUT, attempt).await.map_err(|_| "GitHub did not answer in time".to_string())?
}

fn record(slot: &mut Option<Found>, name: &str, answer: Result<Option<Found>, String>) {
	match answer {
		Ok(found) => {
			if found.as_ref().map(|found| &found.version) != slot.as_ref().map(|found| &found.version) {tracing::info!("update check: the newest {name} release is {}", found.as_ref().map_or("none", |found| found.version.as_str()))}
			*slot = found;
		}
		Err(error) => tracing::warn!("update check of the {name} failed: {error}"),
	}
}

/// One check of each repository. Says whether both answered; the last good answer stays for one that did not.
async fn check_once(app: &App) -> bool {
	let (panel, node) = (fetch(PANEL_PATH).await.and_then(|body| release(&body, PANEL_NOTES)), fetch(NODE_PATH).await.and_then(|body| release(&body, NODE_NOTES)));
	let failed = panel.is_err() || node.is_err();
	let mut state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	record(&mut state.found, "panel", panel);
	record(&mut state.node_found, "node", node);
	if !failed {state.checked_at = Some(now())}
	!failed
}

/// A check at start and every six hours. A failure is logged and tried again in half an hour.
pub fn spawn_checks(app: Arc<App>) {
	if !app.cfg.update_check {return}
	tokio::spawn(async move {loop {let done = check_once(&app).await; tokio::time::sleep(if done {EVERY} else {RETRY}).await;}});
}

/// The operator's "Check for updates": one check now, at most once a minute, then the same answer as `info`.
pub async fn check(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	if !app.cfg.update_check {return Err(Failure::conflict("Update checks are off in panel.json (update_check)."))}
	if !app.limits.hit("update-check", 1, 60) {return Err(Failure::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Checked a moment ago. Try again in a minute."))}
	if !check_once(&app).await {return Err(Failure::new(StatusCode::BAD_GATEWAY, "check_failed", "GitHub could not be reached. The last check's answer stays."))}
	app.db.audit(&ctx.actor, &ctx.source, "update.check", "", "").await;
	info(State(app)).await
}

#[derive(Serialize, JsonSchema)]
pub struct UpdateInfo {
	pub current: String,
	/// The newest release, when it is newer than this panel.
	pub latest: Option<String>,
	pub notes_url: Option<String>,
	pub checked_at: Option<i64>,
	/// Whether the folder for update requests exists, which a host installed or updated by `veilway.sh` has.
	pub can_update: bool,
	/// A panel update was requested and this panel has not come back as another version yet.
	pub updating: bool,
	/// The node's version, when the node is reachable and reports one.
	pub node_current: Option<String>,
	/// The newest node release, when it is newer than the node's version.
	pub node_latest: Option<String>,
	pub node_notes_url: Option<String>,
	/// A node update was requested and the node has not come back with another version yet.
	pub node_updating: bool,
}

pub async fn info(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let node_current = node_version(&app);
	let state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	let (latest, node_latest) = (offered(state.found.as_ref(), Some(CURRENT)), offered(state.node_found.as_ref(), node_current.as_deref()));
	let within = state.requested_at.is_some_and(|at| now() - at < UPDATING);
	let updating = within && latest.is_some() && state.requested.is_some_and(|part| part != Part::Node);
	let node_updating = within && state.requested.is_some_and(|part| part != Part::Panel) && node_current.as_deref().is_none_or(|version| state.node_from.as_deref() == Some(version));
	ok(&UpdateInfo {current: CURRENT.into(), latest: latest.as_ref().map(|found| found.version.clone()), notes_url: latest.as_ref().map(|found| found.notes_url.clone()), checked_at: state.checked_at, can_update: app.cfg.update_request.parent().is_some_and(|folder| folder.is_dir()), updating, node_current: node_current.clone(), node_latest: node_latest.as_ref().map(|found| found.version.clone()), node_notes_url: node_latest.map(|found| found.notes_url), node_updating})
}

#[derive(Serialize, JsonSchema)]
pub struct Requested {pub ok: bool, pub version: String, pub part: Part}

/// Puts `word` in the request file for the root service. Written whole under another name and renamed, so the path unit only ever sees a complete file. The root side reads `request` alone and ignores the other name.
fn write_request(app: &App, word: &str) -> Result<(), Failure> {
	if app.cfg.update_request.exists() {return Err(Failure::conflict("An update or a restart is already requested."))}
	let temporary = app.cfg.update_request.with_extension("tmp");
	let _ = std::fs::remove_file(&temporary);
	let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary).map_err(|error| match error.kind() {
		ErrorKind::NotFound | ErrorKind::PermissionDenied => Failure::conflict("This server has no update service. Run `sudo bash veilway.sh update panel` on it once."),
		_ => Failure::internal(error),
	})?;
	file.write_all(word.as_bytes()).and_then(|()| file.sync_all()).and_then(|()| std::fs::rename(&temporary, &app.cfg.update_request)).map_err(Failure::internal)
}

/// Asks the host to restart the node, the panel or both. The host script of v0.2.9 or later does it; an older one ignores the request, and its next update installs one that does.
pub async fn restart(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Choice>) -> Result<Response, Failure> {
	{
		let state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if state.requested_at.is_some_and(|at| now() - at < UPDATING) && state.requested.is_some() {return Err(Failure::conflict("An update was requested a moment ago."))}
		write_request(&app, &format!("restart-{}", input.part.word()))?;
	}
	app.db.audit(&ctx.actor, &ctx.source, "restart.request", input.part.word(), "").await;
	ok(&json!({"ok": true, "part": input.part}))
}

/// Writes the request. Nothing in it names a version, path or argument: the host script updates to the release it finds and verifies itself.
pub async fn request(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, body: Bytes) -> Result<Response, Failure> {
	let asked = requested_part(&body).ok_or_else(|| Failure::bad("The part is panel, node or both."))?;
	let node_now = node_version(&app);
	// Held until the request is written, so two requests cannot both pass the checks. Nothing awaits while it is held.
	let (part, detail, version) = {
		let mut state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let (panel, node) = (offered(state.found.as_ref(), Some(CURRENT)), offered(state.node_found.as_ref(), node_now.as_deref()));
		let part = chosen(asked, panel.is_some(), node.is_some()).ok_or_else(|| Failure::conflict("There is no newer release for the chosen part."))?;
		if state.requested_at.is_some_and(|at| now() - at < UPDATING) {return Err(Failure::conflict("An update was requested a moment ago."))}
		if app.cfg.update_request.exists() {return Err(Failure::conflict("An update is already requested."))}
		let (panel, node) = (panel.filter(|_| part != Part::Node), node.filter(|_| part != Part::Panel));
		let changes: Vec<String> = [panel.as_ref().map(|found| format!("panel from {CURRENT} to {}", found.version)), node.as_ref().map(|found| format!("node from {} to {}", node_now.as_deref().unwrap_or_default(), found.version))].into_iter().flatten().collect();
		let version = panel.or(node).map(|found| found.version).unwrap_or_default();
		write_request(&app, part.word())?;
		(state.requested_at, state.requested, state.node_from) = (Some(now()), Some(part), node_now);
		(part, changes.join("; "), version)
	};
	app.db.audit(&ctx.actor, &ctx.source, "update.request", part.word(), &detail).await;
	ok(&Requested {ok: true, version, part})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn v(text: &str) -> Version {Version::parse(text).unwrap()}

	#[test]
	fn versions_order_like_semver() {
		let ordered = ["0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-alpha.beta", "0.1.0-beta", "0.1.0-beta.2", "0.1.0-beta.11", "0.1.0-rc.1", "0.1.0", "0.1.1", "0.2.0", "1.0.0", "1.0.10", "2.0.0"];
		for pair in ordered.windows(2) {assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1])}
		assert_eq!(v("v1.2.3"), v("1.2.3"));
		assert_eq!(v("1.2.3+build.5").cmp(&v("1.2.3+other")), Ordering::Equal);
	}

	#[test]
	fn malformed_versions_are_refused() {
		for bad in ["", "v", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-", "1.2.3-01", "1.2.3-a..b", "1.2.3+", "1.2.x", "1.2.3 ", "1.2.3\n", "../1.2.3", "1.2.3-a_b", "99999999999.0.0", &"1".repeat(65), "vv1.2.3", "V1.2.3"] {assert!(Version::parse(bad).is_none(), "{bad:?}")}
	}

	#[test]
	fn a_published_release_is_read_with_a_link_made_from_its_tag() {
		let answer = |tag: &str, extra: &str| format!("{{\"tag_name\": \"{tag}\", \"html_url\": \"https://evil.example/x\"{extra}}}");
		let found = release(answer("v0.2.0", "").as_bytes(), NODE_NOTES).unwrap().unwrap();
		assert_eq!((found.version.as_str(), found.notes_url.as_str()), ("0.2.0", "https://github.com/veilway-project/veilway/releases/tag/v0.2.0"));
		assert!(release(answer("v0.3.0", ", \"prerelease\": true").as_bytes(), NODE_NOTES).unwrap().is_none());
		assert!(release(answer("v0.3.0", ", \"draft\": true").as_bytes(), NODE_NOTES).unwrap().is_none());
		for bad in [answer("latest", ""), answer("../../etc", ""), answer("v0.2.0\\nx", ""), "{}".into(), "[]".into(), "not json".into(), "{\"tag_name\": 5}".into()] {assert!(release(bad.as_bytes(), NODE_NOTES).is_err(), "{bad}")}
	}

	#[test]
	fn only_a_release_newer_than_the_running_version_is_offered() {
		let found = |version: &str| Found {version: version.into(), notes_url: String::new()};
		assert_eq!(offered(Some(&found("0.2.0")), Some("0.1.0")).map(|found| found.version), Some("0.2.0".to_string()));
		assert!(offered(Some(&found("0.1.0")), Some("0.1.0")).is_none());
		assert!(offered(Some(&found("0.0.9")), Some("0.1.0")).is_none());
		assert!(offered(Some(&found("0.2.0-rc.1")), Some("0.2.0")).is_none());
		assert!(offered(Some(&found("0.2.0")), None).is_none());
		assert!(offered(Some(&found("0.2.0")), Some("not a version")).is_none());
		assert!(offered(None, Some("0.1.0")).is_none());
	}

	#[test]
	fn a_node_older_newer_or_unknown_gets_the_right_offer() {
		let found = Found {version: "0.3.0".into(), notes_url: String::new()};
		assert!(offered(Some(&found), Some("0.2.1")).is_some());
		assert!(offered(Some(&found), Some("0.3.0-alpha")).is_some());
		assert!(offered(Some(&found), Some("0.3.0")).is_none());
		assert!(offered(Some(&found), Some("0.4.0")).is_none());
		assert!(offered(Some(&found), None).is_none());
	}

	#[test]
	fn the_request_takes_one_of_three_parts_and_nothing_else() {
		assert_eq!(requested_part(b""), Some(Part::Panel));
		assert_eq!(requested_part(br#"{"part": "node"}"#), Some(Part::Node));
		assert_eq!(requested_part(br#"{"part": "both"}"#), Some(Part::Both));
		for bad in [r#"{"part": "all"}"#, r#"{"part": "Panel"}"#, r#"{"part": ""}"#, r#"{}"#, r#"{"part": null}"#, r#"{"part": ["panel"]}"#, r#"["panel"]"#, r#""panel""#, "null", "{", " "] {assert!(requested_part(bad.as_bytes()).is_none(), "{bad}")}
	}

	#[test]
	fn the_word_written_follows_what_has_a_newer_release() {
		assert_eq!([Part::Panel, Part::Node, Part::Both].map(Part::word), ["panel", "node", "both"]);
		assert_eq!(chosen(Part::Panel, true, true), Some(Part::Panel));
		assert_eq!(chosen(Part::Panel, false, true), None);
		assert_eq!(chosen(Part::Node, true, true), Some(Part::Node));
		assert_eq!(chosen(Part::Node, true, false), None);
		assert_eq!(chosen(Part::Both, true, true), Some(Part::Both));
		assert_eq!(chosen(Part::Both, true, false), Some(Part::Panel));
		assert_eq!(chosen(Part::Both, false, true), Some(Part::Node));
		assert_eq!(chosen(Part::Both, false, false), None);
	}
}
