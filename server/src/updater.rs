//! Finding out that a newer panel or node exists, and asking for it. The panel runs unprivileged and never updates itself: a request is a file with the word `panel`, `node` or `both` in a folder only the panel and root can write, which a root service on the host answers (see `veilway.sh`). Everything GitHub sends is untrusted.
use crate::{app::{App, LOCAL}, crypto::now, nodecfg, http::{ok, Body, Ctx, Failure}};
use axum::{extract::State, http::StatusCode, response::Response, Extension};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{cmp::Ordering, fs::OpenOptions, io::{ErrorKind, Read, Write}, net::{IpAddr, SocketAddr}, os::unix::fs::OpenOptionsExt, path::Path, sync::Arc, time::Duration};
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
fn write_request(request: &Path, word: &str) -> Result<(), Failure> {
	if request.exists() {return Err(Failure::conflict("An update or a restart is already requested."))}
	let temporary = request.with_extension("tmp");
	let _ = std::fs::remove_file(&temporary);
	let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary).map_err(|error| match error.kind() {
		ErrorKind::NotFound | ErrorKind::PermissionDenied => Failure::conflict("This server has no update service. Run `sudo bash veilway.sh update panel` on it once."),
		_ => Failure::internal(error),
	})?;
	file.write_all(word.as_bytes()).and_then(|()| file.sync_all()).and_then(|()| std::fs::rename(&temporary, request)).map_err(Failure::internal)
}

/// Asks the host to restart the node, the panel or both. The host script of v0.2.9 or later does it; an older one ignores the request, and its next update installs one that does.
pub async fn restart(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<Choice>) -> Result<Response, Failure> {
	{
		let state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if state.requested_at.is_some_and(|at| now() - at < UPDATING) && state.requested.is_some() {return Err(Failure::conflict("An update was requested a moment ago."))}
		write_request(&app.cfg.update_request, &format!("restart-{}", input.part.word()))?;
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
		write_request(&app.cfg.update_request, part.word())?;
		(state.requested_at, state.requested, state.node_from) = (Some(now()), Some(part), node_now);
		(part, changes.join("; "), version)
	};
	app.db.audit(&ctx.actor, &ctx.source, "update.request", part.word(), &detail).await;
	ok(&Requested {ok: true, version, part})
}

/// One path of the node that the web server sends to a loopback listener. This is what `web-routes.json` holds.
#[derive(Serialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
pub struct WebRoute {pub path: String, pub port: u16, #[serde(rename = "type")] pub kind: String}

/// A path of the node that is left out of the routes, and why.
#[derive(Serialize, JsonSchema, Debug, PartialEq, Eq)]
pub struct WebSkipped {pub path: String, pub reason: String}

/// What the root helper wrote to `web-routes.result` after its last run.
#[derive(Serialize, Deserialize, JsonSchema, Debug, PartialEq, Eq)]
pub struct WebResult {pub ok: bool, pub message: String, pub at: i64, pub routes: u32, pub web: String}

#[derive(Serialize, JsonSchema)]
pub struct WebRoutes {
	/// The routes the panel sends now, or sent just now.
	pub routes: Vec<WebRoute>,
	/// The paths left out and why.
	pub skipped: Vec<WebSkipped>,
	/// The helper's answer to its last run, when there is one.
	pub result: Option<WebResult>,
	/// A request is waiting for the root service.
	pub waiting: bool,
	/// When this request was written, which the helper's `at` is compared with. Only a request has one.
	pub sent_at: Option<i64>,
}

const WEB_MAX: usize = 32;
/// The helper's answer is a short line. Past this it is not read.
const RESULT_MAX: u64 = 8192;

/// The path rule of the root helper, so a route sent is never refused there.
fn web_path_problem(path: &str, prefix: &str, sub_path: &str) -> Option<&'static str> {
	let bytes = path.as_bytes();
	if !(13..=129).contains(&bytes.len()) || bytes[0] != b'/' || !bytes[1..].iter().all(|byte| byte.is_ascii_alphanumeric() || b"._~-/".contains(byte)) || bytes[1] == b'/' {return Some("The path is 12 to 128 characters after the slash: letters, digits and . _ ~ - /")}
	if path.contains("//") || path.contains("..") {return Some("The path has // or ..")}
	if [prefix, sub_path].iter().any(|own| path == *own || path.starts_with(&format!("{own}/")) || own.starts_with(path)) {return Some("The path is the panel's own, under it or the start of it")}
	None
}

/// The paths of the node's running config that sit behind a web server: the enabled `ws` and `fronted` transports of enabled veilway inbounds with a path and a listener on 127.0.0.1, the only address the host helper forwards to. Any other listener is left out with the reason.
fn web_routes(document: &Value, prefix: &str, sub_path: &str) -> (Vec<WebRoute>, Vec<WebSkipped>) {
	let (mut routes, mut skipped): (Vec<WebRoute>, Vec<WebSkipped>) = (Vec::new(), Vec::new());
	for inbound in document["inbounds"].as_array().into_iter().flatten().filter(|inbound| inbound["type"] == "veilway" && inbound["enabled"] != false) {
		for transport in inbound["transports"].as_array().into_iter().flatten().filter(|transport| transport["enabled"] != false && matches!(transport["type"].as_str(), Some("ws" | "fronted"))) {
			let (Some(path), Some(listen), Some(kind)) = (transport["path"].as_str(), transport["listen"].as_str().and_then(|listen| listen.parse::<SocketAddr>().ok()), transport["type"].as_str()) else {continue};
			let problem = (listen.port() == 0 || listen.ip() != IpAddr::from([127, 0, 0, 1])).then_some("The transport does not listen on 127.0.0.1, where the web server sends it").or_else(|| web_path_problem(path, prefix, sub_path)).or_else(|| routes.iter().any(|route| route.path == path).then_some("Two transports have this path")).or_else(|| (routes.len() >= WEB_MAX).then_some("Only 32 paths fit"));
			match problem {
				Some(reason) => skipped.push(WebSkipped {path: path.chars().take(130).collect(), reason: reason.into()}),
				None => routes.push(WebRoute {path: path.into(), port: listen.port(), kind: kind.into()}),
			}
		}
	}
	(routes, skipped)
}

/// The helper's last answer, from the folder of the request file. A file that is missing, large or not the expected shape is no answer.
fn web_result(request: &Path) -> Option<WebResult> {
	let mut body = Vec::new();
	std::fs::File::open(request.with_file_name("web-routes.result")).ok()?.take(RESULT_MAX).read_to_end(&mut body).ok()?;
	serde_json::from_slice(&body).ok()
}

/// Writes `web-routes.json` whole under another name and renamed, readable by the helper's group, and then the request word. A request that waits refuses the whole thing before the file is touched.
fn send_routes(request: &Path, routes: &[WebRoute]) -> Result<(), Failure> {
	if request.exists() {return Err(Failure::conflict("An update, a restart or a web server request is already waiting."))}
	let (target, temporary) = (request.with_file_name("web-routes.json"), request.with_file_name("web-routes.json.tmp"));
	let _ = std::fs::remove_file(&temporary);
	let mut file = OpenOptions::new().write(true).create_new(true).mode(0o640).open(&temporary).map_err(|error| match error.kind() {
		ErrorKind::NotFound | ErrorKind::PermissionDenied => Failure::conflict("This server has no update service. Run `sudo bash veilway.sh update panel` on it once."),
		_ => Failure::internal(error),
	})?;
	file.write_all(&serde_json::to_vec(&json!({"routes": routes})).map_err(Failure::internal)?).and_then(|()| file.sync_all()).and_then(|()| std::fs::rename(&temporary, &target)).map_err(Failure::internal)?;
	write_request(request, "web-routes")
}

/// The routes the panel would send now and the helper's last answer.
pub async fn web_routes_info(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (_, _, document) = nodecfg::running(&app, LOCAL).await?;
	let (routes, skipped) = web_routes(&document, &app.cfg.prefix, &app.cfg.sub_path);
	ok(&WebRoutes {routes, skipped, result: web_result(&app.cfg.update_request), waiting: app.cfg.update_request.exists(), sent_at: None})
}

/// Asks the host to make the web server send these paths to the node. The set replaces what the helper added before.
pub async fn web_routes_send(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let (_, _, document) = nodecfg::running(&app, LOCAL).await?;
	let (routes, skipped) = web_routes(&document, &app.cfg.prefix, &app.cfg.sub_path);
	send_routes(&app.cfg.update_request, &routes)?;
	app.db.audit(&ctx.actor, &ctx.source, "web.routes", "", &format!("{} paths", routes.len())).await;
	ok(&WebRoutes {routes, skipped, result: web_result(&app.cfg.update_request), waiting: true, sent_at: Some(now())})
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::os::unix::fs::PermissionsExt;

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

	#[test]
	fn web_routes_are_the_enabled_loopback_ws_and_fronted_paths() {
		let document = json!({"inbounds": [
			{"type": "veilway", "transports": [
				{"type": "ws", "listen": "127.0.0.1:8443", "path": "/aaaaaaaaaaaaaaaaaaaa"},
				{"type": "fronted", "listen": "[::1]:9443", "path": "/bbbbbbbbbbbbbbbbbbbb"},
				{"type": "ws", "listen": "0.0.0.0:8444", "path": "/cccccccccccccccccccc"},
				{"type": "ws", "listen": "127.0.0.1:8445", "path": "/dddddddddddddddddddd", "enabled": false},
				{"type": "ws", "listen": "127.0.0.1:8446", "path": "/panel/eeeeeeeeeeeeeeeeeeee"},
				{"type": "ws", "listen": "127.0.0.1:8447", "path": "/short"},
				{"type": "ws", "listen": "127.0.0.1:8448", "path": "/aaaaaaaaaaaaaaaaaaaa"},
				{"type": "tls", "listen": "127.0.0.1:8449", "path": "/ffffffffffffffffffff"},
				{"type": "ws", "listen": "127.0.0.1:8450", "path": "/aa/../aaaaaaaaaaaaaaa"}]},
			{"type": "veilway", "enabled": false, "transports": [{"type": "ws", "listen": "127.0.0.1:8451", "path": "/gggggggggggggggggggg"}]},
			{"type": "socks5", "transports": [{"type": "ws", "listen": "127.0.0.1:8452", "path": "/hhhhhhhhhhhhhhhhhhhh"}]}]});
		let (routes, skipped) = web_routes(&document, "/panel", "/sub");
		assert_eq!(routes, vec![WebRoute {path: "/aaaaaaaaaaaaaaaaaaaa".into(), port: 8443, kind: "ws".into()}]);
		assert_eq!(skipped.iter().map(|skipped| skipped.path.as_str()).collect::<Vec<_>>(), ["/bbbbbbbbbbbbbbbbbbbb", "/cccccccccccccccccccc", "/panel/eeeeeeeeeeeeeeeeeeee", "/short", "/aaaaaaaaaaaaaaaaaaaa", "/aa/../aaaaaaaaaaaaaaa"]);
		assert!(web_path_problem("/sub", "/panel", "/sub").is_some());
		assert!(web_path_problem("/bff82055c6d2", "/bff82055c6d25edc", "/sub").is_some());
		assert!(web_path_problem("/panelx-aaaaaaaaaaaa", "/panel", "/sub").is_none());
	}

	#[test]
	fn a_web_routes_request_writes_the_file_and_the_word_and_refuses_a_second() {
		let dir = std::env::temp_dir().join(format!("vwweb-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let request = dir.join("request");
		let routes = vec![WebRoute {path: "/aaaaaaaaaaaaaaaaaaaa".into(), port: 8443, kind: "ws".into()}];
		assert!(send_routes(&request, &routes).is_ok());
		assert_eq!(std::fs::read_to_string(&request).unwrap(), "web-routes");
		assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(dir.join("web-routes.json")).unwrap()).unwrap(), json!({"routes": [{"path": "/aaaaaaaaaaaaaaaaaaaa", "port": 8443, "type": "ws"}]}));
		assert_eq!(std::fs::metadata(dir.join("web-routes.json")).unwrap().permissions().mode() & 0o777, 0o640);
		assert!(send_routes(&request, &[]).is_err());
		assert!(web_result(&request).is_none());
		std::fs::write(dir.join("web-routes.result"), r#"{"ok": true, "message": "done", "at": 5, "routes": 1, "web": "caddy"}"#).unwrap();
		assert_eq!(web_result(&request), Some(WebResult {ok: true, message: "done".into(), at: 5, routes: 1, web: "caddy".into()}));
		std::fs::remove_dir_all(&dir).unwrap();
	}
}
