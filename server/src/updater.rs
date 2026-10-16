//! Finding out that a newer panel exists, and asking for it. The panel runs unprivileged and never updates itself: a request is a file with the word `panel` in a folder only the panel and root can write, which a root service on the host answers (see `veilway.sh`). Everything GitHub sends is untrusted.
use crate::{app::App, crypto::now, http::{ok, Ctx, Failure}};
use axum::{extract::State, http::StatusCode, response::Response, Extension};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;
use std::{cmp::Ordering, fs::OpenOptions, io::{ErrorKind, Write}, os::unix::fs::OpenOptionsExt, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const HOST: &str = "api.github.com";
const PATH: &str = "/repos/veilway-project/veilway-panel/releases/latest";
const NOTES: &str = "https://github.com/veilway-project/veilway-panel/releases/tag/";
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

/// What the last good check found: a release newer than this build.
#[derive(Clone, Debug)]
pub struct Found {pub version: String, pub notes_url: String}

#[derive(Default)]
pub struct Known {pub found: Option<Found>, pub checked_at: Option<i64>, pub requested_at: Option<i64>}

/// The tag of a published release, if the answer is one and is newer than `current`. The link is made here from the tag, since the answer's own links are not trusted.
pub fn newer(body: &[u8], current: &str) -> Result<Option<Found>, String> {
	let release: Value = serde_json::from_slice(body).map_err(|_| "the answer is not JSON".to_string())?;
	if release.get("draft").and_then(Value::as_bool).unwrap_or(false) || release.get("prerelease").and_then(Value::as_bool).unwrap_or(false) {return Ok(None)}
	let tag = release.get("tag_name").and_then(Value::as_str).ok_or("the answer has no tag")?;
	let (latest, current) = (Version::parse(tag).ok_or("the tag is not a version")?, Version::parse(current).ok_or("this build has no valid version")?);
	Ok((latest > current).then(|| Found {version: tag.strip_prefix('v').unwrap_or(tag).to_string(), notes_url: format!("{NOTES}{tag}")}))
}

fn connector() -> TlsConnector {
	let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	TlsConnector::from(Arc::new(rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().expect("the default protocol versions").with_root_certificates(roots).with_no_client_auth()))
}

async fn fetch() -> Result<Vec<u8>, String> {
	let attempt = async {
		let tcp = TcpStream::connect((HOST, 443)).await.map_err(|error| error.to_string())?;
		let tls = connector().connect(ServerName::try_from(HOST).map_err(|error| error.to_string())?, tcp).await.map_err(|error| error.to_string())?;
		let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.map_err(|error| error.to_string())?;
		tokio::spawn(connection);
		let request = Request::builder().uri(PATH).header("host", HOST).header("user-agent", format!("veilway-panel/{CURRENT}")).header("accept", "application/vnd.github+json").body(Empty::<Bytes>::new()).map_err(|error| error.to_string())?;
		let response = sender.send_request(request).await.map_err(|error| error.to_string())?;
		if response.status() != StatusCode::OK {return Err(format!("GitHub answered {}", response.status().as_u16()))}
		Ok(Limited::new(response.into_body(), BODY_MAX).collect().await.map_err(|_| "the answer is larger than allowed or was cut".to_string())?.to_bytes().to_vec())
	};
	tokio::time::timeout(TIMEOUT, attempt).await.map_err(|_| "GitHub did not answer in time".to_string())?
}

/// One check, at start and every six hours. A failure is logged and tried again in half an hour, so one bad answer never stops the checks.
pub fn spawn_checks(app: Arc<App>) {
	if !app.cfg.update_check {return}
	tokio::spawn(async move {
		loop {
			let wait = match fetch().await.and_then(|body| newer(&body, CURRENT)) {
				Ok(found) => {
					let mut state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
					if found.as_ref().map(|found| &found.version) != state.found.as_ref().map(|found| &found.version) {tracing::info!("update check: {}", found.as_ref().map_or("this panel is current".to_string(), |found| format!("{} is available", found.version)))}
					(state.found, state.checked_at) = (found, Some(now()));
					EVERY
				}
				Err(error) => {tracing::warn!("update check failed: {error}"); RETRY}
			};
			tokio::time::sleep(wait).await;
		}
	});
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
	/// A request was made and this panel has not come back as another version yet.
	pub updating: bool,
}

pub async fn info(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	let updating = state.found.is_some() && state.requested_at.is_some_and(|at| now() - at < UPDATING);
	ok(&UpdateInfo {current: CURRENT.into(), latest: state.found.as_ref().map(|found| found.version.clone()), notes_url: state.found.as_ref().map(|found| found.notes_url.clone()), checked_at: state.checked_at, can_update: app.cfg.update_request.parent().is_some_and(|folder| folder.is_dir()), updating})
}

#[derive(Serialize, JsonSchema)]
pub struct Requested {pub ok: bool, pub version: String}

/// Writes the request. Nothing in it names a version, path or argument: the host script updates to the release it finds and verifies itself.
pub async fn request(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	// Held until the request is written, so two requests cannot both pass the checks. Nothing awaits while it is held.
	let version = {
		let mut state = app.update.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let found = state.found.as_ref().ok_or_else(|| Failure::conflict("There is no newer release."))?;
		if state.requested_at.is_some_and(|at| now() - at < UPDATING) {return Err(Failure::conflict("An update was requested a moment ago."))}
		let version = found.version.clone();
		if app.cfg.update_request.exists() {return Err(Failure::conflict("An update is already requested."))}
		// Written whole under another name and renamed, so the path unit only ever sees a complete file. The root side reads `request` alone and ignores this name.
		let temporary = app.cfg.update_request.with_extension("tmp");
		let _ = std::fs::remove_file(&temporary);
		let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary).map_err(|error| match error.kind() {
			ErrorKind::NotFound | ErrorKind::PermissionDenied => Failure::conflict("This server has no update service. Run `sudo bash veilway.sh update panel` on it once."),
			_ => Failure::internal(error),
		})?;
		file.write_all(b"panel").and_then(|()| file.sync_all()).and_then(|()| std::fs::rename(&temporary, &app.cfg.update_request)).map_err(Failure::internal)?;
		state.requested_at = Some(now());
		version
	};
	app.db.audit(&ctx.actor, &ctx.source, "update.request", "panel", &format!("from {CURRENT} to {version}")).await;
	ok(&Requested {ok: true, version})
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
	fn only_a_newer_published_release_is_found() {
		let release = |tag: &str, extra: &str| format!("{{\"tag_name\": \"{tag}\", \"html_url\": \"https://evil.example/x\"{extra}}}");
		let found = newer(release("v0.2.0", "").as_bytes(), "0.1.0").unwrap().unwrap();
		assert_eq!((found.version.as_str(), found.notes_url.as_str()), ("0.2.0", "https://github.com/veilway-project/veilway-panel/releases/tag/v0.2.0"));
		assert!(newer(release("v0.1.0", "").as_bytes(), "0.1.0").unwrap().is_none());
		assert!(newer(release("v0.0.9", "").as_bytes(), "0.1.0").unwrap().is_none());
		assert!(newer(release("v0.2.0-rc.1", "").as_bytes(), "0.2.0").unwrap().is_none());
		assert!(newer(release("v0.3.0", ", \"prerelease\": true").as_bytes(), "0.1.0").unwrap().is_none());
		assert!(newer(release("v0.3.0", ", \"draft\": true").as_bytes(), "0.1.0").unwrap().is_none());
		for bad in [release("latest", ""), release("../../etc", ""), release("v0.2.0\\nx", ""), "{}".into(), "[]".into(), "not json".into(), "{\"tag_name\": 5}".into()] {assert!(newer(bad.as_bytes(), "0.1.0").is_err(), "{bad}")}
	}
}
