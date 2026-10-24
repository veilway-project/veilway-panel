//! Another provider's subscription as an exit of the node ("upstream"). The panel only parses the pasted link, makes the device the node enrolls with, and writes the config entry once the operator has read what the provider sent and said yes again. The node does the fetching, so the provider sees the node's address and never the panel's. Previews wait in memory with the device key and secret, which are in no answer, no log and no audit line, and a restart drops them.
use crate::{app::{App, LOCAL}, crypto::{now, random}, http::{ok, Body, Ctx, Failure}, node, nodecfg};
use axum::{extract::{Path, State}, http::StatusCode, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use veilway_proto::subscription::link::Link;

/// How long the node keeps a preview, and so how long the panel keeps the device that goes with it.
const LIFETIME: i64 = 600;
const PENDING_MAX: usize = 4;
/// The fetch takes as long as the provider does.
const FETCH: Duration = Duration::from_secs(90);
/// The classes of transports besides `cover`, which is always allowed.
const CLASSES: [&str; 3] = ["no_cover", "exposed", "plain"];

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
pub struct Quota {pub used_bytes: u64, pub quota_bytes: u64}

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
pub struct ProfileExit {pub tag: String, pub name: String}

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
pub struct Profile {
	pub id: String,
	pub name: String,
	/// Transport types in the provider's order.
	pub transports: Vec<String>,
	pub classes: Vec<String>,
	/// "protected", "detectable" or "unsafe": what a censor can see, worked out by the node.
	pub rating: String,
	/// Private addresses the profile names to dial.
	pub private_addresses: Vec<String>,
	pub mtu: u16,
	pub exits: Vec<ProfileExit>,
	/// Why this node would not use the profile under the settings of the preview. Null when it would.
	pub refused: Option<String>,
}

/// What the provider's document holds, verified by the node under the key of the link. It names no key and no secret.
#[derive(Serialize, Deserialize, JsonSchema, Clone)]
pub struct Review {
	pub id: String,
	pub expires_in_secs: u64,
	pub provider: String,
	/// The fingerprint of the key the document is signed with, which is the one in the link.
	pub fingerprint: String,
	pub serial: u64,
	pub expires_at: i64,
	pub quota: Option<Quota>,
	pub account_expires_at: Option<i64>,
	pub device_limit: Option<u16>,
	pub devices: u32,
	/// The classes the profiles list. The operator consents to each besides `cover`.
	pub classes: Vec<String>,
	pub profiles: Vec<Profile>,
	/// Filled in by the panel: whether the node may dial private addresses of the profiles under this preview.
	#[serde(default)]
	pub allow_private: bool,
	/// Filled in by the panel: the host and port of the provider's endpoint, as the link names them.
	#[serde(default)]
	pub host: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Bytes {pub up_bytes: u64, pub down_bytes: u64}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Counters {pub sent: u64, pub unsent: u64, pub refused: u64, pub dropped: u64, pub state_flips: u64, pub starts: u64, pub refreshes: u64, pub refresh_failures: u64, pub traffic: Bytes}

/// What the node is doing for one upstream.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Upstream {
	pub tag: String,
	/// "fetching", "connecting", "up" or "down".
	pub state: String,
	/// Plain words for why the state is what it is. Empty while it is up.
	pub reason: String,
	pub state_secs: u64,
	pub provider: Option<String>,
	pub profile: Option<String>,
	pub transport: Option<String>,
	pub exit: Option<String>,
	pub offered_exits: Vec<String>,
	/// What the provider says to the device, as plain text.
	pub notices: Vec<String>,
	pub quota: Option<Quota>,
	pub expires_at: Option<i64>,
	pub refreshed_at: Option<i64>,
	pub refresh_error: Option<String>,
	pub mtu: Option<u16>,
	/// A move of the provider's endpoint that waits for the operator.
	pub pending_move: Option<String>,
	/// Refresh hosts that wait for the operator.
	pub pending_hosts: Vec<String>,
	pub counters: Counters,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Upstreams {pub upstreams: Vec<Upstream>}

/// What a preview needs to become a config entry. No Debug on purpose: it holds the device key and secret.
struct Held {link: String, private_key: String, device_secret: String, via: Option<String>, review: Review, at: i64}

#[derive(Default)]
pub struct Previews(HashMap<String, Held>);

/// Turns the node's refusal into the panel's, with the node's own plain words.
fn refused(status: u16, body: &Value) -> Failure {
	let message: String = body["error"]["message"].as_str().unwrap_or("The node refused the request.").chars().take(600).collect();
	match body["error"]["code"].as_str() {
		Some("provider_failed") => Failure::new(StatusCode::BAD_GATEWAY, "provider_failed", message),
		Some("previews_full") => Failure::new(StatusCode::CONFLICT, "previews_full", message),
		Some("preview_not_found") => Failure::new(StatusCode::NOT_FOUND, "preview_gone", message),
		Some("upstream_not_found") => Failure::new(StatusCode::NOT_FOUND, "not_found", message),
		Some("body_invalid") => Failure::bad(message),
		_ => Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node answered {status}: {message}")),
	}
}

/// A tag or an id as it goes into the node's path.
fn segment(text: &str) -> Result<&str, Failure> {
	if !text.is_empty() && text.len() <= 64 && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {Ok(text)} else {Err(Failure::missing("upstream"))}
}

/// The provider's host and the fingerprint of its key, read from the link alone. Only a native `veilway://sub/` link is an upstream: the node refuses every other form, and so does the panel before anything is fetched. Nothing of the link is in a message.
fn read(text: &str) -> Result<(String, String), Failure> {
	if !text.starts_with("veilway://sub/") {return Err(Failure::bad("Only a native Veilway subscription link works here: it starts with veilway://sub/. Older links, links that hold a whole document and plain http links cannot be an upstream."))}
	match Link::parse(text) {
		Ok(Link::Native(native)) => Ok((native.endpoint().authority(), native.key().fingerprint().to_string())),
		Ok(_) => Err(Failure::bad("This is not a native subscription link. Older links and links that hold a whole document cannot be an upstream.")),
		Err(_) => Err(Failure::bad("This is not a valid Veilway subscription link. Copy it again from the provider.")),
	}
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectIn {pub link: String}

#[derive(Serialize, JsonSchema)]
pub struct Inspected {
	/// The host and port of the provider's endpoint. This is where the node will connect.
	pub host: String,
	/// The fingerprint of the provider's signing key, as 8 groups of 4 hex digits. The provider can read it out for comparison.
	pub fingerprint: String,
}

/// Step 1, offline: what the pasted link says. Nothing is sent anywhere.
pub async fn inspect(Body(input): Body<InspectIn>) -> Result<Response, Failure> {
	let (host, fingerprint) = read(input.link.trim())?;
	ok(&Inspected {host, fingerprint})
}

/// Makes a device for the provider and has the node fetch the subscription with it. The fetch takes a place at the provider, which is given back when the preview is declined or runs out.
async fn fetch(app: &Arc<App>, link: String, host: String, via: Option<String>, allow_private: bool) -> Result<Review, Failure> {
	{
		let mut previews = app.previews.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		previews.0.retain(|_, held| held.at + LIFETIME > now());
		if previews.0.len() >= PENDING_MAX {return Err(Failure::new(StatusCode::CONFLICT, "previews_full", "Four fetches already wait. Decline one or wait for it to run out."))}
	}
	let (private_key, device_secret) = (STANDARD.encode(random::<32>()), URL_SAFE_NO_PAD.encode(random::<16>()));
	let mut body = json!({"link": link, "private_key": private_key, "device_secret": device_secret, "allow_private": allow_private});
	if let Some(via) = &via {body["via"] = json!(via)}
	let (status, bytes) = node::request_within(&app, LOCAL, "POST", "/v1/upstreams/preview", None, Some(&body), FETCH).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
	if status != 200 {return Err(refused(status, &answer))}
	let mut review: Review = serde_json::from_value(answer).map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node's preview does not read: {error}")))?;
	(review.allow_private, review.host) = (allow_private, host);
	app.previews.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.insert(review.id.clone(), Held {link, private_key, device_secret, via, review: review.clone(), at: now()});
	Ok(review)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewIn {
	/// The native `veilway://sub/` link of the provider.
	pub link: String,
	/// The tag of a direct or socks5 outbound the node reaches the provider through. Left out: from the node itself.
	pub via: Option<String>,
	/// Whether the node may dial private addresses the profiles name. Default false.
	pub allow_private: Option<bool>,
}

/// Step 2, after the operator said "fetch": the node enrolls a new device and shows what the provider sent.
pub async fn preview(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<PreviewIn>) -> Result<Response, Failure> {
	let link = input.link.trim().to_string();
	let (host, fingerprint) = read(&link)?;
	let review = fetch(&app, link, host, input.via.filter(|via| !via.is_empty()), input.allow_private == Some(true)).await?;
	app.db.audit(&ctx.actor, &ctx.source, "upstream.preview", &review.id, &format!("key {fingerprint}")).await;
	ok(&review)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivateIn {pub allow_private: bool}

/// Fetches again with the other answer to "allow private addresses": the old preview is declined first, so its place at the provider is given back, and the new one has a new device.
pub async fn again(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>, Body(input): Body<PrivateIn>) -> Result<Response, Failure> {
	let id = segment(&id)?.to_string();
	let held = app.previews.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.remove(&id).ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "preview_gone", "This fetch ran out or was declined. Start again from the link."))?;
	let (status, answer) = nodecfg::call(&app, LOCAL, "POST", &format!("/v1/upstreams/preview/{id}/decline"), None, None).await?;
	if status != 200 && status != 404 {return Err(refused(status, &answer))}
	let review = fetch(&app, held.link, held.review.host, held.via, input.allow_private).await?;
	app.db.audit(&ctx.actor, &ctx.source, "upstream.preview", &review.id, &format!("key {}, private addresses {}", review.fingerprint, input.allow_private)).await;
	ok(&review)
}

/// The operator says no: the provider is told to release the place.
pub async fn decline(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>) -> Result<Response, Failure> {
	let id = segment(&id)?.to_string();
	app.previews.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.remove(&id);
	let (status, answer) = nodecfg::call(&app, LOCAL, "POST", &format!("/v1/upstreams/preview/{id}/decline"), None, None).await?;
	if status != 200 {return Err(refused(status, &answer))}
	app.db.audit(&ctx.actor, &ctx.source, "upstream.decline", &id, "").await;
	ok(&crate::admin::Done {ok: true})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddIn {
	/// The tag of the upstream in the node's config, and of the exit that leaves through it: 1 to 64 of a-z, 0-9, - and _.
	pub tag: String,
	/// The exit's display name. Defaults to the tag.
	pub name: Option<String>,
	/// The profile of the provider to use. Left out: the first one the node would use.
	pub profile: Option<String>,
	/// The provider's exit to leave through. Left out: the provider's default.
	pub exit: Option<String>,
	/// The classes besides `cover` that the operator allows: no_cover, exposed, plain.
	#[serde(default)]
	pub allow: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct Added {pub tag: String, pub generation: u64}

/// Step 3, with a recent re-authentication: the upstream and the exit that uses it go into the node's config. The node takes the fetched document when the link and the device are the ones it holds.
pub async fn add(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>, Body(input): Body<AddIn>) -> Result<Response, Failure> {
	let id = segment(&id)?;
	let tag = input.tag.trim().to_string();
	if tag.is_empty() || tag.len() > 64 || !tag.starts_with(|first: char| first.is_ascii_lowercase() || first.is_ascii_digit()) || !tag.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_') {return Err(Failure::bad("The tag is 1 to 64 characters of a-z, 0-9, - and _, and starts with a letter or a digit."))}
	let held = app.previews.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.get(id).filter(|held| held.at + LIFETIME > now()).map(|held| (held.link.clone(), held.private_key.clone(), held.device_secret.clone(), held.via.clone(), held.review.clone()));
	let Some((link, private_key, device_secret, via, review)) = held else {return Err(Failure::new(StatusCode::NOT_FOUND, "preview_gone", "This fetch ran out or was declined. Start again from the link."))};
	let profile = input.profile.as_deref().filter(|profile| !profile.is_empty());
	let chosen = match profile {Some(profile) => review.profiles.iter().find(|found| found.id == profile), None => review.profiles.iter().find(|found| found.refused.is_none())};
	let Some(chosen) = chosen.filter(|chosen| chosen.refused.is_none()) else {return Err(Failure::bad("The provider has no profile this node would use. Allow private addresses, or ask the provider for another."))};
	let exit = input.exit.as_deref().filter(|exit| !exit.is_empty());
	if exit.is_some_and(|exit| !chosen.exits.iter().any(|found| found.tag == exit)) {return Err(Failure::bad("The profile does not offer that exit."))}
	if input.allow.iter().any(|class| !CLASSES.contains(&class.as_str()) || !review.classes.contains(class)) {return Err(Failure::bad("A class of transports is not one the provider lists."))}
	let _turn = app.turn(LOCAL).await;
	let (revision, _, mut document) = nodecfg::running(&app, LOCAL).await?;
	let named = |section: &str| document[section].as_array().into_iter().flatten().any(|item| item["tag"] == tag.as_str());
	if named("upstreams") || named("exits") {return Err(Failure::conflict("An upstream or an exit already has this tag. Choose another."))}
	let mut entry = json!({"tag": tag, "link": link, "signing_key": review.fingerprint, "private_key": private_key, "device_secret": device_secret});
	if profile.is_some() {entry["profile"] = json!(chosen.id)}
	if let Some(exit) = exit {entry["exit"] = json!(exit)}
	if let Some(via) = via {entry["via"] = json!(via)}
	if !input.allow.is_empty() {entry["allow"] = json!(CLASSES.iter().filter(|class| input.allow.iter().any(|allowed| allowed == *class)).collect::<Vec<_>>())}
	if review.allow_private {entry["allow_private"] = json!(true)}
	let mut exit_entry = json!({"tag": tag, "backend": {"type": "upstream", "upstream": tag}});
	if let Some(name) = input.name.as_deref().map(str::trim).filter(|name| !name.is_empty()) {exit_entry["name"] = json!(name)}
	let object = document.as_object_mut().ok_or_else(|| Failure::internal("the node's config is not an object"))?;
	for (section, item) in [("upstreams", entry), ("exits", exit_entry)] {
		match object.entry(section).or_insert_with(|| json!([])) {Value::Array(items) => items.push(item), other => *other = json!([item])}
	}
	let applied = nodecfg::apply(&app, LOCAL, &ctx, document, &revision, &tag).await?;
	app.previews.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.remove(id);
	app.db.audit(&ctx.actor, &ctx.source, "upstream.add", &tag, &format!("provider key {}", review.fingerprint)).await;
	ok(&Added {tag, generation: applied.get("generation").and_then(Value::as_u64).unwrap_or(0)})
}

/// The node's upstreams with their state, as the node reports them. Only the fields below pass.
pub async fn list(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (status, body) = nodecfg::call(&app, LOCAL, "GET", "/v1/upstreams", None, None).await?;
	if status != 200 {return Err(refused(status, &body))}
	ok(&serde_json::from_value::<Upstreams>(body).map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node's upstreams do not read: {error}")))?)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveIn {
	/// Follow the move of the provider's endpoint the node reported as pending.
	#[serde(rename = "move")]
	pub moving: Option<bool>,
	/// Take the refresh hosts the node reported as pending.
	pub hosts: Option<bool>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Moved {pub moved: bool, pub hosts: bool}

/// Says yes to what the provider announced: a new endpoint, new refresh hosts. Until then the node keeps the old ones. With no field given both are confirmed.
pub async fn confirm_move(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(tag): Path<String>, Body(input): Body<MoveIn>) -> Result<Response, Failure> {
	let tag = segment(&tag)?;
	let body = (input.moving.is_some() || input.hosts.is_some()).then(|| json!({"move": input.moving == Some(true), "hosts": input.hosts == Some(true)}));
	let (status, answer) = nodecfg::call(&app, LOCAL, "POST", &format!("/v1/upstreams/{tag}/confirm"), None, body.as_ref()).await?;
	if status != 200 {return Err(refused(status, &answer))}
	let moved = serde_json::from_value::<Moved>(answer).map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node's answer does not read: {error}")))?;
	app.db.audit(&ctx.actor, &ctx.source, "upstream.confirm", tag, &format!("move {}, hosts {}", moved.moved, moved.hosts)).await;
	ok(&moved)
}

#[derive(Serialize, JsonSchema)]
pub struct Retried {pub tag: String}

/// Asks the upstream to connect again now.
pub async fn retry(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(tag): Path<String>) -> Result<Response, Failure> {
	let tag = segment(&tag)?;
	let (status, answer) = nodecfg::call(&app, LOCAL, "POST", &format!("/v1/upstreams/{tag}/retry"), None, None).await?;
	if status != 200 {return Err(refused(status, &answer))}
	app.db.audit(&ctx.actor, &ctx.source, "upstream.retry", tag, "").await;
	ok(&Retried {tag: tag.to_string()})
}

#[derive(Serialize, JsonSchema)]
pub struct Removed {
	pub tag: String,
	/// Whether the provider took the word that the device left. False: its place stays until the provider removes it. Null: the node never ran this upstream, so there was nothing to tell.
	pub confirmed: Option<bool>,
}

/// With a recent re-authentication: the provider is told the device left (up to ten seconds), then the config is applied without the upstream and the exits that use it. The config without them is checked first, so a rule that still uses the exit stops the removal before the provider is told anything.
pub async fn remove(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(tag): Path<String>) -> Result<Response, Failure> {
	let tag = segment(&tag)?.to_string();
	let _turn = app.turn(LOCAL).await;
	let (revision, _, mut document) = nodecfg::running(&app, LOCAL).await?;
	if !document["upstreams"].as_array().into_iter().flatten().any(|item| item["tag"] == tag.as_str()) {return Err(Failure::missing("upstream"))}
	if let Some(items) = document["upstreams"].as_array_mut() {items.retain(|item| item["tag"] != tag.as_str())}
	if let Some(items) = document["exits"].as_array_mut() {items.retain(|item| !(item["backend"]["type"] == "upstream" && item["backend"]["upstream"] == tag.as_str()))}
	let (status, checked) = nodecfg::call(&app, LOCAL, "POST", "/v1/config/validate", None, Some(&nodecfg::with_users(&app, LOCAL, document.clone()).await?)).await?;
	if status != 200 || checked.get("valid") != Some(&Value::Bool(true)) {
		let first = &checked["report"]["errors"][0];
		return Err(Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", format!("The config without this provider is refused, so nothing was removed: {} {}", first["path"].as_str().unwrap_or_default(), first["message"].as_str().unwrap_or("see the config page")).trim().to_string()))
	}
	let (status, answer) = nodecfg::call(&app, LOCAL, "DELETE", &format!("/v1/upstreams/{tag}"), None, None).await?;
	let confirmed = match status {200 => answer["confirmed"].as_bool(), 404 => None, _ => return Err(refused(status, &answer))};
	nodecfg::apply(&app, LOCAL, &ctx, document, &revision, &tag).await?;
	app.db.audit(&ctx.actor, &ctx.source, "upstream.remove", &tag, match confirmed {Some(true) => "the provider confirmed the leave", Some(false) => "the provider did not confirm the leave", None => "nothing to leave"}).await;
	ok(&Removed {tag, confirmed})
}
