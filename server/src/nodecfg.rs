//! The node's config through its control API: the schema, the document as a whole and by section, dry runs, the one path that applies a change, and the profile templates derived from the inbounds.
use crate::{app::{App, Settings}, crypto::now, db::audit, http::{json, ok, Body, Ctx, Failure}, node};
use axum::{extract::{Path, State}, http::{header::CONTENT_TYPE, HeaderValue, StatusCode}, response::{IntoResponse, Response}, Extension};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// `veilway schema` of the core, kept next to the manifest. The node's own validation stays the authority: this is for an editor.
const SCHEMA: &str = include_str!("../config.schema.json");
/// The parts of the document that are edited as structured objects. `users` is the panel's own and never appears here.
const SECTIONS: [&str; 9] = ["inbounds", "outbounds", "exits", "routing", "notices", "dns", "log", "links", "replay"];
/// The sections that are an object. The others are lists.
const OBJECTS: [&str; 4] = ["routing", "dns", "log", "replay"];

pub async fn schema() -> Response {(StatusCode::OK, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], SCHEMA).into_response()}

async fn call(app: &App, method: &str, path: &str, if_match: Option<&str>, body: Option<&Value>) -> Result<(u16, Value), Failure> {
	let (status, bytes) = node::request(&app.cfg.node_socket, method, path, if_match, body).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
}

/// The revision, the generation and the document the node runs, secrets as the node's marker.
pub(crate) async fn running(app: &App) -> Result<(String, u64, Value), Failure> {
	let (status, body) = call(app, "GET", "/v1/config", None, None).await?;
	let (Some(revision), Some(document)) = (body.get("revision").and_then(Value::as_str), body.get("document")) else {return Err(Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node answered {status} to the config.")))};
	Ok((revision.to_string(), body.get("generation").and_then(Value::as_u64).unwrap_or(0), document.clone()))
}

pub async fn get_config(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (revision, generation, mut document) = running(&app).await?;
	document.as_object_mut().map(|document| document.remove("users"));
	ok(&json!({"revision": revision, "generation": generation, "document": document}))
}

pub async fn get_section(State(app): State<Arc<App>>, Path(section): Path<String>) -> Result<Response, Failure> {
	if !SECTIONS.contains(&section.as_str()) {return Err(Failure::missing("section"))}
	let (revision, generation, document) = running(&app).await?;
	let mut answer = json!({"revision": revision, "generation": generation, "value": document.get(&section).cloned().unwrap_or(Value::Null)});
	// The node reads the size of its replay memory once, at start.
	if section == "replay" {answer["read_at_start"] = json!(["cache"]);}
	ok(&answer)
}

/// The document with the panel's users in it, and their Xray credentials, since the node's `users` is what the panel owns.
fn with_users(app: &App, mut document: Value) -> Result<Value, Failure> {
	if !document.is_object() {return Err(Failure::bad("The document is a JSON object."))}
	node::fill(app, &mut document).map_err(|error| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "users_unavailable", error))?;
	Ok(document)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentIn {pub document: Value}

/// Asks the node whether the document is valid, or what applying it would change. Nothing changes.
pub async fn dry_run(app: Arc<App>, document: Value, path: &str) -> Result<Response, Failure> {
	let (status, body) = call(&app, "POST", path, None, Some(&with_users(&app, document)?)).await?;
	Ok(json(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), &body))
}

pub async fn validate(State(app): State<Arc<App>>, Body(input): Body<DocumentIn>) -> Result<Response, Failure> {dry_run(app, input.document, "/v1/config/validate").await}

pub async fn diff(State(app): State<Arc<App>>, Body(input): Body<DocumentIn>) -> Result<Response, Failure> {dry_run(app, input.document, "/v1/config/diff").await}

/// Validates the document on the node, then puts it in force with If-Match, under the panel's one turn at the node's config. A document the node refuses, or a revision that moved, changes nothing.
pub(crate) async fn apply(app: &Arc<App>, ctx: &Ctx, document: Value, revision: &str, target: &str) -> Result<Value, Failure> {
	let document = with_users(app, document)?;
	let _turn = app.node_lock.lock().await;
	let (status, checked) = call(app, "POST", "/v1/config/validate", None, Some(&document)).await?;
	if status != 200 || checked.get("valid") != Some(&Value::Bool(true)) {return Err(Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", checked.to_string().chars().take(4000).collect::<String>()))}
	let (status, applied) = call(app, "PUT", "/v1/config", Some(revision), Some(&document)).await?;
	match status {
		200 => {
			audit(&app.db.lock(), &ctx.actor, &ctx.source, "config.apply", target, &format!("generation {}", applied.get("generation").and_then(Value::as_u64).unwrap_or(0)));
			Ok(applied)
		}
		409 | 428 => Err(Failure::conflict("The node's config is not the revision this change was made on. Read it again.")),
		other => Err(Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "node_refused", format!("The node answered {other}: {}", applied.to_string().chars().take(1000).collect::<String>()))),
	}
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigIn {
	/// The revision the change was made on, which the node checks as If-Match.
	pub revision: String,
	pub document: Value,
}

pub async fn put_config(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<ConfigIn>) -> Result<Response, Failure> {ok(&apply(&app, &ctx, input.document, &input.revision, "config").await?)}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionIn {
	pub revision: String,
	/// The new content of the section: an object for routing, dns, log and replay, a list for the others. A change to `replay.cache` takes effect at the node's next start.
	pub value: Value,
}

pub async fn put_section(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(section): Path<String>, Body(input): Body<SectionIn>) -> Result<Response, Failure> {
	if !SECTIONS.contains(&section.as_str()) {return Err(Failure::missing("section"))}
	if input.value.is_object() != OBJECTS.contains(&section.as_str()) || !(input.value.is_object() || input.value.is_array()) {return Err(Failure::bad(if OBJECTS.contains(&section.as_str()) {"This section is an object."} else {"This section is a list."}))}
	let (_, _, mut document) = running(&app).await?;
	document[&section] = input.value;
	ok(&apply(&app, &ctx, document, &input.revision, &section).await?)
}

fn host_port(host: &str, listen: &str) -> Option<String> {
	let port = listen.rsplit_once(':')?.1;
	Some(if host.contains(':') && !host.starts_with('[') {format!("[{host}]:{port}")} else {format!("{host}:{port}")})
}

/// One template per `veilway` inbound, with the overrides laid over it. `missing` lists what a profile still needs from the operator, since the node never reveals a public key and does not know its own public address.
fn derive(settings: &Settings, document: &Value) -> Vec<Value> {
	let inbounds = document.get("inbounds").and_then(Value::as_array).cloned().unwrap_or_default();
	inbounds.iter().filter(|inbound| inbound["type"] == "veilway").map(|inbound| {
		let (tag, host) = (inbound["tag"].as_str().unwrap_or_default().to_string(), settings.node_host.as_str());
		let transports: Vec<&Value> = inbound["transports"].as_array().map(|list| list.iter().collect()).unwrap_or_default();
		let obfs = transports.iter().any(|transport| transport["type"] == "udp-obfs");
		let gateways: Vec<Value> = inbound["address"].as_array().into_iter().flatten().filter_map(|address| address.as_str()?.split('/').next().map(|ip| json!(ip))).collect();
		let listed: Vec<Value> = transports.iter().filter_map(|transport| {
			let endpoint = host_port(host, transport["listen"].as_str()?)?;
			Some(match transport["type"].as_str()? {
				kind @ ("udp" | "udp-obfs") => json!({"type": kind, "endpoints": [endpoint]}),
				kind @ ("tls" | "ws") if transport.get("decoy").is_some() => json!({"type": kind, "path": transport["path"], "candidates": [{"address": endpoint, "sni": host, "host": host}]}),
				_ => return None,
			})
		}).collect();
		let mut profile = json!({"id": tag.to_lowercase(), "name": tag, "type": "veilway", "gateways": gateways, "mtu": inbound["mtu"].as_u64().unwrap_or(if obfs {1390} else {1420}), "transports": listed});
		// The Xray inbounds answer on this server's address like the profiles do, so no profile may claim more than Detectable. An override can lower it further and not raise it.
		if document["xray"]["inbounds"].as_array().is_some_and(|list| !list.is_empty()) {profile["rating_cap"] = json!("detectable");}
		if let Some(edits) = settings.profile_overrides.get(&tag).and_then(Value::as_object) {for (key, value) in edits {profile[key] = value.clone();}}
		let mut missing = Vec::new();
		if profile.get("inbound_public_key").is_none() {missing.push("inbound_public_key")}
		if host.is_empty() {missing.push("node_host")}
		if profile["transports"].as_array().is_some_and(|list| list.iter().any(|transport| transport["type"] == "tls" || transport["type"] == "ws")) && profile.get("transport_public_key").is_none() {missing.push("transport_public_key")}
		json!({"inbound": tag, "profile": profile, "missing": missing, "overridden": settings.profile_overrides.get(&tag).and_then(Value::as_object).map(|edits| edits.keys().cloned().collect::<Vec<_>>()).unwrap_or_default()})
	}).collect()
}

pub async fn derived_profiles(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (revision, _, document) = running(&app).await?;
	ok(&json!({"revision": revision, "templates": derive(&app.settings(), &document)}))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverrideIn {
	/// Members that replace the derived ones, such as `inbound_public_key`, `name` or `transports`. An empty object clears the override.
	pub set: serde_json::Map<String, Value>,
}

pub async fn put_override(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(inbound): Path<String>, Body(input): Body<OverrideIn>) -> Result<Response, Failure> {
	if inbound.is_empty() || inbound.len() > 64 || input.set.contains_key("device") || input.set.contains_key("id") || input.set.len() > 32 {return Err(Failure::bad("An override has at most 32 members and none of them is `id` or `device`."))}
	let mut settings = app.settings();
	if input.set.is_empty() {settings.profile_overrides.remove(&inbound);} else {settings.profile_overrides.insert(inbound.clone(), Value::Object(input.set));}
	app.save_settings(&settings);
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "profile.override", &inbound, "");
	ok(&json!({"overrides": settings.profile_overrides}))
}

/// Writes the derived templates into the settings' `profiles`, which is what the subscription endpoint serves. A profile that is not derived from an inbound stays. A template with something missing stops the publish.
pub async fn publish_profiles(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let (_, _, document) = running(&app).await?;
	let mut settings = app.settings();
	let templates = derive(&settings, &document);
	if let Some(bad) = templates.iter().find(|template| !template["missing"].as_array().is_some_and(Vec::is_empty)) {return Err(Failure::bad(format!("The profile of inbound {} still needs: {}.", bad["inbound"].as_str().unwrap_or_default(), bad["missing"])))}
	let ids: Vec<Value> = templates.iter().map(|template| template["profile"]["id"].clone()).collect();
	settings.profiles.retain(|profile| !ids.contains(&profile["id"]));
	settings.profiles.extend(templates.iter().map(|template| template["profile"].clone()));
	app.save_settings(&settings);
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "settings.update", "settings", &format!("profiles changed at {}", now()));
	ok(&json!({"profiles": settings.profiles}))
}
