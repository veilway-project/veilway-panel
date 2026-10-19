//! The node's config through its control API: the schema, the document as a whole and by section, dry runs, the one path that applies a change, and the profile templates derived from the inbounds.
use crate::{app::{store_settings, App, Settings}, auth::reauthed, crypto::now, http::{json, ok, Body, Ctx, Failure}, node, subs::UserRow, users::name_ok};
use axum::{extract::{Path, State}, http::{header::CONTENT_TYPE, HeaderValue, StatusCode}, response::{IntoResponse, Response}, Extension};
use rusqlite::Connection;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, BTreeSet}, net::{IpAddr, SocketAddr}, sync::{Arc, RwLock}};
use veilway_proto::subscription::{is_host, payload::{dialable, CANDIDATES_MAX}};

/// `veilway schema` of the core, kept next to the manifest. The node's own validation stays the authority: this is for an editor.
const SCHEMA: &str = include_str!("../config.schema.json");
/// The parts of the document that are edited as structured objects. `users` is the panel's own and never appears here.
const SECTIONS: [&str; 10] = ["inbounds", "outbounds", "exits", "routing", "notices", "dns", "log", "links", "tunnels", "replay"];
/// The sections that are an object. The others are lists.
const OBJECTS: [&str; 4] = ["routing", "dns", "log", "replay"];
/// Sections that change the node's links, tunnels, log, resolvers or notices. Only a session that confirmed its password and code again may change them, and no API token may change them through the whole document either.
const GUARDED: [&str; 5] = ["links", "tunnels", "log", "dns", "notices"];
/// Sections the document may leave out, which a null removes.
const OPTIONAL: [&str; 6] = ["dns", "log", "notices", "replay", "links", "tunnels"];
/// The transports a relay can carry, by their type in a profile.
const RELAYED: [&str; 6] = ["udp", "udp-obfs", "tls", "ws", "fronted", "fronted-shaped"];
/// Every transport keeps at least one candidate of its own, so this many relays always fit in the payload's 16.
pub const RELAYS_MAX: usize = CANDIDATES_MAX - 1;

/// A forwarder on another address that passes bytes to the node unchanged: nginx `stream`, a DNAT rule, HAProxy, or a content delivery network. TLS, the proofs and WireGuard run end to end through it, so it sees nothing and cannot pass for the node.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Relay {
	/// 1 to 32 characters, unique among the relays.
	pub name: String,
	/// An IP address: apps dial candidates by address, never by name.
	pub address: String,
	/// The tags of the `veilway` inbounds it carries. Empty for all of them.
	#[serde(default)]
	pub inbounds: Vec<String>,
	/// The transport types it carries: udp, udp-obfs, tls, ws, fronted, fronted-shaped. Empty for all of them.
	#[serde(default)]
	pub transports: Vec<String>,
	/// The relay's port per transport type, where it is not the node's own port.
	#[serde(default)]
	pub ports: BTreeMap<String, u16>,
	/// Put its candidates before the node's own address instead of after it.
	#[serde(default)]
	pub prefer: bool,
	/// Groups whose accounts get it. Empty with `users` too means everyone gets it.
	#[serde(default)]
	pub groups: Vec<String>,
	/// Accounts that get it, by id. Empty with `groups` too means everyone gets it.
	#[serde(default)]
	pub users: Vec<i64>,
	pub enabled: bool,
}

/// Reads `relays` and refuses what could not become a candidate, so a saved list is always one the profiles can carry.
pub fn checked_relays<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Relay>, D::Error> {
	let relays = Vec::<Relay>::deserialize(deserializer)?;
	let fail = |text: String| Err(serde::de::Error::custom(text));
	if relays.len() > RELAYS_MAX {return fail(format!("relays: at most {RELAYS_MAX}, so every transport keeps a candidate of its own within the {CANDIDATES_MAX} a profile may list."))}
	for (index, relay) in relays.iter().enumerate() {
		let name = relay.name.trim();
		if name.is_empty() || name != relay.name || name.chars().count() > 32 || relays[..index].iter().any(|other| other.name == relay.name) {return fail(format!("relay {}: the name is 1 to 32 characters, without spaces around it, and no other relay has it.", index + 1))}
		if !relay.address.parse::<IpAddr>().is_ok_and(dialable) {return fail(format!("relay {name}: the address is an IP address that apps may dial, not a host name and not a loopback, link-local or multicast address."))}
		if relay.transports.len() > RELAYED.len() || relay.transports.iter().enumerate().any(|(i, kind)| !RELAYED.contains(&kind.as_str()) || relay.transports[..i].contains(kind)) || relay.ports.iter().any(|(kind, port)| !RELAYED.contains(&kind.as_str()) || *port == 0) {return fail(format!("relay {name}: transports and ports name udp, udp-obfs, tls, ws, fronted or fronted-shaped once each, and a port is 1 to 65535."))}
		if relay.inbounds.len() > 16 || relay.inbounds.iter().enumerate().any(|(i, tag)| tag.is_empty() || tag.len() > 64 || relay.inbounds[..i].contains(tag)) {return fail(format!("relay {name}: inbounds is at most 16 different tags of 1 to 64 characters."))}
		if relay.groups.len() > 64 || relay.groups.iter().any(|group| !name_ok(group, true)) || relay.users.len() > 1000 {return fail(format!("relay {name}: groups is at most 64 group names and users at most 1000 account ids."))}
	}
	Ok(relays)
}

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
async fn with_users(app: &Arc<App>, mut document: Value) -> Result<Value, Failure> {
	if !document.is_object() {return Err(Failure::bad("The document is a JSON object."))}
	node::fill(app, &mut document).await.map_err(|error| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "users_unavailable", error))?;
	Ok(document)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentIn {pub document: Value}

/// The refusal for the panel's own checks of the borrowed-site transports, in the shape of the node's report.
fn invalid(found: &[String]) -> Failure {Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", json!({"valid": false, "report": {"errors": found.iter().map(|text| json!({"path": text.split(':').next().unwrap_or_default(), "message": text.split_once(": ").map_or(text.as_str(), |(_, message)| message)})).collect::<Vec<_>>(), "warnings": [], "more_errors": 0, "more_warnings": 0}}).to_string())}

/// Asks the node whether the document is valid, or what applying it would change. Nothing changes.
pub async fn dry_run(app: Arc<App>, document: Value, path: &str) -> Result<Response, Failure> {
	let (_, _, live) = running(&app).await?;
	let found = [crate::borrowed::problems(&document, &live), crate::via::problems(&document, &live)].concat();
	if !found.is_empty() {return Err(invalid(&found))}
	let (status, body) = call(&app, "POST", path, None, Some(&with_users(&app, document).await?)).await?;
	Ok(json(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY), &body))
}

pub async fn validate(State(app): State<Arc<App>>, Body(input): Body<DocumentIn>) -> Result<Response, Failure> {dry_run(app, input.document, "/v1/config/validate").await}

pub async fn diff(State(app): State<Arc<App>>, Body(input): Body<DocumentIn>) -> Result<Response, Failure> {dry_run(app, input.document, "/v1/config/diff").await}

/// Validates the document on the node, then puts it in force with If-Match. The caller holds the panel's one turn at the node's config. A document the node refuses, or a revision that moved, changes nothing. The audit line names what changed, never a secret. The Xray inbounds are left out: their own audit lines name their changes, and the node shows their credentials as markers.
pub(crate) async fn apply(app: &Arc<App>, ctx: &Ctx, document: Value, revision: &str, target: &str) -> Result<Value, Failure> {
	let document = with_users(app, document).await?;
	let (_, _, before) = running(app).await?;
	// The site of a borrowed-site transport has not agreed to it, so adding one or changing its site or acknowledgment is a person's act, as the guarded sections are. A token never passes.
	if crate::borrowed::sensitive(&before, &document) {reauthed(app, ctx).await?}
	let found = [crate::borrowed::problems(&document, &before), crate::via::problems(&document, &before)].concat();
	if !found.is_empty() {return Err(invalid(&found))}
	let (status, checked) = call(app, "POST", "/v1/config/validate", None, Some(&document)).await?;
	if status != 200 || checked.get("valid") != Some(&Value::Bool(true)) {return Err(Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", checked.to_string().chars().take(4000).collect::<String>()))}
	let (status, applied) = call(app, "PUT", "/v1/config", Some(revision), Some(&document)).await?;
	match status {
		200 => {
			node::clear_defaults(app, &document).await;
			let (kept, published) = (document.clone(), app.settings().profiles);
			// A profile of a borrowed site that was published is made again from what the node runs now, or taken down when it can no longer be emitted, so that no document carries the key or the listener it had before. One that was never published, and one written by hand, stay as they are.
			let republished = app.update_settings(move |settings| {
				crate::borrowed::remember(settings, &kept);
				let templates = derive(settings, &kept, &[], None);
				let ids: Vec<String> = settings.relay_profiles.keys().filter(|id| id.ends_with("-faketls") && settings.profiles.iter().any(|profile| profile["id"] == id.as_str() && profile["transports"].as_array().is_some_and(|list| !list.is_empty() && list.iter().all(|transport| transport["type"] == "faketls")))).cloned().collect();
				for id in ids {
					let fresh = templates.iter().find(|template| template["kind"] == "faketls" && template["profile"]["id"] == id.as_str() && template["missing"].as_array().is_some_and(Vec::is_empty) && template["profile"]["transports"].as_array().is_some_and(|list| !list.is_empty())).map(|template| template["profile"].clone());
					match (fresh, settings.profiles.iter_mut().find(|profile| profile["id"] == id.as_str())) {
						(Some(fresh), Some(slot)) => *slot = fresh,
						_ => {settings.profiles.retain(|profile| profile["id"] != id.as_str()); settings.relay_profiles.remove(&id);}
					}
				}
			}).await;
			if let Err(error) = &republished {tracing::warn!("the public keys and profiles of the borrowed-site transports were not kept: {error}")}
			let mut changed = vec![format!("generation {}", applied.get("generation").and_then(Value::as_u64).unwrap_or(0))];
			if republished.is_ok() && app.settings().profiles != published {changed.push("borrowed-site profiles republished".into())}
			for key in before.as_object().into_iter().chain(document.as_object()).flat_map(|object| object.keys()).filter(|key| !["users", "xray"].contains(&key.as_str())).collect::<BTreeSet<_>>() {changes(key, &before[key.as_str()], &document[key.as_str()], &mut changed)}
			app.db.audit(&ctx.actor, &ctx.source, "config.apply", target, &changed.join(", ")).await;
			Ok(applied)
		}
		409 | 428 => Err(Failure::conflict("The node's config is not the revision this change was made on. Read it again.")),
		other => Err(Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "node_refused", format!("The node answered {other}: {}", applied.to_string().chars().take(1000).collect::<String>()))),
	}
}

/// Names what changed between two parts of the config: the keys of objects, the entries of lists whose items carry a tag, and bools and numbers before and after. Anything else is only named as changed.
fn changes(name: &str, before: &Value, after: &Value, out: &mut Vec<String>) {
	if before == after {return}
	match (before, after) {
		(Value::Object(old), Value::Object(new)) => for key in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {changes(&format!("{name}.{key}"), old.get(key).unwrap_or(&Value::Null), new.get(key).unwrap_or(&Value::Null), out)},
		(Value::Array(old), Value::Array(new)) if old.iter().chain(new).all(|item| item["tag"].is_string()) => {
			for tag in old.iter().chain(new).filter_map(|item| item["tag"].as_str()).collect::<BTreeSet<_>>() {
				match (old.iter().find(|item| item["tag"] == tag), new.iter().find(|item| item["tag"] == tag)) {
					(Some(was), Some(next)) => changes(&format!("{name}[{tag}]"), was, next, out),
					(None, Some(_)) => out.push(format!("{name} +{tag}")),
					(Some(_), None) => out.push(format!("{name} -{tag}")),
					(None, None) => {}
				}
			}
		}
		(Value::Null, Value::Array(_)) => changes(name, &json!([]), after, out),
		(Value::Null, Value::Object(_)) => changes(name, &json!({}), after, out),
		(Value::Array(_), Value::Null) => changes(name, before, &json!([]), out),
		(Value::Object(_), Value::Null) => changes(name, before, &json!({}), out),
		(Value::Bool(_) | Value::Number(_) | Value::Null, Value::Bool(_) | Value::Number(_) | Value::Null) => out.push(format!("{name} {before} -> {after}")),
		_ => out.push(format!("{name} changed")),
	}
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigIn {
	/// The revision the change was made on, which the node checks as If-Match.
	pub revision: String,
	pub document: Value,
}

pub async fn put_config(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<ConfigIn>) -> Result<Response, Failure> {
	let _turn = app.node_lock.lock().await;
	let (_, _, live) = running(&app).await?;
	let changed = |sections: &[&str]| sections.iter().any(|section| live[*section] != input.document[*section]);
	if ctx.token_id.is_some() && changed(&["exits", "outbounds", "links", "tunnels", "log", "dns", "notices"]) {return Err(Failure::new(StatusCode::FORBIDDEN, "forbidden", "An API token cannot change exits, outbounds, links, tunnels, log, dns or notices through the whole config."))}
	if changed(&GUARDED) {reauthed(&app, &ctx).await?}
	ok(&apply(&app, &ctx, input.document, &input.revision, "config").await?)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionIn {
	pub revision: String,
	/// The new content of the section: an object for routing, dns, log and replay, a list for the others. A change to `replay.cache` takes effect at the node's next start.
	pub value: Value,
}

pub async fn put_section(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(section): Path<String>, Body(input): Body<SectionIn>) -> Result<Response, Failure> {
	if !SECTIONS.contains(&section.as_str()) {return Err(Failure::missing("section"))}
	if input.value.is_null() && !OPTIONAL.contains(&section.as_str()) {return Err(Failure::bad("This section is required, so it cannot be null."))}
	if !input.value.is_null() && (input.value.is_object() != OBJECTS.contains(&section.as_str()) || !(input.value.is_object() || input.value.is_array())) {return Err(Failure::bad(if OBJECTS.contains(&section.as_str()) {"This section is an object."} else {"This section is a list."}))}
	if GUARDED.contains(&section.as_str()) {reauthed(&app, &ctx).await?}
	let _turn = app.node_lock.lock().await;
	let (_, _, mut document) = running(&app).await?;
	if input.value.is_null() {document.as_object_mut().map(|document| document.remove(&section));} else {document[&section] = input.value;}
	ok(&apply(&app, &ctx, document, &input.revision, &section).await?)
}

fn host_port(host: &str, listen: &str) -> Option<String> {
	let port = listen.rsplit_once(':')?.1;
	Some(if host.contains(':') && !host.starts_with('[') {format!("[{host}]:{port}")} else {format!("{host}:{port}")})
}

/// The relays that reach an account, with the tier of the audience that names it: 0 for the account itself, 1 for one of its groups, 2 for everyone. Without an account only the relays for everyone reach.
pub fn reaching<'a>(relays: &'a [Relay], user: Option<(i64, &[String])>) -> Vec<(u8, &'a Relay)> {
	relays.iter().filter(|relay| relay.enabled).filter_map(|relay| {
		let tier = if relay.users.is_empty() && relay.groups.is_empty() {2} else if user.is_some_and(|(id, _)| relay.users.contains(&id)) {0} else if user.is_some_and(|(_, groups)| relay.groups.iter().any(|group| groups.contains(group))) {1} else {return None};
		Some((tier, relay))
	}).collect()
}

/// Adds the relays that reach an account to the candidates of the transports they carry in the profile of the inbound `tag`. Within the cap of a transport, the account's own relays come first, then its groups', then everyone's. Returns what the cap cut, as `transport` and `relay`.
pub fn carry(profile: &mut Value, tag: &str, reaching: &[(u8, &Relay)]) -> Vec<Value> {
	let mut trimmed = Vec::new();
	for transport in profile["transports"].as_array_mut().into_iter().flatten() {
		let (kind, list) = (transport["type"].as_str().unwrap_or_default().to_string(), if transport["endpoints"].is_array() {"endpoints"} else {"candidates"});
		// A forwarder in front of the borrowed-site handshake would sit between the app and the node's answer, which is made to look like the site's own.
		if kind == "faketls" {continue}
		let Some(own) = transport[list].as_array().filter(|own| !own.is_empty()).cloned() else {continue};
		let address_of = |entry: &Value| entry.as_str().or_else(|| entry["address"].as_str()).map(str::to_string);
		let first_port = address_of(&own[0]).and_then(|address| address.rsplit_once(':')?.1.parse::<u16>().ok());
		let mut carried: Vec<(u8, bool, String, Value)> = reaching.iter().filter(|(_, relay)| (relay.inbounds.is_empty() || relay.inbounds.iter().any(|held| held == tag)) && (relay.transports.is_empty() || relay.transports.contains(&kind))).filter_map(|(tier, relay)| {
			let address = SocketAddr::new(relay.address.parse().ok()?, relay.ports.get(&kind).copied().or(first_port)?).to_string();
			Some((*tier, relay.prefer, relay.name.clone(), if list == "endpoints" {json!(address)} else {let mut candidate = own[0].clone(); candidate["address"] = json!(address); candidate}))
		}).collect();
		carried.sort_by_key(|(tier, prefer, _, _)| (*tier, !prefer));
		let mut seen: BTreeSet<String> = own.iter().filter_map(address_of).collect();
		let unique: Vec<(bool, String, Value)> = carried.into_iter().filter(|(_, _, _, entry)| address_of(entry).is_some_and(|address| seen.insert(address))).map(|(_, prefer, name, entry)| (prefer, name, entry)).collect();
		let room = CANDIDATES_MAX.saturating_sub(own.len());
		trimmed.extend(unique.iter().skip(room).map(|(_, name, _)| json!({"transport": kind, "relay": name})));
		let picked: Vec<(bool, Value)> = unique.into_iter().take(room).map(|(prefer, _, entry)| (prefer, entry)).collect();
		transport[list] = picked.iter().filter(|(prefer, _)| *prefer).map(|(_, entry)| entry.clone()).chain(own).chain(picked.iter().filter(|(prefer, _)| !prefer).map(|(_, entry)| entry.clone())).collect();
	}
	trimmed
}

/// One template per `veilway` inbound, with the overrides laid over it and the relays that reach `user` carried in. `user` is the account's id and groups, or None for the relays that reach everyone. `missing` lists what a profile still needs from the operator, since the node never reveals a public key and does not know its own public address.
fn derive(settings: &Settings, document: &Value, relays: &[Relay], user: Option<(i64, &[String])>) -> Vec<Value> {
	let inbounds = document.get("inbounds").and_then(Value::as_array).cloned().unwrap_or_default();
	let reached = reaching(relays, user);
	inbounds.iter().filter(|inbound| inbound["type"] == "veilway").flat_map(|inbound| {
		let (tag, host) = (inbound["tag"].as_str().unwrap_or_default().to_string(), settings.node_host.as_str());
		let transports: Vec<&Value> = inbound["transports"].as_array().map(|list| list.iter().collect()).unwrap_or_default();
		let obfs = transports.iter().any(|transport| transport["type"] == "udp-obfs");
		let gateways: Vec<Value> = inbound["address"].as_array().into_iter().flatten().filter_map(|address| address.as_str()?.split('/').next().map(|ip| json!(ip))).collect();
		let mut refused: Vec<Value> = Vec::new();
		let listed: Vec<Value> = transports.iter().filter_map(|transport| {
			let endpoint = host_port(host, transport["listen"].as_str()?)?;
			Some(match transport["type"].as_str()? {
				kind @ ("udp" | "udp-obfs") => json!({"type": kind, "endpoints": [endpoint]}),
				kind @ ("tls" | "ws" | "fronted-shaped") if transport.get("decoy").is_some() => {
					let Some(name) = [transport["tls"]["name"].as_str(), transport["decoy"]["origin"].as_str().and_then(|origin| origin.split("://").last()?.split(['/', ':']).next()), Some(host)].into_iter().flatten().find(|name| is_host(name)) else {
						refused.push(json!({"transport": transport["listen"], "code": "no_name", "reason": "apps need a host name to send and check: the certificate names none, the decoy's origin is not a host name, and the node's address is an IP address"}));
						return None;
					};
					let mut stream = json!({"type": kind, "path": transport["path"], "candidates": [{"address": endpoint, "sni": name, "host": name}]});
					if kind == "fronted-shaped" {stream["shape"] = transport["shape"].clone()}
					stream
				}
				_ => return None,
			})
		}).collect();
		let mut profile = json!({"id": tag.to_lowercase(), "name": tag, "type": "veilway", "gateways": gateways, "mtu": inbound["mtu"].as_u64().unwrap_or(if obfs {1390} else {1420}), "transports": listed});
		// The Xray inbounds answer on this server's address like the profiles do, so no profile may claim more than Detectable. An override can lower it further and not raise it.
		if document["xray"]["inbounds"].as_array().is_some_and(|list| !list.is_empty()) {profile["rating_cap"] = json!("detectable");}
		if let Some(edits) = settings.profile_overrides.get(&tag).and_then(Value::as_object) {for (key, value) in edits.iter().filter(|(key, _)| *key != crate::borrowed::ADDRESSES) {profile[key] = value.clone();}}
		// Relays come after the overrides, so a transport an override wrote gets them too.
		let trimmed = carry(&mut profile, &tag, &reached);
		let mut missing = Vec::new();
		if profile.get("inbound_public_key").is_none() {missing.push("inbound_public_key")}
		if host.is_empty() {missing.push("node_host")}
		if profile["transports"].as_array().is_some_and(|list| list.iter().any(|transport| transport["type"] == "tls" || transport["type"] == "ws" || transport["type"] == "fronted-shaped")) && profile.get("transport_public_key").is_none() {missing.push("transport_public_key")}
		let own = json!({"inbound": tag, "profile": profile, "missing": missing, "overridden": settings.profile_overrides.get(&tag).and_then(Value::as_object).map(|edits| edits.keys().filter(|key| *key != crate::borrowed::ADDRESSES).cloned().collect::<Vec<_>>()).unwrap_or_default(), "trimmed": trimmed, "refused": refused});
		std::iter::once(own).chain(crate::borrowed::template(settings, document, inbound, &gateways)).collect::<Vec<_>>()
	}).collect()
}

pub async fn derived_profiles(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (revision, _, document) = running(&app).await?;
	let settings = app.settings();
	ok(&json!({"revision": revision, "templates": derive(&settings, &document, &settings.relays, None)}))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewIn {
	#[serde(deserialize_with = "checked_relays")]
	pub relays: Vec<Relay>,
	/// The account whose documents are shown. Null shows what accounts without a relay of their own get.
	pub user: Option<i64>,
}

/// The templates as they would be with these relays instead of the saved ones, for the account given or for no account. Nothing is saved.
pub async fn preview_profiles(State(app): State<Arc<App>>, Body(input): Body<PreviewIn>) -> Result<Response, Failure> {
	let (revision, _, document) = running(&app).await?;
	let account = match input.user {
		Some(id) => Some(app.db.call(move |db| UserRow::load(db, id)).await??),
		None => None,
	};
	let groups: Vec<String> = account.as_ref().map(|user| serde_json::from_str(&user.groups).unwrap_or_default()).unwrap_or_default();
	ok(&json!({"revision": revision, "templates": derive(&app.settings(), &document, &input.relays, account.as_ref().map(|user| (user.id, groups.as_slice())))}))
}

/// Takes a deleted account out of the audiences of the saved and the published relays, in the transaction that deletes it. SQLite gives a new account the id of the last one deleted, so no relay may keep it.
pub fn forget_user(connection: &Connection, cache: &RwLock<Settings>, id: i64) -> Result<Settings, String> {
	store_settings(connection, cache, |settings| for relay in settings.relays.iter_mut().chain(settings.published_relays.iter_mut()) {relay.users.retain(|held| *held != id)})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverrideIn {
	/// Members that replace the derived ones, such as `inbound_public_key`, `name` or `transports`. An empty object clears the override.
	pub set: serde_json::Map<String, Value>,
}

pub async fn put_override(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(inbound): Path<String>, Body(input): Body<OverrideIn>) -> Result<Response, Failure> {
	if inbound.is_empty() || inbound.len() > 64 || input.set.contains_key("device") || input.set.contains_key("id") || input.set.len() > 32 {return Err(Failure::bad("An override has at most 32 members and none of them is `id` or `device`."))}
	if input.set.get(crate::borrowed::ADDRESSES).is_some_and(|list| !list.as_array().is_some_and(|list| list.len() < CANDIDATES_MAX && list.iter().all(|text| text.as_str().is_some_and(|text| text.parse::<SocketAddr>().map(|found| found.ip()).or_else(|_| text.parse::<IpAddr>()).is_ok_and(dialable))))) {return Err(Failure::bad(format!("{} is at most {} IP addresses that apps may dial, each with a port or without one.", crate::borrowed::ADDRESSES, CANDIDATES_MAX - 1)))}
	let (tag, set) = (inbound.clone(), input.set);
	app.update_settings(move |settings| if set.is_empty() {settings.profile_overrides.remove(&tag);} else {settings.profile_overrides.insert(tag, Value::Object(set));}).await.map_err(Failure::internal)?;
	app.db.audit(&ctx.actor, &ctx.source, "profile.override", &inbound, "").await;
	ok(&json!({"overrides": app.settings().profile_overrides}))
}

/// Writes the derived templates into the settings' `profiles`, which is what the subscription endpoint serves. A profile that is not derived from an inbound stays. A template with something missing stops the publish.
pub async fn publish_profiles(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let (_, _, document) = running(&app).await?;
	let current = app.settings();
	let templates = derive(&current, &document, &[], None);
	// A profile whose transports were all refused is not published, and what it said before is taken down. Its refusals are shown on the Profiles page and block nothing else.
	let empty = |template: &Value| template["profile"]["transports"].as_array().is_none_or(Vec::is_empty) && (template["kind"] == "faketls" || template["refused"].as_array().is_some_and(|list| !list.is_empty()));
	if let Some(bad) = templates.iter().filter(|template| !empty(template)).find(|template| !template["missing"].as_array().is_some_and(Vec::is_empty)) {return Err(Failure::bad(format!("The profile of inbound {} still needs: {}.", bad["inbound"].as_str().unwrap_or_default(), bad["missing"])))}
	// A profile written by hand under the id of a borrowed-site profile is refused by the template, and stays.
	let ids: Vec<Value> = templates.iter().filter(|template| !template["refused"].as_array().into_iter().flatten().any(|refusal| refusal["code"] == "profile_id")).map(|template| template["profile"]["id"].clone()).collect();
	let fresh: Vec<Value> = templates.iter().filter(|template| !empty(template)).map(|template| template["profile"].clone()).collect();
	// Profiles are published without relays: each document adds the published relays that reach its account.
	let carrying: BTreeMap<String, String> = templates.iter().filter(|template| !empty(template)).map(|template| (template["profile"]["id"].as_str().unwrap_or_default().to_string(), template["inbound"].as_str().unwrap_or_default().to_string())).collect();
	let relays = current.relays.clone();
	app.update_settings(move |settings| {
		settings.profiles.retain(|profile| !ids.contains(&profile["id"]));
		settings.profiles.extend(fresh);
		settings.relay_profiles = carrying;
		settings.published_relays = relays;
	}).await.map_err(Failure::internal)?;
	app.db.audit(&ctx.actor, &ctx.source, "settings.update", "settings", &format!("profiles changed at {}", now())).await;
	ok(&json!({"profiles": app.settings().profiles}))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn document() -> Value {json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "tls", "listen": "0.0.0.0:443", "tls": {"self_signed": true, "name": "node.example.org"}, "decoy": "127.0.0.1:8443", "path": "/a-long-enough-path"}]}, {"tag": "Other", "type": "veilway", "address": ["10.67.0.1/24"], "transports": [{"type": "udp-obfs", "listen": "0.0.0.0:51821"}]}]})}

	fn relay(extra: Value) -> Relay {
		let mut relay = json!({"name": "edge", "address": "198.51.100.7", "enabled": true});
		relay.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		serde_json::from_value(relay).unwrap()
	}

	fn derived(relays: Vec<Relay>) -> Vec<Value> {
		let mut settings = Settings {node_host: "192.0.2.10".into(), relays, ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transport_public_key": "key"}));
		derive(&settings, &document(), &settings.relays, None).into_iter().map(|template| template["profile"]["transports"].clone()).collect()
	}

	fn for_account(relays: &[Relay], id: i64, groups: &[&str]) -> Vec<String> {
		let groups: Vec<String> = groups.iter().map(|group| group.to_string()).collect();
		let mut found = reaching(relays, Some((id, &groups)));
		found.sort_by_key(|(tier, _)| *tier);
		found.into_iter().map(|(_, relay)| relay.name.clone()).collect()
	}

	#[test]
	fn relays_add_candidates_to_the_transports_they_carry() {
		assert_eq!(derived(vec![])[0][0]["endpoints"], json!(["192.0.2.10:51820"]));
		let all = derived(vec![relay(json!({}))]);
		assert_eq!((all[0][0]["endpoints"].clone(), all[1][0]["endpoints"].clone()), (json!(["192.0.2.10:51820", "198.51.100.7:51820"]), json!(["192.0.2.10:51821", "198.51.100.7:51821"])));
		assert_eq!(all[0][1]["candidates"], json!([{"address": "192.0.2.10:443", "sni": "node.example.org", "host": "node.example.org"}, {"address": "198.51.100.7:443", "sni": "node.example.org", "host": "node.example.org"}]), "the name the app checks stays the node's");
		let matched = derived(vec![relay(json!({"inbounds": ["Main"], "transports": ["tls"], "ports": {"tls": 8443}}))]);
		assert_eq!((matched[0][0]["endpoints"].as_array().unwrap().len(), matched[0][1]["candidates"][1]["address"].clone(), matched[1][0]["endpoints"].as_array().unwrap().len()), (1, json!("198.51.100.7:8443"), 1));
		let off = derived(vec![relay(json!({"enabled": false})), relay(json!({"name": "none", "inbounds": ["Missing"]}))]);
		assert_eq!((off[0][0]["endpoints"].as_array().unwrap().len(), off[1][0]["endpoints"].as_array().unwrap().len()), (1, 1));
	}

	#[test]
	fn preferred_relays_go_first_and_the_list_stays_within_the_cap() {
		let ordered = derived(vec![relay(json!({"name": "late"})), relay(json!({"name": "early", "address": "2001:db8::7", "prefer": true})), relay(json!({"name": "twin"}))]);
		assert_eq!(ordered[0][0]["endpoints"], json!(["[2001:db8::7]:51820", "192.0.2.10:51820", "198.51.100.7:51820"]), "a relay on an address already listed adds nothing");
		let many: Vec<Relay> = (0..RELAYS_MAX).map(|i| relay(json!({"name": format!("r{i}"), "address": format!("198.51.100.{}", i + 1), "prefer": i == 3}))).collect();
		let mut settings = Settings {node_host: "192.0.2.10".into(), relays: many, ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820", "192.0.2.11:51820"]}]}));
		let endpoints = derive(&settings, &document(), &settings.relays, None)[0]["profile"]["transports"][0]["endpoints"].as_array().unwrap().clone();
		assert_eq!((endpoints.len(), endpoints[0].clone(), endpoints[1].clone(), endpoints[2].clone()), (CANDIDATES_MAX, json!("198.51.100.4:51820"), json!("192.0.2.10:51820"), json!("192.0.2.11:51820")), "the node's own are kept and the preferred relay leads");
	}

	#[test]
	fn a_relay_reaches_the_accounts_its_audience_names_and_everyone_without_one() {
		let relays = vec![relay(json!({"name": "all"})), relay(json!({"name": "team", "groups": ["office"]})), relay(json!({"name": "ann", "users": [7]})), relay(json!({"name": "other", "users": [8], "groups": ["family"]})), relay(json!({"name": "off", "enabled": false}))];
		assert_eq!(for_account(&relays, 7, &["office"]), vec!["ann", "team", "all"], "own first, then the group's, then everyone's");
		assert_eq!(for_account(&relays, 8, &["family"]), vec!["other", "all"]);
		assert_eq!(for_account(&relays, 9, &[]), vec!["all"]);
		assert_eq!(reaching(&relays, None).len(), 1, "without an account only the relays for everyone reach");
	}

	#[test]
	fn the_cap_drops_the_relays_for_everyone_before_the_accounts_own_or_its_groups() {
		let mut relays: Vec<Relay> = (0..13).map(|i| relay(json!({"name": format!("all{i}"), "address": format!("198.51.100.{}", i + 1)}))).collect();
		relays.push(relay(json!({"name": "team", "address": "198.51.100.90", "groups": ["office"]})));
		relays.push(relay(json!({"name": "ann", "address": "198.51.100.91", "users": [7]})));
		let mut settings = Settings {node_host: "192.0.2.10".into(), relays: relays.clone(), ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820", "192.0.2.11:51820"]}]}));
		let groups = vec!["office".to_string()];
		let template = derive(&settings, &document(), &relays, Some((7, &groups)))[0].clone();
		let endpoints = template["profile"]["transports"][0]["endpoints"].as_array().unwrap().clone();
		assert_eq!((endpoints.len(), endpoints[2].clone(), endpoints[3].clone()), (CANDIDATES_MAX, json!("198.51.100.91:51820"), json!("198.51.100.90:51820")), "the account's relay leads the ones it gets, then its group's");
		assert_eq!(template["trimmed"], json!([{"transport": "udp", "relay": "all12"}]), "the preview names what the cap cut");
	}

	#[test]
	fn a_published_profile_carries_for_each_account_what_the_preview_shows() {
		let relays = vec![relay(json!({"name": "all", "address": "198.51.100.8"})), relay(json!({"name": "ann", "address": "198.51.100.9", "users": [7]})), relay(json!({"name": "other-inbound", "address": "198.51.100.10", "inbounds": ["Other"]}))];
		let settings = Settings {node_host: "192.0.2.10".into(), relays: relays.clone(), ..Settings::default()};
		let groups: Vec<String> = Vec::new();
		let published = derive(&settings, &document(), &[], None)[0]["profile"].clone();
		let mut carried = published.clone();
		carry(&mut carried, "Main", &reaching(&relays, Some((7, &groups))));
		assert_eq!(carried["transports"], derive(&settings, &document(), &relays, Some((7, &groups)))[0]["profile"]["transports"], "the stored base plus the account's relays is the preview for the account");
		let mut stranger = published.clone();
		carry(&mut stranger, "Main", &reaching(&relays, Some((8, &groups))));
		assert_eq!(stranger["transports"][0]["endpoints"], json!(["192.0.2.10:51820", "198.51.100.8:51820"]), "an account without its own relay gets only the relays for everyone");
	}

	#[test]
	fn a_fronted_shaped_transport_carries_its_shape_into_the_profile() {
		let shape = json!({"up": {"method": "POST", "in": "body"}, "down": {"mode": "sse"}});
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "fronted-shaped", "listen": "127.0.0.1:8443", "path": "/a-long-enough-path", "decoy": {"origin": "http://origin.example.org:8080"}, "trusted_proxies": ["127.0.0.1"], "shape": shape.clone()}]}]});
		let settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		let template = derive(&settings, &document, &[], None).remove(0);
		assert_eq!(template["profile"]["transports"], json!([{"type": "fronted-shaped", "path": "/a-long-enough-path", "candidates": [{"address": "192.0.2.10:8443", "sni": "origin.example.org", "host": "origin.example.org"}], "shape": shape}]), "the shape is the node's object, as the subscription format wants it");
		assert_eq!(template["missing"], json!(["inbound_public_key", "transport_public_key"]), "a fronted-shaped transport needs the transport public key like tls and ws");
	}

	#[test]
	fn relays_are_validated_when_settings_are_read() {
		let read = |relays: Value| serde_json::from_value::<Settings>(json!({"relays": relays})).map(|settings| settings.relays.len()).map_err(|error| error.to_string());
		assert_eq!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["tls"], "ports": {"tls": 443}}])), Ok(1));
		assert_eq!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["fronted-shaped"], "ports": {"fronted-shaped": 9443}}])), Ok(1), "a fronted-shaped relay is carried like a fronted one");
		for bad in [json!({"name": "a", "address": "relay.example.org", "enabled": true}), json!({"name": "a", "address": "127.0.0.1", "enabled": true}), json!({"name": " a", "address": "198.51.100.7", "enabled": true}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["quic"]}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "ports": {"udp": 0}}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["udp", "udp"]}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["faketls"]}), json!({"name": "a", "address": "198.51.100.7"})] {assert!(read(json!([bad])).is_err(), "{bad}")}
		assert!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true}, {"name": "a", "address": "198.51.100.8", "enabled": true}])).is_err(), "names are unique");
		assert!(read(json!((0..=RELAYS_MAX).map(|i| json!({"name": format!("r{i}"), "address": "198.51.100.7", "enabled": true})).collect::<Vec<_>>())).unwrap_err().contains("at most 15"));
		assert_eq!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true, "groups": ["office"], "users": [7]}])), Ok(1), "audiences are optional and an old relay without them is for everyone");
		assert!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true, "groups": ["Bad Group"]}])).is_err());
	}

	#[test]
	fn a_fronted_shaped_relay_is_a_candidate_with_the_nodes_shape() {
		let shape = json!({"up": {"method": "POST", "in": "body"}, "down": {"mode": "sse"}});
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "fronted-shaped", "listen": "127.0.0.1:8443", "path": "/a-long-enough-path", "decoy": {"origin": "http://origin.example.org:8080"}, "trusted_proxies": ["127.0.0.1"], "shape": shape.clone()}]}]});
		let relays = vec![relay(json!({"transports": ["fronted-shaped"], "ports": {"fronted-shaped": 9443}}))];
		let settings = Settings {node_host: "192.0.2.10".into(), relays: relays.clone(), ..Settings::default()};
		let template = derive(&settings, &document, &relays, None).remove(0);
		assert_eq!(template["profile"]["transports"], json!([{"type": "fronted-shaped", "path": "/a-long-enough-path", "candidates": [{"address": "192.0.2.10:8443", "sni": "origin.example.org", "host": "origin.example.org"}, {"address": "198.51.100.7:9443", "sni": "origin.example.org", "host": "origin.example.org"}], "shape": shape}]), "the relay's candidate keeps the node's names and shape");
	}

	#[test]
	fn a_stream_transport_without_a_name_is_refused_and_the_others_stay() {
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "ws", "listen": "0.0.0.0:443", "decoy": {"origin": "http://127.0.0.1:8080"}, "path": "/a-long-enough-path"}]}]});
		let settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		let template = derive(&settings, &document, &[], None).remove(0);
		assert_eq!(template["profile"]["transports"], json!([{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]), "an address is never a name, so the ws transport is left out");
		assert_eq!((template["refused"][0]["transport"].clone(), template["refused"][0]["code"].clone(), template["refused"].as_array().unwrap().len()), (json!("0.0.0.0:443"), json!("no_name"), 1));
	}

	#[test]
	fn the_certificate_name_comes_before_the_decoy_host() {
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "tls", "listen": "0.0.0.0:443", "tls": {"self_signed": true, "name": "node.example.org"}, "decoy": {"origin": "http://decoy.example.net:8080"}, "path": "/a-long-enough-path"}]}]});
		let settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		let template = derive(&settings, &document, &[], None).remove(0);
		assert_eq!((template["profile"]["transports"][0]["candidates"].clone(), template["refused"].clone()), (json!([{"address": "192.0.2.10:443", "sni": "node.example.org", "host": "node.example.org"}]), json!([])));
	}
}
