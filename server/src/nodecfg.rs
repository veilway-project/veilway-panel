//! The node's config through its control API: the schema, the document as a whole and by section, dry runs, the one path that applies a change, and the profile templates derived from the inbounds.
use crate::{app::{store_settings, App, Settings, TransportClock}, auth::reauthed, crypto::{now, random}, http::{json, ok, Body, Ctx, Failure}, node, subs::UserRow, users::name_ok, xray::{self, addresses, Exposure}};
use axum::{extract::{Path, State}, http::{header::CONTENT_TYPE, HeaderValue, StatusCode}, response::{IntoResponse, Response}, Extension};
use base64::{engine::general_purpose::STANDARD, Engine};
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
/// Sections that change the node's links, tunnels, log, resolvers, notices or upstreams. Only a session that confirmed its password and code again may change them, and no API token may change them through the whole document either.
const GUARDED: [&str; 6] = ["links", "tunnels", "log", "dns", "notices", "upstreams"];
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
	/// An IP address, or a host name such as a content delivery network's, which each document turns into the addresses it has then: apps dial candidates by address, never by name.
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
	/// The relay's port per inbound and transport type, keyed `<inbound tag>/<type>`. It wins over `ports`. Every transport of that type in the inbound gets it: two of one type in an inbound share the web port or the address anyway. A key naming no inbound or transport of the node is ignored.
	#[serde(default)]
	pub inbound_ports: BTreeMap<String, u16>,
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
		if !reachable(&relay.address) {return fail(format!("relay {name}: the address is a host name or an IP address that apps may dial, not a loopback, link-local or multicast address."))}
		if relay.transports.len() > RELAYED.len() || relay.transports.iter().enumerate().any(|(i, kind)| !RELAYED.contains(&kind.as_str()) || relay.transports[..i].contains(kind)) || relay.ports.iter().any(|(kind, port)| !RELAYED.contains(&kind.as_str()) || *port == 0) || relay.inbound_ports.len() > 64 || relay.inbound_ports.iter().any(|(key, port)| *port == 0 || !key.rsplit_once('/').is_some_and(|(tag, kind)| !tag.is_empty() && tag.len() <= 64 && RELAYED.contains(&kind))) {return fail(format!("relay {name}: transports and ports name udp, udp-obfs, tls, ws, fronted or fronted-shaped once each, and a port is 1 to 65535."))}
		if relay.inbounds.len() > 16 || relay.inbounds.iter().enumerate().any(|(i, tag)| tag.is_empty() || tag.len() > 64 || relay.inbounds[..i].contains(tag)) {return fail(format!("relay {name}: inbounds is at most 16 different tags of 1 to 64 characters."))}
		if relay.groups.len() > 64 || relay.groups.iter().any(|group| !name_ok(group, true)) || relay.users.len() > 1000 {return fail(format!("relay {name}: groups is at most 64 group names and users at most 1000 account ids."))}
	}
	Ok(relays)
}

pub async fn schema() -> Response {(StatusCode::OK, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], SCHEMA).into_response()}

pub(crate) async fn call(app: &App, method: &str, path: &str, if_match: Option<&str>, body: Option<&Value>) -> Result<(u16, Value), Failure> {
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
pub(crate) async fn with_users(app: &Arc<App>, mut document: Value) -> Result<Value, Failure> {
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
				remember_keys(settings, &kept);
				let templates = derive(settings, &kept, &[], None, &Exposure::default(), false);
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
	if ctx.token_id.is_some() && changed(&["exits", "outbounds", "links", "tunnels", "log", "dns", "notices", "upstreams"]) {return Err(Failure::new(StatusCode::FORBIDDEN, "forbidden", "An API token cannot change exits, outbounds, links, tunnels, log, dns, notices or upstreams through the whole config."))}
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

/// The override member with the addresses apps reach an inbound's profiles at, IP addresses or host names, in place of the node address.
pub const NODE_ADDRESSES: &str = "node_addresses";
/// The port of the web server in front of an inbound's `ws` and `fronted-shaped` transports, which is where apps connect: the node only reads plain HTTP from that web server on its own listener. 443 when not set.
pub const WEB_PORT: &str = "web_port";
/// The host name of the web server in front of an inbound's `ws-plain` transport. It may be no name any covered transport of the profile uses, so the transport is offered only when this is set.
pub const PLAIN_HOST: &str = "plain_host";
/// The port of that web server for plain HTTP. 80 when not set.
pub const PLAIN_PORT: &str = "plain_port";
/// When true, apps get only relay addresses for the inbound: the node's own are in no profile, no published snapshot and no document. A transport no relay that reaches the account carries is left out.
pub const RELAYS_ONLY: &str = "relays_only";
/// The override members that steer how a profile is made and are no member of the profile.
pub const NOT_MEMBERS: [&str; 5] = [NODE_ADDRESSES, WEB_PORT, PLAIN_HOST, PLAIN_PORT, RELAYS_ONLY];
/// Stands in for the node's address in the published profile of a relays-only inbound, which keeps the ports and names the relays are given. It never resolves, and each document replaces it with relay addresses.
pub const NO_ADDRESS: &str = "relays.invalid";

pub fn relays_only(settings: &Settings, tag: &str) -> bool {settings.profile_overrides.get(tag).is_some_and(|edits| edits[RELAYS_ONLY] == true)}

/// Whether apps may be sent to `host`: an IP address they may dial, or a host name, which each document turns into the addresses it has then.
pub fn reachable(host: &str) -> bool {host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>().map_or_else(|_| is_host(host), dialable)}

/// Where apps reach a transport of the inbound `tag` that listens on `listen`: the inbound's own addresses when it has them, else the listener's address when it is a public one, else the node address. A private listen address is often behind the provider's NAT, so it is never used by itself.
pub fn hosts(settings: &Settings, tag: &str, listen: &str) -> Vec<String> {
	let own: Vec<String> = settings.profile_overrides.get(tag).and_then(|edits| edits[NODE_ADDRESSES].as_array()).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
	if !own.is_empty() {return own}
	let public = |ip: &IpAddr| dialable(*ip) && match ip {IpAddr::V4(v4) => !v4.is_private() && !(v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64), IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 != 0xfc00};
	if let Some(ip) = listen.parse::<SocketAddr>().ok().map(|bound| bound.ip()).filter(public) {return vec![ip.to_string()]}
	if settings.node_host.is_empty() {Vec::new()} else {vec![settings.node_host.clone()]}
}

pub fn host_port(host: &str, listen: &str) -> Option<String> {
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

/// Adds the relays that reach an account to the candidates of the transports they carry in the profile of the inbound `tag`. Within the cap of a transport, the account's own relays come first, then its groups', then everyone's. Returns what the cap cut, as `transport` and `relay`. With `only`, the profile's own addresses are dropped and only the relays stay, and a transport left with none (or that no relay can carry) is removed.
pub fn carry(profile: &mut Value, tag: &str, reaching: &[(u8, &Relay)], only: bool) -> Vec<Value> {
	let mut trimmed = Vec::new();
	if only {if let Some(list) = profile["transports"].as_array_mut() {list.retain(|transport| transport["type"] != "faketls" && transport["type"] != "ws-plain")}}
	for transport in profile["transports"].as_array_mut().into_iter().flatten() {
		let (kind, list) = (transport["type"].as_str().unwrap_or_default().to_string(), if transport["endpoints"].is_array() {"endpoints"} else {"candidates"});
		// A forwarder in front of the borrowed-site handshake would sit between the app and the node's answer, which is made to look like the site's own.
		if kind == "faketls" || kind == "ws-plain" {continue}
		let Some(own) = transport[list].as_array().filter(|own| !own.is_empty()).cloned() else {continue};
		let address_of = |entry: &Value| entry.as_str().or_else(|| entry["address"].as_str()).map(str::to_string);
		let first_port = address_of(&own[0]).and_then(|address| address.rsplit_once(':')?.1.parse::<u16>().ok());
		let mut carried: Vec<(u8, bool, String, Value)> = reaching.iter().filter(|(_, relay)| (relay.inbounds.is_empty() || relay.inbounds.iter().any(|held| held == tag)) && (relay.transports.is_empty() || relay.transports.contains(&kind))).filter_map(|(tier, relay)| {
			let address = host_port(&relay.address, &format!(":{}", relay.inbound_ports.get(&format!("{tag}/{kind}")).or_else(|| relay.ports.get(&kind)).copied().or(first_port)?))?;
			Some((*tier, relay.prefer, relay.name.clone(), if list == "endpoints" {json!(address)} else {let mut candidate = own[0].clone(); candidate["address"] = json!(address); candidate}))
		}).collect();
		carried.sort_by_key(|(tier, prefer, _, _)| (*tier, !prefer));
		let mut seen: BTreeSet<String> = if only {BTreeSet::new()} else {own.iter().filter_map(address_of).collect()};
		let unique: Vec<(bool, String, Value)> = carried.into_iter().filter(|(_, _, _, entry)| address_of(entry).is_some_and(|address| seen.insert(address))).map(|(_, prefer, name, entry)| (prefer, name, entry)).collect();
		let room = if only {CANDIDATES_MAX} else {CANDIDATES_MAX.saturating_sub(own.len())};
		trimmed.extend(unique.iter().skip(room).map(|(_, name, _)| json!({"transport": kind, "relay": name})));
		let picked: Vec<(bool, Value)> = unique.into_iter().take(room).map(|(prefer, _, entry)| (prefer, entry)).collect();
		transport[list] = if only {picked.into_iter().map(|(_, entry)| entry).collect()} else {picked.iter().filter(|(prefer, _)| *prefer).map(|(_, entry)| entry.clone()).chain(own).chain(picked.iter().filter(|(prefer, _)| !prefer).map(|(_, entry)| entry.clone())).collect()};
	}
	if only {if let Some(list) = profile["transports"].as_array_mut() {list.retain(|transport| transport["endpoints"].as_array().or_else(|| transport["candidates"].as_array()).is_some_and(|found| !found.is_empty()))}}
	trimmed
}

/// Keeps the public half of each `veilway` inbound's key, of its first transport key and of the first key of each of its `ws-plain` transports (by tag and path). The node shows a key only as a marker once it holds it, so the half is made when an apply carries the key in full, and kept from before otherwise. An override of a public key that differs from a key made here is dropped, since the node runs this one.
pub fn remember_keys(settings: &mut Settings, document: &Value) {
	let (mut kept, mut transport) = (BTreeMap::new(), BTreeMap::new());
	for inbound in document["inbounds"].as_array().into_iter().flatten().filter(|inbound| inbound["type"] == "veilway") {
		let tag = inbound["tag"].as_str().unwrap_or_default().to_string();
		let read = |key: &Value| key.as_str().and_then(|key| <[u8; 32]>::try_from(STANDARD.decode(key).ok()?).ok());
		let fresh = read(&inbound["private_key"]).map(|key| STANDARD.encode(crate::gateway::public_of(&key)));
		let fresh_transport = read(&inbound["transport_keys"][0]).map(|key| STANDARD.encode(veilway_proto::proof::public_key(&key)));
		if let Some(edits) = settings.profile_overrides.get_mut(&tag).and_then(Value::as_object_mut) {
			for (member, public) in [("inbound_public_key", &fresh), ("transport_public_key", &fresh_transport)] {if public.as_ref().is_some_and(|public| edits.get(member).is_some_and(|old| old != public.as_str())) {edits.remove(member);}}
			if edits.is_empty() {settings.profile_overrides.remove(&tag);}
		}
		if let Some(public) = fresh.or_else(|| settings.inbound_keys.get(&tag).cloned()) {kept.insert(tag.clone(), public);}
		for stream in inbound["transports"].as_array().into_iter().flatten().filter(|stream| stream["type"] == "ws-plain") {
			let name = slot(&tag, stream["path"].as_str().unwrap_or_default());
			let fresh = read(&stream["transport_keys"][0]).map(|key| STANDARD.encode(veilway_proto::proof::public_key(&key)));
			if let Some(public) = fresh.or_else(|| settings.transport_keys.get(&name).cloned()).filter(|_| stream["transport_keys"].as_array().is_some_and(|keys| !keys.is_empty())) {transport.insert(name, public);}
		}
		if let Some(public) = fresh_transport.or_else(|| settings.transport_keys.get(&tag).cloned()).filter(|_| inbound["transport_keys"].as_array().is_some_and(|keys| !keys.is_empty())) {transport.insert(tag, public);}
	}
	(settings.inbound_keys, settings.transport_keys) = (kept, transport);
}

/// One template per `veilway` inbound, with the overrides laid over it and the relays that reach `user` carried in. `user` is the account's id and groups, or None for the relays that reach everyone. `missing` lists what a profile still needs from the operator, since the node never reveals a public key and does not know its own public address.
/// With `skeleton`, a relays-only inbound keeps its transports with `NO_ADDRESS` for the node's address, which is what is published: each document then carries the relays that reach its account.
fn derive(settings: &Settings, document: &Value, relays: &[Relay], user: Option<(i64, &[String])>, exposure: &Exposure, skeleton: bool) -> Vec<Value> {
	let inbounds = document.get("inbounds").and_then(Value::as_array).cloned().unwrap_or_default();
	let reached = reaching(relays, user);
	// Every profile is made up to its overrides first, since the host names and paths a `ws-plain` transport must not share are those of all the inbounds: one subscription carries them all.
	let bases: Vec<(&Value, String, Value, Vec<Value>, Vec<Value>)> = inbounds.iter().filter(|inbound| inbound["type"] == "veilway").map(|inbound| {
		let (tag, host) = (inbound["tag"].as_str().unwrap_or_default().to_string(), settings.node_host.as_str());
		let transports: Vec<&Value> = inbound["transports"].as_array().map(|list| list.iter().collect()).unwrap_or_default();
		let obfs = transports.iter().any(|transport| transport["type"] == "udp-obfs");
		let gateways: Vec<Value> = inbound["address"].as_array().into_iter().flatten().filter_map(|address| address.as_str()?.split('/').next().map(|ip| json!(ip))).collect();
		let only = relays_only(settings, &tag);
		let mut refused: Vec<Value> = Vec::new();
		let listed: Vec<Value> = transports.iter().filter_map(|transport| {
			let listen = transport["listen"].as_str()?;
			let reached = if only {vec![NO_ADDRESS.to_string()]} else {hosts(settings, &tag, listen)};
			let endpoints: Vec<String> = reached.iter().filter_map(|host| host_port(host, listen)).collect();
			if endpoints.is_empty() {return None}
			Some(match transport["type"].as_str()? {
				kind @ ("udp" | "udp-obfs") => json!({"type": kind, "endpoints": endpoints}),
				kind @ ("tls" | "ws" | "fronted-shaped") if transport.get("decoy").is_some() => {
					// `tls` ends TLS on the node's own listener. `ws` and `fronted-shaped` sit behind the operator's web server, so apps get that server's port and not the listener's.
					let endpoints: Vec<String> = if kind == "tls" {endpoints} else {let port = settings.profile_overrides.get(&tag).and_then(|edits| edits[WEB_PORT].as_u64()).unwrap_or(443); reached.iter().filter_map(|host| host_port(host, &format!("web:{port}"))).collect()};
					let Some(name) = [transport["tls"]["name"].as_str(), transport["decoy"]["origin"].as_str().and_then(|origin| origin.split("://").last()?.split(['/', ':']).next()), (!only).then_some(host)].into_iter().flatten().chain(reached.iter().map(String::as_str).filter(|_| !only)).find(|name| is_host(name)) else {
						refused.push(json!({"transport": transport["listen"], "code": "no_name", "reason": "apps need a host name to send and check: the certificate names none, the decoy's origin is not a host name, and the node's address is an IP address"}));
						return None;
					};
					let mut stream = json!({"type": kind, "path": transport["path"], "candidates": endpoints.iter().map(|endpoint| json!({"address": endpoint, "sni": name, "host": name})).collect::<Vec<_>>()});
					if kind == "fronted-shaped" {stream["shape"] = transport["shape"].clone()}
					stream
				}
				_ => return None,
			})
		}).collect();
		let mut profile = json!({"id": tag.to_lowercase(), "name": tag, "type": "veilway", "gateways": gateways, "mtu": inbound["mtu"].as_u64().unwrap_or(if obfs {1390} else {1420}), "transports": listed});
		if let Some(public) = settings.inbound_keys.get(&tag) {profile["inbound_public_key"] = json!(public);}
		if let Some(public) = settings.transport_keys.get(&tag).filter(|_| profile["transports"].as_array().is_some_and(|list| list.iter().any(|transport| transport.get("candidates").is_some() && transport["type"] != "ws-plain"))) {profile["transport_public_key"] = json!(public);}
		if let Some(edits) = settings.profile_overrides.get(&tag).and_then(Value::as_object) {for (key, value) in edits.iter().filter(|(key, _)| *key != crate::borrowed::ADDRESSES && !NOT_MEMBERS.contains(&key.as_str())) {profile[key] = value.clone();}}
		(inbound, tag, profile, refused, gateways)
	}).collect();
	// A `ws-plain` transport shares no host name and no path with a covered one, on any inbound.
	let streams: Vec<&Value> = bases.iter().flat_map(|(_, _, profile, _, _)| profile["transports"].as_array().into_iter().flatten()).filter(|stream| stream.get("candidates").is_some() && stream["type"] != "ws-plain").collect();
	let names: Vec<String> = streams.iter().flat_map(|stream| stream["candidates"].as_array().into_iter().flatten().flat_map(|candidate| [candidate["host"].as_str(), candidate["sni"].as_str()]).flatten().map(str::to_lowercase)).collect();
	let paths: Vec<String> = streams.iter().filter_map(|stream| stream["path"].as_str()).map(str::to_string).collect();
	bases.into_iter().flat_map(|(inbound, tag, mut profile, mut refused, gateways)| {
		let transports: Vec<&Value> = inbound["transports"].as_array().map(|list| list.iter().collect()).unwrap_or_default();
		let (edits, only) = (settings.profile_overrides.get(&tag), relays_only(settings, &tag));
		if let Some(list) = profile.get_mut("transports").and_then(Value::as_array_mut) {list.retain(|transport| transport["type"] != "ws-plain")}
		for transport in transports.iter().filter(|transport| transport["type"] == "ws-plain") {
			if only {refused.push(json!({"transport": transport["listen"], "code": "relays_only", "reason": "a relay cannot sit in front of a ws-plain transport, and the node's own address is not given to apps"})); continue}
			let (path, listen) = (transport["path"].as_str().unwrap_or_default(), transport["listen"].as_str().unwrap_or_default());
			let endpoints: Vec<String> = hosts(settings, &tag, listen).iter().filter_map(|host| host_port(host, &format!("web:{}", edits.and_then(|edits| edits[PLAIN_PORT].as_u64()).unwrap_or(80)))).collect();
			if endpoints.is_empty() {continue}
			let (name, public, cookie) = (edits.and_then(|edits| edits[PLAIN_HOST].as_str()).filter(|name| is_host(name)), settings.transport_keys.get(&slot(&tag, path)), inbound["upgrade_cookie"].as_str());
			let (Some(name), Some(public), Some(cookie)) = (name, public, cookie) else {
				let (code, reason) = if name.is_none() {("plain_host", "plain HTTP shows the server's name to the whole path, so this transport needs a host name of its own, different from the names of the other transports: set the plain host of this inbound")} else if public.is_none() {("plain_key", "the panel has not seen this transport's key: apply the config with the key made here")} else {("plain_cookie", "the inbound has no upgrade cookie, which this transport sends its token in")};
				refused.push(json!({"transport": transport["listen"], "code": code, "reason": reason}));
				continue;
			};
			if names.iter().any(|used| used == name) {refused.push(json!({"transport": transport["listen"], "code": "plain_shared", "reason": "its host name is also used by another transport of the profiles, so the network could tie them together: use a host name of its own"})); continue}
			if paths.iter().any(|used| used == path) {refused.push(json!({"transport": transport["listen"], "code": "plain_shared", "reason": "its path is also used by another transport of the profiles, so the network could tie them together: use a path of its own"})); continue}
			if let Some(list) = profile.get_mut("transports").and_then(Value::as_array_mut) {list.push(json!({"type": "ws-plain", "path": path, "cookie": cookie, "transport_public_key": public, "candidates": endpoints.iter().map(|endpoint| json!({"address": endpoint, "host": name})).collect::<Vec<_>>()}));}
		}
		// The Xray inbounds answer on the addresses a profile names, so one that shares an address may not claim more than Detectable. An override of `unsafe` is the operator's own choice and stays.
		if exposure.shares(&addresses(&profile)) && profile["rating_cap"] != "unsafe" {profile["rating_cap"] = json!("detectable");}
		// Relays come after the overrides, so a transport an override wrote gets them too.
		let kinds: Vec<Value> = profile["transports"].as_array().into_iter().flatten().map(|transport| transport["type"].clone()).collect();
		let trimmed = if only && skeleton {Vec::new()} else {carry(&mut profile, &tag, &reached, only)};
		if only && !skeleton {
			let kept: Vec<&Value> = profile["transports"].as_array().into_iter().flatten().map(|transport| &transport["type"]).collect();
			let lost: Vec<Value> = kinds.iter().enumerate().filter(|(at, kind)| !kept.contains(kind) && !kinds[..*at].contains(kind)).map(|(_, kind)| json!({"transport": kind, "code": "relays_only", "reason": "no relay that reaches this account carries this transport, and the node's own address is not given to apps"})).collect();
			refused.extend(lost);
		}
		let mut missing = Vec::new();
		if profile.get("inbound_public_key").is_none() {missing.push("inbound_public_key")}
		let used: Vec<String> = transports.iter().filter_map(|transport| transport["listen"].as_str()).flat_map(|listen| hosts(settings, &tag, listen)).collect();
		if !only && (used.is_empty() || !used.iter().all(|host| reachable(host))) {missing.push("node_host")}
		if profile["transports"].as_array().is_some_and(|list| list.iter().any(|transport| transport["type"] == "tls" || transport["type"] == "ws" || transport["type"] == "fronted-shaped")) && profile.get("transport_public_key").is_none() {missing.push("transport_public_key")}
		let own = json!({"inbound": tag, "profile": profile, "missing": missing, "overridden": settings.profile_overrides.get(&tag).and_then(Value::as_object).map(|edits| edits.keys().filter(|key| *key != crate::borrowed::ADDRESSES && !NOT_MEMBERS.contains(&key.as_str())).cloned().collect::<Vec<_>>()).unwrap_or_default(), "trimmed": trimmed, "refused": refused});
		let faketls = crate::borrowed::template(settings, document, inbound, &gateways).map(|mut template| {
			if only {template["profile"]["transports"] = json!([]); template["missing"] = json!([]); template["refused"] = json!([{"transport": "faketls", "code": "relays_only", "reason": "a relay cannot sit in front of the borrowed-site handshake, and the node's own address is not given to apps"}]);}
			template
		});
		std::iter::once(own).chain(faketls).collect::<Vec<_>>()
	}).collect()
}

/// The templates with each profile's rating decided by the Xray inbounds it shares an address with. The names the profiles carry are looked up first, so the derivation itself does no lookup.
pub async fn rated(settings: &Settings, document: &Value, relays: &[Relay], user: Option<(i64, &[String])>, hosts: &[(String, String)], skeleton: bool) -> Vec<Value> {
	let names: Vec<String> = derive(settings, document, relays, user, &Exposure::default(), skeleton).iter().flat_map(|template| addresses(&template["profile"])).collect();
	let exposure = xray::exposure(document, hosts, &settings.node_host, names).await;
	derive(settings, document, relays, user, &exposure, skeleton)
}

pub async fn derived_profiles(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (revision, _, document) = running(&app).await?;
	let settings = app.settings();
	let hosts = app.db.call(|db| xray::inbound_hosts(db)).await??;
	ok(&json!({"revision": revision, "templates": rated(&settings, &document, &settings.relays, None, &hosts, false).await}))
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
	let hosts = app.db.call(|db| xray::inbound_hosts(db)).await??;
	ok(&json!({"revision": revision, "templates": rated(&app.settings(), &document, &input.relays, account.as_ref().map(|user| (user.id, groups.as_slice())), &hosts, false).await}))
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
	if input.set.get(NODE_ADDRESSES).is_some_and(|list| !list.as_array().is_some_and(|list| (1..CANDIDATES_MAX).contains(&list.len()) && list.iter().all(|host| host.as_str().is_some_and(|host| (!host.contains(':') || host.parse::<IpAddr>().is_ok()) && reachable(host))))) {return Err(Failure::bad(format!("{NODE_ADDRESSES} is 1 to {} IP addresses or host names, without ports. Each transport adds its own port.", CANDIDATES_MAX - 1)))}
	if input.set.get(WEB_PORT).is_some_and(|port| !port.as_u64().is_some_and(|port| (1..=65535).contains(&port))) {return Err(Failure::bad(format!("{WEB_PORT} is the port of the web server in front of the node, 1 to 65535.")))}
	if input.set.get(RELAYS_ONLY).is_some_and(|value| !value.is_boolean()) {return Err(Failure::bad(format!("{RELAYS_ONLY} is true or false.")))}
	if input.set.get(PLAIN_HOST).is_some_and(|host| !host.as_str().is_some_and(is_host)) {return Err(Failure::bad(format!("{PLAIN_HOST} is a lowercase host name such as plain.example.org, not an IP address.")))}
	if input.set.get(PLAIN_PORT).is_some_and(|port| !port.as_u64().is_some_and(|port| (1..=65535).contains(&port))) {return Err(Failure::bad(format!("{PLAIN_PORT} is the port of the web server for plain HTTP, 1 to 65535.")))}
	if plain_written(&input.set) {return Err(Failure::bad("An override of transports may not hold a ws-plain transport: the panel makes it from the node's config, with a key and a host name of its own."))}
	let (tag, set) = (inbound.clone(), input.set);
	app.update_settings(move |settings| if set.is_empty() {settings.profile_overrides.remove(&tag);} else {settings.profile_overrides.insert(tag, Value::Object(set));}).await.map_err(Failure::internal)?;
	app.db.audit(&ctx.actor, &ctx.source, "profile.override", &inbound, "").await;
	ok(&json!({"overrides": app.settings().profile_overrides}))
}

/// Writes the derived templates into the settings' `profiles`, which is what the subscription endpoint serves. A profile that is not derived from an inbound stays. A template with something missing stops the publish.
pub async fn publish_profiles(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>) -> Result<Response, Failure> {
	let (_, _, document) = running(&app).await?;
	let current = app.settings();
	let hosts = app.db.call(|db| xray::inbound_hosts(db)).await??;
	let templates = rated(&current, &document, &[], None, &hosts, true).await;
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
		let stale = stale_keys(settings);
		retarget(&mut settings.profiles, &stale);
		settings.relay_profiles = carrying;
		settings.published_relays = relays;
	}).await.map_err(Failure::internal)?;
	app.db.audit(&ctx.actor, &ctx.source, "settings.update", "settings", &format!("profiles changed at {}", now())).await;
	ok(&json!({"profiles": app.settings().profiles}))
}

/// The name a transport's key is kept under in the settings: the inbound's tag for its own transport key, the tag and the path for the keys of one of its `ws-plain` transports.
fn slot(tag: &str, path: &str) -> String {if path.is_empty() {tag.to_string()} else {format!("{tag}\n{path}")}}

/// The key list of a slot in a node document: the inbound's `transport_keys`, or the ones of its `ws-plain` transport on `path`.
fn keys_at<'a>(document: &'a mut Value, tag: &str, path: &str) -> Option<&'a mut Value> {
	let inbound = document["inbounds"].as_array_mut()?.iter_mut().find(|inbound| inbound["tag"] == tag)?;
	if path.is_empty() {Some(&mut inbound["transport_keys"])} else {inbound["transports"].as_array_mut()?.iter_mut().find(|stream| stream["type"] == "ws-plain" && stream["path"] == path).map(|stream| &mut stream["transport_keys"])}
}

/// Rewrites, in profiles, each `transport_public_key` (the profile's own and its transports') that is a `from` of `pairs` to the matching `to`. A pair with an empty side does nothing.
pub fn retarget(profiles: &mut [Value], pairs: &[(String, String)]) {
	let swap = |key: &Value| key.as_str().and_then(|key| pairs.iter().find(|(from, to)| !from.is_empty() && !to.is_empty() && from == key)).map(|(_, to)| json!(to));
	for profile in profiles.iter_mut() {
		if let Some(to) = swap(&profile["transport_public_key"]) {profile["transport_public_key"] = to;}
		for transport in profile.get_mut("transports").and_then(Value::as_array_mut).into_iter().flatten() {if let Some(to) = swap(&transport["transport_public_key"]) {transport["transport_public_key"] = to;}}
	}
}

/// The keys no profile may carry, each with the key of its slot that replaces it: the one the node holds second, which the next rotation destroys, and the ones it destroyed before.
pub fn stale_keys(settings: &Settings) -> Vec<(String, String)> {
	settings.transport_clocks.iter().filter_map(|(name, clock)| Some((settings.transport_keys.get(name)?, clock))).flat_map(|(current, clock)| std::iter::once(&clock.previous).chain(&clock.dropped).filter(|old| *old != current).map(|old| (old.clone(), current.clone())).collect::<Vec<_>>()).collect()
}

/// Whether an override puts a `ws-plain` transport in a profile. Those are made from the node's config, with a key and a host name of their own, and never written by hand.
pub fn plain_written(edits: &serde_json::Map<String, Value>) -> bool {edits.get("transports").and_then(Value::as_array).is_some_and(|list| list.iter().any(|transport| transport["type"] == "ws-plain"))}

/// The hourly rotation of the transport keys the panel makes: the first key of each `veilway` inbound (every `transport_key_days`) and of each of its `ws-plain` transports (every 7 days at most, since its proofs travel in clear). A slot holds two keys at most, so a rotation sets the node's list to the fresh key and the current one: the one that was second is destroyed and the current one lives one more period. Before that, no published profile may carry the key that is destroyed, and once the node holds the fresh key the profiles that carry the current one take the fresh one. A rotation is written before the node is asked, so one whose answer was lost is finished by a later pass, and one that stays unconfirmed for 2 days (the node's markers change when it restarts) is given up. The panel keeps no private key: the new one goes to the node and the old one is only ever a marker here.
pub async fn rotate_keys(app: &Arc<App>, at: i64) {
	let ctx = Ctx {actor: "system".into(), admin_id: 0, token_id: None, session_id: None, source: "upkeep".into()};
	let _turn = app.node_lock.lock().await;
	let (_, _, listed) = match running(app).await {Ok(found) => found, Err(error) => {tracing::warn!("transport keys: the node's config could not be read, so no key was checked: {}", error.message); return}};
	let slots: Vec<(String, String)> = listed["inbounds"].as_array().into_iter().flatten().filter(|inbound| inbound["type"] == "veilway").flat_map(|inbound| {
		let tag = inbound["tag"].as_str().unwrap_or_default().to_string();
		let own = inbound["transport_keys"].as_array().is_some_and(|keys| !keys.is_empty()).then(|| (tag.clone(), String::new()));
		let plain = inbound["transports"].as_array().into_iter().flatten().filter(|stream| stream["type"] == "ws-plain").map(move |stream| (tag.clone(), stream["path"].as_str().unwrap_or_default().to_string()));
		own.into_iter().chain(plain).collect::<Vec<_>>()
	}).collect();
	for (tag, path) in slots {
		let (name, label) = (slot(&tag, &path), format!("{tag}{path}"));
		let (revision, _, mut document) = match running(app).await {Ok(found) => found, Err(error) => {tracing::warn!("transport keys: the node's config could not be read again: {}", error.message); return}};
		let Some(keys) = keys_at(&mut document, &tag, &path).and_then(|keys| keys.as_array().cloned()) else {continue};
		let settings = app.settings();
		let public = settings.transport_keys.get(&name).cloned().unwrap_or_default();
		let days = if path.is_empty() {i64::from(settings.transport_key_days)} else {i64::from(settings.transport_key_days).min(7)};
		let clock = match settings.transport_clocks.get(&name).cloned() {
			Some(clock) if clock.public == public || (!clock.next.is_empty() && clock.next == public) => clock,
			_ => {
				// A first key nobody here chose, so its age starts now. What the old clock knew of destroyed keys is kept, since a form may still bring them back.
				if keys.len() == 2 {tracing::info!("transport keys of {label}: a clock starts on a slot that holds 2 keys, so the next rotation destroys the second one")}
				let (held, old) = (name.clone(), settings.transport_clocks.get(&name).cloned().unwrap_or_default());
				let result = app.update_settings(move |settings| {
					let mut fresh = TransportClock {public: public.clone(), since: at, dropped: old.dropped.clone(), ..TransportClock::default()};
					fresh.drop_keys(&[old.public.as_str(), old.previous.as_str()]);
					fresh.dropped.retain(|gone| *gone != public);
					settings.transport_clocks.insert(held, fresh);
				}).await;
				if let Err(error) = result {tracing::warn!("transport keys of {label}: the clock was not saved: {error}")}
				continue;
			}
		};
		let mut failed = false;
		if clock.next.is_empty() && (1..=2).contains(&keys.len()) && at - clock.since >= days * 86_400 {
			let fresh: [u8; 32] = random();
			let next = STANDARD.encode(veilway_proto::proof::public_key(&fresh));
			let (held, before, marker, intent) = (name.clone(), clock.clone(), keys[0].as_str().unwrap_or_default().to_string(), next.clone());
			let result = app.update_settings(move |settings| {
				retarget(&mut settings.profiles, &[(before.previous.clone(), before.public.clone())]);
				settings.transport_clocks.insert(held, TransportClock {next: intent, old_marker: marker, started: at, ..before});
			}).await;
			if let Err(error) = result {tracing::warn!("transport keys of {label}: the rotation was not started: {error}"); continue}
			keys_at(&mut document, &tag, &path).map(|list| *list = json!([STANDARD.encode(fresh), keys[0]]));
			if let Err(error) = apply(app, &ctx, document, &revision, &tag).await {tracing::warn!("transport keys of {label}: the node did not take the new key, so the profiles keep the old one: {}", error.message); failed = true}
		}
		let settings = app.settings();
		let (public, clock) = (settings.transport_keys.get(&name).cloned().unwrap_or_default(), settings.transport_clocks.get(&name).cloned().unwrap_or_default());
		if clock.next.is_empty() {continue}
		let held = running(app).await.ok().and_then(|(_, _, mut found)| keys_at(&mut found, &tag, &path).and_then(|list| list.as_array().cloned()));
		// The node holds the old key second only when it took this rotation, also when its answer to the apply was lost.
		let taken = clock.next == public || held.as_ref().is_some_and(|keys| keys.len() == 2 && !clock.old_marker.is_empty() && keys[1] == clock.old_marker.as_str());
		if taken {
			let (held, done) = (name.clone(), clock.clone());
			let result = app.update_settings(move |settings| {
				retarget(&mut settings.profiles, &[(done.previous.clone(), done.next.clone()), (done.public.clone(), done.next.clone())]);
				settings.transport_keys.insert(held.clone(), done.next.clone());
				let mut now_first = TransportClock {public: done.next.clone(), since: at, previous: done.public.clone(), dropped: done.dropped.clone(), ..TransportClock::default()};
				now_first.drop_keys(&[done.previous.as_str()]);
				settings.transport_clocks.insert(held, now_first);
			}).await;
			if let Err(error) = result {tracing::warn!("transport keys of {label}: the node holds the new key but the profiles were not updated, this is tried again: {error}"); continue}
			tracing::info!("transport keys of {label}: a new first key is in force and the profiles carry it, the old key is held one more period");
			app.db.audit(&ctx.actor, &ctx.source, "transport_key.rotate", &label, "").await;
		} else {
			let expired = at - clock.started >= 2 * 86_400;
			if !expired && !(failed && held.is_some()) {tracing::warn!("transport keys of {label}: the node's answer to the rotation is not confirmed yet, no other rotation starts until it is or 2 days pass"); continue}
			let held = name.clone();
			let _ = app.update_settings(move |settings| if let Some(clock) = settings.transport_clocks.get_mut(&held) {clock.next.clear(); clock.old_marker.clear(); clock.started = 0}).await;
			if expired {
				tracing::warn!("transport keys of {label}: a rotation stayed unconfirmed for 2 days and is given up, the next pass may start another");
				app.db.audit(&ctx.actor, &ctx.source, "transport_key.reset", &label, "a rotation stayed unconfirmed for 2 days").await;
			}
		}
	}
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
		derive(&settings, &document(), &settings.relays, None, &Exposure::default(), false).into_iter().map(|template| template["profile"]["transports"].clone()).collect()
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
		let endpoints = derive(&settings, &document(), &settings.relays, None, &Exposure::default(), false)[0]["profile"]["transports"][0]["endpoints"].as_array().unwrap().clone();
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
		let template = derive(&settings, &document(), &relays, Some((7, &groups)), &Exposure::default(), false)[0].clone();
		let endpoints = template["profile"]["transports"][0]["endpoints"].as_array().unwrap().clone();
		assert_eq!((endpoints.len(), endpoints[2].clone(), endpoints[3].clone()), (CANDIDATES_MAX, json!("198.51.100.91:51820"), json!("198.51.100.90:51820")), "the account's relay leads the ones it gets, then its group's");
		assert_eq!(template["trimmed"], json!([{"transport": "udp", "relay": "all12"}]), "the preview names what the cap cut");
	}

	#[test]
	fn a_published_profile_carries_for_each_account_what_the_preview_shows() {
		let relays = vec![relay(json!({"name": "all", "address": "198.51.100.8"})), relay(json!({"name": "ann", "address": "198.51.100.9", "users": [7]})), relay(json!({"name": "other-inbound", "address": "198.51.100.10", "inbounds": ["Other"]}))];
		let settings = Settings {node_host: "192.0.2.10".into(), relays: relays.clone(), ..Settings::default()};
		let groups: Vec<String> = Vec::new();
		let published = derive(&settings, &document(), &[], None, &Exposure::default(), false)[0]["profile"].clone();
		let mut carried = published.clone();
		carry(&mut carried, "Main", &reaching(&relays, Some((7, &groups))), false);
		assert_eq!(carried["transports"], derive(&settings, &document(), &relays, Some((7, &groups)), &Exposure::default(), false)[0]["profile"]["transports"], "the stored base plus the account's relays is the preview for the account");
		let mut stranger = published.clone();
		carry(&mut stranger, "Main", &reaching(&relays, Some((8, &groups))), false);
		assert_eq!(stranger["transports"][0]["endpoints"], json!(["192.0.2.10:51820", "198.51.100.8:51820"]), "an account without its own relay gets only the relays for everyone");
	}

	#[test]
	fn relays_only_gives_apps_no_address_of_the_node() {
		let mut document = document();
		document["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws-plain", "listen": "127.0.0.1:8080", "path": "/plain-path-long-enough"}));
		let mut settings = Settings {node_host: "192.0.2.10".into(), relays: vec![relay(json!({"name": "late", "transports": ["udp", "tls"]})), relay(json!({"name": "udp-only", "address": "198.51.100.8", "transports": ["udp"], "users": [7]}))], ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transport_public_key": "key", "relays_only": true, "node_addresses": ["192.0.2.11"]}));
		let groups: Vec<String> = Vec::new();
		let template = derive(&settings, &document, &settings.relays, Some((7, &groups)), &Exposure::default(), false).remove(0);
		let text = template["profile"].to_string();
		assert!(!text.contains("192.0.2.1") && !text.contains(NO_ADDRESS), "no address of the node, not even the stand-in: {text}");
		assert_eq!(template["profile"]["transports"][0]["endpoints"], json!(["198.51.100.8:51820", "198.51.100.7:51820"]));
		assert_eq!(template["profile"]["transports"][1]["candidates"], json!([{"address": "198.51.100.7:443", "sni": "node.example.org", "host": "node.example.org"}]), "the name the app checks stays");
		assert_eq!((template["profile"]["transports"].as_array().unwrap().len(), template["refused"][0]["code"].clone(), template["overridden"].clone(), template["missing"].clone()), (2, json!("relays_only"), json!(["transport_public_key"]), json!(["inbound_public_key"])), "ws-plain is refused, the override is no member, and no node host is asked for");
		let stranger = derive(&settings, &document, &settings.relays, Some((8, &groups)), &Exposure::default(), false).remove(0);
		assert_eq!(stranger["profile"]["transports"][0]["endpoints"], json!(["198.51.100.7:51820"]));
		let tls_only = Settings {relays: vec![relay(json!({"transports": ["udp"]}))], ..settings.clone()};
		let none = derive(&tls_only, &document, &tls_only.relays, None, &Exposure::default(), false).remove(0);
		assert_eq!((none["profile"]["transports"].clone(), none["refused"].as_array().unwrap().iter().map(|found| found["transport"].clone()).collect::<Vec<_>>()), (json!([{"type": "udp", "endpoints": ["198.51.100.7:51820"]}]), vec![json!("127.0.0.1:8080"), json!("tls")]), "a transport no relay carries is refused, not given with the node's address");
		let nobody = Settings {relays: Vec::new(), ..settings.clone()};
		let empty = derive(&nobody, &document, &nobody.relays, None, &Exposure::default(), false).remove(0);
		assert_eq!((empty["profile"]["transports"].clone(), empty["refused"].as_array().unwrap().len()), (json!([]), 3), "an audience no relay reaches gets no transport");
	}

	#[test]
	fn the_published_profile_of_a_relays_only_inbound_holds_no_node_address_and_documents_fill_it_from_relays() {
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transport_public_key": "key", "relays_only": true}));
		let published = derive(&settings, &document(), &[], None, &Exposure::default(), true).remove(0)["profile"].clone();
		assert!(!published.to_string().contains("192.0.2."), "{published}");
		let relays = vec![relay(json!({"name": "edge", "ports": {"tls": 8443}}))];
		let groups: Vec<String> = Vec::new();
		let mut served = published.clone();
		carry(&mut served, "Main", &reaching(&relays, Some((7, &groups))), true);
		assert_eq!(served["transports"][0]["endpoints"], json!(["198.51.100.7:51820"]));
		assert_eq!(served["transports"][1]["candidates"][0]["address"], json!("198.51.100.7:8443"));
		let mut stranger = published.clone();
		carry(&mut stranger, "Main", &[], true);
		assert_eq!(stranger["transports"], json!([]), "no relay reaches the account, so nothing of the profile is left");
		let mut older = json!({"transports": [{"type": "udp", "endpoints": ["192.0.2.10:51820"]}, {"type": "faketls", "candidates": [{"address": "192.0.2.10:443", "sni": "www.example.org"}]}]});
		carry(&mut older, "Main", &reaching(&relays, Some((7, &groups))), true);
		assert_eq!(older["transports"], json!([{"type": "udp", "endpoints": ["198.51.100.7:51820"]}]), "a snapshot made before the switch loses the node's addresses and faketls");
	}

	#[test]
	fn a_port_per_inbound_and_transport_wins_over_the_port_per_type() {
		let mut settings = Settings {node_host: "192.0.2.10".into(), relays: vec![relay(json!({"ports": {"tls": 8443, "udp": 6000}, "inbound_ports": {"Main/tls": 9443, "Other/udp-obfs": 7000, "Gone/ws": 1}}))], ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transport_public_key": "key"}));
		let templates = derive(&settings, &document(), &settings.relays, None, &Exposure::default(), false);
		assert_eq!((templates[0]["profile"]["transports"][0]["endpoints"][1].clone(), templates[0]["profile"]["transports"][1]["candidates"][1]["address"].clone(), templates[1]["profile"]["transports"][0]["endpoints"][1].clone()), (json!("198.51.100.7:6000"), json!("198.51.100.7:9443"), json!("198.51.100.7:7000")), "the inbound's key first, then the type's port, and the node's own port when neither is set");
		let read = |ports: Value| serde_json::from_value::<Settings>(json!({"relays": [{"name": "a", "address": "198.51.100.7", "enabled": true, "inbound_ports": ports}]})).is_ok();
		assert!(read(json!({"Main/ws": 8443})) && read(json!({"A/B/ws": 8443})));
		assert!(!read(json!({"Main/ws": 0})) && !read(json!({"Main": 80})) && !read(json!({"Main/quic": 80})) && !read(json!({"/ws": 80})) && !read(json!({"Main/faketls": 80})));
	}

	#[test]
	fn a_fronted_shaped_transport_carries_its_shape_into_the_profile() {
		let shape = json!({"up": {"method": "POST", "in": "body"}, "down": {"mode": "sse"}});
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "fronted-shaped", "listen": "127.0.0.1:8443", "path": "/a-long-enough-path", "decoy": {"origin": "http://origin.example.org:8080"}, "trusted_proxies": ["127.0.0.1"], "shape": shape.clone()}]}]});
		let settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["profile"]["transports"], json!([{"type": "fronted-shaped", "path": "/a-long-enough-path", "candidates": [{"address": "192.0.2.10:443", "sni": "origin.example.org", "host": "origin.example.org"}], "shape": shape}]), "the shape is the node's object, as the subscription format wants it");
		assert_eq!(template["missing"], json!(["inbound_public_key", "transport_public_key"]), "a fronted-shaped transport needs the transport public key like tls and ws");
	}

	#[test]
	fn relays_are_validated_when_settings_are_read() {
		let read = |relays: Value| serde_json::from_value::<Settings>(json!({"relays": relays})).map(|settings| settings.relays.len()).map_err(|error| error.to_string());
		assert_eq!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["tls"], "ports": {"tls": 443}}])), Ok(1));
		assert_eq!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["fronted-shaped"], "ports": {"fronted-shaped": 9443}}])), Ok(1), "a fronted-shaped relay is carried like a fronted one");
		for bad in [json!({"name": "a", "address": "Relay Example", "enabled": true}), json!({"name": "a", "address": "127.0.0.1", "enabled": true}), json!({"name": " a", "address": "198.51.100.7", "enabled": true}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["quic"]}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "ports": {"udp": 0}}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["udp", "udp"]}), json!({"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["faketls"]}), json!({"name": "a", "address": "198.51.100.7"})] {assert!(read(json!([bad])).is_err(), "{bad}")}
		assert!(read(json!([{"name": "a", "address": "198.51.100.7", "enabled": true}, {"name": "a", "address": "198.51.100.8", "enabled": true}])).is_err(), "names are unique");
		assert_eq!(read(json!([{"name": "a", "address": "cdn.example.net", "enabled": true}])), Ok(1), "a host name, such as a content delivery network's");
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
		let template = derive(&settings, &document, &relays, None, &Exposure::default(), false).remove(0);
		assert_eq!(template["profile"]["transports"], json!([{"type": "fronted-shaped", "path": "/a-long-enough-path", "candidates": [{"address": "192.0.2.10:443", "sni": "origin.example.org", "host": "origin.example.org"}, {"address": "198.51.100.7:9443", "sni": "origin.example.org", "host": "origin.example.org"}], "shape": shape}]), "the relay's candidate keeps the node's names and shape");
	}

	#[test]
	fn a_stream_transport_without_a_name_is_refused_and_the_others_stay() {
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "ws", "listen": "0.0.0.0:443", "decoy": {"origin": "http://127.0.0.1:8080"}, "path": "/a-long-enough-path"}]}]});
		let settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["profile"]["transports"], json!([{"type": "udp", "endpoints": ["192.0.2.10:51820"]}]), "an address is never a name, so the ws transport is left out");
		assert_eq!((template["refused"][0]["transport"].clone(), template["refused"][0]["code"].clone(), template["refused"].as_array().unwrap().len()), (json!("0.0.0.0:443"), json!("no_name"), 1));
	}

	#[test]
	fn the_certificate_name_comes_before_the_decoy_host() {
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "tls", "listen": "0.0.0.0:443", "tls": {"self_signed": true, "name": "node.example.org"}, "decoy": {"origin": "http://decoy.example.net:8080"}, "path": "/a-long-enough-path"}]}]});
		let settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!((template["profile"]["transports"][0]["candidates"].clone(), template["refused"].clone()), (json!([{"address": "192.0.2.10:443", "sni": "node.example.org", "host": "node.example.org"}]), json!([])));
	}

	#[test]
	fn a_node_address_apps_cannot_reach_holds_the_profile_back() {
		let missing = |host: &str| derive(&Settings {node_host: host.into(), ..Settings::default()}, &document(), &[], None, &Exposure::default(), false)[1]["missing"].as_array().unwrap().iter().any(|name| name == "node_host");
		for host in ["", "127.0.0.1", "0.0.0.0", "[fe80::1]", "not a name", "Node.Example.org"] {assert!(missing(host), "{host:?}")}
		for host in ["192.0.2.10", "2001:db8::10", "[2001:db8::10]", "node.example.org"] {assert!(!missing(host), "{host:?}: a host name becomes its addresses in each document")}
	}

	#[test]
	fn an_inbound_has_addresses_of_its_own_and_a_public_listener_speaks_for_itself() {
		let mut settings = Settings {node_host: "node.example.org".into(), ..Settings::default()};
		let endpoints = |settings: &Settings, document: &Value| derive(settings, document, &[], None, &Exposure::default(), false)[0]["profile"]["transports"][0]["endpoints"].clone();
		let bound = |listen: &str| json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "udp-obfs", "listen": listen}]}]});
		assert_eq!(endpoints(&settings, &bound("0.0.0.0:8443")), json!(["node.example.org:8443"]));
		assert_eq!(endpoints(&settings, &bound("198.51.100.7:8443")), json!(["198.51.100.7:8443"]), "a listener on a public address is reached there");
		assert_eq!(endpoints(&settings, &bound("10.0.0.5:8443")), json!(["node.example.org:8443"]), "a private one is behind NAT more often than not");
		settings.profile_overrides.insert("Main".into(), json!({NODE_ADDRESSES: ["203.0.113.5", "edge.example.net", "2001:db8::5"]}));
		let template = derive(&settings, &bound("198.51.100.7:8443"), &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["profile"]["transports"][0]["endpoints"], json!(["203.0.113.5:8443", "edge.example.net:8443", "[2001:db8::5]:8443"]));
		assert!(template["profile"].get(NODE_ADDRESSES).is_none() && template["overridden"] == json!([]), "the list is no member of the profile");
	}

	#[test]
	fn apps_reach_a_ws_transport_at_the_web_server_in_front_and_a_tls_one_at_its_listener() {
		let mut settings = Settings {node_host: "node.example.org".into(), ..Settings::default()};
		let decoy = json!({"origin": "http://127.0.0.1:8080"});
		let document = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [{"type": "ws", "listen": "0.0.0.0:8081", "path": "/a-long-secret-path", "decoy": decoy, "trusted_proxies": ["127.0.0.1"]}, {"type": "tls", "listen": "0.0.0.0:8443", "path": "/another-secret-path", "decoy": decoy}]}]});
		let addresses = |settings: &Settings| derive(settings, &document, &[], None, &Exposure::default(), false)[0]["profile"]["transports"].as_array().unwrap().iter().map(|transport| transport["candidates"][0]["address"].clone()).collect::<Vec<_>>();
		assert_eq!(addresses(&settings), [json!("node.example.org:443"), json!("node.example.org:8443")], "the node's own listener of `ws` speaks plain HTTP to the web server alone");
		settings.profile_overrides.insert("Main".into(), json!({WEB_PORT: 2083}));
		assert_eq!(addresses(&settings), [json!("node.example.org:2083"), json!("node.example.org:8443")]);
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert!(template["profile"].get(WEB_PORT).is_none() && template["overridden"] == json!([]), "the port is no member of the profile");
	}

	#[test]
	fn a_relay_may_be_a_host_name() {
		let relay = relay(json!({"address": "cdn.example.net", "transports": ["fronted"]}));
		assert_eq!(relay.address, "cdn.example.net");
		let mut profile = json!({"transports": [{"type": "fronted", "candidates": [{"address": "192.0.2.10:443", "sni": "front.example.com"}]}]});
		carry(&mut profile, "Main", &[(2, &relay)], false);
		assert_eq!(profile["transports"][0]["candidates"][1], json!({"address": "cdn.example.net:443", "sni": "front.example.com"}));
	}

	#[test]
	fn a_transport_key_applied_in_full_gives_its_profile_the_public_half() {
		let key = [7u8; 32];
		let public = STANDARD.encode(veilway_proto::proof::public_key(&key));
		let mut document = document();
		document["inbounds"][0]["transport_keys"] = json!([STANDARD.encode(key)]);
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({"transport_public_key": "an old one"}));
		remember_keys(&mut settings, &document);
		assert!(!settings.profile_overrides.contains_key("Main"), "an override of another key is dropped");
		let derived = derive(&settings, &document, &[], None, &Exposure::default(), false);
		assert_eq!((derived[0]["profile"]["transport_public_key"].clone(), derived[0]["missing"].as_array().unwrap().contains(&json!("transport_public_key"))), (json!(public), false));
		assert!(derived[1]["profile"].get("transport_public_key").is_none(), "a profile with no stream transport carries none");
		document["inbounds"][0]["transport_keys"] = json!(["<redacted>"]);
		remember_keys(&mut settings, &document);
		assert_eq!(settings.transport_keys["Main"], public, "a redacted key keeps the half made before");
	}

	fn plain_document(key: [u8; 32]) -> Value {
		let mut document = document();
		document["inbounds"][0]["upgrade_cookie"] = json!("session_id");
		document["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "ws-plain", "listen": "127.0.0.1:8081", "path": "/a-plain-long-path", "decoy": {"origin": "http://origin.example.org:8080"}, "trusted_proxies": ["127.0.0.1"], "transport_keys": [STANDARD.encode(key)]}));
		document
	}

	#[test]
	fn a_ws_plain_transport_carries_its_cookie_its_own_key_and_a_host_of_its_own() {
		let (key, document) = ([9u8; 32], plain_document([9u8; 32]));
		let public = STANDARD.encode(veilway_proto::proof::public_key(&key));
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		remember_keys(&mut settings, &document);
		assert_eq!(settings.transport_keys["Main\n/a-plain-long-path"], public, "kept by tag and path");
		assert!(!settings.transport_keys.contains_key("Main"), "the inbound's own key is not made from it");
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["refused"][0]["code"], "plain_host", "no host name of its own, no transport");
		assert_eq!(template["refused"].as_array().unwrap().len(), 1);
		assert!(template["profile"]["transports"].as_array().unwrap().iter().all(|transport| transport["type"] != "ws-plain"));
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "plain.example.org"}));
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		let plain = template["profile"]["transports"].as_array().unwrap().iter().find(|transport| transport["type"] == "ws-plain").unwrap().clone();
		assert_eq!(plain, json!({"type": "ws-plain", "path": "/a-plain-long-path", "cookie": "session_id", "transport_public_key": public, "candidates": [{"address": "192.0.2.10:80", "host": "plain.example.org"}]}), "port 80 by default, address and host only");
		assert!(template["profile"].get("transport_public_key").is_none() && template["profile"].get(PLAIN_HOST).is_none() && template["overridden"] == json!([]) && template["refused"] == json!([]));
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "plain.example.org", PLAIN_PORT: 8080}));
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["profile"]["transports"][2]["candidates"], json!([{"address": "192.0.2.10:8080", "host": "plain.example.org"}]));
		let relays = vec![relay(json!({"address": "198.51.100.7"}))];
		let template = derive(&settings, &document, &relays, None, &Exposure::default(), false).remove(0);
		assert_eq!(template["profile"]["transports"][2]["candidates"].as_array().unwrap().len(), 1, "a relay never carries it");
		assert!(serde_json::from_value::<Settings>(json!({"relays": [{"name": "a", "address": "198.51.100.7", "enabled": true, "transports": ["ws-plain"]}]})).is_err(), "and cannot be told to");
	}

	#[test]
	fn a_ws_plain_host_may_not_be_a_host_of_a_covered_transport() {
		let document = plain_document([9u8; 32]);
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		remember_keys(&mut settings, &document);
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "node.example.org"}));
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["refused"][0]["code"], "plain_shared");
		assert!(template["profile"]["transports"].as_array().unwrap().iter().all(|transport| transport["type"] != "ws-plain"));
		assert!(template["missing"].as_array().unwrap().is_empty() || template["missing"] == json!(["inbound_public_key", "transport_public_key"]), "the covered transports are not blocked by it");
	}

	#[test]
	fn a_ws_plain_transport_shares_no_host_or_path_with_a_covered_transport_of_any_inbound() {
		let mut document = plain_document([9u8; 32]);
		document["inbounds"][1]["transports"].as_array_mut().unwrap().push(json!({"type": "tls", "listen": "0.0.0.0:444", "tls": {"self_signed": true, "name": "other.example.org"}, "decoy": "127.0.0.1:8443", "path": "/other-long-path-here"}));
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		remember_keys(&mut settings, &document);
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "other.example.org"}));
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["refused"][0]["code"], "plain_shared", "the host of another inbound's transport");
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "plain.example.org"}));
		assert_eq!(derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0)["refused"], json!([]), "a host of its own is fine");
		document["inbounds"][1]["transports"][1]["path"] = json!("/a-plain-long-path");
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["refused"][0]["code"], "plain_shared", "the path of another inbound's transport");
		document["inbounds"][1]["transports"][1]["path"] = json!("/other-long-path-here");
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "plain.example.org", "transports": [{"type": "ws-plain", "path": "/by-hand", "transport_public_key": "key", "candidates": [{"address": "192.0.2.10:80", "host": "plain.example.org"}]}]}));
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		let plain: Vec<&Value> = template["profile"]["transports"].as_array().unwrap().iter().filter(|transport| transport["type"] == "ws-plain").collect();
		assert_eq!((plain.len(), plain[0]["path"].clone()), (1, json!("/a-plain-long-path")), "a ws-plain written by hand never stays");
	}

	#[test]
	fn a_ws_plain_transport_the_panel_never_saw_the_key_of_is_refused() {
		let document = plain_document([9u8; 32]);
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		settings.profile_overrides.insert("Main".into(), json!({PLAIN_HOST: "plain.example.org"}));
		let template = derive(&settings, &document, &[], None, &Exposure::default(), false).remove(0);
		assert_eq!(template["refused"][0]["code"], "plain_key");
	}
}
