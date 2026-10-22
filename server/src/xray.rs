//! The Xray add-on: its inbounds in the node's config, which the panel makes with a credential per user, and the users' share links. The credentials are sealed in the panel's database, which is what the links are made from, since the node only ever shows its marker.
use crate::{admin::Done, app::{publish_settings, store_settings, App}, auth::reauthed, crypto::{self, now}, db::audit, http::{ok, Body, Ctx, Failure}, node, nodecfg, subs::UserRow, users::{self, name_ok, NodeState}};
use axum::{extract::{Path, State}, http::StatusCode, response::Response, Extension};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ipnet::IpNet;
use std::{collections::{BTreeSet, HashMap}, net::IpAddr, sync::Arc, time::Duration};

const PROTOCOLS: [&str; 3] = ["vless", "trojan", "shadowsocks"];

/// The key Shadowsocks 2022 uses at the server and, for each user, at the client: 32 random bytes as standard base64.
pub(crate) fn key32() -> String {STANDARD.encode(crypto::random::<32>())}

/// What the sealed server key of a Shadowsocks inbound is bound to, since it belongs to no user.
pub(crate) fn server_label(tag: &str) -> String {format!("xray_server:{tag}")}

/// The origin of the first `tls` transport of the node's inbounds that has a decoy: the operator's own web server, which a connection that is not an Xray user's is handed to.
fn node_decoy(document: &Value) -> Option<String> {
	document["inbounds"].as_array()?.iter().flat_map(|inbound| inbound["transports"].as_array().into_iter().flatten()).find(|transport| transport["type"] == "tls").and_then(|transport| transport["decoy"]["origin"].as_str().map(str::to_string))
}

/// Whether the node has the add-on, and its release. A node that says nothing of add-ons has none.
async fn addon(app: &App) -> (bool, Option<String>) {
	let status = match node::request(&app.cfg.node_socket, "GET", "/v1/status", None, None).await {Ok((200, body)) => serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null), _ => Value::Null};
	let xray = &status["addons"]["xray"];
	(xray["installed"] == true, xray["release"].as_str().map(str::to_string))
}

/// The address links name: the inbound's own, else the node's first public address, else the panel's node host.
async fn host_of(app: &App, document: &Value, own: &str) -> String {
	if !own.is_empty() {return own.to_string()}
	match document["public_addresses"].get(0).and_then(Value::as_str) {Some(host) => host.to_string(), None => app.settings().node_host}
}

#[derive(Serialize, JsonSchema)]
pub struct XrayInboundOut {
	pub tag: String,
	/// vless, trojan or shadowsocks.
	pub protocol: String,
	pub listen: String, pub port: u16,
	/// "tls" or "none".
	pub security: String,
	pub clients: usize,
	/// The host the links name.
	pub host: String,
	/// The host the panel was given for this inbound, empty when links name the node's address.
	pub own_host: String,
	/// Whether the panel made this inbound and holds its credentials, which links need.
	pub managed: bool,
	/// A vless or trojan inbound without certificate files, which the node refuses.
	pub certificate_missing: bool,
	pub cert: Option<String>, pub key: Option<String>,
	/// The origin of the web server a stranger is handed to, for vless and trojan.
	pub decoy: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct XrayOut {pub installed: bool, pub release: Option<String>, pub inbounds: Vec<XrayInboundOut>}

pub async fn get(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let ((installed, release), (_, _, document)) = (addon(&app).await, nodecfg::running(&app).await?);
	let made = app.db.call(|db| inbound_hosts(db)).await??;
	let node_host = host_of(&app, &document, "").await;
	let inbounds = document["xray"]["inbounds"].as_array().into_iter().flatten().map(|inbound| {
		let (tag, listen) = (inbound["tag"].as_str().unwrap_or_default().to_string(), inbound["listen"].as_str().unwrap_or_default().to_string());
		let own = made.iter().find(|(made, _)| *made == tag);
		XrayInboundOut {protocol: inbound["protocol"].as_str().unwrap_or_default().to_string(), port: listen.rsplit_once(':').and_then(|(_, port)| port.parse().ok()).unwrap_or(0), security: if inbound.get("tls").is_some() {"tls"} else {"none"}.into(), clients: inbound["clients"].as_array().map_or(0, Vec::len), host: own.map(|(_, host)| host.clone()).filter(|host| !host.is_empty()).unwrap_or_else(|| node_host.clone()), own_host: own.map_or(String::new(), |(_, host)| host.clone()), managed: own.is_some(), certificate_missing: inbound["protocol"] != "shadowsocks" && inbound.get("tls").is_none(), cert: inbound["tls"]["cert"].as_str().map(str::to_string), key: inbound["tls"]["key"].as_str().map(str::to_string), decoy: inbound["decoy"].as_str().map(str::to_string), tag, listen}
	}).collect();
	ok(&XrayOut {installed, release, inbounds})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundIn {
	pub tag: String,
	/// vless, trojan or shadowsocks.
	pub protocol: String,
	pub port: u16,
	/// The address Xray listens on. 0.0.0.0 when left out.
	pub listen: Option<String>,
	/// Paths of the certificate and key files on the node. Needed for vless and trojan, refused for shadowsocks.
	pub cert: Option<String>, pub key: Option<String>,
	/// The host the links name, in the place of the node's first public address.
	pub host: Option<String>,
	/// For vless and trojan, the origin of the operator's own web server (http://127.0.0.1:8080) that anything that is not a user's connection is handed to. Taken from the node's `tls` transport when left out; the inbound is refused when the node has none.
	pub decoy: Option<String>,
}

/// The checks create and edit share: the listen address with the port, the certificate files and the host. Shadowsocks takes no certificate; vless and trojan need both files.
fn checked(protocol: &str, port: u16, listen: Option<&str>, cert: &Option<String>, key: &Option<String>, host: Option<String>) -> Result<(String, Option<Value>, String), Failure> {
	if port == 0 {return Err(Failure::bad("port is 1 to 65535."))}
	let listen: IpAddr = listen.unwrap_or("0.0.0.0").parse().map_err(|_| Failure::bad("listen is an IP address."))?;
	let path_ok = |path: &Option<String>| path.as_ref().is_some_and(|path| path.starts_with('/') && path.len() <= 4096 && !path.contains('\0'));
	let tls = match (protocol == "shadowsocks", cert.is_some() || key.is_some()) {
		(true, true) => return Err(Failure::bad("shadowsocks takes no certificate: it encrypts itself.")),
		(true, false) => None,
		(false, _) if path_ok(cert) && path_ok(key) => Some(json!({"cert": cert, "key": key})),
		_ => return Err(Failure::bad("vless and trojan need the absolute paths of the certificate and key files on the node.")),
	};
	let host = host.unwrap_or_default();
	if host.len() > 253 || !host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte)) {return Err(Failure::bad("host is a domain name or an IP address."))}
	Ok((if listen.is_ipv6() {format!("[{listen}]:{port}")} else {format!("{listen}:{port}")}, tls, host))
}

/// The private and documentation ranges of the node's `GEOIP_PRIVATE`, where a decoy may sit.
const PRIVATE: [&str; 13] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "fc00::/7", "2001:db8::/32"];

/// A decoy is the origin of the operator's own web server, plain http on the node: a loopback or private address, or localhost. The node warns about any other address, and the panel refuses it.
fn decoy_ok(decoy: Option<String>) -> Result<String, Failure> {
	let refused = || Failure::bad("A vless or trojan inbound needs a decoy: the origin of your own web server on this node (http://127.0.0.1:8080), which anything that is not a user's connection is handed to, so the port answers a stranger as a web server would. It must be a loopback or private address. The node has no tls transport with one to take it from, so give `decoy`.");
	let text = decoy.filter(|decoy| decoy.len() <= 300 && decoy.starts_with("http://") && !decoy.contains(char::is_whitespace)).ok_or_else(refused)?;
	let authority = text["http://".len()..].split('/').next().unwrap_or_default();
	let host = match authority.strip_prefix('[') {Some(bracketed) => bracketed.split(']').next().unwrap_or_default(), None => authority.split(':').next().unwrap_or_default()};
	let local = match host.parse::<IpAddr>() {Ok(ip) => ip.is_loopback() || PRIVATE.iter().any(|net| net.parse::<IpNet>().is_ok_and(|net| net.contains(&ip))), Err(_) => host == "localhost"};
	if local {Ok(text)} else {Err(refused())}
}

/// The host each Xray inbound the panel made names in its links, by tag.
pub fn inbound_hosts(db: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
	let mut statement = db.prepare("select tag, host from xray_inbounds")?;
	let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect();
	rows
}

/// The address without its port, with the brackets of an IPv6 address taken off.
fn bare_host(address: &str) -> &str {
	match address.strip_prefix('[') {Some(bracketed) => bracketed.split(']').next().unwrap_or_default(), None => address.rsplit_once(':').map_or(address, |(host, _)| host)}
}

/// Every address and host name a profile names in the candidates and endpoints of its transports, without ports. Read before the relays are carried in, so relays do not count.
pub fn addresses(profile: &Value) -> Vec<String> {
	let mut found = Vec::new();
	for transport in profile["transports"].as_array().into_iter().flatten() {
		for candidate in transport["candidates"].as_array().into_iter().flatten() {
			found.extend([candidate.as_str(), candidate["address"].as_str(), candidate["sni"].as_str(), candidate["host"].as_str()].into_iter().flatten().map(|text| bare_host(text).to_string()));
		}
		found.extend(transport["endpoints"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|text| bare_host(text).to_string()));
	}
	found
}

/// Where the Xray inbounds answer, for the rating of the profiles: every profile when one listens on every address, otherwise the listen IPs and the host names the inbounds' links carry. `resolved` holds what the profiles' names looked up to. A name with no answer counts as shared, since an unknown address is treated as shared.
#[derive(Default)]
pub struct Exposure {all: bool, ips: Vec<IpAddr>, names: Vec<String>, resolved: HashMap<String, Vec<IpAddr>>}

impl Exposure {
	/// Whether a profile that names these addresses shares one with an Xray inbound.
	pub fn shares(&self, addresses: &[String]) -> bool {
		self.all || !self.ips.is_empty() && addresses.iter().any(|address| {
			let host = bare_host(address).to_ascii_lowercase();
			match host.parse::<IpAddr>() {
				Ok(ip) => self.ips.contains(&ip),
				Err(_) => self.names.contains(&host) || self.resolved.get(&host).is_none_or(|found| found.is_empty() || found.iter().any(|ip| self.ips.contains(ip)))
			}
		})
	}
}

/// The exposure of a document. `hosts` are the inbounds' own host names by tag, and `node_host` stands in for one that is not set. Every name in `names` is looked up at once, and each lookup waits at most two seconds.
pub async fn exposure(document: &Value, hosts: &[(String, String)], node_host: &str, names: Vec<String>) -> Exposure {
	let mut exposure = Exposure::default();
	for inbound in document["xray"]["inbounds"].as_array().into_iter().flatten() {
		match bare_host(inbound["listen"].as_str().unwrap_or_default()).parse::<IpAddr>() {
			Ok(ip) if !ip.is_unspecified() => exposure.ips.push(ip),
			_ => exposure.all = true,
		}
		let tag = inbound["tag"].as_str().unwrap_or_default();
		let host = hosts.iter().find(|(held, host)| held == tag && !host.is_empty()).map_or(node_host, |(_, host)| host.as_str()).to_ascii_lowercase();
		if let Ok(ip) = host.parse::<IpAddr>() {exposure.ips.push(ip)} else if !host.is_empty() {exposure.names.push(host)}
	}
	let mut lookups = tokio::task::JoinSet::new();
	for name in names.iter().map(|name| bare_host(name).to_ascii_lowercase()).filter(|name| name.parse::<IpAddr>().is_err()).collect::<BTreeSet<_>>() {
		lookups.spawn(async move {
			let found = tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host((name.clone(), 0))).await;
			(name, found.ok().and_then(Result::ok).map(|found| found.map(|address| address.ip()).collect::<Vec<_>>()))
		});
	}
	while let Some(joined) = lookups.join_next().await {
		if let Ok((name, Some(found))) = joined {exposure.resolved.insert(name, found);}
	}
	exposure
}

/// Adds an inbound with a credential for every user the node carries, and applies the config on the node. A profile that shares an address with the inbound is capped at Detectable in the stored profiles, which publishing derives the same way.
pub async fn create(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<InboundIn>) -> Result<Response, Failure> {
	if !name_ok(&input.tag, false) {return Err(Failure::bad("tag is 1 to 64 characters of a-z, 0-9, dash and underscore, starting with a letter or digit."))}
	if !PROTOCOLS.contains(&input.protocol.as_str()) {return Err(Failure::bad("protocol is vless, trojan or shadowsocks."))}
	let (listen, tls, host) = checked(&input.protocol, input.port, input.listen.as_deref(), &input.cert, &input.key, input.host)?;
	if app.keys.is_none() {return Err(Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))}
	if !addon(&app).await.0 {return Err(Failure::new(StatusCode::CONFLICT, "addon_missing", "The Xray add-on is not installed on the node. Run sudo bash veilway.sh addon xray install on the server."))}
	let _turn = app.node_lock.lock().await;
	let (revision, _, mut document) = nodecfg::running(&app).await?;
	let mut inbounds = document["xray"]["inbounds"].as_array().cloned().unwrap_or_default();
	if inbounds.len() >= 16 {return Err(Failure::conflict("The node takes at most 16 Xray inbounds."))}
	if inbounds.iter().any(|inbound| inbound["tag"] == input.tag.as_str()) {return Err(Failure::conflict("An Xray inbound has this tag."))}
	let mut inbound = json!({"tag": input.tag, "protocol": input.protocol, "listen": listen, "clients": []});
	if let Some(tls) = tls {inbound["tls"] = tls;}
	let server_key = (input.protocol == "shadowsocks").then(key32);
	if let Some(key) = &server_key {inbound["server_key"] = json!(key);}
	else {
		inbound["decoy"] = json!(decoy_ok(input.decoy.clone().or_else(|| node_decoy(&document)))?);
	}
	inbounds.push(inbound);
	document["xray"] = json!({"inbounds": inbounds});
	let sealed = server_key.as_ref().and_then(|key| app.keys.as_ref().map(|keys| keys.seal_secret(&[0; 16], &server_label(&input.tag), key.as_bytes())));
	let mut hosts = app.db.call(|db| inbound_hosts(db)).await??;
	hosts.push((input.tag.clone(), host.clone()));
	let templates = nodecfg::rated(&app.settings(), &document, &[], None, &hosts, true).await;
	let shared: Vec<Value> = templates.iter().filter(|template| template["profile"]["rating_cap"] == "detectable").map(|template| template["profile"]["id"].clone()).collect();
	let derived: Vec<Value> = templates.iter().map(|template| template["profile"]["id"].clone()).collect();
	let (tag, protocol, cache) = (input.tag.clone(), input.protocol.clone(), app.settings.clone());
	// A profile no inbound derives has no known address, so it is capped as well.
	let touched = app.db.call(move |db| -> Result<Vec<(Value, Value)>, String> {
		let tx = db.transaction().map_err(|error| error.to_string())?;
		tx.execute("delete from xray_inbounds where tag = ?", [&tag]).map_err(|error| error.to_string())?;
		tx.execute("insert into xray_inbounds (tag, protocol, host, created, server_key) values (?, ?, ?, ?, ?)", params![tag, protocol, host, now(), sealed]).map_err(|error| error.to_string())?;
		let mut touched = Vec::new();
		let stored = store_settings(&tx, &cache, |settings| for profile in settings.profiles.iter_mut().filter(|profile| profile["type"] == "veilway" && profile["rating_cap"] != "unsafe" && (shared.contains(&profile["id"]) || !derived.contains(&profile["id"]))) {
			touched.push((profile["id"].clone(), profile["rating_cap"].clone()));
			profile["rating_cap"] = json!("detectable");
		})?;
		tx.commit().map_err(|error| error.to_string())?;
		publish_settings(&cache, stored);
		Ok(touched)
	}).await?.map_err(Failure::internal)?;
	let capped: Vec<String> = touched.iter().filter_map(|(id, _)| id.as_str().map(str::to_string)).collect();
	let detail = if capped.is_empty() {format!("{} on port {}, no profile shares its address", input.protocol, input.port)} else {format!("{} on port {}, profiles capped at detectable: {}", input.protocol, input.port, capped.join(", "))};
	if let Err(error) = nodecfg::apply(&app, &ctx, document, &revision, &format!("xray:{}", input.tag)).await {
		let (tag, cache) = (input.tag.clone(), app.settings.clone());
		let undone = app.db.call(move |db| -> Result<(), String> {
			let tx = db.transaction().map_err(|error| error.to_string())?;
			tx.execute("delete from xray_inbounds where tag = ?", [&tag]).map_err(|error| error.to_string())?;
			let stored = store_settings(&tx, &cache, |settings| for (id, cap) in touched {
				let Some(object) = settings.profiles.iter_mut().find(|profile| profile["id"] == id).and_then(Value::as_object_mut) else {continue};
				if cap.is_null() {object.remove("rating_cap");} else {object.insert("rating_cap".into(), cap);}
			})?;
			tx.commit().map_err(|error| error.to_string())?;
			publish_settings(&cache, stored);
			Ok(())
		}).await.map_err(|error| error.to_string()).and_then(|result| result);
		if let Err(failed) = undone {tracing::error!("a refused Xray inbound could not be taken back: {failed}")}
		return Err(error)
	}
	app.db.audit(&ctx.actor, &ctx.source, "xray.create", &input.tag, &detail).await;
	ok(&Done {ok: true})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundEdit {
	pub port: u16,
	/// The address Xray listens on. 0.0.0.0 when left out.
	pub listen: Option<String>,
	/// As on create: needed for vless and trojan, refused for shadowsocks.
	pub cert: Option<String>, pub key: Option<String>,
	/// The host the links name. Empty or left out for the node's first public address.
	pub host: Option<String>,
	/// For vless and trojan. The inbound's own decoy stays when left out.
	pub decoy: Option<String>,
	/// For shadowsocks: a new server key. Every share link of the inbound holds the old one, so every user needs a new link.
	#[serde(default)] pub new_server_key: bool,
}

/// Changes where an inbound the panel made listens, its certificate files, its decoy, its host and, for Shadowsocks, its server key. Every user keeps their credential, which `node::fill` puts back in from the panel's database. Share links change when the port, the host or the server key do.
pub async fn edit(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(tag): Path<String>, Body(input): Body<InboundEdit>) -> Result<Response, Failure> {
	let lookup = tag.clone();
	let (protocol, old_host) = app.db.call(move |db| -> rusqlite::Result<Option<(String, String)>> {db.query_row("select protocol, host from xray_inbounds where tag = ?", [&lookup], |row| Ok((row.get(0)?, row.get(1)?))).optional()}).await??.ok_or_else(|| Failure::missing("Xray inbound the panel made"))?;
	let (listen, tls, host) = checked(&protocol, input.port, input.listen.as_deref(), &input.cert, &input.key, input.host)?;
	if input.new_server_key && protocol != "shadowsocks" {return Err(Failure::bad("Only a shadowsocks inbound has a server key."))}
	if input.new_server_key && app.keys.is_none() {return Err(Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))}
	if input.new_server_key {reauthed(&app, &ctx).await?}
	let _turn = app.node_lock.lock().await;
	let (revision, _, mut document) = nodecfg::running(&app).await?;
	let mut inbounds = document["xray"]["inbounds"].as_array().cloned().unwrap_or_default();
	let node_default = node_decoy(&document);
	let Some(inbound) = inbounds.iter_mut().find(|inbound| inbound["tag"] == tag.as_str()) else {return Err(Failure::missing("Xray inbound"))};
	let before = inbound["listen"].as_str().unwrap_or_default().to_string();
	inbound["listen"] = json!(listen);
	let object = inbound.as_object_mut().ok_or_else(|| Failure::internal("an Xray inbound is not an object"))?;
	let (old_decoy, old_tls) = (object.get("decoy").and_then(Value::as_str).unwrap_or_default().to_string(), object.get("tls").cloned());
	match tls {Some(tls) => {object.insert("tls".into(), tls);} None => {object.remove("tls");}}
	if protocol != "shadowsocks" {
		let decoy = decoy_ok(input.decoy.clone().or_else(|| object.get("decoy").and_then(Value::as_str).map(str::to_string)).or(node_default))?;
		object.insert("decoy".into(), json!(decoy));
	}
	let new_key = input.new_server_key.then(key32);
	if let Some(key) = &new_key {object.insert("server_key".into(), json!(key));}
	let mut changed = vec![format!("listen {before} -> {listen}")];
	if object.get("tls").cloned() != old_tls {changed.push("cert/key changed".into())}
	let decoy = object.get("decoy").and_then(Value::as_str).unwrap_or_default().to_string();
	if decoy != old_decoy {changed.push(format!("decoy {old_decoy:?} -> {decoy:?}"))}
	if host != old_host {changed.push(format!("host {old_host:?} -> {host:?}"))}
	if new_key.is_some() {changed.push("new server key".into())}
	document["xray"]["inbounds"] = Value::Array(inbounds);
	let sealed = new_key.as_ref().and_then(|key| app.keys.as_ref().map(|keys| keys.seal_secret(&[0; 16], &server_label(&tag), key.as_bytes())));
	nodecfg::apply(&app, &ctx, document, &revision, &format!("xray:{tag}")).await?;
	app.db.call({
		let tag = tag.clone();
		move |db| -> rusqlite::Result<()> {
			db.execute("update xray_inbounds set host = ? where tag = ?", params![host, tag])?;
			if let Some(sealed) = &sealed {db.execute("update xray_inbounds set server_key = ? where tag = ?", params![sealed, tag])?;}
			Ok(())
		}
	}).await??;
	app.db.audit(&ctx.actor, &ctx.source, "xray.edit", &tag, &changed.join(", ")).await;
	ok(&Done {ok: true})
}

/// Removes the inbound from the node's config and the panel's credentials for it.
pub async fn remove(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(tag): Path<String>) -> Result<Response, Failure> {
	let _turn = app.node_lock.lock().await;
	let (revision, _, mut document) = nodecfg::running(&app).await?;
	let mut inbounds = document["xray"]["inbounds"].as_array().cloned().unwrap_or_default();
	let before = inbounds.len();
	inbounds.retain(|inbound| inbound["tag"] != tag.as_str());
	let found = inbounds.len() != before;
	if found {
		if inbounds.is_empty() {document.as_object_mut().map(|document| document.remove("xray"));} else {document["xray"]["inbounds"] = Value::Array(inbounds);}
		nodecfg::apply(&app, &ctx, document, &revision, &format!("xray:{tag}")).await?;
	}
	let lookup = tag.clone();
	if app.db.call(move |db| db.execute("delete from xray_inbounds where tag = ?", [&lookup])).await?? == 0 && !found {return Err(Failure::missing("Xray inbound"))}
	app.db.audit(&ctx.actor, &ctx.source, "xray.delete", &tag, "").await;
	ok(&Done {ok: true})
}

#[derive(Serialize, JsonSchema)]
pub struct XrayLink {
	pub tag: String, pub protocol: String,
	/// A secret, like the subscription link.
	pub link: String,
	/// The same link as an SVG QR code.
	pub qr_svg: String,
}

#[derive(Serialize, JsonSchema)]
pub struct XrayLinks {pub links: Vec<XrayLink>}

/// The user's share link for each Xray inbound the panel made. A user with no device is not on the node, so they have none.
pub async fn links(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let keys = app.keys.as_ref().ok_or_else(|| Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))?;
	let (user, held) = app.db.call(move |db| -> rusqlite::Result<_> {
		let user = UserRow::load(db, id)?;
		let mut statement = db.prepare("select i.tag, i.protocol, i.host, c.secret, i.server_key from xray_clients c join xray_inbounds i on i.tag = c.tag where c.user_id = ? order by i.tag")?;
		let held: Vec<(String, String, String, Vec<u8>, Option<Vec<u8>>)> = statement.query_map([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?.collect::<Result<_, _>>()?;
		Ok((user, held))
	}).await??;
	let (_, _, document) = nodecfg::running(&app).await?;
	let provider = app.settings().provider_name;
	let mut links = Vec::new();
	for (tag, protocol, own, sealed, server) in held {
		let Some(port) = document["xray"]["inbounds"].as_array().into_iter().flatten().find(|inbound| inbound["tag"] == tag.as_str()).and_then(|inbound| inbound["listen"].as_str()?.rsplit_once(':').map(|(_, port)| port.to_string())) else {continue};
		let secret = keys.open_secret(&user.record_id, &format!("xray:{tag}"), &sealed).and_then(|plain| String::from_utf8(plain).ok()).ok_or_else(|| Failure::internal("an Xray secret does not open"))?;
		let host = host_of(&app, &document, &own).await;
		if host.is_empty() {return Err(Failure::conflict("No host to put in links: set the node's public_addresses, the panel's node host or the inbound's host."))}
		let address = if host.contains(':') {format!("[{host}]:{port}")} else {format!("{host}:{port}")};
		let escape = |text: &str| -> String {text.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {(byte as char).to_string()} else {format!("%{byte:02X}")}).collect()};
		let name = escape(&format!("{provider} {tag}"));
		let link = match protocol.as_str() {
			"vless" => format!("vless://{secret}@{address}?encryption=none&security=tls&sni={host}&type=tcp#{name}"),
			"trojan" => format!("trojan://{secret}@{address}?security=tls&sni={host}&type=tcp#{name}"),
			// The userinfo of a 2022 cipher is the method and the password in the clear, and the password of a multi-user server is its key and the user's, each escaped.
			_ => {
				let server = server.and_then(|sealed| keys.open_secret(&[0; 16], &server_label(&tag), &sealed)).and_then(|plain| String::from_utf8(plain).ok()).ok_or_else(|| Failure::internal("the server key of a Shadowsocks inbound does not open"))?;
				format!("ss://2022-blake3-aes-256-gcm:{}:{}@{address}#{name}", escape(&server), escape(&secret))
			}
		};
		let qr_svg = qrcode::QrCode::new(link.as_bytes()).map_err(Failure::internal)?.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).build();
		links.push(XrayLink {tag, protocol, link, qr_svg});
	}
	app.db.audit(&ctx.actor, &ctx.source, "xray.links.show", &format!("user:{id}"), "").await;
	ok(&XrayLinks {links})
}

#[derive(Serialize, JsonSchema)]
pub struct Rotated {pub ok: bool, pub node: NodeState}

/// Gives the user new credentials in every Xray inbound, which ends the old ones as the node takes the change. A share link the user holds stops working. Subscription links do not change.
pub async fn rotate(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let (actor, source) = (ctx.actor.clone(), ctx.source.clone());
	app.db.call(move |db| -> rusqlite::Result<()> {
		UserRow::load(db, id)?;
		db.execute("delete from xray_clients where user_id = ?", [id])?;
		audit(db, &actor, &source, "xray.rotate", &format!("user:{id}"), "");
		Ok(())
	}).await??;
	ok(&Rotated {ok: true, node: users::push(&app).await})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn document(listen: &str) -> Value {json!({"xray": {"inbounds": [{"tag": "Xray", "protocol": "vless", "listen": listen}]}})}

	fn names(list: &[&str]) -> Vec<String> {list.iter().map(|name| name.to_string()).collect()}

	#[tokio::test]
	async fn an_inbound_on_every_address_caps_every_profile() {
		for listen in ["0.0.0.0:443", "[::]:443", ""] {
			let exposure = exposure(&document(listen), &[], "192.0.2.10", Vec::new()).await;
			assert!(exposure.shares(&names(&["198.51.100.9:443"])), "{listen}");
		}
	}

	#[tokio::test]
	async fn no_inbound_caps_nothing() {
		assert!(!Exposure::default().shares(&names(&["localhost:443"])));
	}

	#[tokio::test]
	async fn a_separate_address_and_host_leave_other_profiles_uncapped() {
		let hosts = vec![("Xray".to_string(), "xray.example.net".to_string())];
		let exposure = exposure(&document("192.0.2.20:443"), &hosts, "192.0.2.10", names(&["192.0.2.10", "localhost"])).await;
		assert!(!exposure.shares(&names(&["192.0.2.10:443"])));
		assert!(!exposure.shares(&names(&["localhost:443"])));
	}

	#[tokio::test]
	async fn the_same_address_or_host_name_caps() {
		let hosts = vec![("Xray".to_string(), "xray.example.net".to_string())];
		let exposure = exposure(&document("192.0.2.20:443"), &hosts, "192.0.2.10", names(&["192.0.2.20", "XRAY.example.net"])).await;
		assert!(exposure.shares(&names(&["192.0.2.20:8443"])));
		assert!(exposure.shares(&names(&["xray.example.net:443"])));
		assert!(!exposure.shares(&names(&["[2001:db8::20]:443"])));
	}

	#[tokio::test]
	async fn a_name_that_resolves_to_the_xray_address_caps() {
		let exposure = exposure(&document("127.0.0.1:443"), &[], "192.0.2.10", names(&["localhost"])).await;
		assert!(exposure.shares(&names(&["localhost:443"])));
	}

	#[tokio::test]
	async fn a_name_that_does_not_resolve_caps() {
		let exposure = exposure(&document("192.0.2.20:443"), &[], "192.0.2.10", names(&["no-such-name.invalid"])).await;
		assert!(exposure.shares(&names(&["no-such-name.invalid:443"])));
	}
}
