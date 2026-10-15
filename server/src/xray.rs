//! The Xray add-on: its inbounds in the node's config, which the panel makes with a credential per user, and the users' share links. The credentials are sealed in the panel's database, which is what the links are made from, since the node only ever shows its marker.
use crate::{admin::Done, app::App, crypto::now, db::audit, http::{ok, Body, Ctx, Failure}, node, nodecfg, subs::UserRow, users::name_ok};
use axum::{extract::{Path, State}, http::StatusCode, response::Response, Extension};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{net::IpAddr, sync::Arc};

const PROTOCOLS: [&str; 3] = ["vless", "trojan", "shadowsocks"];

/// Whether the node has the add-on, and its release. A node that says nothing of add-ons has none.
async fn addon(app: &App) -> (bool, Option<String>) {
	let status = match node::request(&app.cfg.node_socket, "GET", "/v1/status", None, None).await {Ok((200, body)) => serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null), _ => Value::Null};
	let xray = &status["addons"]["xray"];
	(xray["installed"] == true, xray["release"].as_str().map(str::to_string))
}

/// The address links name: the inbound's own, else the node's first public address, else the panel's node host.
fn host_of(app: &App, document: &Value, own: &str) -> String {
	if !own.is_empty() {return own.to_string()}
	document["public_addresses"].get(0).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| app.settings().node_host)
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
	/// Whether the panel made this inbound and holds its credentials, which links need.
	pub managed: bool,
	/// A vless or trojan inbound without certificate files, which the node refuses.
	pub certificate_missing: bool,
	pub cert: Option<String>, pub key: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct XrayOut {pub installed: bool, pub release: Option<String>, pub inbounds: Vec<XrayInboundOut>}

pub async fn get(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let ((installed, release), (_, _, document)) = (addon(&app).await, nodecfg::running(&app).await?);
	let made: Vec<(String, String)> = {
		let db = app.db.lock();
		let mut statement = db.prepare("select tag, host from xray_inbounds")?;
		let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<Result<_, _>>()?;
		rows
	};
	let inbounds = document["xray"]["inbounds"].as_array().into_iter().flatten().map(|inbound| {
		let (tag, listen) = (inbound["tag"].as_str().unwrap_or_default().to_string(), inbound["listen"].as_str().unwrap_or_default().to_string());
		let own = made.iter().find(|(made, _)| *made == tag);
		XrayInboundOut {protocol: inbound["protocol"].as_str().unwrap_or_default().to_string(), port: listen.rsplit_once(':').and_then(|(_, port)| port.parse().ok()).unwrap_or(0), security: if inbound.get("tls").is_some() {"tls"} else {"none"}.into(), clients: inbound["clients"].as_array().map_or(0, Vec::len), host: host_of(&app, &document, own.map_or("", |(_, host)| host.as_str())), managed: own.is_some(), certificate_missing: inbound["protocol"] != "shadowsocks" && inbound.get("tls").is_none(), cert: inbound["tls"]["cert"].as_str().map(str::to_string), key: inbound["tls"]["key"].as_str().map(str::to_string), tag, listen}
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
}

/// Adds an inbound with a credential for every user the node carries, and applies the config on the node.
pub async fn create(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<InboundIn>) -> Result<Response, Failure> {
	if !name_ok(&input.tag, false) {return Err(Failure::bad("tag is 1 to 64 characters of a-z, 0-9, dash and underscore, starting with a letter or digit."))}
	if !PROTOCOLS.contains(&input.protocol.as_str()) {return Err(Failure::bad("protocol is vless, trojan or shadowsocks."))}
	if input.port == 0 {return Err(Failure::bad("port is 1 to 65535."))}
	let listen: IpAddr = input.listen.as_deref().unwrap_or("0.0.0.0").parse().map_err(|_| Failure::bad("listen is an IP address."))?;
	let path_ok = |path: &Option<String>| path.as_ref().is_some_and(|path| path.starts_with('/') && path.len() <= 4096 && !path.contains('\0'));
	let tls = match (input.protocol == "shadowsocks", input.cert.is_some() || input.key.is_some()) {
		(true, true) => return Err(Failure::bad("shadowsocks takes no certificate: it encrypts itself.")),
		(true, false) => None,
		(false, _) if path_ok(&input.cert) && path_ok(&input.key) => Some(json!({"cert": input.cert, "key": input.key})),
		_ => return Err(Failure::bad("vless and trojan need the absolute paths of the certificate and key files on the node.")),
	};
	let host = input.host.unwrap_or_default();
	if host.len() > 253 || !host.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte)) {return Err(Failure::bad("host is a domain name or an IP address."))}
	if app.keys.is_none() {return Err(Failure::new(StatusCode::SERVICE_UNAVAILABLE, "keys_missing", "The key file is missing."))}
	if !addon(&app).await.0 {return Err(Failure::new(StatusCode::CONFLICT, "addon_missing", "The Xray add-on is not installed on the node. Run scripts/veilway.sh addon xray install on the server."))}
	let (revision, _, mut document) = nodecfg::running(&app).await?;
	let mut inbounds = document["xray"]["inbounds"].as_array().cloned().unwrap_or_default();
	if inbounds.len() >= 16 {return Err(Failure::conflict("The node takes at most 16 Xray inbounds."))}
	if inbounds.iter().any(|inbound| inbound["tag"] == input.tag.as_str()) {return Err(Failure::conflict("An Xray inbound has this tag."))}
	let mut inbound = json!({"tag": input.tag, "protocol": input.protocol, "listen": if listen.is_ipv6() {format!("[{listen}]:{}", input.port)} else {format!("{listen}:{}", input.port)}, "clients": []});
	if let Some(tls) = tls {inbound["tls"] = tls;}
	inbounds.push(inbound);
	document["xray"] = json!({"inbounds": inbounds});
	{
		let db = app.db.lock();
		db.execute("delete from xray_inbounds where tag = ?", [&input.tag])?;
		db.execute("insert into xray_inbounds (tag, protocol, host, created) values (?, ?, ?, ?)", params![input.tag, input.protocol, host, now()])?;
	}
	if let Err(error) = nodecfg::apply(&app, &ctx, document, &revision, &format!("xray:{}", input.tag)).await {
		app.db.lock().execute("delete from xray_inbounds where tag = ?", [&input.tag])?;
		return Err(error)
	}
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "xray.create", &input.tag, &format!("{} on port {}", input.protocol, input.port));
	ok(&Done {ok: true})
}

/// Removes the inbound from the node's config and the panel's credentials for it.
pub async fn remove(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(tag): Path<String>) -> Result<Response, Failure> {
	let (revision, _, mut document) = nodecfg::running(&app).await?;
	let mut inbounds = document["xray"]["inbounds"].as_array().cloned().unwrap_or_default();
	let before = inbounds.len();
	inbounds.retain(|inbound| inbound["tag"] != tag.as_str());
	let found = inbounds.len() != before;
	if found {
		if inbounds.is_empty() {document.as_object_mut().map(|document| document.remove("xray"));} else {document["xray"]["inbounds"] = Value::Array(inbounds);}
		nodecfg::apply(&app, &ctx, document, &revision, &format!("xray:{tag}")).await?;
	}
	let db = app.db.lock();
	if db.execute("delete from xray_inbounds where tag = ?", [&tag])? == 0 && !found {return Err(Failure::missing("Xray inbound"))}
	audit(&db, &ctx.actor, &ctx.source, "xray.delete", &tag, "");
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
	let (user, held) = {
		let db = app.db.lock();
		let user = UserRow::load(&db, id)?;
		let mut statement = db.prepare("select i.tag, i.protocol, i.host, c.secret from xray_clients c join xray_inbounds i on i.tag = c.tag where c.user_id = ? order by i.tag")?;
		let held: Vec<(String, String, String, Vec<u8>)> = statement.query_map([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?.collect::<Result<_, _>>()?;
		(user, held)
	};
	let (_, _, document) = nodecfg::running(&app).await?;
	let provider = app.settings().provider_name;
	let mut links = Vec::new();
	for (tag, protocol, own, sealed) in held {
		let Some(port) = document["xray"]["inbounds"].as_array().into_iter().flatten().find(|inbound| inbound["tag"] == tag.as_str()).and_then(|inbound| inbound["listen"].as_str()?.rsplit_once(':').map(|(_, port)| port.to_string())) else {continue};
		let secret = keys.open_secret(&user.record_id, &format!("xray:{tag}"), &sealed).and_then(|plain| String::from_utf8(plain).ok()).ok_or_else(|| Failure::internal("an Xray secret does not open"))?;
		let host = host_of(&app, &document, &own);
		if host.is_empty() {return Err(Failure::conflict("No host to put in links: set the node's public_addresses, the panel's node host or the inbound's host."))}
		let address = if host.contains(':') {format!("[{host}]:{port}")} else {format!("{host}:{port}")};
		let name: String = format!("{provider} {tag}").bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {(byte as char).to_string()} else {format!("%{byte:02X}")}).collect();
		let link = match protocol.as_str() {
			"vless" => format!("vless://{secret}@{address}?encryption=none&security=tls&sni={host}&type=tcp#{name}"),
			"trojan" => format!("trojan://{secret}@{address}?security=tls&sni={host}&type=tcp#{name}"),
			_ => format!("ss://{}@{address}#{name}", URL_SAFE_NO_PAD.encode(format!("chacha20-ietf-poly1305:{secret}"))),
		};
		let qr_svg = qrcode::QrCode::new(link.as_bytes()).map_err(Failure::internal)?.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).build();
		links.push(XrayLink {tag, protocol, link, qr_svg});
	}
	audit(&app.db.lock(), &ctx.actor, &ctx.source, "xray.links.show", &format!("user:{id}"), "");
	ok(&XrayLinks {links})
}
