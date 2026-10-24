//! The node's control API over its unix socket, and the one place the panel's users become the node's `users`.
use crate::{app::{App, Node, LOCAL}, crypto::{self, now}, subs};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::xray::{key32, server_label};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::{collections::{HashMap, HashSet}, sync::{atomic::Ordering, Arc}, time::{Duration, Instant}};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::net::UnixStream;

/// One request to a node. The answer is the status and the body. Node 1 is reached on the panel's own control socket. Any other node is reached through node 1, on the relay route of the link the node is bound to, which also answers for the link: a failure of the relay is an error here, never an answer of the node.
pub async fn request(app: &App, node: Node, method: &str, path: &str, if_match: Option<&str>, body: Option<&Value>) -> Result<(u16, Vec<u8>), String> {request_within(app, node, method, path, if_match, body, Duration::from_secs(20)).await}

/// What the relay route of node 1 says when it could not carry a request, by its error code. Only an answer that carries the header `veilway-relay: node1` is node 1's: the same code in any other answer is the remote node's own.
const RELAY_ERRORS: [(&str, &str); 9] = [("no_such_link", "node 1 has no such link"), ("not_managed", "the link is not one that node 1 manages"), ("not_allowed_through_link", "the call is not on the list a managed node answers"), ("link_down", "the link is down"), ("busy", "the link is busy"), ("peer_refused", "the node does not serve management"), ("peer_silent", "the node did not answer through the link"), ("answer_too_large", "the node's answer was too large"), ("bad_answer", "the node's answer was not understood")];
/// The refusal for a remote node whose tag node 1 now gives to another link: nothing is sent through it, so no config is pushed to a node the panel did not add.
pub const LINK_REUSED: &str = "the link with this name is not the one this server was added with";

/// Like `request`, for a call that waits on a third party (the fetch of another provider's subscription).
pub async fn request_within(app: &App, node: Node, method: &str, path: &str, if_match: Option<&str>, body: Option<&Value>, limit: Duration) -> Result<(u16, Vec<u8>), String> {
	let relayed;
	let path = if node == LOCAL {path} else {
		let found = app.db.call(move |db| db.query_row("select link_tag, link_id from nodes where id = ?", [node.0], |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?))).optional()).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
		let Some((Some(tag), link_id)) = found else {return Err(format!("node {} cannot be reached: {}", node.0, if found.is_none() {"the panel has no such node"} else {"it is bound to no link"}))};
		let Some(links) = crate::nodes::link_states(app).await else {return Err(format!("node {} cannot be reached: node 1 does not answer for its links", node.0))};
		if links.get(&tag).map(|(_, id)| id) != link_id.as_ref() {return Err(LINK_REUSED.into())}
		relayed = format!("/v1/links/{tag}/api{path}");
		&relayed
	};
	let (status, via_node_1, bytes) = exchange(app, method, path, if_match, body, limit).await?;
	if node != LOCAL && status >= 400 && via_node_1 {
		let code = serde_json::from_slice::<Value>(&bytes).ok().and_then(|answer| answer["error"]["code"].as_str().map(str::to_string)).unwrap_or_default();
		if let Some((_, said)) = RELAY_ERRORS.iter().find(|(known, _)| *known == code) {return Err(format!("node {}: {said} ({code})", node.0))}
	}
	Ok((status, bytes))
}

/// One request on the panel's own control socket, within `limit`: the status, whether node 1 marked the answer as its own relay failure, and the body.
pub(crate) async fn exchange(app: &App, method: &str, path: &str, if_match: Option<&str>, body: Option<&Value>, limit: Duration) -> Result<(u16, bool, Vec<u8>), String> {
	let attempt = async {
		let stream = UnixStream::connect(&app.cfg.node_socket).await.map_err(|error| format!("the node's socket: {error}"))?;
		let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|error| error.to_string())?;
		tokio::spawn(connection);
		let mut builder = Request::builder().method(method).uri(path).header("host", "node");
		if let Some(revision) = if_match {builder = builder.header("if-match", format!("\"{revision}\""));}
		if body.is_some() {builder = builder.header("content-type", "application/json");}
		let request = builder.body(Full::new(Bytes::from(body.map(|body| serde_json::to_vec(body).unwrap_or_default()).unwrap_or_default()))).map_err(|error| error.to_string())?;
		let response = sender.send_request(request).await.map_err(|error| error.to_string())?;
		let status = response.status().as_u16();
		let via_node_1 = response.headers().get("veilway-relay").is_some_and(|value| value == "node1");
		let bytes = response.into_body().collect().await.map_err(|error| error.to_string())?.to_bytes().to_vec();
		Ok::<_, String>((status, via_node_1, bytes))
	};
	tokio::time::timeout(limit, attempt).await.map_err(|_| "the node did not answer in time".to_string())?
}

/// The node's users by name, with their usage, for the pages and for a document's `usage`. Empty when the node cannot be reached.
pub async fn usage(app: &App, node: Node) -> HashMap<String, Value> {
	let Ok((200, body)) = request(app, node, "GET", "/v1/users", None, None).await else {return HashMap::new()};
	serde_json::from_slice::<Value>(&body).ok().and_then(|value| value.get("users").cloned()).and_then(|users| users.as_array().cloned()).unwrap_or_default().into_iter().filter_map(|user| Some((user.get("name")?.as_str()?.to_string(), user))).collect()
}

/// Whether a stored default exit still holds in this document: the node has the exit and the user may use it.
fn default_holds(document: &Value, exits: &str, exit: &str) -> bool {
	let exits: Value = serde_json::from_str(exits).unwrap_or(json!("all"));
	document["exits"].as_array().is_some_and(|list| list.iter().any(|found| found["tag"] == exit)) && (exits == json!("all") || exits.as_array().is_some_and(|tags| tags.iter().any(|tag| tag == exit)))
}

/// After the node took a document, forgets the default exits it left out, so the panel shows what the node runs.
pub(crate) async fn clear_defaults(app: &App, document: &Value) {
	let document = document.clone();
	let result = app.db.call(move |db| -> rusqlite::Result<()> {
		let stale: Vec<(i64, String, String)> = db.prepare("select id, name, exits, default_exit from users where default_exit is not null")?.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?.collect::<Result<Vec<_>, _>>()?.into_iter().filter(|(_, _, exits, exit)| !default_holds(&document, exits, exit)).map(|(id, name, _, exit)| (id, name, exit)).collect();
		for (id, name, exit) in stale {
			if let Err(error) = db.execute("update users set default_exit = null where id = ?", [id]) {tracing::error!("the default exit of {name} could not be cleared: {error}"); continue}
			tracing::info!("user {name} no longer has default exit {exit}: the node has no such exit or the user may not use it");
		}
		Ok(())
	}).await;
	if let Err(error) = result.map_err(|error| error.to_string()).and_then(|done| done.map_err(|error| error.to_string())) {tracing::error!("the default exits could not be checked: {error}")}
}

/// Puts the panel's users into the document's `users`, and the panel's credentials into the `clients` of the Xray inbounds it made, making one for a user who has none yet. A user with no device and no proxy password is left out, since the node needs one of them. An Xray inbound the panel did not make keeps its clients, less those whose user is gone.
pub(crate) async fn fill(app: &Arc<App>, node: Node, document: &mut Value) -> Result<(), String> {
	let (handle, app, mut copy, dirty) = (app.db.clone(), app.clone(), document.clone(), app.node(node).dirty.clone());
	*document = handle.call(move |db| -> Result<Value, String> {
		let (document, keys) = (&mut copy, app.keys.as_ref().ok_or("the key file is missing, so no secret can be opened")?);
		// An inbound a node link uses carries no users' devices (the node refuses a config that gives it one), so no device gets an address there.
		let linked: Vec<Value> = document["links"].as_array().into_iter().flatten().filter_map(|link| link.get("inbound").cloned()).collect();
		let (pool, uid): (String, Vec<u8>) = db.query_row("select pool_v4, uid from nodes where id = ?", [node.0], |row| Ok((row.get(0)?, row.get(1)?))).map_err(|error| error.to_string())?;
		// A remote node knows a user and a device by opaque names and holds secrets derived for it alone. Node 1 keeps the names and the stored secrets.
		let remote = node != LOCAL;
		let declared: Vec<Value> = document["groups"].as_array().cloned().unwrap_or_default();
		let inbounds: Vec<Value> = document["inbounds"].as_array().into_iter().flatten().filter(|inbound| !linked.contains(&inbound["tag"])).cloned().collect();
		let mut taken: HashSet<String> = db.prepare("select address from device_addresses where node_id = ?").and_then(|mut statement| statement.query_map([node.0], |row| row.get(0))?.collect()).map_err(|error| error.to_string())?;
		taken.extend(document["links"].as_array().into_iter().flatten().flat_map(|link| ["dialler", "listener"].map(|side| link["addresses"][side].clone())).flat_map(|list| list.as_array().cloned().unwrap_or_default()).filter_map(|address| Some(address.as_str()?.split('/').next()?.to_string())));
		subs::expire_pending(db, now()).map_err(|error| error.to_string())?;
		let mut statement = db.prepare("select id, name, enabled, groups, exits, quota_bytes, quota_period, expires_at, record_id, default_exit, nodes, cut_until from users order by id").map_err(|error| error.to_string())?;
		let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Option<String>>(6)?, row.get::<_, Option<i64>>(7)?, row.get::<_, Vec<u8>>(8)?, row.get::<_, Option<String>>(9)?, row.get::<_, String>(10)?, row.get::<_, Option<i64>>(11)?))).map_err(|error| error.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
		let (mut out, mut present) = (Vec::new(), Vec::new());
		let at = now();
		for (id, name, enabled, groups, exits, quota, period, expires, record, exit, allowed, cut) in rows {
			if !subs::allowed(&allowed, node) {continue}
			let record: [u8; 16] = record.try_into().map_err(|_| "a user record id is not 16 bytes")?;
			let mut devices = db.prepare("select devices.id, devices.public_key, device_addresses.address, devices.transport_secret from devices join device_addresses on device_addresses.device_id = devices.id and device_addresses.node_id = ? where devices.user_id = ? and devices.state = 'enrolled' order by devices.id").map_err(|error| error.to_string())?;
			let devices = devices.query_map([node.0, id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?))).map_err(|error| error.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
			let proxy: Option<Vec<u8>> = db.query_row("select proxy_password from users where id = ?", [id], |row| row.get(0)).map_err(|error| error.to_string())?;
			if devices.is_empty() && proxy.is_none() {continue}
			let devices: Vec<Value> = devices.into_iter().map(|(device, public_key, address, sealed)| {
				let secret = keys.open_secret(&record, &format!("transport_secret:{public_key}"), &sealed).ok_or("a transport secret does not open")?;
				let secret = if remote {crypto::node_secret(crypto::NODE_TRANSPORT_SALT, &uid, &secret).to_vec()} else {secret};
				Ok::<_, String>(json!({"name": if remote {keys.node_device(&uid, device)} else {format!("d{device}")}, "public_key": public_key, "transport_secrets": [App::standard(&secret)], "addresses": subs::node_addresses(&pool, &inbounds, &address, &taken)}))
			}).collect::<Result<_, _>>()?;
			let given = if remote {keys.node_user(&uid, &record)} else {name.clone()};
			let mut exits_given = serde_json::from_str::<Value>(&exits).unwrap_or(json!("all"));
			// The tags of exits are node 1's. A remote node is given the ones it has.
			if remote {if let Some(tags) = exits_given.as_array_mut() {tags.retain(|tag| document["exits"].as_array().is_some_and(|list| list.iter().any(|found| found["tag"] == *tag)))}}
			let mut groups = serde_json::from_str::<Value>(&groups).unwrap_or(json!([]));
			// A remote node is given only the groups its config declares: any other name makes its config refuse the whole document.
			if remote {groups = json!(groups.as_array().into_iter().flatten().filter(|group| declared.contains(group)).collect::<Vec<_>>())}
			let mut user = json!({"name": given, "enabled": enabled, "groups": groups, "devices": devices, "exits": exits_given});
			// A default the document no longer allows is left out here, and cleared once the node takes the document.
			if let Some(exit) = exit.filter(|exit| default_holds(document, &exits, exit)) {user["exit"] = json!(exit);}
			// A user over the quota of all nodes together is cut by setting this node's limit to what it counted, which it enforces as its own quota.
			let quota = match (quota, cut.is_some_and(|until| until > at)) {
				(Some(_), true) => Some(db.query_row("select max(1, used_bytes) from node_usage where node_id = ? and user_id = ?", params![node.0, id], |row| row.get::<_, i64>(0)).optional().map_err(|error| error.to_string())?.unwrap_or(1)),
				(quota, _) => quota,
			};
			if let Some(quota) = quota {user["quota_bytes"] = json!(quota);}
			if let (Some(_), Some(period)) = (quota, period) {user["quota_period"] = json!(period);}
			if let Some(expires) = expires {user["expires_at"] = json!(OffsetDateTime::from_unix_timestamp(expires).map_err(|error| error.to_string())?.format(&Rfc3339).map_err(|error| error.to_string())?);}
			if let Some(sealed) = proxy {
				let password = keys.open_secret(&record, "proxy_password", &sealed).ok_or("a proxy password does not open")?;
				user["proxy_password"] = json!(if remote {URL_SAFE_NO_PAD.encode(crypto::node_secret(crypto::NODE_PROXY_SALT, &uid, &password))} else {String::from_utf8(password).map_err(|error| error.to_string())?});
			}
			out.push(user);
			present.push((id, given, record));
		}
		document["users"] = Value::Array(out);
		// The Xray inbounds the panel made are node 1's.
		let made: HashMap<String, String> = if remote {HashMap::new()} else {db.prepare("select tag, protocol from xray_inbounds").and_then(|mut statement| statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect()).map_err(|error| error.to_string())?};
		for inbound in document.get_mut("xray").and_then(|xray| xray.get_mut("inbounds")).and_then(Value::as_array_mut).into_iter().flatten() {
			let tag = inbound["tag"].as_str().unwrap_or_default().to_string();
			let Some(protocol) = made.get(&tag) else {
				if let Some(clients) = inbound["clients"].as_array_mut() {clients.retain(|client| present.iter().any(|(_, name, _)| client["user"] == name.as_str()));}
				continue
			};
			if protocol == "shadowsocks" {
				let sealed: Option<Vec<u8>> = db.query_row("select server_key from xray_inbounds where tag = ?", [&tag], |row| row.get(0)).optional().map_err(|error| error.to_string())?.flatten();
				// A key the document already carries is the one being applied, and the panel's copy follows once the node accepts it.
				let marked = inbound["server_key"].as_str().is_none_or(|sent| sent.starts_with("<redacted"));
				if let Some(key) = sealed.and_then(|sealed| keys.open_secret(&[0; 16], &server_label(&tag), &sealed)).filter(|_| marked) {inbound["server_key"] = json!(String::from_utf8(key).map_err(|error| error.to_string())?);}
			}
			let clients = present.iter().map(|(id, name, record)| {
				let sealed: Option<Vec<u8>> = db.query_row("select secret from xray_clients where tag = ? and user_id = ?", params![tag, id], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
				let secret = match sealed {
					Some(sealed) => String::from_utf8(keys.open_secret(record, &format!("xray:{tag}"), &sealed).ok_or("an Xray secret does not open")?).map_err(|error| error.to_string())?,
					None => {
						let bytes = crypto::random::<16>();
						let secret = if protocol == "vless" {
							let hex: String = bytes.iter().enumerate().map(|(at, byte)| format!("{:02x}", match at {6 => byte & 0x0f | 0x40, 8 => byte & 0x3f | 0x80, _ => *byte})).collect();
							format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
						} else if protocol == "shadowsocks" {key32()} else {URL_SAFE_NO_PAD.encode([bytes.as_slice(), &crypto::random::<8>()].concat())};
						db.execute("insert into xray_clients (tag, user_id, secret) values (?, ?, ?)", params![tag, id, keys.seal_secret(record, &format!("xray:{tag}"), secret.as_bytes())]).map_err(|error| error.to_string())?;
						dirty.store(true, Ordering::Relaxed);
						secret
					}
				};
				Ok(json!({"user": name, "secret": secret}))
			}).collect::<Result<Vec<_>, String>>()?;
			inbound["clients"] = Value::Array(clients);
		}
		Ok(copy)
	}).await.map_err(|error| error.to_string())??;
	Ok(())
}

/// Sends the usage resets a remote node has not had yet. A user the node no longer has counts as reset, but only when its user list confirms it. Stops at the first failure and leaves the rest for the next sync.
async fn flush_resets(app: &Arc<App>, node: Node) -> Result<(), String> {
	let keys = app.keys.as_ref().ok_or("the key file is missing")?;
	let (uid, rows) = app.db.call(move |db| -> rusqlite::Result<(Vec<u8>, Vec<(i64, bool, Vec<u8>)>)> {
		let uid = db.query_row("select uid from nodes where id = ?", [node.0], |row| row.get(0))?;
		let rows = db.prepare("select node_resets.user_id, node_resets.totals, users.record_id from node_resets join users on users.id = node_resets.user_id where node_resets.node_id = ? order by node_resets.wanted_at")?.query_map([node.0], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
		Ok((uid, rows))
	}).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	for (user, totals, record) in rows {
		let name = keys.node_user(&uid, &record.try_into().map_err(|_| "a user record id is not 16 bytes")?);
		let (status, _) = request(app, node, "POST", &format!("/v1/users/{name}/usage/reset"), None, Some(&json!({"totals": totals}))).await?;
		// A 404 is a reset done only when the node no longer has the user. Otherwise the node lacks the route, and the reset waits for a node that has it.
		let gone = status == 404 && {
			let (listed, body) = request(app, node, "GET", "/v1/users", None, None).await?;
			listed == 200 && serde_json::from_slice::<Value>(&body).ok().and_then(|answer| answer["users"].as_array().map(|users| users.iter().all(|found| found["name"] != name.as_str()))).unwrap_or(false)
		};
		if status != 200 && !gone {
			if status == 404 {tracing::info!("node {}: it answers 404 to the usage reset of a user it still has, so the reset is sent again at its next push", node.0)}
			return Err(format!("the node answered {status} to a usage reset"))
		}
		app.db.call(move |db| db.execute("delete from node_resets where node_id = ? and user_id = ?", params![node.0, user])).await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())?;
	}
	Ok(())
}

/// Puts the panel's users into the node's running config. A stale revision is read again once. A remote node's push counts only once its node confirms it (see `Confirm`), and then the usage resets that wait for the node are sent.
pub async fn sync(app: &Arc<App>, node: Node) -> Result<(), String> {
	let _turn = app.turn(node).await;
	let state = app.node(node);
	let mut pushed = None;
	// Cleared before the document is read, so a change committed while this push runs keeps the flag set.
	state.dirty.store(false, Ordering::Relaxed);
	// Everything wanted up to here is in the document read next, so it is applied once the push worked.
	let wanted: i64 = app.db.call(move |db| db.query_row("select wanted_rev from nodes where id = ?", [node.0], |row| row.get(0))).await.map_err(|error| error.to_string())?.map_err(|_| format!("node {} cannot be reached: the panel has no such node", node.0))?;
	let mut version = None;
	let mut profiles = None;
	let result = async {
		for _ in 0..3 {
			let (status, body) = request(app, node, "GET", "/v1/config", None, None).await?;
			if status != 200 {return Err(format!("the node answered {status} to the config"))}
			let running: Value = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
			let (Some(revision), Some(mut document)) = (running.get("revision").and_then(Value::as_str).map(str::to_string), running.get("document").cloned()) else {return Err("the node's config answer has no revision or document".into())};
			fill(app, node, &mut document).await?;
			// A cut answer of a remote node may still be a push that landed: the revision the node runs decides it below.
			let (status, body) = match request(app, node, "PUT", "/v1/config", Some(&revision), Some(&document)).await {
				Err(error) if node != LOCAL && (error.ends_with("(bad_answer)") || error.ends_with("(peer_silent)")) => (200, Vec::new()),
				answer => answer?,
			};
			match status {
				200 => {
					let landed = serde_json::from_slice::<Value>(&body).ok().and_then(|answer| answer["revision"].as_str().map(str::to_string));
					if node == LOCAL {
						// Defaults are the user's, and are judged against the document of node 1 alone.
						clear_defaults(app, &document).await;
						pushed = landed;
						return Ok(())
					}
					// The node keeps a config pushed through its link only if a request comes through the link at least `settle` after the push, over a session the link made after it. The link is made again soon after the push, so a request may fail until then and is asked again.
					let started = Instant::now();
					tokio::time::sleep(app.cfg.confirm.settle).await;
					let confirmed = loop {
						match request(app, node, "GET", "/v1/status", None, None).await {
							Ok((200, body)) => {
								let shown: Value = serde_json::from_slice(&body).unwrap_or_default();
								if shown["revision"].as_str().is_some_and(|seen| landed.as_deref().map_or(seen != revision, |landed| seen == landed)) {break Ok(shown)}
								break Err(format!("the node runs revision {} and not the one pushed", shown["revision"].as_str().unwrap_or("none")))
							}
							_ if started.elapsed() >= app.cfg.confirm.within => break Err(format!("the node did not confirm the config within {} s", app.cfg.confirm.within.as_secs())),
							_ => tokio::time::sleep(app.cfg.confirm.every).await,
						}
					};
					let confirmed = match confirmed {
						Ok(shown) => shown,
						Err(error) => {
							tracing::info!("node {}: {error}, so the config pushed through its link is not applied and the node rolls it back", node.0);
							return Err(format!("{error}, so it is not applied"))
						}
					};
					pushed = confirmed["revision"].as_str().map(str::to_string);
					version = confirmed["version"].as_str().map(str::to_string);
					profiles = Some(crate::nodecfg::remote_profiles(app, node, &document).await?);
					flush_resets(app, node).await?;
					return Ok(())
				}
				409 => continue,
				other => return Err(format!("the node refused the config with {other}: {}", String::from_utf8_lossy(&body).chars().take(300).collect::<String>())),
			}
		}
		Err("the node's config kept changing underneath the panel".into())
	}.await;
	*state.last_sync.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(match &result {Ok(()) => format!("ok at {}", now()), Err(error) => format!("failed at {}: {error}", now())});
	if result.is_err() {state.dirty.store(true, Ordering::Relaxed)}
	let (seen, failure, applied) = (result.is_ok().then(now), result.as_ref().err().cloned(), result.is_ok().then_some(wanted));
	let cache = profiles.map(|profiles: Value| json!({"profiles": profiles}).to_string());
	let _ = app.db.call(move |db| db.execute("update nodes set config_rev = coalesce(?, config_rev), last_seen = coalesce(?, last_seen), last_error = ?, applied_rev = max(applied_rev, coalesce(?, applied_rev)), version = coalesce(?, version), settings = coalesce(?, settings) where id = ?", params![pushed, seen, failure, applied, version, cache, node.0])).await;
	if let Err(error) = &result {tracing::warn!("node {} was not updated: {error}", node.0)}
	result
}
