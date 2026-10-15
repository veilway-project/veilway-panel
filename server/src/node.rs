//! The node's control API over its unix socket, and the one place the panel's users become the node's `users`.
use crate::{app::App, crypto::{self, now}, subs};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::xray::{key32, server_label};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::{collections::HashMap, path::Path, sync::{atomic::Ordering, Arc}, time::Duration};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::net::UnixStream;

/// One request to the node. The answer is the status and the body.
pub async fn request(socket: &Path, method: &str, path: &str, if_match: Option<&str>, body: Option<&Value>) -> Result<(u16, Vec<u8>), String> {
	let attempt = async {
		let stream = UnixStream::connect(socket).await.map_err(|error| format!("the node's socket: {error}"))?;
		let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|error| error.to_string())?;
		tokio::spawn(connection);
		let mut builder = Request::builder().method(method).uri(path).header("host", "node");
		if let Some(revision) = if_match {builder = builder.header("if-match", format!("\"{revision}\""));}
		if body.is_some() {builder = builder.header("content-type", "application/json");}
		let request = builder.body(Full::new(Bytes::from(body.map(|body| serde_json::to_vec(body).unwrap_or_default()).unwrap_or_default()))).map_err(|error| error.to_string())?;
		let response = sender.send_request(request).await.map_err(|error| error.to_string())?;
		let status = response.status().as_u16();
		Ok::<_, String>((status, response.into_body().collect().await.map_err(|error| error.to_string())?.to_bytes().to_vec()))
	};
	tokio::time::timeout(Duration::from_secs(20), attempt).await.map_err(|_| "the node did not answer in time".to_string())?
}

/// The node's users by name, with their usage, for the pages and for a document's `usage`. Empty when the node cannot be reached.
pub async fn usage(app: &App) -> HashMap<String, Value> {
	let Ok((200, body)) = request(&app.cfg.node_socket, "GET", "/v1/users", None, None).await else {return HashMap::new()};
	serde_json::from_slice::<Value>(&body).ok().and_then(|value| value.get("users").cloned()).and_then(|users| users.as_array().cloned()).unwrap_or_default().into_iter().filter_map(|user| Some((user.get("name")?.as_str()?.to_string(), user))).collect()
}

/// Puts the panel's users into the document's `users`, and the panel's credentials into the `clients` of the Xray inbounds it made, making one for a user who has none yet. A user with no device is left out, since the node needs one. An Xray inbound the panel did not make keeps its clients, less those whose user is gone.
pub(crate) fn fill(app: &App, document: &mut Value) -> Result<(), String> {
	let keys = app.keys.as_ref().ok_or("the key file is missing, so no secret can be opened")?;
	let db = app.db.lock();
	subs::expire_pending(&db, now()).map_err(|error| error.to_string())?;
	let mut statement = db.prepare("select id, name, enabled, groups, exits, quota_bytes, quota_period, expires_at, record_id from users order by id").map_err(|error| error.to_string())?;
	let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Option<String>>(6)?, row.get::<_, Option<i64>>(7)?, row.get::<_, Vec<u8>>(8)?))).map_err(|error| error.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
	let (mut out, mut present) = (Vec::new(), Vec::new());
	for (id, name, enabled, groups, exits, quota, period, expires, record) in rows {
		let record: [u8; 16] = record.try_into().map_err(|_| "a user record id is not 16 bytes")?;
		let mut devices = db.prepare("select id, public_key, address, transport_secret from devices where user_id = ? and state = 'enrolled' order by id").map_err(|error| error.to_string())?;
		let devices = devices.query_map([id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?))).map_err(|error| error.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
		if devices.is_empty() {continue}
		let devices: Vec<Value> = devices.into_iter().map(|(device, public_key, address, sealed)| {
			let secret = keys.open_secret(&record, &format!("transport_secret:{public_key}"), &sealed).ok_or("a transport secret does not open")?;
			Ok::<_, String>(json!({"name": format!("d{device}"), "public_key": public_key, "transport_secrets": [App::standard(&secret)], "addresses": [address]}))
		}).collect::<Result<_, _>>()?;
		let mut user = json!({"name": name, "enabled": enabled, "groups": serde_json::from_str::<Value>(&groups).unwrap_or(json!([])), "devices": devices, "exits": serde_json::from_str::<Value>(&exits).unwrap_or(json!("all"))});
		if let Some(quota) = quota {user["quota_bytes"] = json!(quota);}
		if let (Some(_), Some(period)) = (quota, period) {user["quota_period"] = json!(period);}
		if let Some(expires) = expires {user["expires_at"] = json!(OffsetDateTime::from_unix_timestamp(expires).map_err(|error| error.to_string())?.format(&Rfc3339).map_err(|error| error.to_string())?);}
		out.push(user);
		present.push((id, name, record));
	}
	document["users"] = Value::Array(out);
	let made: HashMap<String, String> = db.prepare("select tag, protocol from xray_inbounds").and_then(|mut statement| statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect()).map_err(|error| error.to_string())?;
	for inbound in document.get_mut("xray").and_then(|xray| xray.get_mut("inbounds")).and_then(Value::as_array_mut).into_iter().flatten() {
		let tag = inbound["tag"].as_str().unwrap_or_default().to_string();
		let Some(protocol) = made.get(&tag) else {
			if let Some(clients) = inbound["clients"].as_array_mut() {clients.retain(|client| present.iter().any(|(_, name, _)| client["user"] == name.as_str()));}
			continue
		};
		if protocol == "shadowsocks" {
			let sealed: Option<Vec<u8>> = db.query_row("select server_key from xray_inbounds where tag = ?", [&tag], |row| row.get(0)).optional().map_err(|error| error.to_string())?.flatten();
			if let Some(key) = sealed.and_then(|sealed| keys.open_secret(&[0; 16], &server_label(&tag), &sealed)) {inbound["server_key"] = json!(String::from_utf8(key).map_err(|error| error.to_string())?);}
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
					secret
				}
			};
			Ok(json!({"user": name, "secret": secret}))
		}).collect::<Result<Vec<_>, String>>()?;
		inbound["clients"] = Value::Array(clients);
	}
	Ok(())
}

/// Puts the panel's users into the node's running config. A stale revision is read again once.
pub async fn sync(app: &Arc<App>) -> Result<(), String> {
	let _turn = app.node_lock.lock().await;
	let result = async {
		for _ in 0..3 {
			let (status, body) = request(&app.cfg.node_socket, "GET", "/v1/config", None, None).await?;
			if status != 200 {return Err(format!("the node answered {status} to the config"))}
			let running: Value = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
			let (Some(revision), Some(mut document)) = (running.get("revision").and_then(Value::as_str).map(str::to_string), running.get("document").cloned()) else {return Err("the node's config answer has no revision or document".into())};
			fill(app, &mut document)?;
			let (status, body) = request(&app.cfg.node_socket, "PUT", "/v1/config", Some(&revision), Some(&document)).await?;
			match status {
				200 => return Ok(()),
				409 => continue,
				other => return Err(format!("the node refused the config with {other}: {}", String::from_utf8_lossy(&body).chars().take(300).collect::<String>())),
			}
		}
		Err("the node's config kept changing underneath the panel".into())
	}.await;
	*app.last_sync.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(match &result {Ok(()) => format!("ok at {}", now()), Err(error) => format!("failed at {}: {error}", now())});
	app.dirty.store(result.is_err(), Ordering::Relaxed);
	if let Err(error) = &result {tracing::warn!("the node was not updated: {error}")}
	result
}
