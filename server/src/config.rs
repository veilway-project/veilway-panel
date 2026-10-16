//! The panel's own file: where it listens, its two paths, where its secrets and database live and how it reaches the node.
use schemars::JsonSchema;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, net::SocketAddr, path::PathBuf};

/// What the endpoint (and every path the panel does not serve) answers to a request it will not take. The operator copies it from the web server in front, see "The endpoint" on the subscription format page.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct NotFound {
	pub status: u16,
	pub headers: Vec<(String, String)>,
	pub body: String,
}

impl Default for NotFound {
	fn default() -> Self {
		Self {status: 404, headers: vec![("content-type".into(), "text/html".into())], body: "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n</body>\r\n</html>\r\n".into()}
	}
}

/// A relay mirror the provider runs: a server that forwards requests to the endpoint and signs the address they came from with `secret`, which is 32 to 64 random bytes in unpadded base64url.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TrustedMirror {
	pub name: String,
	pub secret: String,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
	pub listen: SocketAddr,
	/// The path of the admin pages and API, random at install. No trailing slash.
	pub prefix: String,
	/// The path of the subscription endpoint behind the operator's web server.
	pub sub_path: String,
	pub database: PathBuf,
	/// The three keys of sealed secrets: lookup, copy and secret. Mode 600, kept apart from the database.
	pub keys: PathBuf,
	/// The subscription signing keys. Mode 600, kept apart from both of the above.
	pub signing: PathBuf,
	pub node_socket: PathBuf,
	/// Host header values the admin side answers to. Empty accepts any, which is only for a panel behind a web server that checks it.
	pub allowed_hosts: Vec<String>,
	/// Peers whose X-Forwarded-For is believed. The source address is the socket's otherwise.
	pub trusted_proxies: Vec<String>,
	pub not_found: NotFound,
	/// Relay mirrors whose signed header names the real address of a request on the subscription endpoint. At most 8.
	pub trusted_mirrors: Vec<TrustedMirror>,
	/// Off only for tests and for a panel reached over plain HTTP on localhost.
	pub secure_cookies: bool,
	/// Set when no proxy is in front of the panel. Without one, trusted_proxies stays empty and every request counts from the socket.
	pub direct: bool,
	/// Asks GitHub every six hours whether a newer panel exists. Nothing else about this panel is sent.
	pub update_check: bool,
	/// Where an update request is written. The folder is made by `veilway.sh`, belongs to root and is writable by the panel's group only.
	pub update_request: PathBuf,
	/// "off" turns the authenticator code off everywhere: sign-in, setup, adding an admin and re-authentication ask for the password only. Any other value, and the default, keeps it on. This is for tutorials and demos and is dangerous: anyone with a password gets in. It is read from this file only and no panel page or API route can change it, because whoever can write this file already owns the panel.
	pub two_step: String,
}

impl Default for Config {
	fn default() -> Self {
		Self {listen: "127.0.0.1:8480".parse().unwrap(), prefix: "/panel".into(), sub_path: "/sub".into(), database: "panel.db".into(), keys: "panel.keys".into(), signing: "signing.keys".into(), node_socket: "/run/veilway/control.sock".into(), allowed_hosts: Vec::new(), trusted_proxies: Vec::new(), not_found: NotFound::default(), trusted_mirrors: Vec::new(), secure_cookies: true, direct: false, update_check: true, update_request: "/var/lib/veilway-panel-update/request".into(), two_step: "on".into()}
	}
}

impl Config {
	pub fn two_step_on(&self) -> bool {self.two_step != "off"}
	pub fn load(path: &str) -> Result<Self, String> {
		let config: Config = serde_json::from_slice(&fs::read(path).map_err(|error| format!("{path}: {error}"))?).map_err(|error| format!("{path}: {error}"))?;
		config.check().map_err(|error| format!("{path}: {error}"))?;
		Ok(config)
	}
	/// What the panel refuses to start with. It has no TLS of its own, so it listens on loopback behind the operator's web server, and that server is named in trusted_proxies unless the panel is `direct`.
	pub fn check(&self) -> Result<(), String> {
		let path_ok = |path: &str| path.starts_with('/') && path.len() > 1 && !path.ends_with('/') && path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/-_.".contains(&byte));
		if !path_ok(&self.prefix) || !path_ok(&self.sub_path) || self.prefix == self.sub_path || self.sub_path.starts_with(&format!("{}/", self.prefix)) || self.prefix.starts_with(&format!("{}/", self.sub_path)) {return Err("prefix and sub_path must be two different paths, each with a leading slash, no trailing slash and only letters, digits and - _ . /".into())}
		if !self.listen.ip().is_loopback() {return Err(format!("listen is {}, which is not a loopback address. The panel has no TLS of its own yet, so it listens on 127.0.0.1 or ::1 behind the operator's web server, which terminates TLS", self.listen))}
		if self.trusted_proxies.is_empty() && !self.direct {return Err("trusted_proxies is empty, so behind the web server every request would count as one source. List the web server's address in trusted_proxies, or set \"direct\": true when no proxy is in front".into())}
		let mut names = HashSet::new();
		if self.trusted_mirrors.len() > 8 {return Err("trusted_mirrors has at most 8 entries".into())}
		for mirror in &self.trusted_mirrors {
			if !(1..=32).contains(&mirror.name.len()) || !mirror.name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)) || !names.insert(&mirror.name) {return Err("each trusted_mirrors name is unique, 1 to 32 characters from a-z 0-9 - _".into())}
			if !URL_SAFE_NO_PAD.decode(&mirror.secret).is_ok_and(|secret| (32..=64).contains(&secret.len())) {return Err(format!("the secret of the mirror {} is not 32 to 64 bytes in unpadded base64url", mirror.name))}
		}
		Ok(())
	}
}
