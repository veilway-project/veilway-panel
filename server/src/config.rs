//! The panel's own file: where it listens, its two paths, where its secrets and database live and how it reaches the node.
use serde::Deserialize;
use std::{fs, net::SocketAddr, path::PathBuf};

/// What the endpoint (and every path the panel does not serve) answers to a request it will not take. The operator copies it from the web server in front, see "The endpoint" on the subscription format page.
#[derive(Deserialize, Clone, Debug)]
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
	/// Off only for tests and for a panel reached over plain HTTP on localhost.
	pub secure_cookies: bool,
	/// Set when no proxy is in front of the panel. Without one, trusted_proxies stays empty and every request counts from the socket.
	pub direct: bool,
}

impl Default for Config {
	fn default() -> Self {
		Self {listen: "127.0.0.1:8480".parse().unwrap(), prefix: "/panel".into(), sub_path: "/sub".into(), database: "panel.db".into(), keys: "panel.keys".into(), signing: "signing.keys".into(), node_socket: "/run/veilway/control.sock".into(), allowed_hosts: Vec::new(), trusted_proxies: Vec::new(), not_found: NotFound::default(), secure_cookies: true, direct: false}
	}
}

impl Config {
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
		Ok(())
	}
}
