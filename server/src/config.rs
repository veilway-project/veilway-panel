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
}

impl Default for Config {
	fn default() -> Self {
		Self {listen: "127.0.0.1:8480".parse().unwrap(), prefix: "/panel".into(), sub_path: "/sub".into(), database: "panel.db".into(), keys: "panel.keys".into(), signing: "signing.keys".into(), node_socket: "/run/veilway/control.sock".into(), allowed_hosts: Vec::new(), trusted_proxies: Vec::new(), not_found: NotFound::default(), secure_cookies: true}
	}
}

impl Config {
	pub fn load(path: &str) -> Result<Self, String> {
		let config: Config = serde_json::from_slice(&fs::read(path).map_err(|error| format!("{path}: {error}"))?).map_err(|error| format!("{path}: {error}"))?;
		let path_ok = |path: &str| path.starts_with('/') && path.len() > 1 && !path.ends_with('/') && path.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/-_.".contains(&byte));
		if !path_ok(&config.prefix) || !path_ok(&config.sub_path) || config.prefix == config.sub_path || config.sub_path.starts_with(&format!("{}/", config.prefix)) || config.prefix.starts_with(&format!("{}/", config.sub_path)) {return Err("prefix and sub_path must be two different paths, each with a leading slash, no trailing slash and only letters, digits and - _ . /".into())}
		Ok(config)
	}
}
