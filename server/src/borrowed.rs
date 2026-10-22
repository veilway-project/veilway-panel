//! The borrowed-site transport (`faketls`, alpha) in the panel: the node's rules for it checked before the node is asked, the public half of its key kept, and the profile of its own that carries it.
use crate::app::Settings;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{collections::BTreeMap, net::{IpAddr, SocketAddr}};
use veilway_proto::subscription::{is_host, payload::{dialable, CANDIDATES_MAX}};

/// The profile member a faketls profile never takes from the overrides of its inbound: the label, the id, the type, the keys that belong to the other transports, and the cap on how it is rated, which is the transport's own and stays at Detectable.
const OWN: [&str; 6] = ["id", "name", "type", "transports", "transport_public_key", "rating_cap"];
/// The override member that lists more addresses the node is reached at, such as a forwarder's. Each is an IP address, which takes the listener's port, or an address with a port. It becomes candidates of the faketls transports and nothing else, and no other profile takes it.
pub const ADDRESSES: &str = "faketls_addresses";
/// What a `faketls` transport never has: it ends no TLS, has no decoy origin and no path, and sits behind no proxy.
const NOT: [&str; 7] = ["path", "tls", "decoy", "trusted_proxies", "client_address_header", "shape", "http2"];
const SITE: [&str; 5] = ["host", "names", "port", "address", "acknowledged"];
const NAMES_MAX: usize = 4;
const RELAYED_MAX: u64 = 65536;
const SITE_RATE_MAX: u64 = 1024;

fn faketls(inbound: &Value) -> impl Iterator<Item = &Value> {inbound["transports"].as_array().into_iter().flatten().filter(|transport| transport["type"] == "faketls")}

fn key_of(text: &str) -> Option<[u8; 32]> {STANDARD.decode(text).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()).filter(|key| text.len() == 44 && *key != [0; 32])}

/// Whether two listen addresses are one socket: the same port and family, and the same address or either one the wildcard.
fn same_socket(one: SocketAddr, two: SocketAddr) -> bool {one.port() == two.port() && one.is_ipv4() == two.is_ipv4() && (one.ip() == two.ip() || one.ip().is_unspecified() || two.ip().is_unspecified())}

/// Whether a connection to `origin` arrives at the listener `listen`, as the node's validation counts it: the same address and port, or one of them the wildcard and the other an address of this host for certain.
fn loops(listen: SocketAddr, origin: SocketAddr) -> bool {
	let ((here, there), local) = ((listen.ip().to_canonical(), origin.ip().to_canonical()), |ip: IpAddr| ip.is_loopback() || ip.is_unspecified());
	listen.port() == origin.port() && (here == there || (here.is_unspecified() && local(there) || there.is_unspecified() && local(here)) && (here.is_ipv4() == there.is_ipv4() || here == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)))
}

/// Whether the change from the running document to `document` adds a `faketls` transport, or changes the site or the acknowledgment of one, found by inbound tag and listen address. The site is a third party that has not agreed to be borrowed, so only a person who confirmed their password and code again may do this.
pub fn sensitive(running: &Value, document: &Value) -> bool {
	let places = |document: &Value| -> Vec<(String, String, Value)> {document["inbounds"].as_array().into_iter().flatten().flat_map(|inbound| faketls(inbound).map(|transport| (inbound["tag"].as_str().unwrap_or_default().to_string(), transport["listen"].as_str().unwrap_or_default().to_string(), transport["site"].clone()))).collect()};
	let before = places(running);
	places(document).iter().any(|(tag, listen, site)| !before.iter().any(|(was_tag, was_listen, was_site)| was_tag == tag && was_listen == listen && was_site == site))
}

/// The node's rules for its `faketls` transports (config validation, "Config and profile fields" of the borrowed-site page), as messages. The node stays the authority: this says it early, with the reason, and before anything is sent. `running` is the document the node runs, whose keys are markers: the node matches a marker by its digits wherever a transport sits, so a marker is taken only on the inbound and listener that held it.
pub fn problems(document: &Value, running: &Value) -> Vec<String> {
	let mut found = Vec::new();
	let marked: Vec<(&str, &str, &str)> = running["inbounds"].as_array().into_iter().flatten().flat_map(|inbound| faketls(inbound).filter_map(|transport| Some((inbound["tag"].as_str().unwrap_or_default(), transport["listen"].as_str().unwrap_or_default(), transport["transport_key"].as_str()?)))).collect();
	let inbounds = document["inbounds"].as_array().map(Vec::as_slice).unwrap_or_default();
	let streams: Vec<(String, SocketAddr)> = inbounds.iter().enumerate().flat_map(|(i, inbound)| inbound["transports"].as_array().into_iter().flatten().enumerate().filter(|(_, transport)| !["udp", "udp-obfs"].contains(&transport["type"].as_str().unwrap_or_default())).filter_map(move |(j, transport)| Some((format!("inbounds[{i}].transports[{j}]"), transport["listen"].as_str()?.parse().ok()?)))).collect();
	let held: Vec<&str> = inbounds.iter().flat_map(|inbound| inbound["transport_keys"].as_array().into_iter().flatten().chain(faketls(inbound).map(|transport| &transport["transport_key"])).filter_map(Value::as_str)).collect();
	for (i, inbound) in inbounds.iter().enumerate() {
		for (j, transport) in inbound["transports"].as_array().into_iter().flatten().enumerate().filter(|(_, transport)| transport["type"] == "faketls") {
			let at = format!("inbounds[{i}].transports[{j}]");
			if inbound["type"] != "veilway" {found.push(format!("{at}.type: faketls is a transport of a veilway inbound, whose devices have the transport secrets its proofs are keyed with"))}
			for key in NOT.iter().filter(|key| transport.get(**key).is_some()) {found.push(format!("{at}.{key}: expected no such key, a faketls listener ends no TLS, has no decoy origin and sits behind no proxy"))}
			let listen = transport["listen"].as_str().and_then(|listen| listen.parse::<SocketAddr>().ok());
			if let Some(here) = listen {
				if let Some((other, _)) = streams.iter().find(|(other, there)| *other != at && same_socket(here, *there)) {found.push(format!("{at}.listen: conflicts with {other}, a faketls transport never shares an address and port with another transport"))}
			}
			match transport["site"].as_object() {
				None => found.push(format!("{at}.site: expected the site to borrow")),
				Some(site) => {
					for key in site.keys().filter(|key| !SITE.contains(&key.as_str())) {found.push(format!("{at}.site.{key}: expected no such key"))}
					if site.get("acknowledged") != Some(&Value::Bool(true)) {found.push(format!("{at}.site.acknowledged: expected true, every stranger's connection and every early connection of a user goes to the site from this node's address, and its owner has not agreed to any of it"))}
					let host = site.get("host").and_then(Value::as_str);
					if !host.is_some_and(is_host) {found.push(format!("{at}.site.host: expected a lowercase DNS name such as www.example.com"))}
					if let Some(names) = site.get("names") {
						match names.as_array() {
							Some(names) if names.len() <= NAMES_MAX => for (k, name) in names.iter().enumerate() {
								if !name.as_str().is_some_and(is_host) {found.push(format!("{at}.site.names[{k}]: expected a lowercase DNS name such as www.example.com"))} else if name.as_str() == host {found.push(format!("{at}.site.names[{k}]: expected a name other than site.host, which is accepted already"))} else if names[..k].contains(name) {found.push(format!("{at}.site.names[{k}]: expected a name once"))}
							},
							_ => found.push(format!("{at}.site.names: expected at most {NAMES_MAX} names")),
						}
					}
					if site.get("port").is_some_and(|port| !port.as_u64().is_some_and(|port| (1..=65535).contains(&port))) {found.push(format!("{at}.site.port: expected a port from 1 to 65535"))}
					if let Some(address) = site.get("address") {
						match address.as_str().and_then(|address| address.parse::<SocketAddr>().ok()) {
							None => found.push(format!("{at}.site.address: expected an address and port such as 192.0.2.10:443")),
							Some(there) => if let Some((other, _)) = streams.iter().find(|(_, here)| loops(*here, there)) {found.push(format!("{at}.site.address: expected the real site, found the address and port {other} listens on, every stranger's connection would come back to the node"))},
						}
					}
				}
			}
			match transport["transport_key"].as_str() {
				None => found.push(format!("{at}.transport_key: expected a key of its own")),
				Some(key) if key.starts_with("<redacted") || key_of(key).is_some() => {
					if key.starts_with("<redacted") && !marked.contains(&(inbound["tag"].as_str().unwrap_or_default(), transport["listen"].as_str().unwrap_or_default(), key)) {found.push(format!("{at}.transport_key: expected the key in full, a marker stands for the key the node holds on the inbound and listener that had it, and a transport that moved or is new takes the key only when it is typed again"))}
					if held.iter().filter(|other| **other == key).count() > 1 {found.push(format!("{at}.transport_key: expected a key of its own, the key of a faketls transport equals no other transport key of the node, so that a leak of it opens nothing else"))}
				}
				Some(_) => found.push(format!("{at}.transport_key: expected a key of 44 characters of base64 that is not all zero")),
			}
			if let Some(limits) = transport.get("limits") {
				for (key, bound) in [("relayed", RELAYED_MAX), ("site_rate", SITE_RATE_MAX)] {
					if limits.get(key).is_some_and(|limit| !limit.as_u64().is_some_and(|limit| (1..=bound).contains(&limit))) {found.push(format!("{at}.limits.{key}: expected an integer from 1 to {bound}"))}
				}
				for key in limits.as_object().into_iter().flat_map(|limits| limits.keys()).filter(|key| !["relayed", "site_rate"].contains(&key.as_str())) {found.push(format!("{at}.limits.{key}: expected no such key, a faketls listener takes relayed and site_rate alone"))}
			}
		}
	}
	found
}

/// Keeps the public half of each `faketls` key the document carries in full, by inbound tag and listen address. The node shows a key only as a marker once it holds it, so this is the one time the panel can make the public half. A marker keeps what was kept, and a transport that is gone loses its entry.
pub fn remember(settings: &mut Settings, document: &Value) {
	let mut kept: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
	for inbound in document["inbounds"].as_array().into_iter().flatten().filter(|inbound| inbound["type"] == "veilway") {
		let tag = inbound["tag"].as_str().unwrap_or_default();
		for transport in faketls(inbound) {
			let listen = transport["listen"].as_str().unwrap_or_default();
			let public = transport["transport_key"].as_str().and_then(key_of).map(|key| STANDARD.encode(veilway_proto::proof::public_key(&key))).or_else(|| settings.faketls_keys.get(tag)?.get(listen).cloned());
			if let Some(public) = public {kept.entry(tag.to_string()).or_default().insert(listen.to_string(), public);}
		}
	}
	settings.faketls_keys = kept;
}

/// The profile of its own that carries the `faketls` transports of an inbound, in the template shape of the other profiles, or None when the inbound has none. A transport that cannot be emitted is left out and named in `refused` with a code and a reason, so the node page can say why. Older apps refuse an unknown transport type with the profile that holds it, which is why it is never in the profile of the other transports.
pub fn template(settings: &Settings, document: &Value, inbound: &Value, gateways: &[Value]) -> Option<Value> {
	let (tag, host) = (inbound["tag"].as_str().unwrap_or_default(), settings.node_host.as_str());
	let mine: Vec<&Value> = faketls(inbound).collect();
	if mine.is_empty() {return None}
	let id = format!("{}-faketls", tag.to_lowercase());
	let inbounds = document["inbounds"].as_array().map(Vec::as_slice).unwrap_or_default();
	let id_wrong = id.len() > 64 || inbounds.iter().any(|other| other["type"] == "veilway" && other["tag"].as_str().is_some_and(|other| other.to_lowercase() == id)) || settings.profiles.iter().any(|profile| profile["id"] == id.as_str()) && !settings.relay_profiles.contains_key(&id);
	let held: Vec<&str> = inbounds.iter().flat_map(|inbound| inbound["transport_keys"].as_array().into_iter().flatten().chain(faketls(inbound).map(|transport| &transport["transport_key"])).filter_map(Value::as_str)).collect();
	let publics: Vec<&str> = settings.faketls_keys.values().flat_map(|listens| listens.values()).map(String::as_str).collect();
	let others: Vec<&str> = settings.profile_overrides.values().filter_map(|edits| edits["transport_public_key"].as_str()).collect();
	let own: Vec<String> = settings.profile_overrides.get(tag).and_then(|edits| edits[crate::nodecfg::NODE_ADDRESSES].as_array()).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
	// The inbound's own addresses, else the node's, each after the address the listener is bound to.
	let reached = if own.is_empty() {vec![host.to_string()]} else {own};
	let (mut emitted, mut refused) = (Vec::new(), Vec::new());
	for transport in mine {
		let listen = transport["listen"].as_str().unwrap_or_default();
		let public = settings.faketls_keys.get(tag).and_then(|listens| listens.get(listen));
		let key = transport["transport_key"].as_str().unwrap_or_default();
		let port = listen.parse::<SocketAddr>().ok().map(|listen| listen.port());
		let site = transport["site"]["host"].as_str().filter(|site| is_host(site));
		let mut candidates: Vec<String> = Vec::new();
		if let (Some(ip), Some(port)) = (listen.parse::<SocketAddr>().ok().map(|bound| bound.ip()).filter(|ip| dialable(*ip)), port) {candidates.push(SocketAddr::new(ip, port).to_string())}
		if port.is_some() {candidates.extend(reached.iter().filter(|host| crate::nodecfg::reachable(host)).filter_map(|host| crate::nodecfg::host_port(host, listen)))}
		for text in settings.profile_overrides.get(tag).and_then(|edits| edits[ADDRESSES].as_array()).into_iter().flatten().filter_map(Value::as_str) {candidates.extend(text.parse::<SocketAddr>().ok().or_else(|| Some(SocketAddr::new(text.parse().ok()?, port?))).filter(|found| dialable(found.ip())).map(|found| found.to_string()))}
		let mut seen = Vec::new();
		candidates.retain(|found| {let new = !seen.contains(found); seen.push(found.clone()); new});
		candidates.truncate(CANDIDATES_MAX);
		let why = if id_wrong {Some(("profile_id", "the id of its profile, the inbound tag and -faketls, is longer than 64 characters, is the tag of another inbound, or is the id of a profile written by hand, which publishing would replace"))}
			else if transport["site"]["acknowledged"] != true {Some(("not_acknowledged", "the operator has not acknowledged that the site has not agreed to this"))}
			else if ["trusted_proxies", "client_address_header"].iter().any(|key| transport.get(*key).is_some()) {Some(("behind_proxy", "the listener sits behind trusted proxies or a content delivery network, which would sit between the app and the node's handshake"))}
			else if held.iter().filter(|other| **other == key).count() > 1 || public.is_some_and(|public| others.contains(&public.as_str()) || publics.iter().filter(|other| **other == public.as_str()).count() > 1) {Some(("key_shared", "its key equals the key of another transport of the node"))}
			else if public.is_none() {Some(("no_public_key", "the panel holds no public half of its key, because it never saw the key in full: enter the key again and apply"))}
			else if site.is_none() || port.is_none() {Some(("bad_site", "its site name or listen address does not read"))}
			else if candidates.is_empty() {Some(("node_host", "the node's public address is not set to a host name or an IP address that apps may dial, and the listener is not bound to one"))}
			else {None};
		match (why, public, site) {
			(None, Some(public), Some(site)) => emitted.push(json!({"type": "faketls", "transport_public_key": public, "candidates": candidates.iter().map(|found| json!({"address": found, "sni": site})).collect::<Vec<_>>()})),
			(why, ..) => refused.push(json!({"transport": listen, "code": why.map(|(code, _)| code).unwrap_or("unreadable"), "reason": why.map(|(_, reason)| reason).unwrap_or("it does not read")})),
		}
	}
	let mut profile = json!({"id": id, "name": format!("{tag} (borrowed site, alpha)"), "type": "veilway", "gateways": gateways, "mtu": inbound["mtu"].as_u64().unwrap_or(1420), "transports": emitted, "rating_cap": "detectable"});
	if let Some(public) = settings.inbound_keys.get(tag) {profile["inbound_public_key"] = json!(public);}
	let edits = settings.profile_overrides.get(tag).and_then(Value::as_object);
	for (key, value) in edits.into_iter().flatten().filter(|(key, _)| !OWN.contains(&key.as_str()) && *key != ADDRESSES && !crate::nodecfg::NOT_MEMBERS.contains(&key.as_str())) {profile[key] = value.clone();}
	let mut missing = Vec::new();
	if profile.get("inbound_public_key").is_none() {missing.push("inbound_public_key")}
	if host.is_empty() && settings.profile_overrides.get(tag).and_then(|edits| edits[crate::nodecfg::NODE_ADDRESSES].as_array()).is_none_or(Vec::is_empty) {missing.push("node_host")}
	Some(json!({"inbound": tag, "kind": "faketls", "profile": profile, "missing": missing, "refused": refused, "overridden": edits.into_iter().flatten().map(|(key, _)| key).filter(|key| !OWN.contains(&key.as_str()) && !crate::nodecfg::NOT_MEMBERS.contains(&key.as_str())).collect::<Vec<_>>(), "trimmed": []}))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn key(fill: u8) -> String {STANDARD.encode([fill; 32])}

	/// The rules with the document as the running one too, so that a marker stays where it was.
	fn problems(document: &Value) -> Vec<String> {super::problems(document, document)}

	fn at(tag: &str, listen: &str, key: &str) -> Value {json!({"tag": tag, "type": "veilway", "address": ["10.66.0.1/24"], "transports": [transport(json!({"listen": listen, "transport_key": key}))]})}

	fn transport(extra: Value) -> Value {
		let mut transport = json!({"type": "faketls", "listen": "0.0.0.0:443", "site": {"host": "www.example.com", "acknowledged": true}, "transport_key": key(5)});
		transport.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
		transport
	}

	fn document(transports: Vec<Value>) -> Value {json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": transports}]})}

	fn public(fill: u8) -> String {STANDARD.encode(veilway_proto::proof::public_key(&[fill; 32]))}

	fn settings(document: &Value) -> Settings {
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		remember(&mut settings, document);
		settings
	}

	fn made(settings: &Settings, document: &Value) -> Value {template(settings, document, &document["inbounds"][0], &[json!("10.66.0.1")]).unwrap()}

	fn why(template: &Value) -> Vec<String> {template["refused"].as_array().unwrap().iter().map(|refusal| refusal["code"].as_str().unwrap().to_string()).collect()}

	#[test]
	fn a_transport_that_follows_the_nodes_rules_has_no_problem() {
		let site = json!({"host": "www.example.com", "names": ["example.com", "cdn.example.com"], "port": 8443, "address": "198.51.100.7:443", "acknowledged": true});
		assert_eq!(problems(&document(vec![transport(json!({})), transport(json!({"listen": "0.0.0.0:8443", "site": site, "transport_key": key(6), "limits": {"relayed": 64, "site_rate": 4}}))])), Vec::<String>::new());
		assert_eq!(problems(&document(vec![json!({"type": "udp", "listen": "0.0.0.0:443"}), transport(json!({"transport_key": "<redacted:0a1b2c3d>"}))])), Vec::<String>::new(), "a marker stands for a key the node holds, and a udp listener has its own sockets");
	}

	#[test]
	fn each_rule_of_the_node_is_said_with_its_place() {
		let site = |change: Value| {
			let mut site = json!({"host": "www.example.com", "acknowledged": true});
			site.as_object_mut().unwrap().extend(change.as_object().unwrap().clone());
			json!({"site": site})
		};
		let said = |extra: Value| problems(&document(vec![transport(extra)])).join("\n");
		for (extra, expected) in [
			(site(json!({"acknowledged": false})), "site.acknowledged: expected true"),
			(site(json!({"acknowledged": "yes"})), "site.acknowledged: expected true"),
			(site(json!({"host": "WWW.Example.com"})), "site.host: expected a lowercase DNS name"),
			(site(json!({"host": "*.example.com"})), "site.host: expected a lowercase DNS name"),
			(site(json!({"names": ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"]})), "site.names: expected at most 4 names"),
			(site(json!({"names": ["www.example.com"]})), "site.names[0]: expected a name other than site.host"),
			(site(json!({"names": ["a.example.com", "a.example.com"]})), "site.names[1]: expected a name once"),
			(site(json!({"names": ["Bad Name"]})), "site.names[0]: expected a lowercase DNS name"),
			(site(json!({"port": 0})), "site.port: expected a port from 1 to 65535"),
			(site(json!({"port": 70000})), "site.port: expected a port from 1 to 65535"),
			(site(json!({"address": "not an address"})), "site.address: expected an address and port"),
			(site(json!({"address": "127.0.0.1:443"})), "site.address: expected the real site"),
			(site(json!({"colour": "blue"})), "site.colour: expected no such key"),
			(json!({"site": null}), "site: expected the site to borrow"),
			(json!({"transport_key": "short"}), "transport_key: expected a key of 44 characters"),
			(json!({"transport_key": STANDARD.encode([0u8; 32])}), "transport_key: expected a key of 44 characters"),
			(json!({"transport_key": null}), "transport_key: expected a key of its own"),
			(json!({"trusted_proxies": ["127.0.0.1"]}), "trusted_proxies: expected no such key"),
			(json!({"decoy": {"origin": "http://127.0.0.1:8080"}}), "decoy: expected no such key"),
			(json!({"path": "/a-long-enough-path"}), "path: expected no such key"),
			(json!({"limits": {"relayed": 0}}), "limits.relayed: expected an integer from 1 to 65536"),
			(json!({"limits": {"site_rate": 2000}}), "limits.site_rate: expected an integer from 1 to 1024"),
			(json!({"limits": {"sessions": 5}}), "limits.sessions: expected no such key"),
		] {assert!(said(extra.clone()).contains(expected), "{extra}: {}", said(extra.clone()))}
	}

	#[test]
	fn it_takes_a_listener_of_its_own_a_key_of_its_own_and_a_veilway_inbound() {
		let clash = problems(&document(vec![transport(json!({})), json!({"type": "tls", "listen": "192.0.2.10:443"})])).join("\n");
		assert!(clash.contains("never shares an address and port"), "{clash}");
		assert!(problems(&document(vec![transport(json!({})), transport(json!({"listen": "0.0.0.0:444"}))])).join("\n").contains("transport_key: expected a key of its own"));
		let mut other = document(vec![transport(json!({}))]);
		other["inbounds"][0]["transport_keys"] = json!([key(5)]);
		assert!(problems(&other).join("\n").contains("equals no other transport key"), "the key of the inbound's own tls transports");
		other["inbounds"][0]["transport_keys"] = json!([key(6)]);
		assert!(problems(&other).is_empty());
		other["inbounds"][0]["type"] = json!("wireguard");
		assert!(problems(&other).join("\n").contains("faketls is a transport of a veilway inbound"));
		assert!(problems(&document(vec![transport(json!({"transport_key": "<redacted:0a1b2c3d>"})), transport(json!({"listen": "0.0.0.0:444", "transport_key": "<redacted:0a1b2c3d>"}))])).join("\n").contains("equals no other transport key"), "two markers with the same digits are one key");
	}

	#[test]
	fn the_public_half_is_made_when_the_key_comes_in_full_and_kept_through_markers() {
		let full = document(vec![transport(json!({}))]);
		let mut kept = settings(&full);
		assert_eq!(kept.faketls_keys["Main"]["0.0.0.0:443"], public(5));
		remember(&mut kept, &document(vec![transport(json!({"transport_key": "<redacted:0a1b2c3d>", "site": {"host": "www.example.org", "acknowledged": true}}))]));
		assert_eq!(kept.faketls_keys["Main"]["0.0.0.0:443"], public(5), "a marker keeps it, whatever else changed");
		remember(&mut kept, &document(vec![transport(json!({"listen": "0.0.0.0:444", "transport_key": "<redacted:0a1b2c3d>"}))]));
		assert!(kept.faketls_keys.is_empty(), "a marker on a listener the panel never saw has no public half");
		remember(&mut kept, &document(vec![transport(json!({"transport_key": key(9)}))]));
		remember(&mut kept, &document(vec![json!({"type": "udp", "listen": "0.0.0.0:51820"})]));
		assert!(kept.faketls_keys.is_empty(), "a transport that is gone loses its entry");
	}

	#[test]
	fn the_profile_of_its_own_carries_the_transport_with_the_nodes_address_and_the_sites_name() {
		let document = document(vec![json!({"type": "udp", "listen": "0.0.0.0:51820"}), transport(json!({"site": {"host": "www.example.com", "names": ["example.com"], "acknowledged": true}}))]);
		let template = made(&settings(&document), &document);
		let profile = &template["profile"];
		assert_eq!((profile["id"].clone(), profile["name"].clone(), profile["gateways"].clone(), profile["mtu"].clone(), profile["rating_cap"].clone()), (json!("main-faketls"), json!("Main (borrowed site, alpha)"), json!(["10.66.0.1"]), json!(1420), json!("detectable")));
		assert_eq!(profile["transports"], json!([{"type": "faketls", "transport_public_key": public(5), "candidates": [{"address": "192.0.2.10:443", "sni": "www.example.com"}]}]));
		assert_eq!((template["refused"].clone(), template["missing"].clone(), template["kind"].clone()), (json!([]), json!(["inbound_public_key"]), json!("faketls")));
		assert!(profile.get("transport_public_key").is_none(), "no profile key: the transport has its own");
		assert!(template_without(&json!({"inbounds": [{"tag": "Main", "type": "veilway", "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}]})), "an inbound without a borrowed site has no such profile");
	}

	fn template_without(document: &Value) -> bool {template(&Settings::default(), document, &document["inbounds"][0], &[]).is_none()}

	#[test]
	fn the_overrides_of_the_inbound_reach_it_except_what_belongs_to_the_other_profile() {
		let document = document(vec![transport(json!({}))]);
		let mut settings = settings(&document);
		settings.profile_overrides.insert("Main".into(), json!({"inbound_public_key": key(7), "name": "Edited", "transports": [], "transport_public_key": key(8), "id": "x", "parallel": 2, "rating_cap": "unsafe", "type": "other"}));
		let template = made(&settings, &document);
		let profile = &template["profile"];
		assert_eq!((profile["inbound_public_key"].clone(), profile["parallel"].clone(), profile["name"].clone(), profile["id"].clone(), profile["transports"].as_array().unwrap().len(), template["missing"].clone()), (json!(key(7)), json!(2), json!("Main (borrowed site, alpha)"), json!("main-faketls"), 1, json!([])));
		assert!(profile.get("transport_public_key").is_none());
		assert_eq!((profile["rating_cap"].clone(), profile["type"].clone()), (json!("detectable"), json!("veilway")), "the cap and the type are the transport's own");
		assert_eq!(template["overridden"], json!(["inbound_public_key", "parallel"]));
	}

	#[test]
	fn a_transport_that_cannot_be_emitted_is_left_out_with_its_reason() {
		let refused = |extra: Value, change: &dyn Fn(&mut Settings)| {
			let document = document(vec![transport(extra)]);
			let mut settings = settings(&document);
			change(&mut settings);
			let template = made(&settings, &document);
			assert_eq!(template["profile"]["transports"], json!([]));
			(why(&template), template["refused"][0]["reason"].as_str().unwrap().to_string())
		};
		let nothing = |_: &mut Settings| {};
		assert_eq!(refused(json!({"site": {"host": "www.example.com", "acknowledged": false}}), &nothing).0, ["not_acknowledged"]);
		assert_eq!(refused(json!({"site": {"host": "www.example.com"}}), &nothing).0, ["not_acknowledged"]);
		assert_eq!(refused(json!({"trusted_proxies": ["127.0.0.1"]}), &nothing).0, ["behind_proxy"]);
		assert_eq!(refused(json!({"client_address_header": "X-Forwarded-For"}), &nothing).0, ["behind_proxy"]);
		assert_eq!(refused(json!({}), &|settings| {settings.profile_overrides.insert("Main".into(), json!({"transport_public_key": public(5)}));}).0, ["key_shared"], "the key of the tls and ws transports of the inbound");
		assert_eq!(refused(json!({}), &|settings| {settings.profile_overrides.insert("Other".into(), json!({"transport_public_key": public(5)}));}).0, ["key_shared"], "or of any other inbound");
		assert_eq!(refused(json!({}), &|settings| {settings.faketls_keys.entry("Other".into()).or_default().insert("0.0.0.0:444".into(), public(5));}).0, ["key_shared"], "or of another borrowed site");
		assert_eq!(refused(json!({}), &|settings| settings.faketls_keys.clear()).0, ["no_public_key"]);
		assert_eq!(refused(json!({}), &|settings| settings.node_host = String::new()).0, ["node_host"]);
		assert_eq!(refused(json!({}), &|settings| settings.node_host = "127.0.0.1".into()).0, ["node_host"]);
		assert_eq!(refused(json!({"listen": "not an address"}), &nothing).0, ["bad_site"], "a listener that does not read has no port to emit");
		let (codes, reason) = refused(json!({"site": {"host": "Bad Name", "acknowledged": true}}), &nothing);
		assert_eq!((codes, reason.is_empty()), (vec!["bad_site".to_string()], false));
	}

	#[test]
	fn a_key_shared_with_another_transport_by_marker_is_refused_too() {
		let mut document = document(vec![transport(json!({"transport_key": "<redacted:0a1b2c3d>"}))]);
		document["inbounds"][0]["transport_keys"] = json!(["<redacted:0a1b2c3d>"]);
		let mut settings = Settings {node_host: "192.0.2.10".into(), ..Settings::default()};
		settings.faketls_keys.entry("Main".into()).or_default().insert("0.0.0.0:443".into(), public(5));
		assert_eq!(why(&made(&settings, &document)), ["key_shared"]);
	}

	#[test]
	fn a_profile_id_that_would_be_another_inbounds_is_refused() {
		let mut document = document(vec![transport(json!({}))]);
		document["inbounds"].as_array_mut().unwrap().push(json!({"tag": "main-faketls", "type": "veilway", "transports": []}));
		let settings = settings(&document);
		assert_eq!(why(&made(&settings, &document)), ["profile_id"]);
	}

	#[test]
	fn a_marker_is_taken_only_on_the_inbound_and_listener_that_held_it() {
		let (one, two) = ("<redacted:0a1b2c3d>", "<redacted:1a2b3c4d>");
		let running = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [transport(json!({"transport_key": one})), transport(json!({"listen": "0.0.0.0:444", "transport_key": two}))]}]});
		assert_eq!(super::problems(&running, &running), Vec::<String>::new(), "markers where they were");
		let swapped = json!({"inbounds": [{"tag": "Main", "type": "veilway", "address": ["10.66.0.1/24"], "transports": [transport(json!({"listen": "0.0.0.0:444", "transport_key": one})), transport(json!({"transport_key": two}))]}]});
		let said = super::problems(&swapped, &running);
		assert_eq!(said.len(), 2, "{said:?}");
		assert!(said.iter().all(|text| text.contains("transport_key: expected the key in full")) && said[0].starts_with("inbounds[0].transports[0]") && said[1].starts_with("inbounds[0].transports[1]"), "{said:?}");
		let moved = json!({"inbounds": [at("Main", "0.0.0.0:445", one)]});
		assert_eq!(super::problems(&moved, &running).len(), 1, "a listener that moved");
		let renamed = json!({"inbounds": [at("Other", "0.0.0.0:443", one)]});
		assert_eq!(super::problems(&renamed, &running).len(), 1, "an inbound that was renamed");
		let typed = json!({"inbounds": [at("Other", "0.0.0.0:445", &key(5))]});
		assert_eq!(super::problems(&typed, &running), Vec::<String>::new(), "the key typed in full goes anywhere");
		assert_eq!(super::problems(&running, &json!({})).len(), 2, "a marker of a transport the node did not have");
	}

	#[test]
	fn adding_a_borrowed_site_or_changing_its_site_or_acknowledgment_is_sensitive() {
		let running = document(vec![transport(json!({}))]);
		let site = |change: Value| {
			let mut site = json!({"host": "www.example.com", "acknowledged": true});
			site.as_object_mut().unwrap().extend(change.as_object().unwrap().clone());
			site
		};
		assert!(!sensitive(&running, &running));
		assert!(!sensitive(&running, &document(vec![transport(json!({"transport_key": key(6), "limits": {"relayed": 4}}))])), "the key and the limits are the node's rules to check, not the site's");
		assert!(!sensitive(&running, &document(vec![])), "removing one");
		assert!(!sensitive(&json!({}), &document(vec![json!({"type": "udp", "listen": "0.0.0.0:51820"})])));
		for changed in [site(json!({"host": "www.example.org"})), site(json!({"acknowledged": false})), site(json!({"names": ["example.com"]})), site(json!({"address": "198.51.100.7:443"}))] {assert!(sensitive(&running, &document(vec![transport(json!({"site": changed}))])), "{changed}")}
		assert!(sensitive(&running, &document(vec![transport(json!({})), transport(json!({"listen": "0.0.0.0:444", "transport_key": key(6)}))])), "a second one");
		assert!(sensitive(&running, &document(vec![transport(json!({"listen": "0.0.0.0:444"}))])), "one that moved is new at its listener");
		assert!(sensitive(&json!({}), &running));
	}

	#[test]
	fn one_candidate_per_address_the_node_is_reached_at_and_the_extra_ones_from_the_override() {
		let candidates = |listen: &str, host: &str, extra: Option<Value>| {
			let document = document(vec![transport(json!({"listen": listen}))]);
			let mut settings = settings(&document);
			settings.node_host = host.into();
			if let Some(extra) = extra {settings.profile_overrides.insert("Main".into(), json!({ADDRESSES: extra}));}
			let template = made(&settings, &document);
			assert!(template["profile"].get(ADDRESSES).is_none(), "the list is no member of the profile");
			template["profile"]["transports"][0]["candidates"].as_array().map(|list| list.iter().map(|candidate| candidate["address"].as_str().unwrap().to_string()).collect::<Vec<_>>()).unwrap_or_default()
		};
		assert_eq!(candidates("0.0.0.0:443", "192.0.2.10", None), ["192.0.2.10:443"], "a wildcard listener is reached at the node's address alone");
		assert_eq!(candidates("198.51.100.7:8443", "192.0.2.10", None), ["198.51.100.7:8443", "192.0.2.10:8443"], "the bound address first, then the node's");
		assert_eq!(candidates("192.0.2.10:443", "192.0.2.10", None), ["192.0.2.10:443"], "one address once");
		assert_eq!(candidates("198.51.100.7:443", "", None), ["198.51.100.7:443"], "a bound address needs no node host");
		assert_eq!(candidates("0.0.0.0:443", "node.example.org", None), ["node.example.org:443"], "a host name becomes its addresses in each document");
		assert_eq!(candidates("[2001:db8::7]:443", "192.0.2.10", None), ["[2001:db8::7]:443", "192.0.2.10:443"]);
		assert_eq!(candidates("127.0.0.1:443", "192.0.2.10", None), ["192.0.2.10:443"], "a loopback listener is no address to dial");
		assert_eq!(candidates("0.0.0.0:443", "192.0.2.10", Some(json!(["203.0.113.5", "203.0.113.6:8443", "192.0.2.10", "127.0.0.1", "not an address", "[2001:db8::9]:443"]))), ["192.0.2.10:443", "203.0.113.5:443", "203.0.113.6:8443", "[2001:db8::9]:443"], "the port is the listener's unless given; undialable and unreadable entries and repeats add nothing");
		let many: Vec<Value> = (1..=30).map(|i| json!(format!("203.0.113.{i}"))).collect();
		let all = candidates("198.51.100.7:443", "192.0.2.10", Some(json!(many)));
		assert_eq!((all.len(), all[0].as_str(), all[1].as_str(), all[2].as_str(), all[15].as_str()), (CANDIDATES_MAX, "198.51.100.7:443", "192.0.2.10:443", "203.0.113.1:443", "203.0.113.14:443"));
	}

	#[test]
	fn a_profile_written_by_hand_under_its_id_is_refused_and_one_the_panel_published_is_not() {
		let document = document(vec![transport(json!({}))]);
		let mut settings = settings(&document);
		settings.profiles.push(json!({"id": "main-faketls", "name": "Mine", "type": "veilway"}));
		let template = made(&settings, &document);
		assert_eq!((why(&template), template["profile"]["transports"].clone()), (vec!["profile_id".to_string()], json!([])));
		assert!(template["refused"][0]["reason"].as_str().unwrap().contains("written by hand"));
		settings.relay_profiles.insert("main-faketls".into(), "Main".into());
		assert_eq!(why(&made(&settings, &document)), Vec::<String>::new(), "the panel's own earlier publish is replaced");
	}
}
