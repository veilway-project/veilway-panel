//! Host names in profiles. A profile is published with the names the operator gave (the node address, an inbound's addresses, a relay's), and each document the panel makes carries the IP addresses those names have at that moment, since apps dial an address and make no lookup for it. A name is looked up again after five minutes, and when a lookup fails its last addresses are used for up to a week.
use serde_json::{json, Value};
use std::{collections::{BTreeSet, HashMap}, net::{IpAddr, SocketAddr}, sync::Mutex, time::{Duration, Instant}};
use veilway_proto::subscription::payload::{dialable, CANDIDATES_MAX};

const FRESH: Duration = Duration::from_secs(300);
const STALE: Duration = Duration::from_secs(7 * 86_400);
const NAMES_MAX: usize = 256;

/// What a name was found to be: when it was last asked, when it last answered, and its addresses then.
#[derive(Clone)]
struct Held {asked: Instant, answered: Option<Instant>, ips: Vec<IpAddr>}

#[derive(Default)]
pub struct Names {held: Mutex<HashMap<String, Held>>}

impl Names {
	/// The addresses apps may dial that `name` has now, or its last ones within a week when a lookup fails. Empty for a name that never answered.
	pub async fn ips(&self, name: &str) -> Vec<IpAddr> {
		let name = name.to_ascii_lowercase();
		let held = self.held.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(&name).cloned();
		if let Some(held) = held.as_ref().filter(|held| held.asked.elapsed() < FRESH) {return held.ips.clone()}
		let found = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((name.clone(), 0))).await.ok().and_then(Result::ok).map(|found| found.map(|address| address.ip().to_canonical()).filter(|ip| dialable(*ip)).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>()).filter(|ips| !ips.is_empty());
		let now = Instant::now();
		let next = match found {
			Some(ips) => {
				if held.as_ref().is_none_or(|held| held.ips != ips) {tracing::info!("the host name {name} is at {}", ips.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", "))}
				Held {asked: now, answered: Some(now), ips}
			}
			None => {
				let kept = held.filter(|held| held.answered.is_some_and(|at| at.elapsed() < STALE));
				tracing::warn!("the host name {name} did not resolve to an address apps may dial; {}", if kept.is_some() {"its last addresses are used"} else {"profiles leave it out"});
				kept.map_or(Held {asked: now, answered: None, ips: Vec::new()}, |held| Held {asked: now, ..held})
			}
		};
		let mut map = self.held.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if map.len() >= NAMES_MAX {map.retain(|_, held| held.asked.elapsed() < FRESH)}
		map.insert(name, next.clone());
		next.ips
	}

	/// The profiles with each host name in the addresses of their transports replaced by the addresses it has now, one entry per address, at most `CANDIDATES_MAX` per transport. A transport left with no address is dropped, and so is a profile left with no transport. A profile without transports is passed on as it is.
	pub async fn resolve(&self, profiles: Vec<Value>) -> Vec<Value> {
		let mut out = Vec::new();
		for mut profile in profiles {
			if !profile["transports"].is_array() {
				out.push(profile);
				continue;
			}
			for transport in profile["transports"].as_array_mut().into_iter().flatten() {
				let list = if transport["endpoints"].is_array() {"endpoints"} else {"candidates"};
				let (mut kept, mut seen) = (Vec::new(), BTreeSet::new());
				for entry in transport[list].as_array().cloned().unwrap_or_default() {
					let address = entry.as_str().or_else(|| entry["address"].as_str()).unwrap_or_default().to_string();
					let found = match address.rsplit_once(':') {
						Some((host, port)) if !host.starts_with('[') && host.parse::<IpAddr>().is_err() => match port.parse::<u16>() {Ok(port) => self.ips(host).await.into_iter().map(|ip| SocketAddr::new(ip, port).to_string()).collect(), Err(_) => Vec::new()},
						_ => vec![address],
					};
					for address in found.into_iter().filter(|address| seen.insert(address.clone())) {kept.push(if entry.is_string() {json!(address)} else {let mut candidate = entry.clone(); candidate["address"] = json!(address); candidate});}
				}
				kept.truncate(CANDIDATES_MAX);
				transport[list] = Value::Array(kept);
			}
			if let Some(list) = profile["transports"].as_array_mut() {list.retain(|transport| [&transport["endpoints"], &transport["candidates"]].iter().any(|list| list.as_array().is_some_and(|list| !list.is_empty())));}
			if profile["transports"].as_array().is_some_and(|list| !list.is_empty()) {out.push(profile)}
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn names_become_the_addresses_they_have_and_a_profile_left_with_none_is_dropped() {
		let names = Names::default();
		names.held.lock().unwrap().insert("node.example.org".into(), Held {asked: Instant::now(), answered: Some(Instant::now()), ips: vec!["192.0.2.10".parse().unwrap(), "2001:db8::10".parse().unwrap()]});
		names.held.lock().unwrap().insert("gone.example.org".into(), Held {asked: Instant::now(), answered: None, ips: Vec::new()});
		let profiles = vec![
			json!({"id": "main", "transports": [{"type": "udp-obfs", "endpoints": ["node.example.org:8443", "192.0.2.10:8443", "198.51.100.7:8443"]}, {"type": "tls", "candidates": [{"address": "Node.Example.org:443", "sni": "node.example.org"}]}, {"type": "udp", "endpoints": ["gone.example.org:51820"]}]}),
			json!({"id": "dead", "transports": [{"type": "udp", "endpoints": ["gone.example.org:51820"]}]}),
			json!({"id": "legacy", "type": "other"}),
		];
		let resolved = names.resolve(profiles).await;
		assert_eq!(resolved.iter().map(|profile| profile["id"].clone()).collect::<Vec<_>>(), [json!("main"), json!("legacy")], "a profile with no address left is not sent, one without transports is untouched");
		assert_eq!(resolved[0]["transports"], json!([{"type": "udp-obfs", "endpoints": ["192.0.2.10:8443", "[2001:db8::10]:8443", "198.51.100.7:8443"]}, {"type": "tls", "candidates": [{"address": "192.0.2.10:443", "sni": "node.example.org"}, {"address": "[2001:db8::10]:443", "sni": "node.example.org"}]}]), "each address once, the names gone, a transport with none left out");
	}

	#[tokio::test]
	async fn a_name_that_stops_answering_keeps_its_last_addresses_for_a_week() {
		let names = Names::default();
		let long_ago = Instant::now() - FRESH;
		names.held.lock().unwrap().insert("nothing.invalid".into(), Held {asked: long_ago, answered: Some(long_ago), ips: vec!["192.0.2.10".parse().unwrap()]});
		assert_eq!(names.ips("nothing.invalid").await, ["192.0.2.10".parse::<IpAddr>().unwrap()]);
		assert!(names.held.lock().unwrap()["nothing.invalid"].asked.elapsed() < FRESH, "the failed lookup is not asked again on every document");
		if let Some(week_ago) = Instant::now().checked_sub(STALE) {
			names.held.lock().unwrap().insert("nothing.invalid".into(), Held {asked: week_ago, answered: Some(week_ago), ips: vec!["192.0.2.10".parse().unwrap()]});
			assert!(names.ips("nothing.invalid").await.is_empty());
		}
	}
}
