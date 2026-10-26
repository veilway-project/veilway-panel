//! The `via` of outbounds and node links in the panel: the node's rules checked before the node is asked, the way `borrowed.rs` checks its transports. The node stays the authority; this says it early, with the reason.
use serde_json::Value;

/// The `via` links a connection may go through, from the outbound or link that dials to the outbound that dials directly.
const HOPS_MAX: usize = 8;

/// Follows the chain from `via` until a socks5 outbound that dials directly. A tag this change removes or renames is left to its own message, so one fault is named once.
fn chain<'a>(outbounds: &'a [Value], gone: &[&str], mut seen: Vec<&'a str>, via: &'a str) -> Result<(), &'static str> {
	let (mut at, mut hops) = (via, 1);
	loop {
		if gone.contains(&at) {return Ok(())}
		let Some(item) = outbounds.iter().find(|item| item["tag"] == at).filter(|item| item["type"] == "socks5") else {return Err("names no socks5 outbound of this config")};
		if seen.contains(&at) {return Err("is in a loop of Through, which comes back to itself")}
		seen.push(at);
		let Some(next) = item["via"].as_str() else {return Ok(())};
		hops += 1;
		if hops > HOPS_MAX {return Err("goes through more than 8 hops, the most a chain may have")}
		at = next;
	}
}

/// The `via` rules of a document's outbounds and node links, as messages in the shape of the node's report. `running` is the document the node runs, which tells what this change removes or renames.
pub fn problems(document: &Value, running: &Value) -> Vec<String> {
	let outbounds = document["outbounds"].as_array().map(Vec::as_slice).unwrap_or_default();
	let links = document["links"].as_array().map(Vec::as_slice).unwrap_or_default();
	let gone: Vec<&str> = running["outbounds"].as_array().into_iter().flatten().filter_map(|item| item["tag"].as_str()).filter(|tag| !outbounds.iter().any(|item| item["tag"] == *tag)).collect();
	let mut found = Vec::new();
	for (i, item) in outbounds.iter().enumerate() {
		let (at, Some(via)) = (format!("outbounds[{i}].via"), item["via"].as_str()) else {continue};
		if item["type"] != "socks5" {found.push(format!("{at}: only a socks5 outbound can go through another one"))}
		else if let Err(reason) = chain(outbounds, &gone, vec![item["tag"].as_str().unwrap_or_default()], via) {found.push(format!("{at}: {reason}"))}
	}
	for (i, link) in links.iter().enumerate() {
		let (at, Some(via)) = (format!("links[{i}].via"), link["via"].as_str()) else {continue};
		if link["peer"].is_null() {found.push(format!("{at}: only a link this node dials can go through an outbound"))}
		else if let Err(reason) = chain(outbounds, &gone, vec![], via) {found.push(format!("{at}: {reason}"))}
	}
	let backend_of = |tag: &str| document["exits"].as_array().into_iter().flatten().find(|exit| exit["tag"] == tag).and_then(|exit| exit["backend"]["type"].as_str());
	for (i, link) in links.iter().enumerate() {
		for (j, tag) in link["exits"].as_array().into_iter().flatten().filter_map(Value::as_str).enumerate() {
			match backend_of(tag) {
				Some("upstream") => found.push(format!("links[{i}].exits[{j}]: an upstream is another provider's account, not for the users of a third node")),
				Some("chain") if link["allow_chain"] != true => found.push(format!("links[{i}].exits[{j}]: a link leaves through another link only with allow_chain on")),
				_ => {}
			}
		}
	}
	let chained = |tag: &str| outbounds.iter().any(|item| item["tag"] == tag && !item["via"].is_null());
	for (i, exit) in document["exits"].as_array().into_iter().flatten().enumerate() {
		let (backend, Some(tag)) = (&exit["backend"], exit["backend"]["outbound"].as_str()) else {continue};
		if backend["type"] == "netstack" && !backend["unsupported"]["udp"].is_null() && !matches!(backend["unsupported"]["udp"].as_str(), Some("reject" | "drop")) && outbounds.iter().any(|item| item["tag"] == tag && item["type"] == "xray") {found.push(format!("exits[{i}].backend.unsupported.udp: an Xray outbound carries UDP itself, and while it is down the flow ends rather than leave this exit around it: choose reject or drop"))}
		if backend["type"] == "netstack" && backend["unsupported"]["udp"] == "direct" && chained(tag) {found.push(format!("exits[{i}].backend.unsupported.udp: direct UDP would leave from the node's own address around the chain of outbound {tag}: choose reject, drop or via"))}
	}
	for tag in gone {
		let users: Vec<(String, String)> = outbounds.iter().enumerate().filter(|(_, item)| item["via"] == tag).map(|(i, item)| (format!("outbounds[{i}].via"), format!("outbound {}", item["tag"].as_str().unwrap_or_default())))
			.chain(links.iter().enumerate().filter(|(_, link)| link["via"] == tag).map(|(i, link)| (format!("links[{i}].via"), format!("link {}", link["tag"].as_str().unwrap_or_default())))).collect();
		if let Some((at, _)) = users.first() {found.push(format!("{at}: the Through of {} names {tag}, which this change removes or renames: change it first", users.iter().map(|(_, name)| name.as_str()).collect::<Vec<_>>().join(", ")))}
	}
	found
}

#[cfg(test)]
mod tests {
	use super::problems;
	use serde_json::{json, Value};

	fn hops(count: usize) -> Value {
		let mut list = vec![json!({"tag": "h0", "type": "socks5", "server": "x:1"})];
		for i in 1..=count {list.push(json!({"tag": format!("h{i}"), "type": "socks5", "server": "x:1", "via": format!("h{}", i - 1)}))}
		json!({"outbounds": list})
	}

	#[test]
	fn a_chain_is_refused_when_it_loops_misses_or_leaves_out_a_socks5_outbound() {
		let outbounds = json!([{"tag": "a", "type": "socks5", "server": "x:1", "via": "b"}, {"tag": "b", "type": "socks5", "server": "x:2", "via": "a"}, {"tag": "d", "type": "direct"}, {"tag": "e", "type": "socks5", "server": "x:3", "via": "d"}, {"tag": "f", "type": "socks5", "server": "x:4", "via": "nope"}]);
		let found = problems(&json!({"outbounds": outbounds}), &json!({}));
		assert_eq!(found.len(), 4, "{found:?}");
		assert!(found[0].starts_with("outbounds[0].via: is in a loop"));
		assert!(found[1].starts_with("outbounds[1].via: is in a loop"));
		assert!(found[2].starts_with("outbounds[3].via: names no socks5 outbound"));
		assert!(found[3].starts_with("outbounds[4].via: names no socks5 outbound"));
	}

	#[test]
	fn a_chain_of_eight_hops_is_allowed_and_nine_is_not() {
		assert!(problems(&hops(8), &json!({})).is_empty());
		let found = problems(&hops(9), &json!({}));
		assert_eq!(found, vec!["outbounds[9].via: goes through more than 8 hops, the most a chain may have".to_string()]);
	}

	#[test]
	fn direct_udp_is_refused_only_for_an_exit_whose_outbound_has_a_via() {
		let document = json!({"outbounds": [{"tag": "p1", "type": "socks5", "server": "x:1"}, {"tag": "p2", "type": "socks5", "server": "x:2", "via": "p1"}, {"tag": "p3", "type": "socks5", "server": "x:3"}], "exits": [{"tag": "a", "backend": {"type": "netstack", "outbound": "p2", "unsupported": {"udp": "direct"}}}, {"tag": "b", "backend": {"type": "netstack", "outbound": "p1", "unsupported": {"udp": "direct"}}}, {"tag": "c", "backend": {"type": "netstack", "outbound": "p3", "unsupported": {"udp": "direct"}}}, {"tag": "d", "backend": {"type": "netstack", "outbound": "p2", "unsupported": {"udp": "reject"}}}]});
		let found = problems(&document, &json!({}));
		assert_eq!(found.len(), 1, "{found:?}");
		assert!(found[0].starts_with("exits[0].backend.unsupported.udp: direct UDP"));
	}

	#[test]
	fn direct_and_via_udp_are_refused_for_an_exit_whose_outbound_is_xray() {
		let outbounds = json!([{"tag": "x", "type": "xray", "protocol": "trojan", "server": "x:1"}]);
		let exit = |udp: Value| json!({"tag": "e", "backend": {"type": "netstack", "outbound": "x", "unsupported": {"udp": udp}}});
		let found = problems(&json!({"outbounds": outbounds, "exits": [exit(json!("direct")), exit(json!({"via": "other"})), exit(json!("drop")), exit(json!("reject"))]}), &json!({}));
		assert_eq!(found.len(), 2);
		assert!(found[0].starts_with("exits[0].backend.unsupported.udp: an Xray outbound"));
		assert!(found[1].starts_with("exits[1].backend.unsupported.udp: an Xray outbound"));
	}

	#[test]
	fn a_link_leaves_through_a_chain_exit_only_with_allow_chain_and_never_through_an_upstream() {
		let exits = json!([{"tag": "own", "backend": {"type": "netstack"}}, {"tag": "onward", "backend": {"type": "chain", "links": ["l2"]}}, {"tag": "theirs", "backend": {"type": "upstream", "upstream": "u"}}]);
		let link = |list: Value, chain: Value| json!({"tag": "l", "exits": list, "allow_chain": chain});
		assert!(problems(&json!({"exits": exits, "links": [link(json!(["own", "onward"]), json!(true))]}), &json!({})).is_empty());
		assert_eq!(problems(&json!({"exits": exits, "links": [link(json!(["own", "onward"]), Value::Null)]}), &json!({})), vec!["links[0].exits[1]: a link leaves through another link only with allow_chain on".to_string()]);
		assert_eq!(problems(&json!({"exits": exits, "links": [link(json!(["theirs"]), json!(true))]}), &json!({})).len(), 1);
	}

	#[test]
	fn only_a_dialed_link_takes_a_via_and_a_removed_outbound_names_its_users() {
		let before = json!({"outbounds": [{"tag": "p", "type": "socks5", "server": "x:1"}, {"tag": "q", "type": "socks5", "server": "x:2", "via": "p"}], "links": [{"tag": "l", "peer": {}, "via": "p"}]});
		assert!(problems(&before, &before).is_empty());
		let after = json!({"outbounds": [{"tag": "r", "type": "socks5", "server": "x:1"}, {"tag": "q", "type": "socks5", "server": "x:2", "via": "p"}], "links": [{"tag": "l", "peer": {}, "via": "p"}, {"tag": "m", "inbound": "in", "via": "p"}]});
		assert_eq!(problems(&after, &before), vec!["links[1].via: only a link this node dials can go through an outbound".to_string(), "outbounds[1].via: the Through of outbound q, link l, link m names p, which this change removes or renames: change it first".to_string()]);
	}
}
