//! The nodes the panel manages: node 1 on its own socket and the others through the links of node 1 that it manages.
use crate::{app::{App, Node, LOCAL}, crypto::{now, random}, http::{ok, Body, Ctx, Failure}, nodecfg, subs};
use axum::{extract::{Path, Query, State}, http::StatusCode, response::Response, Extension};
use ipnet::Ipv4Net;
use rusqlite::{params, Connection, OptionalExtension};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use std::{collections::{HashMap, HashSet}, sync::{atomic::Ordering, Arc}, time::Duration};
use veilway_proto::subscription::payload::PROFILES_MAX;

/// The links of node 1 by tag, each with its state and its id as node 1 reports them. None when node 1 cannot be reached, which also means no remote node can.
pub async fn link_states(app: &App) -> Option<HashMap<String, (String, String)>> {
	let (200, _, body) = crate::node::exchange(app, "GET", "/v1/links", None, None, Duration::from_secs(20)).await.ok()? else {return None};
	let links = serde_json::from_slice::<Value>(&body).ok()?;
	Some(links["links"].as_array()?.iter().filter_map(|link| Some((link["tag"].as_str()?.to_string(), (link["state"].as_str()?.to_string(), link_id_of(link))))).collect())
}

/// A link's id as text, the form the panel keeps it in.
fn link_id_of(link: &Value) -> String {link["id"].as_str().map_or_else(|| link["id"].to_string(), str::to_string)}

/// The nodes that can be asked now: node 1 always, a remote node while the link of node 1 that reaches it is up and still has the id the node was added with. A node that is not up is skipped without a request, so it holds up nothing, and the time it went down is kept for the pages. A link with another id is refused, and the node keeps that as its last error until it is added again.
pub async fn up(app: &App) -> HashSet<i64> {
	let bound: Vec<(i64, Option<String>, Option<String>)> = app.db.call(|db| db.prepare("select id, link_tag, link_id from nodes order by id")?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?.collect::<rusqlite::Result<_>>()).await.ok().and_then(Result::ok).unwrap_or_default();
	let states = if bound.len() > 1 {link_states(app).await.unwrap_or_default()} else {HashMap::new()};
	let at = now();
	let mut ready = HashSet::new();
	for (id, tag, link_id) in bound {
		let link = tag.as_ref().and_then(|tag| states.get(tag));
		let reused = id != LOCAL.0 && link.is_some_and(|(_, found)| Some(found) != link_id.as_ref());
		let usable = id == LOCAL.0 || (!reused && link.is_some_and(|(state, _)| state == "up"));
		if reused {
			let refused = app.db.call(move |db| db.execute("update nodes set last_error = ? where id = ? and last_error is not ?", params![crate::node::LINK_REUSED, id, crate::node::LINK_REUSED])).await;
			if matches!(refused, Ok(Ok(1))) {tracing::warn!("node {id}: its link {} is not the one it was added with, so it is not used until it is added again", tag.unwrap_or_default())}
		}
		let state = app.node(Node(id));
		let mut since = state.down_since.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		*since = if usable {None} else {since.or(Some(at))};
		if usable {ready.insert(id);}
	}
	ready
}

#[derive(Serialize, JsonSchema)]
pub struct NodeOut {
	pub id: i64,
	pub name: String,
	/// Short and lowercase, put in front of this node's profile ids.
	pub slug: String,
	pub place: i64,
	/// The tag of the link of node 1 that reaches the node. Null for node 1.
	pub link: Option<String>,
	/// The state of that link as node 1 reports it, null for node 1 or when node 1 cannot say.
	pub link_state: Option<String>,
	/// Since when the link has not been up, Unix seconds, null while it is.
	pub down_since: Option<i64>,
	/// The address pool devices get their address at this node from.
	pub pool_v4: String,
	/// Whether what the node counts adds to the users' totals.
	pub counted: bool,
	/// The most the node's counters may grow, in bytes per second. Null is the default of 1.25 GB/s.
	pub max_rate: Option<i64>,
	/// The revision of what the panel wants the node to have, and the last one the node took. A node whose applied revision is lower is behind.
	pub wanted_rev: i64, pub applied_rev: i64,
	/// Whether its users are still to be pushed.
	pub behind: bool,
	pub last_seen: Option<i64>,
	pub last_error: Option<String>,
	pub version: Option<String>,
	/// The devices that have an address in its pool.
	pub devices: i64,
	/// The relays of this node, with the rules of node 1's. Each subscription carries them on this node's profiles for the accounts they reach, as node 1's are carried on its own.
	pub relays: Vec<nodecfg::Relay>,
}

#[derive(Serialize, JsonSchema)]
pub struct NodesOut {pub nodes: Vec<NodeOut>}

fn read(db: &Connection, app: &App, states: &HashMap<String, (String, String)>) -> rusqlite::Result<Vec<NodeOut>> {
	let rows = db.prepare("select id, name, slug, place, link_tag, pool_v4, counted, max_rate, wanted_rev, applied_rev, last_seen, last_error, version, (select count(*) from device_addresses where node_id = nodes.id), relays from nodes order by id")?.query_map([], |row| Ok(NodeOut {id: row.get(0)?, name: row.get(1)?, slug: row.get(2)?, place: row.get(3)?, link: row.get(4)?, link_state: None, down_since: None, pool_v4: row.get(5)?, counted: row.get(6)?, max_rate: row.get(7)?, wanted_rev: row.get(8)?, applied_rev: row.get(9)?, behind: false, last_seen: row.get(10)?, last_error: row.get(11)?, version: row.get(12)?, devices: row.get(13)?, relays: serde_json::from_str(&row.get::<_, String>(14)?).unwrap_or_default()}))?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(rows.into_iter().map(|mut node| {
		let state = app.node(Node(node.id));
		node.link_state = node.link.as_ref().and_then(|tag| states.get(tag)).map(|(state, _)| state.clone());
		node.down_since = *state.down_since.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		node.behind = state.dirty.load(Ordering::Relaxed) || node.applied_rev < node.wanted_rev;
		node
	}).collect())
}

pub async fn list(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let states = link_states(&app).await.unwrap_or_default();
	let held = app.clone();
	ok(&NodesOut {nodes: app.db.call(move |db| read(db, &held, &states)).await??})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeIn {
	/// 1 to 32 characters, without spaces around it.
	pub name: String,
	/// The tag of a link of node 1 that node 1 manages (`manage: "peer"`), made by the link pairing. A link already bound to a node is refused.
	pub link: String,
	/// The IPv4 range devices get their address at this node from.
	pub pool_v4: String,
	pub place: Option<i64>,
}

/// Lowercase letters, digits and dashes of the name, for profile ids. A name with none of them becomes `node`.
fn slug_of(name: &str) -> String {
	let slug: String = name.to_lowercase().chars().map(|letter| if letter.is_ascii_alphanumeric() {letter} else {'-'}).collect::<String>().split('-').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-");
	if slug.is_empty() {"node".into()} else {slug.chars().take(24).collect()}
}

fn name_ok(name: &str) -> bool {!name.is_empty() && name == name.trim() && name.chars().count() <= 32}

/// Adds a remote node bound to a managed link of node 1. Every device of every user that may use all nodes gets an address in its pool, and the node is pushed to at once. A node whose profiles would make an account hold more than 64 is refused, and nothing of it is kept.
pub async fn add(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<NodeIn>) -> Result<Response, Failure> {
	if !name_ok(&input.name) {return Err(Failure::bad("name is 1 to 32 characters, without spaces around it."))}
	let pool: Ipv4Net = input.pool_v4.parse().map_err(|_| Failure::bad("pool_v4 is an IPv4 range such as 10.67.0.0/24."))?;
	if pool.prefix_len() > 29 {return Err(Failure::bad("pool_v4 needs room for a gateway and at least five devices: a /29 or larger."))}
	let (status, body) = crate::node::request(&app, LOCAL, "GET", "/v1/links", None, None).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	let links: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
	let link = links["links"].as_array().filter(|_| status == 200).and_then(|list| list.iter().find(|link| link["tag"] == input.link.as_str())).ok_or_else(|| Failure::bad("Node 1 has no link with that tag."))?;
	if link["manage"] != "peer" {return Err(Failure::bad("Node 1 does not manage that link. Pair it as a managed link first."))}
	let link_id = link_id_of(link);
	let (name, tag, pool_text, place, held) = (input.name.clone(), input.link.clone(), input.pool_v4.clone(), input.place.unwrap_or(0), app.clone());
	let id = app.db.call(move |db| -> Result<i64, Failure> {
		if db.query_row("select exists (select 1 from nodes where link_tag = ?)", [&tag], |row| row.get::<_, bool>(0))? {return Err(Failure::conflict("That link already reaches a node."))}
		let base = slug_of(&name);
		let mut slug = base.clone();
		for at in 2.. {
			if !db.query_row("select exists (select 1 from nodes where slug = ?)", [&slug], |row| row.get::<_, bool>(0))? {break}
			slug = format!("{base}-{at}");
		}
		db.execute("insert into nodes (uid, name, slug, link_id, link_tag, place, pool_v4, created) values (?, ?, ?, ?, ?, ?, ?, ?)", params![random::<16>().as_slice(), name, slug, link_id, tag, place, pool_text, now()])?;
		let id = db.last_insert_rowid();
		subs::add_addresses(db, None)?;
		Ok(id)
	}).await??;
	// What the node gives is known only once it can be read. One that cannot be is kept unchecked, and a document leaves out the profiles that do not fit.
	let added = match nodecfg::running(&app, Node(id)).await {Ok((_, _, document)) => nodecfg::remote_profiles(&app, Node(id), &document).await.ok().and_then(|found| found.as_array().map(Vec::len)), Err(_) => None};
	if let Some(added) = added {
		let (own, node) = (app.settings().profiles.len(), Node(id));
		let refused = app.db.call(move |db| -> rusqlite::Result<Option<usize>> {
			let would = subs::most_held(db, own, Some(node))? + added;
			if added == 0 || would <= PROFILES_MAX {return Ok(None)}
			db.execute("delete from nodes where id = ?", [id])?;
			Ok(Some(would))
		}).await??;
		if let Some(would) = refused {
			app.drop_node(node);
			return Err(subs::too_many(would))
		}
	} else {tracing::warn!("node {id} could not be read, so it was added without a check of how many profiles it gives")}
	app.db.audit(&ctx.actor, &ctx.source, "node.add", &format!("node:{id}"), &format!("{} through link {}", input.name, input.link)).await;
	held.add_node(Node(id));
	let pushed = held.clone();
	tokio::spawn(async move {let _ = crate::node::sync(&pushed, Node(id)).await;});
	one(&app, id).await
}

async fn one(app: &Arc<App>, id: i64) -> Result<Response, Failure> {
	let states = link_states(app).await.unwrap_or_default();
	let held = app.clone();
	ok(&app.db.call(move |db| read(db, &held, &states)).await??.into_iter().find(|node| node.id == id).ok_or_else(|| Failure::missing("node"))?)
}

fn double<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {Ok(Some(Option::deserialize(d)?))}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodePatch {
	pub name: Option<String>,
	pub place: Option<i64>,
	/// Only for a remote node that no device has an address at yet: node 1's pool is the `pool_v4` setting.
	pub pool_v4: Option<String>,
	/// False stops its usage from adding to the users' totals, for a node that reports false usage. Its users stay on it.
	pub counted: Option<bool>,
	/// The most its counters may grow, in bytes per second, or null for the default.
	#[serde(default, deserialize_with = "double")] pub max_rate: Option<Option<i64>>,
	/// The relays of this remote node, which node 1's own rules check. Each one's addresses reach the profiles of this node for the accounts it names, by id or by group, or for everyone when it names neither. Node 1's relays are set in the settings.
	pub relays: Option<Vec<nodecfg::Relay>>,
}

pub async fn patch(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Body(input): Body<NodePatch>) -> Result<Response, Failure> {
	if input.name.as_deref().is_some_and(|name| !name_ok(name)) {return Err(Failure::bad("name is 1 to 32 characters, without spaces around it."))}
	if input.max_rate.is_some_and(|rate| rate.is_some_and(|rate| rate < 1)) {return Err(Failure::bad("max_rate is a number of bytes per second, 1 or more, or null."))}
	if let Some(pool) = &input.pool_v4 {if pool.parse::<Ipv4Net>().map_or(true, |pool| pool.prefix_len() > 29) {return Err(Failure::bad("pool_v4 is an IPv4 range of a /29 or larger."))}}
	if let Some(relays) = &input.relays {nodecfg::check_relays(relays).map_err(Failure::bad)?}
	let dirty = app.node(Node(id)).dirty.clone();
	app.db.call(move |db| -> Result<(), Failure> {
		let tx = db.transaction()?;
		if tx.query_row("select count(*) from nodes where id = ?", [id], |row| row.get::<_, i64>(0))? == 0 {return Err(Failure::missing("node"))}
		if let Some(pool) = &input.pool_v4 {
			if id == LOCAL.0 {return Err(Failure::bad("The pool of node 1 is the pool_v4 setting."))}
			if tx.query_row("select exists (select 1 from device_addresses where node_id = ?)", [id], |row| row.get::<_, bool>(0))? {return Err(Failure::conflict("A device already has an address in this pool, so it cannot change."))}
			tx.execute("update nodes set pool_v4 = ? where id = ?", params![pool, id])?;
		}
		if let Some(name) = &input.name {tx.execute("update nodes set name = ? where id = ?", params![name, id])?;}
		if let Some(place) = input.place {tx.execute("update nodes set place = ? where id = ?", params![place, id])?;}
		if let Some(counted) = input.counted {tx.execute("update nodes set counted = ? where id = ?", params![counted, id])?;}
		if let Some(rate) = input.max_rate {tx.execute("update nodes set max_rate = ? where id = ?", params![rate, id])?;}
		if let Some(relays) = &input.relays {
			if id == LOCAL.0 {return Err(Failure::bad("The relays of node 1 are set in Settings."))}
			let known: Vec<i64> = tx.prepare("select id from users")?.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
			if let Some(user) = relays.iter().flat_map(|relay| relay.users.iter().copied()).find(|user| !known.contains(user)) {return Err(Failure::bad(format!("A relay names the account {user}, which does not exist. Take it off the relay first.")))}
			tx.execute("update nodes set relays = ? where id = ?", params![serde_json::to_string(relays).map_err(Failure::internal)?, id])?;
		}
		crate::db::audit(&tx, &ctx.actor, &ctx.source, "node.update", &format!("node:{id}"), &format!("{}{}{}", if input.counted == Some(false) {"counting stopped"} else if input.counted == Some(true) {"counting started"} else {"edited"}, if input.pool_v4.is_some() {", pool changed"} else {""}, if input.relays.is_some() {", relays changed"} else {""}));
		tx.commit()?;
		Ok(())
	}).await??;
	// A pool or a name changes what the node is given.
	dirty.store(true, Ordering::Relaxed);
	one(&app, id).await
}

#[derive(Serialize, JsonSchema)]
pub struct Synced {pub synced: bool, pub error: Option<String>}

/// Pushes the users to one node now. A node that cannot be reached answers with the reason and stays behind.
pub async fn sync(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	if !app.nodes().contains(&Node(id)) {return Err(Failure::missing("node"))}
	let held = app.clone();
	match tokio::spawn(async move {crate::node::sync(&held, Node(id)).await}).await.map_err(Failure::internal)? {
		Ok(()) => ok(&Synced {synced: true, error: None}),
		Err(error) => ok(&Synced {synced: false, error: Some(error)}),
	}
}

#[derive(Deserialize, JsonSchema)]
pub struct RemoveQuery {
	/// True when the node was taken or is gone: the panel does not ask it to empty itself and only removes the link from node 1.
	pub taken: Option<bool>,
}

#[derive(Serialize, JsonSchema)]
pub struct Removed {pub removed: bool}

/// Removes a remote node. Unless it was taken, the node is first asked to apply a config with no users, no Xray clients and without the link that manages it, the one change it takes of that link. Then the link leaves node 1's config, and the node's rows, addresses and counts go. A node that cannot be asked is kept, and `taken` removes it anyway. A node emptied by an earlier call that failed at node 1 is not asked again.
pub async fn remove(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<i64>, Query(query): Query<RemoveQuery>) -> Result<Response, Failure> {
	if id == LOCAL.0 {return Err(Failure::bad("Node 1 is the node on the panel's own socket and cannot be removed."))}
	let (tag, emptied) = app.db.call(move |db| db.query_row("select link_tag, emptied from nodes where id = ?", [id], |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, bool>(1)?))).optional()).await??.ok_or_else(|| Failure::missing("node"))?;
	let node = Node(id);
	let _turn = app.turn(node).await;
	if query.taken != Some(true) && !emptied {
		let (revision, _, mut document) = nodecfg::running(&app, node).await?;
		document["users"] = json!([]);
		if let Some(links) = document["links"].as_array_mut() {links.retain(|link| link["manage"] != "by_peer");}
		for inbound in document.get_mut("xray").and_then(|xray| xray.get_mut("inbounds")).and_then(Value::as_array_mut).into_iter().flatten() {inbound["clients"] = json!([]);}
		// The node answers before it empties itself, and the answer comes back through the link it removes: one that is lost may still have emptied it.
		let (status, body) = nodecfg::call(&app, node, "PUT", "/v1/config", Some(&revision), Some(&document)).await.map_err(|failure| Failure {message: format!("{} The node may have emptied itself all the same: if it no longer answers, remove it as taken.", failure.message), ..failure})?;
		if status != 200 && status != 202 {return Err(Failure::new(StatusCode::BAD_GATEWAY, "node_refused", format!("The node answered {status} when asked to empty itself: {}. If it was taken or is gone, remove it as taken.", body.to_string().chars().take(300).collect::<String>())))}
		// Kept, so that a removal that then fails at node 1 is retried without asking the node again: once emptied, it no longer serves management through its link.
		app.db.call(move |db| db.execute("update nodes set emptied = 1 where id = ?", [id])).await??;
	}
	if let Some(tag) = tag {
		let (revision, _, mut document) = nodecfg::running(&app, LOCAL).await?;
		let before = document["links"].as_array().map_or(0, Vec::len);
		if let Some(links) = document["links"].as_array_mut() {links.retain(|link| link["tag"] != tag.as_str());}
		if document["links"].as_array().map_or(0, Vec::len) != before {
			let _local = app.turn(LOCAL).await;
			nodecfg::apply(&app, LOCAL, &ctx, document, &revision, &tag).await?;
		}
	}
	let source = ctx.source.clone();
	app.db.call(move |db| -> rusqlite::Result<()> {
		db.execute("delete from nodes where id = ?", [id])?;
		// A user who was limited to this node alone is left with nothing to use, which is for the operator to see: every list names only nodes that exist.
		let users: Vec<(i64, String)> = db.prepare("select id, nodes from users where nodes != '\"all\"'")?.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
		for (user, nodes) in users {
			let kept: Vec<i64> = serde_json::from_str::<Vec<i64>>(&nodes).unwrap_or_default().into_iter().filter(|kept| *kept != id).collect();
			db.execute("update users set nodes = ? where id = ?", params![serde_json::to_string(&kept).unwrap_or_default(), user])?;
		}
		crate::db::audit(db, &ctx.actor, &source, "node.remove", &format!("node:{id}"), if query.taken == Some(true) {"taken"} else {"emptied first"});
		Ok(())
	}).await??;
	app.drop_node(node);
	ok(&Removed {removed: true})
}

/// A node that is not up cannot have its own settings changed: its config is read and written through the link, so an edit is refused with the reason, and users and devices go on saving and reach the node when it is back.
pub(crate) async fn require_up(app: &Arc<App>, node: Node) -> Result<(), Failure> {
	if up(app).await.contains(&node.0) {return Ok(())}
	let since = *app.node(node).down_since.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	Err(Failure::new(StatusCode::SERVICE_UNAVAILABLE, "node_offline", format!("This node is offline{}. Users and devices can change now and reach it when it is back, but its own settings cannot be edited until then.", since.map_or(String::new(), |since| format!(" since {since}")))))
}

pub async fn get_config(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	if !app.nodes().contains(&Node(id)) {return Err(Failure::missing("node"))}
	let (revision, generation, mut document) = nodecfg::running(&app, Node(id)).await?;
	document.as_object_mut().map(|document| document.remove("users"));
	ok(&json!({"revision": revision, "generation": generation, "document": document}))
}

pub async fn put_section(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path((id, section)): Path<(i64, String)>, Body(input): Body<nodecfg::SectionIn>) -> Result<Response, Failure> {
	if !app.nodes().contains(&Node(id)) {return Err(Failure::missing("node"))}
	require_up(&app, Node(id)).await?;
	nodecfg::section_put(app, Node(id), ctx, section, input).await
}
