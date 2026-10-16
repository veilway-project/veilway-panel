//! Named subscription endpoints: the list in the settings, the resolution of an account's endpoint (its own, then its group's, then the default) and the moves between endpoints. A move is the signed `main_endpoint` of "Moving the main endpoint": the panel keeps answering on the old endpoint and the documents it signs name the new one.
use crate::{app::{store_settings, App, Endpoint, Settings}, crypto::now, db::audit, http::{ok, Body, Ctx, Failure}, subs::UserRow, users::name_ok};
use axum::{extract::{Path, State}, response::Response, Extension};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use veilway_proto::subscription::{Url, LINK_URL_MAX};

pub const ENDPOINTS_MAX: usize = 16;
/// An account counts as still refreshing on an endpoint when it did so within this many seconds.
const RECENT: i64 = 30 * 86_400;

/// The URL as the app reads it: `https` by its chain or with pins, or `http` for a plain endpoint.
pub fn read(endpoint: &Endpoint) -> Option<Url> {
	if endpoint.url.starts_with("http://") {Url::plain(&endpoint.url, LINK_URL_MAX, false, false)} else if endpoint.pins.is_empty() {Url::parse(&endpoint.url, LINK_URL_MAX, false, false)} else {Url::pinned(&endpoint.url, LINK_URL_MAX, false, false)}
}

impl Settings {
	pub fn named(&self, name: &str) -> Option<&Endpoint> {self.endpoints.iter().find(|endpoint| endpoint.name == name)}
	pub fn default_endpoint(&self) -> Option<&Endpoint> {self.named(&self.default_endpoint).or(self.endpoints.first())}
	/// The endpoint of an account and where it came from: "user", "group" or "default". A name that no longer exists counts as unset.
	pub fn resolve(&self, own: Option<&str>, groups: &[String]) -> Option<(&Endpoint, &'static str)> {
		own.and_then(|name| self.named(name)).map(|endpoint| (endpoint, "user"))
			.or_else(|| groups.iter().find_map(|group| self.group_endpoints.get(group).and_then(|name| self.named(name))).map(|endpoint| (endpoint, "group")))
			.or_else(|| self.default_endpoint().map(|endpoint| (endpoint, "default")))
	}
	/// The endpoint a request came in on, by the Host header it carried: a host with or without its port.
	pub fn by_host(&self, host: &str) -> Option<&Endpoint> {
		let host = host.to_ascii_lowercase();
		self.endpoints.iter().find(|endpoint| read(endpoint).is_some_and(|url| [url.authority(), url.host().to_string()].iter().any(|found| *found == host) || (url.authority() == format!("{host}:{}", if url.is_plain() {80} else {443}))))
	}
}

/// The rules of the endpoints and of what points at them. The URL rules are the ones a link and a signed document are read by.
pub fn validate(settings: &Settings) -> Result<(), String> {
	if settings.endpoints.len() > ENDPOINTS_MAX {return Err(format!("endpoints has at most {ENDPOINTS_MAX} entries."))}
	if !(30..=365).contains(&settings.gateway_retired_days) {return Err("gateway_retired_days is 30 to 365.".into())}
	let mut seen: Vec<(&str, String)> = Vec::new();
	for endpoint in &settings.endpoints {
		let name = &endpoint.name;
		if !name_ok(name, false) {return Err(format!("The endpoint name {name:?} is 1 to 64 characters of a-z, 0-9, dash and underscore, starting with a letter or digit."))}
		if endpoint.pins.len() > 2 || endpoint.pins.iter().any(|pin| STANDARD.decode(pin).map_or(true, |bytes| bytes.len() != 32)) || (endpoint.pins.len() == 2 && endpoint.pins[0] == endpoint.pins[1]) {return Err(format!("The pins of {name} are one or two different SHA-256 pins in standard base64."))}
		if endpoint.url.starts_with("http://") && !endpoint.pins.is_empty() {return Err(format!("{name} is an http endpoint, and pins apply only to https."))}
		if !endpoint.url.starts_with("http://") && !endpoint.url.starts_with("https://") {return Err(format!("The URL of {name} starts with https:// or http://."))}
		let Some(url) = read(endpoint) else {
			return Err(if endpoint.pins.is_empty() && !endpoint.url.starts_with("http://") && Url::pinned(&endpoint.url, LINK_URL_MAX, false, false).is_some() {format!("{name} has an IP address as its host, which means a self-signed certificate. Add its pin, so that the app checks the endpoint by the pin alone.")} else {format!("The URL of {name} is not one the app can read: https or http, a host name or an IP address, at most {LINK_URL_MAX} characters, no user, query or fragment.")})
		};
		if !endpoint.url[endpoint.url.find("://").map_or(0, |at| at + 3)..].contains('/') {return Err(format!("The URL of {name} needs a path, like https://host.example/s."))}
		let found = url.authority();
		if let Some((other, _)) = seen.iter().find(|(other, held)| *other == name || *held == found) {return Err(format!("{name} and {other} cannot share a name or a host and port. A document tells its endpoint by host and port, so each endpoint needs its own."))}
		seen.push((name, found));
	}
	if !settings.endpoints.is_empty() && settings.named(&settings.default_endpoint).is_none() {return Err(format!("default_endpoint {:?} is not one of the endpoints.", settings.default_endpoint))}
	if settings.group_endpoints.len() > 256 {return Err("group_endpoints has at most 256 entries.".into())}
	for (group, name) in &settings.group_endpoints {
		if !name_ok(group, true) {return Err(format!("The group name {group:?} is 1 to 64 characters of a-z, 0-9, dot, dash and underscore."))}
		if settings.named(name).is_none() {return Err(format!("The group {group} points at {name:?}, which is not one of the endpoints."))}
	}
	Ok(())
}

/// Refuses settings that drop an endpoint an account still has.
pub fn in_use(connection: &Connection, settings: &Settings) -> Result<(), String> {
	let names: Vec<String> = connection.prepare("select distinct endpoint from users where endpoint is not null").map_err(|error| error.to_string())?.query_map([], |row| row.get(0)).map_err(|error| error.to_string())?.filter_map(Result::ok).collect();
	match names.into_iter().find(|name| settings.named(name).is_none()) {
		Some(name) => Err(format!("Accounts still have the endpoint {name:?}. Move them to another endpoint first.")),
		None => Ok(()),
	}
}

/// Every account as (id, name, groups, own endpoint).
fn people(connection: &Connection) -> rusqlite::Result<Vec<(i64, String, Vec<String>, Option<String>)>> {
	connection.prepare("select id, name, groups, endpoint from users order by id")?.query_map([], |row| Ok((row.get(0)?, row.get(1)?, serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(), row.get(3)?)))?.collect()
}

#[derive(Serialize, JsonSchema)]
pub struct EndpointRow {
	pub name: String, pub url: String, pub pins: Vec<String>, pub default: bool,
	/// A plain http endpoint: the network can tell that the app is used, now and later in its records. The exchange itself stays sealed.
	pub plain: bool,
	/// Accounts whose links and documents use this endpoint, by the resolution.
	pub users: i64,
	/// Of those, the ones given this endpoint by name.
	pub assigned: i64,
	/// Accounts that resolve to another endpoint now and refreshed on this one in the last 30 days: moved, and not there yet. The endpoint can be retired when this is none.
	pub still_here: i64,
}

#[derive(Serialize, JsonSchema)]
pub struct GroupRow {pub name: String, pub users: i64, pub endpoint: Option<String>}

#[derive(Serialize, JsonSchema)]
pub struct EndpointsOut {pub default: String, pub endpoints: Vec<EndpointRow>, pub groups: Vec<GroupRow>}

pub async fn list(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let settings = app.settings();
	let at = now();
	let (everyone, used) = app.db.call(move |db| -> rusqlite::Result<_> {
		let used = db.prepare("select endpoint, user_id from endpoint_use where last_at >= ?")?.query_map([at - RECENT], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?.collect::<Result<Vec<_>, _>>()?;
		Ok((people(db)?, used))
	}).await??;
	let (mut counts, mut groups): (BTreeMap<String, (i64, i64)>, BTreeMap<String, i64>) = (BTreeMap::new(), settings.group_endpoints.keys().map(|group| (group.clone(), 0)).collect());
	let mut resolved = BTreeMap::new();
	for (id, _, held, own) in &everyone {
		if let Some((endpoint, source)) = settings.resolve(own.as_deref(), held) {
			let entry = counts.entry(endpoint.name.clone()).or_default();
			entry.0 += 1;
			entry.1 += i64::from(source == "user");
			resolved.insert(*id, endpoint.name.clone());
		}
		for group in held {*groups.entry(group.clone()).or_default() += 1;}
	}
	ok(&EndpointsOut {
		default: settings.default_endpoint().map(|endpoint| endpoint.name.clone()).unwrap_or_default(),
		endpoints: settings.endpoints.iter().map(|endpoint| EndpointRow {name: endpoint.name.clone(), url: endpoint.url.clone(), pins: endpoint.pins.clone(), default: settings.default_endpoint().is_some_and(|default| default.name == endpoint.name), plain: endpoint.url.starts_with("http://"), users: counts.get(&endpoint.name).map_or(0, |found| found.0), assigned: counts.get(&endpoint.name).map_or(0, |found| found.1), still_here: used.iter().filter(|(name, id)| *name == endpoint.name && resolved.get(id).is_some_and(|now| *now != endpoint.name)).count() as i64}).collect(),
		groups: groups.into_iter().map(|(name, users)| GroupRow {endpoint: settings.group_endpoints.get(&name).cloned(), name, users}).collect(),
	})
}

#[derive(Serialize, JsonSchema)]
pub struct UserEndpoint {
	/// The endpoint given to the account by name, null when its group's or the default applies.
	pub own: Option<String>,
	/// The endpoint in use for the account, null while no endpoint is set.
	pub resolved: Option<String>,
	/// "user", "group" or "default".
	pub source: String,
	pub url: Option<String>,
	pub plain: bool,
}

pub async fn user(State(app): State<Arc<App>>, Path(id): Path<i64>) -> Result<Response, Failure> {
	let (user, own) = app.db.call(move |db| -> rusqlite::Result<_> {Ok((UserRow::load(db, id)?, db.query_row("select endpoint from users where id = ?", [id], |row| row.get::<_, Option<String>>(0))?))}).await??;
	let settings = app.settings();
	let found = settings.resolve(own.as_deref(), &serde_json::from_str::<Vec<String>>(&user.groups).unwrap_or_default());
	ok(&UserEndpoint {own, resolved: found.map(|(endpoint, _)| endpoint.name.clone()), source: found.map_or("default", |(_, source)| source).into(), url: found.map(|(endpoint, _)| endpoint.url.clone()), plain: found.is_some_and(|(endpoint, _)| endpoint.url.starts_with("http://"))})
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveIn {
	/// The accounts to move: one, a selection or many. Give this or `group`.
	pub users: Option<Vec<i64>>,
	/// The group to move: sets the endpoint of the group, which every member without an endpoint of their own follows.
	pub group: Option<String>,
	/// The endpoint to move to. Null takes the accounts' own choice away (they follow their group or the default), or the group's.
	pub endpoint: Option<String>,
	/// Only count: say who moves and who stays, and change nothing.
	#[serde(default)] pub dry_run: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct MoveOut {
	pub applied: bool,
	/// Accounts whose endpoint changes. Their next document names the new endpoint, and the app asks its user once.
	pub moving: i64,
	/// Accounts the request names (or the group holds) whose endpoint stays.
	pub staying: i64,
	/// Of those who move, the ones whose endpoint is checked another way at the new one (chain, pins or plain http), which the app says when it asks.
	pub changes_check: i64,
	/// Of those who move, the ones moving to a plain http endpoint.
	pub to_plain: i64,
	pub names: Vec<String>,
}

pub async fn move_users(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<MoveIn>) -> Result<Response, Failure> {
	let settings = app.settings();
	if input.endpoint.as_deref().is_some_and(|name| settings.named(name).is_none()) {return Err(Failure::bad("endpoint is the name of one of the endpoints, or null."))}
	if input.users.as_ref().is_some_and(|ids| ids.len() > 1000) {return Err(Failure::bad("A move takes at most 1000 accounts."))}
	if input.group.as_deref().is_some_and(|group| !name_ok(group, true)) {return Err(Failure::bad("group is a group name."))}
	if input.users.is_some() == input.group.is_some() {return Err(Failure::bad("Give users or group, not both and not neither."))}
	let (dry, cache) = (input.dry_run, app.settings.clone());
	let out = app.db.call(move |db| -> Result<MoveOut, Failure> {
		let before = settings;
		let mut later = before.clone();
		let everyone = people(db)?;
		let mut picks: BTreeMap<i64, Option<String>> = BTreeMap::new();
		let scope: Vec<&(i64, String, Vec<String>, Option<String>)> = match (&input.users, &input.group) {
			(Some(ids), None) => {
				if let Some(missing) = ids.iter().find(|id| !everyone.iter().any(|found| found.0 == **id)) {return Err(Failure::bad(format!("There is no user {missing}.")))}
				for id in ids {picks.insert(*id, input.endpoint.clone());}
				everyone.iter().filter(|found| ids.contains(&found.0)).collect()
			}
			(None, Some(group)) => {
				match &input.endpoint {Some(name) => later.group_endpoints.insert(group.clone(), name.clone()), None => later.group_endpoints.remove(group)};
				everyone.iter().filter(|found| found.2.contains(group)).collect()
			}
			_ => return Err(Failure::bad("Give users or group, not both and not neither.")),
		};
		let (mut moving, mut changes_check, mut to_plain, mut names) = (0, 0, 0, Vec::new());
		for (id, name, groups, own) in &scope {
			let (Some((was, _)), Some((is, _))) = (before.resolve(own.as_deref(), groups), later.resolve(picks.get(id).unwrap_or(own).as_deref(), groups)) else {continue};
			if was.name == is.name {continue}
			moving += 1;
			changes_check += i64::from(was.pins.iter().collect::<std::collections::BTreeSet<_>>() != is.pins.iter().collect() || was.url.starts_with("http://") != is.url.starts_with("http://"));
			to_plain += i64::from(is.url.starts_with("http://"));
			if names.len() < 20 {names.push(name.clone());}
		}
		let out = MoveOut {applied: false, moving, staying: scope.len() as i64 - moving, changes_check, to_plain, names};
		if dry {return Ok(out)}
		if input.group.is_some() {
			let tx = db.transaction()?;
			store_settings(&tx, &cache, |settings| *settings = later).map_err(Failure::internal)?;
			tx.commit()?;
		} else {
			let tx = db.transaction()?;
			for (id, pick) in &picks {tx.execute("update users set endpoint = ? where id = ?", params![pick, id])?;}
			tx.commit()?;
		}
		audit(db, &ctx.actor, &ctx.source, "endpoint.move", &input.group.as_ref().map_or_else(|| format!("{} accounts", picks.len()), |group| format!("group:{group}")), &format!("to {}, {} moved", input.endpoint.as_deref().unwrap_or("default"), out.moving));
		Ok(MoveOut {applied: true, ..out})
	}).await??;
	ok(&out)
}

/// The endpoint name an account was given, if any.
pub fn choice(connection: &Connection, id: i64) -> Option<String> {connection.query_row("select endpoint from users where id = ?", [id], |row| row.get(0)).optional().ok().flatten().flatten()}
