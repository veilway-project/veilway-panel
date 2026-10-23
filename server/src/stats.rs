//! The node's stats: polled every few seconds for the live view, and added up into minute, hour and day buckets in SQLite. The node counts from its last start, so the buckets hold what grew between two polls, which a restart does not reset.
use crate::{app::App, crypto::now, http::{ok, Failure}, node};
use axum::{extract::{Query, State}, response::Response};
use rusqlite::{params, Connection};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

pub const POLL: i64 = 10;
/// Bucket sizes and how long each resolution is kept: a day of minutes, a month of hours, a year of days.
const RESOLUTIONS: [(i64, i64, &str); 3] = [(60, 86_400, "minute"), (3600, 31 * 86_400, "hour"), (86_400, 366 * 86_400, "day")];
const KINDS: [(&str, &str); 4] = [("user", "users"), ("inbound", "inbounds"), ("exit", "exits"), ("outbound", "outbounds")];

/// What the last poll saw, for the pages that show the node now.
#[derive(Serialize, JsonSchema, Clone, Default)]
pub struct Live {
	pub at: i64,
	pub reachable: bool,
	/// Version, uptime, generation, flows and the counters that say the node is unwell.
	pub health: Value,
	/// Rates in bytes per second over the node's window, by user, inbound, exit and outbound.
	pub rates: Value,
	/// Every exit with its state: whether its proxy relays UDP, whether its interface is up, whether its link is up.
	pub exits: Value,
	/// What each tunnel of the node counted since the node started: connections or sessions opened and open now, those refused by reason, and the bytes carried. As the node reports them.
	pub tunnels: Value,
	/// What each proxy inbound (`socks5`, `http`, `mixed`) counted since the node started: connections opened and open now, logins and connections refused, and the bytes carried, under `name`, the inbound's tag. As the node reports them.
	pub proxies: Value,
	pub sessions: usize,
	pub online_users: Vec<String>,
}

async fn fetch(app: &App, path: &str) -> Option<Value> {
	let (200, body) = node::request(&app.cfg.node_socket, "GET", path, None, None).await.ok()? else {return None};
	serde_json::from_slice(&body).ok()
}

pub async fn poll(app: &Arc<App>) {
	let at = now();
	let (Some(stats), status) = (fetch(app, "/v1/stats").await, fetch(app, "/v1/status").await) else {
		let mut live = app.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		match live.as_mut() {Some(last) => (last.at, last.reachable) = (at, false), None => *live = Some(Live {at, ..Live::default()})}
		return;
	};
	let (exits, sessions) = (fetch(app, "/v1/exits").await, fetch(app, "/v1/sessions").await);
	let sessions = sessions.and_then(|value| value.get("sessions").cloned()).and_then(|list| list.as_array().cloned()).unwrap_or_default();
	let mut online: Vec<String> = sessions.iter().filter_map(|session| session["user"].as_str().map(str::to_string)).collect();
	online.sort();
	online.dedup();
	let status = status.unwrap_or(Value::Null);
	let live = Live {at, reachable: true, health: json!({"version": status["version"], "uptime_secs": status["uptime_secs"], "generation": status["generation"], "flows": stats["flows"], "state_write_failures": stats["state_write_failures"], "send_failed": stats["send_failed"], "drops": stats["drops"], "dns": stats["dns"], "replay_ready": stats["replay"]["ready"]}), rates: json!({"users": stats["users"], "inbounds": stats["inbounds"], "exits": stats["exits"], "outbounds": stats["outbounds"]}), exits: exits.and_then(|value| value.get("exits").cloned()).unwrap_or(Value::Null), tunnels: stats["tunnels"].clone(), proxies: stats["proxies"].clone(), sessions: sessions.len(), online_users: online};
	if let Err(error) = app.db.call(move |db| record(db, at, &stats).map_err(|error| error.to_string())).await.map_err(|error| error.to_string()).and_then(|result| result) {tracing::warn!("the stats could not be recorded: {error}")}
	*app.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(live);
}

/// Adds what grew since the last poll to every bucket. A counter that went down means the node restarted, so its whole value is new. A name seen for the first time counts in full, except in a database that has no counters at all, where the history starts now.
fn record(db: &Connection, at: i64, stats: &Value) -> rusqlite::Result<()> {
	let transaction = db.unchecked_transaction()?;
	let fresh = transaction.query_row("select count(*) from counters", [], |row| row.get::<_, i64>(0))? == 0;
	for (kind, key) in KINDS {
		for item in stats[key].as_array().into_iter().flatten() {
			let Some(name) = item["name"].as_str() else {continue};
			let (up, down) = (item["traffic"]["up_bytes"].as_i64().unwrap_or(0), item["traffic"]["down_bytes"].as_i64().unwrap_or(0));
			let (rate_up, rate_down) = (item["up_bytes_per_sec"].as_i64().unwrap_or(0), item["down_bytes_per_sec"].as_i64().unwrap_or(0));
			let before = transaction.query_row("select up, down from counters where kind = ? and name = ?", params![kind, name], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))).ok();
			let grew = |now: i64, was: Option<i64>| match was {Some(was) if now >= was => now - was, Some(_) => now, None if fresh => 0, None => now};
			let (grew_up, grew_down) = (grew(up, before.map(|before| before.0)), grew(down, before.map(|before| before.1)));
			transaction.execute("insert into counters (kind, name, up, down) values (?, ?, ?, ?) on conflict (kind, name) do update set up = excluded.up, down = excluded.down", params![kind, name, up, down])?;
			if grew_up == 0 && grew_down == 0 && rate_up == 0 && rate_down == 0 {continue}
			for (size, _, _) in RESOLUTIONS {
				transaction.execute("insert into usage_buckets (res, at, kind, name, up, down, peak_up, peak_down) values (?, ?, ?, ?, ?, ?, ?, ?) on conflict (res, at, kind, name) do update set up = up + excluded.up, down = down + excluded.down, peak_up = max(peak_up, excluded.peak_up), peak_down = max(peak_down, excluded.peak_down)", params![size, at - at % size, kind, name, grew_up, grew_down, rate_up, rate_down])?;
			}
		}
	}
	transaction.commit()
}

pub fn prune(db: &Connection, at: i64) {
	for (size, kept, _) in RESOLUTIONS {let _ = db.execute("delete from usage_buckets where res = ? and at < ?", params![size, at - kept]);}
}

pub async fn now_view(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	ok(&app.live.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone().unwrap_or_default())
}

#[derive(Deserialize, JsonSchema)]
pub struct UsageQuery {
	/// user, inbound, exit or outbound.
	pub kind: String,
	/// day (the last 24 hours), week, month or year. Default day.
	pub period: Option<String>,
	/// One name only.
	pub name: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct UsageEntry {pub name: String, pub up_bytes: i64, pub down_bytes: i64}

#[derive(Serialize, JsonSchema)]
pub struct UsageOut {pub kind: String, pub period: String, pub since: i64, pub entries: Vec<UsageEntry>}

fn kind_ok(kind: &str) -> Result<(), Failure> {if KINDS.iter().any(|(name, _)| *name == kind) {Ok(())} else {Err(Failure::bad("kind is user, inbound, exit or outbound."))}}

/// What each name carried over the period, by the finest resolution that still reaches back that far.
pub async fn usage(State(app): State<Arc<App>>, Query(query): Query<UsageQuery>) -> Result<Response, Failure> {
	kind_ok(&query.kind)?;
	let period = query.period.unwrap_or_else(|| "day".into());
	let (size, span) = match period.as_str() {"day" => (60, 86_400), "week" => (3600, 7 * 86_400), "month" => (3600, 30 * 86_400), "year" => (86_400, 365 * 86_400), _ => return Err(Failure::bad("period is day, week, month or year."))};
	let since = now() - span;
	let (kind, name) = (query.kind.clone(), query.name.clone());
	let entries = app.db.call(move |db| -> rusqlite::Result<Vec<UsageEntry>> {
		let mut statement = db.prepare("select name, sum(up), sum(down) from usage_buckets where res = ? and at >= ? and kind = ? and (? is null or name = ?) group by name order by sum(up) + sum(down) desc limit 1000")?;
		let rows = statement.query_map(params![size, since, kind, name, name], |row| Ok(UsageEntry {name: row.get(0)?, up_bytes: row.get(1)?, down_bytes: row.get(2)?}))?.collect();
		rows
	}).await??;
	ok(&UsageOut {kind: query.kind, period, since, entries})
}

#[derive(Deserialize, JsonSchema)]
pub struct HistoryQuery {
	pub kind: String,
	pub name: String,
	/// minute (kept a day), hour (kept a month) or day (kept a year). Default hour.
	pub resolution: Option<String>,
	/// Unix seconds. Default: as far back as the resolution is kept.
	pub since: Option<i64>,
}

#[derive(Serialize, JsonSchema)]
pub struct Point {pub at: i64, pub up_bytes: i64, pub down_bytes: i64, pub peak_up_bytes_per_sec: i64, pub peak_down_bytes_per_sec: i64}

#[derive(Serialize, JsonSchema)]
pub struct HistoryOut {pub kind: String, pub name: String, pub resolution: String, pub points: Vec<Point>}

pub async fn history(State(app): State<Arc<App>>, Query(query): Query<HistoryQuery>) -> Result<Response, Failure> {
	kind_ok(&query.kind)?;
	let resolution = query.resolution.unwrap_or_else(|| "hour".into());
	let (size, kept, _) = *RESOLUTIONS.iter().find(|(_, _, name)| *name == resolution).ok_or_else(|| Failure::bad("resolution is minute, hour or day."))?;
	let (since, kind, name) = (query.since.unwrap_or(0).max(now() - kept), query.kind.clone(), query.name.clone());
	let points = app.db.call(move |db| -> rusqlite::Result<Vec<Point>> {
		let mut statement = db.prepare("select at, up, down, peak_up, peak_down from usage_buckets where res = ? and at >= ? and kind = ? and name = ? order by at limit 2000")?;
		let rows = statement.query_map(params![size, since, kind, name], |row| Ok(Point {at: row.get(0)?, up_bytes: row.get(1)?, down_bytes: row.get(2)?, peak_up_bytes_per_sec: row.get(3)?, peak_down_bytes_per_sec: row.get(4)?}))?.collect();
		rows
	}).await??;
	ok(&HistoryOut {kind: query.kind, name: query.name, resolution, points})
}
