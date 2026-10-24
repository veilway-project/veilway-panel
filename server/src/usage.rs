//! Usage across nodes: what each node counted for each user, the sum of it, and the cut of a user whose sum reached the quota. Only a panel with more than one node does any of this, so a single node enforces its quotas alone, as it always did.
use crate::{app::{App, Node, LOCAL}, crypto::now, node};
use rusqlite::{params, Connection, OptionalExtension};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::Value;
use std::{collections::{HashMap, HashSet}, sync::Arc};
use time::OffsetDateTime;

/// The most a node's counters may grow, in bytes per second, when the node has no limit of its own set: 10 Gbit/s. A node that reports more than it could have carried since its last reading is clipped, since a node that is taken could otherwise cut users everywhere with false usage.
pub const MAX_RATE: i64 = 1_250_000_000;
const DAY: i64 = 86_400;

/// The start of the quota period `at` lies in and of the next one, as the nodes count them: 00:00 UTC, a week from Monday and a month from the 1st. Without a period there is one that never ends, starting at 0 as the node reports it.
pub fn bounds(period: Option<&str>, at: i64) -> (i64, i64) {
	let day = at.div_euclid(DAY) * DAY;
	match period {
		Some("daily") => (day, day + DAY),
		// 1 January 1970 was a Thursday.
		Some("weekly") => {let start = day - (day / DAY + 3).rem_euclid(7) * DAY; (start, start + 7 * DAY)}
		Some("monthly") => {
			let first = OffsetDateTime::from_unix_timestamp(day).ok().and_then(|day| day.replace_day(1).ok());
			let next = first.and_then(|first| if first.month() == time::Month::December {first.replace_year(first.year() + 1).ok()?.replace_month(time::Month::January).ok()} else {first.replace_month(first.month().next()).ok()});
			match (first, next) {(Some(first), Some(next)) => (first.unix_timestamp(), next.unix_timestamp()), _ => (day, day + 31 * DAY)}
		}
		_ => (0, i64::MAX),
	}
}

/// What a node said it counted for a user.
pub struct Reading {pub used: i64, pub up: i64, pub down: i64, pub period_start: i64}

/// Takes one node's readings into what the panel keeps for the node and its users. The counters are absolute: a repeat changes nothing, a count that went down inside the same period (the node restarted, or lost its file) banks what was held, a newer period starts over and an older one is ignored. The growth of all the node's users together may be no more than `max_rate` bytes for each second since the node was last read, so a reading above that has each user's growth scaled down by the same share. A user not seen before starts from that last reading too, and a node that was never read starts from one poll interval ago, so a user is never judged from when the node was added.
pub fn merge(db: &Connection, node: i64, readings: &[(i64, Reading)], at: i64, max_rate: i64, poll: i64) -> rusqlite::Result<()> {
	let since = db.query_row("select max(reported_at) from node_usage where node_id = ?", [node], |row| row.get::<_, Option<i64>>(0))?.unwrap_or(at - poll);
	let room = max_rate.saturating_mul((at - since).max(1));
	let mut kept = Vec::with_capacity(readings.len());
	for (user, reading) in readings {
		let held = db.query_row("select period_start, used_bytes, banked_bytes from node_usage where node_id = ? and user_id = ?", params![node, user], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))).optional()?;
		let (start, used, banked) = held.unwrap_or((reading.period_start, 0, 0));
		if reading.period_start < start {continue}
		let (from, banked) = if reading.period_start > start {(0, 0)} else if reading.used < used {(0, banked.saturating_add(used))} else {(used, banked)};
		kept.push((user, reading, from, banked));
	}
	let growth: i128 = kept.iter().map(|(_, reading, from, _)| (reading.used - from) as i128).sum();
	let scaled = growth > room as i128;
	if scaled {tracing::warn!("node {node} reported {growth} bytes more for its users than it could have carried in {}s, so each user's growth is scaled down to {room} bytes in all", at - since)}
	for (user, reading, from, banked) in kept {
		let counted = if scaled {from + ((reading.used - from) as i128 * room as i128 / growth) as i64} else {reading.used};
		db.execute("insert into node_usage (node_id, user_id, period_start, used_bytes, up_bytes, down_bytes, banked_bytes, reported_at) values (?, ?, ?, ?, ?, ?, ?, ?) on conflict (node_id, user_id) do update set period_start = excluded.period_start, used_bytes = excluded.used_bytes, up_bytes = excluded.up_bytes, down_bytes = excluded.down_bytes, banked_bytes = excluded.banked_bytes, reported_at = excluded.reported_at", params![node, user, reading.period_start, counted, reading.up, reading.down, banked, at])?;
	}
	Ok(())
}

/// Reads what one node counted for its users into the table. A user whose usage reset has not reached the node yet is skipped, since the node still holds the count that was reset. A reading is kept only for the period the user is in now, so a period the node made up, or one that is over, is not kept. Nothing is written when the node cannot be reached.
pub async fn collect(app: &Arc<App>, node: Node) {
	let at = now();
	let Ok((200, body)) = node::request(app, node, "GET", "/v1/users", None, None).await else {return};
	let Some(list) = serde_json::from_slice::<Value>(&body).ok().and_then(|answer| answer["users"].as_array().cloned()) else {return};
	let settings = app.settings();
	let poll = if node == LOCAL {settings.usage_poll_secs} else {settings.node_poll_secs} as i64;
	let held = app.clone();
	let result = app.db.call(move |db| -> rusqlite::Result<()> {
		let Some(keys) = held.keys.as_ref() else {return Ok(())};
		let (uid, limit): (Vec<u8>, Option<i64>) = db.query_row("select uid, max_rate from nodes where id = ?", [node.0], |row| Ok((row.get(0)?, row.get(1)?)))?;
		let mut known = HashMap::new();
		for row in db.prepare("select id, name, record_id, quota_period from users")?.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Option<String>>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()? {
			known.insert(if node == LOCAL {row.1} else {keys.node_user(&uid, &row.2.try_into().unwrap_or([0; 16]))}, (row.0, row.3));
		}
		let waiting: HashSet<i64> = db.prepare("select user_id from node_resets where node_id = ?")?.query_map([node.0], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?;
		let readings: Vec<(i64, Reading)> = list.iter().filter_map(|item| {
			let (user, period) = known.get(item["name"].as_str()?)?;
			let number = |value: &Value| value.as_u64().map_or(0, |number| number.min(i64::MAX as u64) as i64);
			let (up, down) = if item["traffic"].is_object() {(number(&item["traffic"]["up_bytes"]), number(&item["traffic"]["down_bytes"]))} else {(number(&item["up_bytes"]), number(&item["down_bytes"]))};
			let reading = Reading {used: number(&item["used_bytes"]), up, down, period_start: item["period_start"].as_i64().unwrap_or(0)};
			(!waiting.contains(user) && reading.period_start == bounds(period.as_deref(), at).0).then_some((*user, reading))
		}).collect();
		let tx = db.transaction()?;
		merge(&tx, node.0, &readings, at, limit.unwrap_or(MAX_RATE), poll)?;
		tx.commit()
	}).await;
	if let Err(error) = result.map_err(|error| error.to_string()).and_then(|done| done.map_err(|error| error.to_string())) {tracing::warn!("the usage of node {} was not kept: {error}", node.0)}
}

/// Cuts the users whose sum over the counted nodes reached their quota, and lets them back when it no longer does (the quota was raised, or the period began). A cut is the user's `cut_until`, which the next push turns into a limit of what each node counted, so each node ends the user's sessions with its quota reason. Says whether anything changed, in which case every node needs a push.
pub async fn enforce(app: &Arc<App>) -> bool {
	let at = now();
	let result = app.db.call(move |db| -> rusqlite::Result<bool> {
		let users = db.prepare("select id, name, quota_bytes, quota_period, cut_until from users where quota_bytes is not null or cut_until is not null")?.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<i64>>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, Option<i64>>(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
		let mut changed = false;
		for (id, name, quota, period, cut) in users {
			let (start, end) = bounds(period.as_deref(), at);
			let total: i64 = db.query_row("select coalesce(sum(banked_bytes + used_bytes), 0) from node_usage join nodes on nodes.id = node_usage.node_id where node_usage.user_id = ? and node_usage.period_start = ? and nodes.counted = 1", params![id, start], |row| row.get(0))?;
			let over = quota.is_some_and(|quota| total >= quota);
			if over && !cut.is_some_and(|until| until > at) {
				db.execute("update users set cut_until = ? where id = ?", params![end, id])?;
				tracing::info!("user {name} used {total} bytes over all nodes, which reached the quota: every node cuts them until {}", if end == i64::MAX {"the quota is raised or reset".to_string()} else {end.to_string()});
				changed = true;
			} else if !over && cut.is_some() {
				db.execute("update users set cut_until = null where id = ?", [id])?;
				tracing::info!("user {name} is under the quota of all nodes again ({total} bytes): every node lets them in");
				changed = true;
			}
		}
		Ok(changed)
	}).await;
	match result.map_err(|error| error.to_string()).and_then(|done| done.map_err(|error| error.to_string())) {
		Ok(changed) => changed,
		Err(error) => {tracing::warn!("the quotas over all nodes were not checked: {error}"); false}
	}
}

/// One pass of usage upkeep for upkeep: reads each node that is due and up, all at once so that a node that does not answer holds up no other, then cuts and lets back. `last` remembers when each node was read.
pub async fn round(app: &Arc<App>, last: &mut HashMap<i64, i64>, up: &HashSet<i64>) {
	let (at, nodes, settings) = (now(), app.nodes(), app.settings());
	if nodes.len() < 2 {return}
	let mut reads = tokio::task::JoinSet::new();
	let due: Vec<Node> = nodes.into_iter().filter(|node| up.contains(&node.0) && at - last.get(&node.0).copied().unwrap_or(0) >= if *node == LOCAL {settings.usage_poll_secs} else {settings.node_poll_secs} as i64).collect();
	for node in due {
		last.insert(node.0, at);
		let held = app.clone();
		reads.spawn(async move {collect(&held, node).await});
	}
	while reads.join_next().await.is_some() {}
	if enforce(app).await {app.dirty_all().set()}
}

/// Starts a user's quota count over everywhere: the readings the panel holds go, the cut is lifted, and each remote node is to be told at its next push. Says whether a remote node has to be told. Node 1 is reset by the caller, at once.
pub fn reset(db: &Connection, user: i64, totals: bool, at: i64) -> rusqlite::Result<bool> {
	db.execute("delete from node_usage where user_id = ?", [user])?;
	db.execute("update users set cut_until = null where id = ?", [user])?;
	Ok(db.execute("insert or replace into node_resets (node_id, user_id, totals, wanted_at) select id, ?, ?, ? from nodes where id != ?", params![user, totals, at, LOCAL.0])? > 0)
}

#[derive(Serialize, JsonSchema)]
pub struct NodeUsage {
	pub node: i64,
	/// What the node counts now in the user's period, and what it counted before it restarted.
	pub used_bytes: i64, pub banked_bytes: i64, pub up_bytes: i64, pub down_bytes: i64,
	/// When the panel last read it. Unix seconds.
	pub reported_at: i64,
	/// Whether it counts toward the user's total. An admin can stop counting a node.
	pub counted: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct Across {
	/// The sum over the counted nodes, in the user's current period.
	pub total_bytes: i64,
	/// Whether every node cuts the user now, because the total reached the quota.
	pub cut: bool,
	pub nodes: Vec<NodeUsage>,
}

/// What the nodes counted for a user in their current period. None for a panel with one node.
pub fn across(db: &Connection, user: i64, at: i64) -> rusqlite::Result<Option<Across>> {
	if db.query_row("select count(*) from nodes", [], |row| row.get::<_, i64>(0))? < 2 {return Ok(None)}
	let (period, cut): (Option<String>, Option<i64>) = db.query_row("select quota_period, cut_until from users where id = ?", [user], |row| Ok((row.get(0)?, row.get(1)?)))?;
	let start = bounds(period.as_deref(), at).0;
	let nodes = db.prepare("select node_usage.node_id, used_bytes, banked_bytes, up_bytes, down_bytes, reported_at, nodes.counted from node_usage join nodes on nodes.id = node_usage.node_id where user_id = ? and period_start = ? order by node_id")?.query_map(params![user, start], |row| Ok(NodeUsage {node: row.get(0)?, used_bytes: row.get(1)?, banked_bytes: row.get(2)?, up_bytes: row.get(3)?, down_bytes: row.get(4)?, reported_at: row.get(5)?, counted: row.get(6)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
	Ok(Some(Across {total_bytes: nodes.iter().filter(|node| node.counted).map(|node| node.used_bytes + node.banked_bytes).sum(), cut: cut.is_some_and(|until| until > at), nodes}))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn world() -> Connection {
		let mut db = Connection::open_in_memory().unwrap();
		crate::db::migrate(&mut db, crate::db::MIGRATIONS).unwrap();
		db.execute("insert into nodes (id, uid, name, slug, pool_v4, created) values (2, x'02', 'Two', 'two', '10.67.0.0/24', 0)", []).unwrap();
		db.execute("insert into users (id, name, device_limit, created, record_id, sub_id, token_lookup, token_created) values (1, 'a', 3, 1, x'00', 's', x'01', 1)", []).unwrap();
		db
	}

	fn held(db: &Connection) -> (i64, i64, i64) {db.query_row("select used_bytes, banked_bytes, period_start from node_usage where node_id = 2 and user_id = 1", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap()}

	fn read(db: &Connection, used: i64, start: i64, at: i64) {merge(db, 2, &[(1, Reading {used, up: 0, down: 0, period_start: start})], at, 1000, 30).unwrap()}

	#[test]
	fn periods_start_and_end_at_midnight_utc_a_week_on_monday_and_a_month_on_the_first() {
		// Wednesday 2026-10-21 13:00 UTC.
		let at = 1_792_587_600;
		assert_eq!(bounds(Some("daily"), at), (1_792_540_800, 1_792_627_200));
		assert_eq!(bounds(Some("weekly"), at), (1_792_368_000, 1_792_972_800), "Monday 2026-10-19 to Monday 2026-10-26");
		assert_eq!(bounds(Some("monthly"), at), (1_790_812_800, 1_793_491_200), "2026-10-01 to 2026-11-01");
		assert_eq!(bounds(Some("monthly"), 1_796_083_200 + 5 * DAY), (1_796_083_200, 1_798_761_600), "December ends at the next January");
		assert_eq!(bounds(None, at), (0, i64::MAX));
	}

	#[test]
	fn a_reading_is_absolute_a_lower_one_in_the_same_period_banks_and_a_new_period_starts_over() {
		let db = world();
		read(&db, 100, 5, 10);
		assert_eq!(held(&db), (100, 0, 5));
		read(&db, 100, 5, 20);
		assert_eq!(held(&db), (100, 0, 5), "a repeat changes nothing");
		read(&db, 150, 5, 30);
		assert_eq!(held(&db), (150, 0, 5));
		read(&db, 20, 5, 40);
		assert_eq!(held(&db), (20, 150, 5), "the node restarted: what it held is banked");
		read(&db, 60, 5, 50);
		assert_eq!(held(&db), (60, 150, 5));
		read(&db, 10, 3, 60);
		assert_eq!(held(&db), (60, 150, 5), "an older period is ignored");
		read(&db, 7, 9, 70);
		assert_eq!(held(&db), (7, 0, 9), "a newer period starts a new count");
	}

	#[test]
	fn growth_is_clipped_to_what_the_node_could_have_carried_since_the_last_reading() {
		let db = world();
		read(&db, 10, 0, 100);
		read(&db, 10_000_000, 0, 102);
		assert_eq!(held(&db).0, 10 + 2 * 1000, "two seconds at the node's rate");
		read(&db, 10_000_000, 0, 103);
		assert_eq!(held(&db).0, 10 + 3 * 1000, "the clip catches up no faster than the rate");
		read(&db, 2_500, 0, 200);
		assert_eq!(held(&db).0, 2_500, "a count that went down is taken as it is, and the old one is banked");
		assert_eq!(held(&db).1, 3_010);
	}

	#[test]
	fn a_user_is_judged_from_the_last_reading_of_the_node_and_a_node_never_read_from_one_poll_interval_ago() {
		let db = world();
		db.execute("insert into users (id, name, device_limit, created, record_id, sub_id, token_lookup, token_created) values (2, 'b', 3, 1, x'00', 't', x'02', 1)", []).unwrap();
		read(&db, 1_000_000, 0, 100);
		assert_eq!(held(&db).0, 30_000, "a node read for the first time gives one poll interval of its rate");
		merge(&db, 2, &[(2, Reading {used: 1_000_000, up: 0, down: 0, period_start: 0})], 110, 1000, 30).unwrap();
		assert_eq!(db.query_row("select used_bytes from node_usage where user_id = 2", [], |row| row.get::<_, i64>(0)).unwrap(), 10_000, "a user added later gets the rate since the node's last reading");
	}

	#[test]
	fn the_growth_of_all_the_users_of_a_node_together_is_held_to_its_rate() {
		let db = world();
		for id in 2..=20 {db.execute("insert into users (id, name, device_limit, created, record_id, sub_id, token_lookup, token_created) values (?, ?, 3, 1, x'00', ?, ?, 1)", params![id, format!("u{id}"), format!("s{id}"), vec![id as u8]]).unwrap();}
		let all = |used: i64| (1..=20).map(|user| (user, Reading {used, up: 0, down: 0, period_start: 0})).collect::<Vec<_>>();
		merge(&db, 2, &all(0), 10, 1000, 30).unwrap();
		merge(&db, 2, &all(1_000_000_000), 11, 1000, 30).unwrap();
		let (total, most): (i64, i64) = db.query_row("select sum(used_bytes), max(used_bytes) from node_usage where node_id = 2", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
		assert_eq!(total, 1000, "twenty users asking for far more get one second of the rate between them");
		assert!(most < 1000, "no user reaches a quota of 1000 in one reading: {most}");
	}

	#[test]
	fn a_reset_forgets_the_counts_lifts_the_cut_and_waits_for_each_remote_node() {
		let db = world();
		read(&db, 100, 0, 10);
		db.execute("update users set cut_until = 99 where id = 1", []).unwrap();
		assert!(reset(&db, 1, true, 50).unwrap());
		assert_eq!(db.query_row("select count(*) from node_usage", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
		assert_eq!(db.query_row("select cut_until from users", [], |row| row.get::<_, Option<i64>>(0)).unwrap(), None);
		assert_eq!(db.query_row("select node_id, totals from node_resets", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))).unwrap(), (2, true));
		db.execute("delete from nodes where id = 2", []).unwrap();
		assert_eq!(db.query_row("select count(*) from node_resets", [], |row| row.get::<_, i64>(0)).unwrap(), 0, "a removed node's resets go with it");
		assert!(!reset(&db, 1, false, 60).unwrap(), "with node 1 alone there is nothing to wait for");
	}
}
