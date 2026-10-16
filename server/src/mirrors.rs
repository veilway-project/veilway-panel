//! Relay mirrors: servers of the provider that forward the subscription endpoint's requests and say, in a signed header, which address a request really came from.
//! The header is `X-Veilway-Mirror: v1;name;address;timestamp;nonce;mac`. The mac is HMAC-SHA-256 under the mirror's secret over the label `veilway mirror v1`, then the name, address, timestamp, nonce and the base64url SHA-256 of the request body, each after a line feed. The nonce is 16 random bytes in unpadded base64url, and the mac is written the same way.
use crate::{app::App, crypto::{self, now}};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use std::{collections::{HashMap, HashSet, VecDeque}, net::IpAddr, sync::Mutex};

pub const HEADER: &str = "x-veilway-mirror";
/// Seconds a header stays fresh on either side of the panel's clock.
pub const WINDOW: i64 = 60;
/// Nonces kept per mirror. Past it the oldest is dropped, so one mirror's traffic never makes another's headers fail.
const SEEN_MAX: usize = 20_000;
const WARN_EVERY: i64 = 60;

#[derive(Default)]
struct Nonces {set: HashSet<String>, order: VecDeque<(i64, String)>}

/// The nonces each mirror had accepted, for as long as a header with them could still be fresh, and the last refusal logged for each mirror.
#[derive(Default)]
pub struct Seen {nonces: Mutex<HashMap<String, Nonces>>, warned: Mutex<HashMap<String, (i64, String)>>}

impl Seen {
	/// The reason of the last refusal that was logged for the mirror, if one was.
	pub fn last_refusal(&self, name: &str) -> Option<String> {self.warned.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(name).map(|(_, reason)| reason.clone())}
}

/// A request's header once its mac and time are checked, before its nonce is taken.
pub struct Verified {pub name: String, pub address: IpAddr, pub nonce: String}

fn signed(name: &str, address: &str, at: i64, nonce: &str, body: &[u8]) -> String {format!("veilway mirror v1\n{name}\n{address}\n{at}\n{nonce}\n{}", URL_SAFE_NO_PAD.encode(crypto::sha256(body)))}

pub fn mac(secret: &[u8], name: &str, address: &str, at: i64, nonce: &str, body: &[u8]) -> Vec<u8> {hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), signed(name, address, at, nonce, body).as_bytes()).as_ref().to_vec()}

/// Logs why a known mirror's header was refused, at most once a minute per mirror. The header and the token are never logged.
fn refused(app: &App, name: &str, reason: &str) {
	let at = now();
	let mut warned = app.mirrors_seen.warned.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	if warned.get(name).is_some_and(|(last, _)| at - last < WARN_EVERY) {return}
	warned.insert(name.to_string(), (at, reason.to_string()));
	tracing::warn!("relay mirror {name}: a request's header was refused, {reason}");
}

/// What the headers say about the request, checked against its body. `Ok(None)` is a request with no mirror header, `Ok(Some)` a valid one, and `Err` one that carries a header that is not valid, which is answered as an unknown request.
pub fn check(app: &App, headers: &HeaderMap, body: &[u8]) -> Result<Option<Verified>, ()> {
	let mut all = headers.get_all(HEADER).iter();
	let Some(value) = all.next() else {return Ok(None)};
	if all.next().is_some() {return Err(())}
	let fields: Vec<&str> = value.to_str().map_err(|_| ())?.split(';').collect();
	let [version, name, address, at, nonce, tag] = fields[..] else {return Err(())};
	let (at, parsed): (i64, IpAddr) = (at.parse().map_err(|_| ())?, address.parse().map_err(|_| ())?);
	let mirror = app.cfg.trusted_mirrors.iter().find(|mirror| mirror.name == name).ok_or(())?;
	let (secret, tag) = (URL_SAFE_NO_PAD.decode(&mirror.secret).map_err(|_| ())?, URL_SAFE_NO_PAD.decode(tag).map_err(|_| ())?);
	let authentic = hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &secret), signed(name, address, at, nonce, body).as_bytes(), &tag).is_ok();
	if !authentic {refused(app, name, "bad mac"); return Err(())}
	if version != "v1" || parsed.to_string() != address || nonce.len() != 22 || !URL_SAFE_NO_PAD.decode(nonce).is_ok_and(|bytes| bytes.len() == 16) {refused(app, name, "malformed"); return Err(())}
	let skew = now() - at;
	if skew.abs() > WINDOW {
		let reason = if skew > 0 {format!("stale, {skew}s old")} else {format!("from the future, {}s ahead", -skew)};
		refused(app, name, &reason);
		return Err(())
	}
	Ok(Some(Verified {name: name.to_string(), address: parsed, nonce: nonce.to_string()}))
}

/// Takes the nonce of a verified header for its mirror. A nonce the mirror already had is refused. Entries past the window go first, then the oldest of the mirror's own list when it is at its cap.
pub fn accept(app: &App, verified: &Verified) -> bool {
	let at = now();
	let mut all = app.mirrors_seen.nonces.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	let seen = all.entry(verified.name.clone()).or_default();
	while seen.order.front().is_some_and(|(kept, _)| at - kept > 2 * WINDOW) || seen.order.len() >= SEEN_MAX {
		let Some((_, old)) = seen.order.pop_front() else {break};
		seen.set.remove(&old);
	}
	if seen.set.contains(&verified.nonce) {
		drop(all);
		refused(app, &verified.name, "replayed header");
		return false
	}
	seen.set.insert(verified.nonce.clone());
	seen.order.push_back((at, verified.nonce.clone()));
	true
}
