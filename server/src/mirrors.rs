//! Relay mirrors: servers of the provider that forward the subscription endpoint's requests and say, in a signed header, which address a request really came from.
//! The header is `X-Veilway-Mirror: v1;name;address;timestamp;nonce;mac`. The mac is HMAC-SHA-256 under the mirror's secret over the label `veilway mirror v1`, then the name, address, timestamp and nonce, each after a line feed. The nonce is 16 random bytes in unpadded base64url, and the mac is written the same way.
use crate::{app::App, crypto::now};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use std::{collections::HashMap, net::IpAddr, sync::Mutex};

pub const HEADER: &str = "x-veilway-mirror";
/// Seconds a header stays fresh on either side of the panel's clock.
pub const WINDOW: i64 = 60;
const SEEN_MAX: usize = 100_000;

/// Nonces that were accepted, for as long as a header with them could still be fresh.
#[derive(Default)]
pub struct Seen(Mutex<HashMap<String, i64>>);

pub fn mac(secret: &[u8], name: &str, address: &str, at: i64, nonce: &str) -> Vec<u8> {hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), format!("veilway mirror v1\n{name}\n{address}\n{at}\n{nonce}").as_bytes()).as_ref().to_vec()}

/// What the headers say about the request. `Ok(None)` is a request with no mirror header, `Ok(Some)` a valid one from the named mirror for the given client address, and `Err` one that carries a header that is not valid, which is answered as an unknown request.
pub fn check(app: &App, headers: &HeaderMap) -> Result<Option<(String, IpAddr)>, ()> {
	let mut all = headers.get_all(HEADER).iter();
	let Some(value) = all.next() else {return Ok(None)};
	if all.next().is_some() {return Err(())}
	let fields: Vec<&str> = value.to_str().map_err(|_| ())?.split(';').collect();
	let [version, name, address, at, nonce, tag] = fields[..] else {return Err(())};
	let (at, address): (i64, IpAddr) = (at.parse().map_err(|_| ())?, address.parse().map_err(|_| ())?);
	let mirror = app.cfg.trusted_mirrors.iter().find(|mirror| mirror.name == name).ok_or(())?;
	let (secret, tag) = (URL_SAFE_NO_PAD.decode(&mirror.secret).map_err(|_| ())?, URL_SAFE_NO_PAD.decode(tag).map_err(|_| ())?);
	let fresh = (now() - at).abs() <= WINDOW && version == "v1" && address.to_string() == fields[2] && URL_SAFE_NO_PAD.decode(nonce).is_ok_and(|bytes| bytes.len() == 16) && nonce.len() == 22;
	let signed = hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &secret), format!("veilway mirror v1\n{name}\n{}\n{at}\n{nonce}", fields[2]).as_bytes(), &tag).is_ok();
	if !(fresh && signed) {return Err(())}
	let mut seen = app.mirrors_seen.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	if seen.len() >= SEEN_MAX {seen.retain(|_, kept| now() - *kept <= 2 * WINDOW)}
	if seen.len() >= SEEN_MAX || seen.insert(format!("{name};{nonce}"), now()).is_some_and(|kept| now() - kept <= 2 * WINDOW) {return Err(())}
	Ok(Some((name.to_string(), address)))
}
