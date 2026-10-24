//! Pairing two nodes with a link, with the codes and the fingerprint of the protocol's pairing page. Everything pending lives in memory: a restart drops it, and a link is in the node's config only after the operator typed the other side's fingerprint.
use crate::{app::{App, LOCAL}, crypto::now, http::{ok, Body, Ctx, Failure}, nodecfg};
use axum::{extract::{Path, State}, http::StatusCode, response::Response, Extension};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, net::IpAddr, sync::Arc};
use veilway_proto::{pairing::{self, Agreed, Direction, Offer, Offers, Pastes, Terms, Unconfirmed}, NoRandom};

const TRIES: u8 = 5;
const LIFETIME: u64 = 600;
const PENDING_MAX: usize = 16;

/// What the operator chose for a pairing, kept beside it until it is confirmed.
struct Meta {tag: String, inbound: Option<String>, listener: bool}

#[derive(Default)]
pub struct Pairing {offers: Offers, pastes: Pastes, meta: HashMap<String, Meta>, pending: HashMap<String, (Agreed, u8)>}

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), bytes).map_err(|_| NoRandom)}

fn code_error(error: pairing::CodeError) -> Failure {Failure::bad(format!("The code is refused: {error}."))}

fn key32(text: &str, what: &str) -> Result<[u8; 32], Failure> {STANDARD.decode(text).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()).ok_or_else(|| Failure::bad(format!("{what} is a 32 byte key in standard base64.")))}

fn id_text(id: &[u8; 16]) -> String {URL_SAFE_NO_PAD.encode(id)}

pub async fn list(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (status, body) = crate::node::request(&app, LOCAL, "GET", "/v1/links", None, None).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	ok(&json!({"status": status, "links": serde_json::from_slice::<Value>(&body).ok().and_then(|value| value.get("links").cloned()).unwrap_or(Value::Null)}))
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Inbound {
	pub tag: String,
	/// "wireguard" or "veilway".
	pub kind: String,
	/// The WireGuard public key of the inbound.
	pub public_key: String,
	/// The public half of the node transport key. Null when the inbound has none.
	pub transport_public_key: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Inbounds {pub inbounds: Vec<Inbound>}

/// The node's inbounds with their public keys, which an offer needs. Only the public keys are read from the node's answer.
pub async fn inbounds(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (status, body) = crate::node::request(&app, LOCAL, "GET", "/v1/inbounds", None, None).await.map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", error))?;
	if status != 200 {return Err(Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", format!("the node answered {status} to the inbounds")))}
	ok(&serde_json::from_slice::<Inbounds>(&body).map_err(|error| Failure::new(StatusCode::BAD_GATEWAY, "node_unreachable", format!("the node's inbounds: {error}")))?)
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferIn {
	/// The tag the link gets in this node's config.
	pub tag: String,
	/// The tag of the `veilway` inbound the link connects to.
	pub inbound: String,
	/// "forward" or "reverse". In a forward link this node is the exit.
	pub direction: String,
	pub name: String,
	/// The inbound's WireGuard public key, as `/links/inbounds` reports it.
	pub inbound_public_key: String,
	/// Needed when `transports` lists tls or ws.
	pub transport_public_key: Option<String>,
	pub dialler: Vec<IpAddr>,
	/// A reverse link only.
	#[serde(default)] pub listener: Vec<IpAddr>,
	pub mtu: Option<u16>,
	/// The transports the other node is offered, in the shape of a profile's `transports`.
	pub transports: Value,
	/// Seconds, 1 to 3600. Default 600.
	pub lifetime: Option<u64>,
}

pub async fn offer(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<OfferIn>) -> Result<Response, Failure> {
	let (_, _, document) = nodecfg::running(&app, LOCAL).await?;
	let found = document["inbounds"].as_array().into_iter().flatten().find(|inbound| inbound["tag"] == input.inbound.as_str());
	let Some(found) = found.filter(|inbound| inbound["type"] == "veilway") else {return Err(Failure::bad("The node has no veilway inbound with that tag."))};
	let direction = match input.direction.as_str() {"forward" => Direction::Forward, "reverse" => Direction::Reverse, _ => return Err(Failure::bad("direction is forward or reverse."))};
	if input.tag.is_empty() || input.tag.len() > 64 || document["links"].as_array().into_iter().flatten().any(|link| link["tag"] == input.tag.as_str()) {return Err(Failure::conflict("The link tag is empty, too long, or already in the config."))}
	let transports = pairing::transports(&serde_json::to_vec(&input.transports).unwrap_or_default()).map_err(code_error)?;
	let mtu = input.mtu.unwrap_or(if found["transports"].as_array().into_iter().flatten().any(|transport| transport["type"] == "udp-obfs") {1390} else {1420});
	let terms = Terms {direction, name: input.name, inbound_public_key: key32(&input.inbound_public_key, "inbound_public_key")?, transport_public_key: input.transport_public_key.as_deref().map(|key| key32(key, "transport_public_key")).transpose()?, dialler: input.dialler, listener: input.listener, manage: None, mtu, transports};
	let (at, lifetime) = (now() as u64, input.lifetime.unwrap_or(LIFETIME));
	let (code, parsed) = {
		let mut pairing = app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if pairing.meta.len() >= PENDING_MAX {return Err(Failure::conflict("Too many pairings are open. Wait for them to expire or drop them."))}
		let code = pairing.offers.issue(&terms, at, lifetime, &mut random).map_err(code_error)?;
		let parsed = Offer::parse(&code).map_err(code_error)?;
		pairing.meta.insert(id_text(&parsed.id), Meta {tag: input.tag.clone(), inbound: Some(input.inbound), listener: true});
		(code, parsed)
	};
	app.db.audit(&ctx.actor, &ctx.source, "link.offer", &input.tag, "").await;
	ok(&json!({"id": id_text(&parsed.id), "code": code, "expires_at": parsed.expires_at}))
}

pub async fn pending(State(app): State<Arc<App>>) -> Result<Response, Failure> {
	let (at, mut pairing) = (now() as u64, app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()));
	let offers: Vec<Value> = pairing.offers.open(at).map(|offer| json!({"id": id_text(&offer.id), "name": offer.name, "direction": offer.direction.word(), "expires_at": offer.expires_at})).collect();
	pairing.pending.retain(|_, (agreed, _)| !agreed.offer().expired(at));
	let answered: Vec<Value> = pairing.pending.iter().map(|(id, (agreed, tries))| json!({"id": id, "name": agreed.offer().name, "direction": agreed.offer().direction.word(), "expires_at": agreed.offer().expires_at, "fingerprint": agreed.shown(), "tries": tries, "role": if pairing.meta.get(id).is_some_and(|meta| meta.listener) {"listener"} else {"dialler"}})).collect();
	let open: Vec<String> = offers.iter().filter_map(|offer| offer["id"].as_str().map(str::to_string)).collect();
	let live = |id: &String| open.contains(id) || pairing.pending.contains_key(id);
	let stale: Vec<String> = pairing.meta.keys().filter(|id| !live(id)).cloned().collect();
	for id in stale {pairing.meta.remove(&id);}
	ok(&json!({"offers": offers, "answered": answered}))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeIn {pub code: String}

/// Step 3: the other node's answer to an open offer. The answer is spent whatever follows. The fingerprint to read to the other operator is in the answer; it is not the one to type.
pub async fn take_answer(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<CodeIn>) -> Result<Response, Failure> {
	let (id, shown) = {
		let mut pairing = app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let agreed = pairing.offers.answer(input.code.trim(), now() as u64).map_err(|error| if matches!(error, pairing::CodeError::Spent) {Failure::conflict("This answer is for no open offer: it expired, or belongs to another one.")} else {code_error(error)})?;
		let (id, shown) = (id_text(&agreed.offer().id), agreed.shown());
		pairing.pending.insert(id.clone(), (agreed, 0));
		(id, shown)
	};
	app.db.audit(&ctx.actor, &ctx.source, "link.answer", &id, "").await;
	ok(&json!({"id": id, "fingerprint": shown}))
}

fn pools(document: &Value) -> Vec<IpNet> {document["inbounds"].as_array().into_iter().flatten().flat_map(|inbound| inbound["address"].as_array().into_iter().flatten()).filter_map(|address| address.as_str()?.parse::<IpNet>().ok()).collect()}

fn overlaps(offer: &Offer, document: &Value) -> bool {
	let pools = pools(document);
	offer.dialler.iter().chain(&offer.listener).any(|address| pools.iter().any(|pool| pool.contains(address)))
}

/// Step 2, read only: what an offer pasted here would make this node dial, for the operator to accept or decline.
pub async fn paste(State(app): State<Arc<App>>, Body(input): Body<CodeIn>) -> Result<Response, Failure> {
	let offer = Offer::parse(input.code.trim()).map_err(code_error)?;
	let (_, _, document) = nodecfg::running(&app, LOCAL).await?;
	let reverse = offer.direction == Direction::Reverse;
	ok(&json!({"id": id_text(&offer.id), "name": offer.name, "direction": offer.direction.word(), "half": if reverse {"exit"} else {"entry"}, "expires_at": offer.expires_at, "expired": offer.expired(now() as u64), "overlaps_pool": overlaps(&offer, &document), "dials": offer.dials().iter().map(|(address, private)| json!({"address": address.to_string(), "private": private})).collect::<Vec<_>>(), "transports": serde_json::from_str::<Value>(&pairing::transports_json(&offer.transports)).unwrap_or_default(), "ws_warning": offer.transports.iter().any(|transport| matches!(transport, veilway_proto::subscription::payload::Transport::Ws(_)))}))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasteIn {
	pub code: String,
	/// The tag the link gets in this node's config.
	pub tag: String,
	/// Must be true: the operator has seen where this node would dial and agrees.
	pub accept: bool,
}

pub async fn paste_answer(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Body(input): Body<PasteIn>) -> Result<Response, Failure> {
	if !input.accept {return Err(Failure::bad("The offer is answered only after its operator accepted the addresses."))}
	let offer = Offer::parse(input.code.trim()).map_err(code_error)?;
	let (_, _, document) = nodecfg::running(&app, LOCAL).await?;
	if overlaps(&offer, &document) {return Err(Failure::conflict("An address of this link lies inside an inbound pool of this node. The other operator has to take the link's addresses from a pool this node does not use."))}
	if input.tag.is_empty() || input.tag.len() > 64 || document["links"].as_array().into_iter().flatten().any(|link| link["tag"] == input.tag.as_str()) {return Err(Failure::conflict("The link tag is empty, too long, or already in the config."))}
	let (code, id, shown) = {
		let mut pairing = app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if pairing.meta.len() >= PENDING_MAX {return Err(Failure::conflict("Too many pairings are open. Wait for them to expire or drop them."))}
		let (code, agreed) = pairing.pastes.answer(&offer, now() as u64, &mut random).map_err(code_error)?;
		let (id, shown) = (id_text(&offer.id), agreed.shown());
		pairing.meta.insert(id.clone(), Meta {tag: input.tag.clone(), inbound: None, listener: false});
		pairing.pending.insert(id.clone(), (agreed, 0));
		(code, id, shown)
	};
	app.db.audit(&ctx.actor, &ctx.source, "link.paste", &input.tag, "").await;
	ok(&json!({"id": id, "answer": code, "fingerprint": shown}))
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfirmIn {
	/// The eight groups the other operator reads out. Typing this side's own does not confirm.
	pub typed: String,
	/// The revision the node's config was last read at, which the change is applied on.
	pub revision: String,
}

pub async fn confirm(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>, Body(input): Body<ConfirmIn>) -> Result<Response, Failure> {
	let (agreed, tries, meta) = {
		let mut pairing = app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let (agreed, tries) = pairing.pending.remove(&id).ok_or_else(|| Failure::missing("pairing"))?;
		let meta = pairing.meta.get(&id).map(|meta| Meta {tag: meta.tag.clone(), inbound: meta.inbound.clone(), listener: meta.listener}).ok_or_else(|| Failure::missing("pairing"))?;
		(agreed, tries, meta)
	};
	let paired = match agreed.confirm(&input.typed, now() as u64) {
		Ok(paired) => paired,
		Err(Unconfirmed::Expired) => {
			app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).meta.remove(&id);
			return Err(Failure::new(StatusCode::GONE, "expired", "The offer expired, so the pairing is discarded. Start again with a new offer."));
		}
		Err(Unconfirmed::Mismatch(kept)) => {
			{
				let mut pairing = app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
				if tries + 1 >= TRIES {pairing.meta.remove(&id);} else {pairing.pending.insert(id.clone(), (*kept, tries + 1));}
			}
			app.db.audit(&ctx.actor, &ctx.source, "link.mismatch", &meta.tag, &format!("try {}", tries + 1)).await;
			return Err(Failure::new(StatusCode::FORBIDDEN, "fingerprint_mismatch", "These are not the groups this pairing has for the other side. If they were read and typed right, somebody changed a code on its way: stop and pair again over another channel."));
		}
	};
	app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).meta.remove(&id);
	let offer = &paired.offer;
	let texts = |addresses: &[IpAddr]| addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>();
	let mut entry = json!({"tag": meta.tag, "id": id_text(&offer.id), "direction": offer.direction.word(), "addresses": {"dialler": texts(&offer.dialler)}, "mtu": offer.mtu, "transport_secret": STANDARD.encode(paired.secret.expose())});
	if !offer.listener.is_empty() {entry["addresses"]["listener"] = json!(texts(&offer.listener))}
	let reverse = offer.direction == Direction::Reverse;
	let _turn = app.turn(LOCAL).await;
	let (_, _, mut document) = nodecfg::running(&app, LOCAL).await?;
	if let Some(inbound) = &meta.inbound {(entry["inbound"], entry["public_key"]) = (json!(inbound), json!(STANDARD.encode(paired.public_key)));}
	if let Some(private) = &paired.private_key {
		let mut peer = json!({"inbound_public_key": STANDARD.encode(offer.inbound_public_key), "transports": serde_json::from_str::<Value>(&pairing::transports_json(&offer.transports)).unwrap_or_default()});
		if let Some(key) = offer.transport_public_key {peer["transport_public_key"] = json!(STANDARD.encode(key))}
		(entry["private_key"], entry["peer"]) = (json!(STANDARD.encode(private.expose())), peer);
	}
	// The half that lets traffic out says what it may leave through, starting with the node's default exit.
	if meta.listener != reverse {entry["exits"] = json!([document["routing"]["default"]])}
	let links = document.as_object_mut().map(|document| document.entry("links").or_insert_with(|| json!([])));
	if let Some(Value::Array(links)) = links {links.push(entry)}
	let applied = nodecfg::apply(&app, LOCAL, &ctx, document, &input.revision, &meta.tag).await?;
	app.db.audit(&ctx.actor, &ctx.source, "link.paired", &meta.tag, "").await;
	ok(&json!({"tag": meta.tag, "applied": applied}))
}

pub async fn drop_pairing(State(app): State<Arc<App>>, Extension(ctx): Extension<Ctx>, Path(id): Path<String>) -> Result<Response, Failure> {
	{
		let mut pairing = app.pairing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		if pairing.meta.remove(&id).is_none() && pairing.pending.remove(&id).is_none() {return Err(Failure::missing("pairing"))}
		pairing.pending.remove(&id);
	}
	app.db.audit(&ctx.actor, &ctx.source, "link.drop", &id, "").await;
	ok(&crate::admin::Done {ok: true})
}
