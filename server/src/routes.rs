//! The route table. One list builds both the router and `openapi.json`, so the document cannot say anything else than what is served.
use crate::{admin, backup, updater, app::{App, Settings}, auth::Access, http::ErrorBody, links, nodecfg, stats, users, xray};
use axum::{extract::State, handler::Handler, http::{header::CONTENT_TYPE, HeaderValue, Method, StatusCode}, response::{IntoResponse, Response}, routing::{on, MethodFilter, MethodRouter}};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use std::{any::TypeId, sync::Arc};

/// The marker for a route without a body.
pub struct Nothing;

pub struct Route {
	pub method: Method,
	pub path: &'static str,
	pub operation: &'static str,
	pub summary: &'static str,
	pub access: Access,
	pub handler: MethodRouter<Arc<App>>,
	pub body: Option<Schema>,
	pub response: Schema,
}

fn route<Req: JsonSchema + 'static, Res: JsonSchema, H: Handler<X, Arc<App>>, X: 'static>(schemas: &mut SchemaGenerator, method: Method, path: &'static str, operation: &'static str, summary: &'static str, access: Access, handler: H) -> Route {
	Route {handler: on(MethodFilter::try_from(method.clone()).unwrap_or(MethodFilter::GET), handler), method, path, operation, summary, access, body: (TypeId::of::<Req>() != TypeId::of::<Nothing>()).then(|| schemas.subschema_for::<Req>()), response: schemas.subschema_for::<Res>()}
}

impl JsonSchema for Nothing {
	fn schema_name() -> std::borrow::Cow<'static, str> {"Nothing".into()}
	fn json_schema(_: &mut SchemaGenerator) -> Schema {schemars::json_schema!({"type": "null"})}
}

async fn openapi_document() -> Response {(StatusCode::OK, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], crate::openapi::openapi()).into_response()}

pub async fn not_found(State(app): State<Arc<App>>) -> Response {app.not_found()}

pub fn routes(schemas: &mut SchemaGenerator) -> Vec<Route> {
	use Method as M;
	let s = schemas;
	vec![
		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/openapi.json", "openapi", "This document.", Access::Public, openapi_document),
		route::<Nothing, admin::Status, _, _>(s, M::GET, "/status", "status", "Whether first-run setup is still to be done.", Access::Public, admin::status),
		route::<admin::Setup, admin::TotpEnrolled, _, _>(s, M::POST, "/setup", "setup", "Creates the first admin from the one-time setup token printed to the console. The TOTP secret in the answer is shown once.", Access::Public, admin::setup),
		route::<admin::Login, admin::LoggedIn, _, _>(s, M::POST, "/login", "login", "Logs in with password and TOTP code. Sets the session cookie and returns the CSRF token to send as X-CSRF-Token on every change.", Access::Public, admin::login),
		route::<Nothing, admin::Done, _, _>(s, M::POST, "/logout", "logout", "Ends this session.", Access::Admin, admin::logout),
		route::<Nothing, admin::SessionInfo, _, _>(s, M::GET, "/session", "session", "This session: its CSRF token and until when a re-authentication holds.", Access::Admin, admin::session),
		route::<admin::Reauth, admin::Done, _, _>(s, M::POST, "/session/reauth", "reauth", "Confirms password and code again, which the routes marked session-reauth ask for within five minutes.", Access::Admin, admin::reauth),
		route::<Nothing, admin::SessionsOut, _, _>(s, M::GET, "/sessions", "listSessions", "The admin's sessions.", Access::Admin, admin::sessions),
		route::<Nothing, admin::Done, _, _>(s, M::DELETE, "/sessions/{sid}", "revokeSession", "Ends a session.", Access::Admin, admin::revoke_session),
		route::<admin::NewPassword, admin::Done, _, _>(s, M::POST, "/account/password", "changePassword", "Changes the password and ends every other session.", Access::AdminReauth, admin::change_password),
		route::<Nothing, admin::TotpEnrolled, _, _>(s, M::POST, "/account/totp", "changeTotp", "Makes a new TOTP secret and ends every other session.", Access::AdminReauth, admin::change_totp),
		route::<Nothing, admin::AdminsOut, _, _>(s, M::GET, "/admins", "listAdmins", "The admin accounts.", Access::Admin, admin::admins),
		route::<admin::NewAdmin, admin::TotpEnrolled, _, _>(s, M::POST, "/admins", "createAdmin", "Makes another admin.", Access::AdminReauth, admin::create_admin),
		route::<Nothing, admin::Done, _, _>(s, M::DELETE, "/admins/{id}", "removeAdmin", "Removes another admin.", Access::AdminReauth, admin::remove_admin),
		route::<admin::NewPassword, admin::TotpEnrolled, _, _>(s, M::POST, "/admins/{id}/reset", "resetAdmin", "Gives another admin a new password and a new TOTP secret, shown once, and ends their sessions. Audited. No API token can do this.", Access::AdminReauth, admin::reset_admin),
		route::<Nothing, admin::AuditOut, _, _>(s, M::GET, "/audit", "audit", "The audit log, newest first. Query: limit, before.", Access::Full, admin::audit_log),
		route::<Nothing, admin::TokensOut, _, _>(s, M::GET, "/tokens", "listTokens", "The admin's API tokens. A token is never shown again.", Access::Admin, admin::tokens),
		route::<admin::NewToken, admin::TokenCreated, _, _>(s, M::POST, "/tokens", "createToken", "Makes an API token, shown once. No API token can do this.", Access::AdminReauth, admin::create_token),
		route::<Nothing, admin::Done, _, _>(s, M::DELETE, "/tokens/{id}", "revokeToken", "Revokes an API token.", Access::Admin, admin::revoke_token),
		route::<Nothing, Settings, _, _>(s, M::GET, "/settings", "getSettings", "Panel settings: provider name, endpoint, pins, address pool, profiles, mirrors.", Access::Read, admin::get_settings),
		route::<Settings, Settings, _, _>(s, M::PUT, "/settings", "putSettings", "Replaces the settings. Publishing profiles needs a recent re-authentication.", Access::AdminReauth, admin::put_settings),
		route::<Nothing, admin::KeysOut, _, _>(s, M::GET, "/signing-keys", "listSigningKeys", "The subscription signing keys, current and retired. No private part is ever shown.", Access::Admin, admin::signing_keys),
		route::<Nothing, admin::KeysOut, _, _>(s, M::POST, "/signing-keys/rotate", "rotateSigningKey", "Adds a second current key. Both are listed in every document until the rotation is finished.", Access::AdminReauth, admin::rotate_signing),
		route::<Nothing, admin::KeysOut, _, _>(s, M::POST, "/signing-keys/finish", "finishSigningRotation", "Retires the older key. It is kept 365 days to sign refusals.", Access::AdminReauth, admin::finish_signing),
		route::<backup::DownloadIn, backup::Downloaded, _, _>(s, M::POST, "/backup/download", "downloadBackup", "An encrypted backup of the database, the sealed-secret keys and the signing keys, as base64 in `file`. The passphrase encrypts it and cannot be recovered. Needs a recent re-authentication and is audited. No API token can do this.", Access::AdminReauth, backup::download),
		route::<backup::RestoreIn, backup::Restored, _, _>(s, M::POST, "/backup/restore", "restoreBackup", "Replaces the database and keys with the ones in a backup, after saving the current ones in the data directory. Every session ends and the server restarts. Needs a recent re-authentication and is audited. No API token can do this.", Access::AdminReauth, backup::restore),
		route::<Nothing, updater::UpdateInfo, _, _>(s, M::GET, "/update", "updateInfo", "This panel's version and the newest release, as the last check found it.", Access::Read, updater::info),
		route::<Nothing, updater::Requested, _, _>(s, M::POST, "/update/request", "requestUpdate", "Asks the host to update the panel to the newest release, which the host script downloads and checks itself. Needs a recent re-authentication and is audited. No API token can do this.", Access::AdminReauth, updater::request),
		route::<Nothing, admin::NodeInfo, _, _>(s, M::GET, "/node", "node", "Whether the node answers on its control socket and when the panel last pushed its users.", Access::Read, admin::node_info),
		route::<Nothing, users::NodeState, _, _>(s, M::POST, "/node/sync", "syncNode", "Pushes the panel's users into the node's config.", Access::Users, admin::node_sync),
		route::<Nothing, users::UsersOut, _, _>(s, M::GET, "/users", "listUsers", "Users with the node's usage. Query: q, group, enabled.", Access::Read, users::list),
		route::<users::UserIn, users::Created, _, _>(s, M::POST, "/users", "createUser", "Makes a user and a subscription link, shown now and again only through the sealed copy.", Access::Users, users::create),
		route::<users::Bulk, users::BulkResult, _, _>(s, M::POST, "/users/bulk", "bulkUsers", "One action on many users.", Access::Users, users::bulk),
		route::<Nothing, users::UserOut, _, _>(s, M::GET, "/users/{id}", "getUser", "One user.", Access::Read, users::get),
		route::<users::UserPatch, users::Changed, _, _>(s, M::PATCH, "/users/{id}", "updateUser", "Changes a user. A field set to null clears it.", Access::Users, users::patch),
		route::<Nothing, users::Deleted, _, _>(s, M::DELETE, "/users/{id}", "deleteUser", "Removes a user and their devices.", Access::Users, users::remove),
		route::<users::ResetUsage, Settings, _, _>(s, M::POST, "/users/{id}/usage/reset", "resetUsage", "Starts the user's quota count over on the node. The answer is the node's record of the user.", Access::Users, users::reset_usage),
		route::<Nothing, users::DevicesOut, _, _>(s, M::GET, "/users/{id}/devices", "listDevices", "The user's devices, pending ones included.", Access::Read, users::devices),
		route::<users::DeviceIn, users::DeviceCreated, _, _>(s, M::POST, "/users/{id}/devices", "createDevice", "Makes a device with a key the panel generates. The weaker choice: the default is that the device enrolls itself through the endpoint.", Access::Users, users::make_device),
		route::<Nothing, users::Deleted, _, _>(s, M::DELETE, "/users/{id}/devices/{did}", "removeDevice", "Removes a device.", Access::Users, users::remove_device),
		route::<Nothing, users::Exported, _, _>(s, M::POST, "/users/{id}/devices/{did}/export", "exportDevice", "The signed document of a panel-keyed device, private key included, as a link or file.", Access::AdminReauth, users::export_device),
		route::<Nothing, users::SubscriptionInfo, _, _>(s, M::GET, "/users/{id}/subscription", "getSubscription", "Non-secret facts about a user's subscription.", Access::Read, users::sub_info),
		route::<Nothing, users::LinkView, _, _>(s, M::POST, "/users/{id}/subscription/show", "showLink", "Opens the sealed copy of the link, with its QR code. Needs a recent re-authentication and is audited without the link.", Access::AdminReauth, users::sub_show),
		route::<users::ResetLink, users::LinkReset, _, _>(s, M::POST, "/users/{id}/subscription/reset", "resetLink", "Makes a new token. The old one stops working. The answer lists the devices enrolled with the old link and removes them when asked.", Access::Users, users::sub_reset),

		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/config/schema", "configSchema", "The core's config schema (`veilway schema`), for an editor. The node's own validation is the authority.", Access::Read, nodecfg::schema),
		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/config", "getConfig", "The config the node runs without its users, which the panel owns, secrets as the node's marker, and its revision.", Access::Read, nodecfg::get_config),
		route::<nodecfg::ConfigIn, serde_json::Value, _, _>(s, M::PUT, "/config", "putConfig", "Replaces the whole document: validated on the node, then applied with If-Match set to the revision given. The panel's users are put in. No API token may change exits, outbounds, links, log, dns or notices here, and links, log, dns and notices need a recent re-authentication. The answer is the node's.", Access::Full, nodecfg::put_config),
		route::<nodecfg::DocumentIn, serde_json::Value, _, _>(s, M::POST, "/config/validate", "validateConfig", "Asks the node whether a document is valid. Nothing changes.", Access::Full, nodecfg::validate),
		route::<nodecfg::DocumentIn, serde_json::Value, _, _>(s, M::POST, "/config/diff", "diffConfig", "What applying a document would add, change and remove on the node. Nothing changes.", Access::Full, nodecfg::diff),
		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/config/{section}", "getConfigSection", "One of inbounds, outbounds, exits, routing, notices, dns, log, links and replay as the node runs it, with the revision to change it on. A section the document leaves out is null. For replay, read_at_start names what changes only at the node's next start.", Access::Read, nodecfg::get_section),
		route::<nodecfg::SectionIn, serde_json::Value, _, _>(s, M::PUT, "/config/{section}", "putConfigSection", "Replaces one section and applies the result like putConfig. A secret left as the node's marker keeps its value. links, log, dns and notices need a recent re-authentication, and no API token can change them. A null removes an optional section: dns, log, notices, replay and links.", Access::Full, nodecfg::put_section),
		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/profiles/derived", "derivedProfiles", "A `veilway` profile template per inbound, made from the node's config and the overrides, with what each still lacks.", Access::Read, nodecfg::derived_profiles),
		route::<nodecfg::OverrideIn, serde_json::Value, _, _>(s, M::PUT, "/profiles/overrides/{inbound}", "putProfileOverride", "Sets the members that replace the derived ones for an inbound. An empty object clears them.", Access::Full, nodecfg::put_override),
		route::<Nothing, serde_json::Value, _, _>(s, M::POST, "/profiles/publish", "publishProfiles", "Writes the derived templates into the settings' profiles, which the subscription endpoint serves. Refused while one lacks a member.", Access::AdminReauth, nodecfg::publish_profiles),
		route::<Nothing, xray::XrayOut, _, _>(s, M::GET, "/xray", "getXray", "The Xray add-on: whether the node has it, its release and its inbounds, without credentials.", Access::Read, xray::get),
		route::<xray::InboundIn, admin::Done, _, _>(s, M::POST, "/xray/inbounds", "createXrayInbound", "Adds an Xray inbound with a credential the panel makes for every user, and applies the config on the node. Refused while the add-on is not installed, and for vless and trojan while there is no decoy web server. It shares the server's address with the native profiles and makes all of them easier to identify, so they are capped at Detectable.", Access::Full, xray::create),
		route::<xray::InboundEdit, admin::Done, _, _>(s, M::PATCH, "/xray/inbounds/{tag}", "editXrayInbound", "Changes an Xray inbound the panel made: port, listen address, certificate files, decoy, host, and for shadowsocks a new server key. Every user keeps their credential. Share links change when the port, the host or the server key do. A new server key needs a recent re-authentication and no API token can ask for one. Validated like createXrayInbound, applied on the node and audited.", Access::Full, xray::edit),
		route::<Nothing, admin::Done, _, _>(s, M::DELETE, "/xray/inbounds/{tag}", "deleteXrayInbound", "Removes an Xray inbound from the node's config, and its credentials.", Access::Full, xray::remove),
		route::<Nothing, xray::XrayLinks, _, _>(s, M::GET, "/users/{id}/xray", "showXrayLinks", "The user's share link for each Xray inbound the panel made, with QR codes. Needs a recent re-authentication and is audited without the links.", Access::AdminReauth, xray::links),
		route::<Nothing, xray::Rotated, _, _>(s, M::POST, "/users/{id}/xray/rotate", "rotateXrayCredentials", "Gives the user new credentials in every Xray inbound. Their old share links stop working once the node takes the change. Needs a recent re-authentication and is audited.", Access::AdminReauth, xray::rotate),
		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/links", "listLinks", "The node's links with their state, as the node reports them.", Access::Read, links::list),
		route::<Nothing, links::Inbounds, _, _>(s, M::GET, "/links/inbounds", "linkInbounds", "The node's inbounds with their WireGuard public key and transport public key, for an offer. Public keys only.", Access::Read, links::inbounds),
		route::<links::OfferIn, serde_json::Value, _, _>(s, M::POST, "/links/offers", "offerLink", "Step 1: makes an offer code for another node, good for the lifetime given. It holds no secret and says where this node is reached.", Access::AdminReauth, links::offer),
		route::<Nothing, serde_json::Value, _, _>(s, M::GET, "/links/pairings", "listPairings", "Open offers and answered pairings that wait for the fingerprint.", Access::Admin, links::pending),
		route::<links::CodeIn, serde_json::Value, _, _>(s, M::POST, "/links/offers/answer", "takeAnswer", "Step 3: takes the other node's answer code. The answer is the fingerprint to read to the other operator.", Access::AdminReauth, links::take_answer),
		route::<links::CodeIn, serde_json::Value, _, _>(s, M::POST, "/links/paste", "pasteOffer", "Step 2, read only: where an offer pasted here would make this node dial, and whether its addresses clash with an inbound pool.", Access::Admin, links::paste),
		route::<links::PasteIn, serde_json::Value, _, _>(s, M::POST, "/links/paste/answer", "answerOffer", "Step 2: answers an offer after its addresses were accepted. The answer code is shown once.", Access::AdminReauth, links::paste_answer),
		route::<links::ConfirmIn, serde_json::Value, _, _>(s, M::POST, "/links/pairings/{id}/confirm", "confirmPairing", "Step 4: confirms with the eight groups the other operator reads out. Only then the link goes into the node's config, through the same apply as putConfig. Five wrong tries drop the pairing.", Access::AdminReauth, links::confirm),
		route::<Nothing, admin::Done, _, _>(s, M::DELETE, "/links/pairings/{id}", "dropPairing", "Drops a pairing that is waiting.", Access::Admin, links::drop_pairing),
		route::<Nothing, stats::Live, _, _>(s, M::GET, "/stats/now", "statsNow", "Speed now and the node's state: rates by user, inbound, exit and outbound, exit states, sessions, online users and health, as of the last poll.", Access::Read, stats::now_view),
		route::<Nothing, stats::UsageOut, _, _>(s, M::GET, "/stats/usage", "statsUsage", "Bytes carried over a day, week, month or year by user, inbound, exit or outbound. Query: kind, period, name.", Access::Read, stats::usage),
		route::<Nothing, stats::HistoryOut, _, _>(s, M::GET, "/stats/history", "statsHistory", "The buckets of one name: minutes for a day, hours for a month, days for a year. Query: kind, name, resolution, since.", Access::Read, stats::history),
	]
}

pub fn failure_schema(schemas: &mut SchemaGenerator) -> Schema {schemas.subschema_for::<ErrorBody>()}
