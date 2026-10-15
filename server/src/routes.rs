//! The route table. One list builds both the router and `openapi.json`, so the document cannot say anything else than what is served.
use crate::{admin, app::{App, Settings}, auth::Access, http::ErrorBody, users};
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
		route::<Nothing, admin::AuditOut, _, _>(s, M::GET, "/audit", "audit", "The audit log, newest first. Query: limit, before.", Access::Full, admin::audit_log),
		route::<Nothing, admin::TokensOut, _, _>(s, M::GET, "/tokens", "listTokens", "The admin's API tokens. A token is never shown again.", Access::Admin, admin::tokens),
		route::<admin::NewToken, admin::TokenCreated, _, _>(s, M::POST, "/tokens", "createToken", "Makes an API token, shown once. No API token can do this.", Access::AdminReauth, admin::create_token),
		route::<Nothing, admin::Done, _, _>(s, M::DELETE, "/tokens/{id}", "revokeToken", "Revokes an API token.", Access::Admin, admin::revoke_token),
		route::<Nothing, Settings, _, _>(s, M::GET, "/settings", "getSettings", "Panel settings: provider name, endpoint, pins, address pool, profiles, mirrors.", Access::Read, admin::get_settings),
		route::<Settings, Settings, _, _>(s, M::PUT, "/settings", "putSettings", "Replaces the settings. Publishing profiles needs a recent re-authentication.", Access::AdminReauth, admin::put_settings),
		route::<Nothing, admin::KeysOut, _, _>(s, M::GET, "/signing-keys", "listSigningKeys", "The subscription signing keys, current and retired. No private part is ever shown.", Access::Admin, admin::signing_keys),
		route::<Nothing, admin::KeysOut, _, _>(s, M::POST, "/signing-keys/rotate", "rotateSigningKey", "Adds a second current key. Both are listed in every document until the rotation is finished.", Access::AdminReauth, admin::rotate_signing),
		route::<Nothing, admin::KeysOut, _, _>(s, M::POST, "/signing-keys/finish", "finishSigningRotation", "Retires the older key. It is kept 365 days to sign refusals.", Access::AdminReauth, admin::finish_signing),
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
	]
}

pub fn failure_schema(schemas: &mut SchemaGenerator) -> Schema {schemas.subschema_for::<ErrorBody>()}
