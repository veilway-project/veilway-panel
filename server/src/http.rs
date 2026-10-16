//! The shapes every handler shares: the failure answer, the JSON body reader and who is calling.
use crate::app::App;
use crate::db::Unavailable;
use axum::{extract::{FromRequest, Request}, http::{header::CONTENT_TYPE, HeaderValue, StatusCode}, response::{IntoResponse, Response}};
use http_body_util::BodyExt;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

/// Largest JSON body the admin API takes.
pub const BODY_MAX: usize = 262_144;

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ErrorBody {pub error: ErrorDetail}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ErrorDetail {pub code: String, pub message: String}

pub struct Failure {pub status: StatusCode, pub code: &'static str, pub message: String}

impl Failure {
	pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {Self {status, code, message: message.into()}}
	pub fn bad(message: impl Into<String>) -> Self {Self::new(StatusCode::BAD_REQUEST, "bad_request", message)}
	pub fn missing(what: &str) -> Self {Self::new(StatusCode::NOT_FOUND, "not_found", format!("No such {what}."))}
	pub fn conflict(message: impl Into<String>) -> Self {Self::new(StatusCode::CONFLICT, "conflict", message)}
	pub fn internal(error: impl std::fmt::Display) -> Self {
		tracing::error!("internal error: {error}");
		Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Something went wrong. The log has the cause.")
	}
}

impl From<Unavailable> for Failure {
	fn from(_: Unavailable) -> Self {Self::new(StatusCode::SERVICE_UNAVAILABLE, "database_busy", "The panel is busy with its database. Try again in a moment.")}
}

impl From<rusqlite::Error> for Failure {
	fn from(error: rusqlite::Error) -> Self {
		match error {
			rusqlite::Error::QueryReturnedNoRows => Self::new(StatusCode::NOT_FOUND, "not_found", "No such record."),
			rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation => Self::conflict("That name or value is already taken."),
			other => Self::internal(other),
		}
	}
}

impl IntoResponse for Failure {
	fn into_response(self) -> Response {json(self.status, &ErrorBody {error: ErrorDetail {code: self.code.into(), message: self.message}})}
}

pub fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
	(status, [(CONTENT_TYPE, HeaderValue::from_static("application/json"))], serde_json::to_vec(body).unwrap_or_default()).into_response()
}

pub fn ok<T: Serialize>(body: &T) -> Result<Response, Failure> {Ok(json(StatusCode::OK, body))}

/// A JSON request body, read up to the limit. A route that takes a file names a higher one.
pub struct Body<T, const MAX: usize = BODY_MAX>(pub T);

impl<T: DeserializeOwned, const MAX: usize> FromRequest<Arc<App>> for Body<T, MAX> {
	type Rejection = Failure;
	async fn from_request(request: Request, _: &Arc<App>) -> Result<Self, Failure> {
		let typed = request.headers().get(CONTENT_TYPE).and_then(|kind| kind.to_str().ok()).is_some_and(|kind| kind.split(';').next().is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json")));
		if !typed {return Err(Failure::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type", "The body must be sent as application/json."))}
		let bytes = http_body_util::Limited::new(request.into_body(), MAX).collect().await.map_err(|_| Failure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "The body could not be read within the size limit."))?.to_bytes();
		serde_json::from_slice(&bytes).map(Body).map_err(|error| Failure::bad(format!("The body is not the expected JSON: {error}")))
	}
}

/// Who is calling, as the guard worked it out.
#[derive(Clone, Debug)]
pub struct Ctx {
	pub actor: String,
	pub admin_id: i64,
	pub token_id: Option<i64>,
	pub session_id: Option<String>,
	pub source: String,
}
