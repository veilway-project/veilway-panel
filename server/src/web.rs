//! The React app, embedded at build time from `web/dist`, and a placeholder while that folder is empty.
use crate::app::App;
use axum::{body::Body, extract::{Path, State}, http::{header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE}, HeaderValue, StatusCode}, response::Response};
use rust_embed::RustEmbed;
use std::sync::Arc;

#[derive(RustEmbed)]
#[folder = "../web/dist"]
#[exclude = ".gitkeep"]
struct Dist;

const PLACEHOLDER: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Veilway panel</title></head><body><p>The panel's web app is not built into this binary. The API is served under api/.</p></body></html>";

fn kind(path: &str) -> &'static str {
	match path.rsplit('.').next().unwrap_or("") {
		"html" => "text/html; charset=utf-8", "js" | "mjs" => "text/javascript", "css" => "text/css", "json" | "map" => "application/json", "svg" => "image/svg+xml",
		"png" => "image/png", "ico" => "image/x-icon", "woff2" => "font/woff2", "txt" => "text/plain", _ => "application/octet-stream",
	}
}

pub async fn index(State(app): State<Arc<App>>) -> Response {file(&app, "index.html")}

pub async fn asset(State(app): State<Arc<App>>, Path(path): Path<String>) -> Response {file(&app, &path)}

fn file(app: &App, path: &str) -> Response {
	let (name, body) = match Dist::get(path) {
		Some(found) => (path.to_string(), found.data.to_vec()),
		// A path that is no file is a route of the single-page app.
		None if !path.contains('.') => match Dist::get("index.html") {Some(found) => ("index.html".to_string(), found.data.to_vec()), None => ("index.html".to_string(), PLACEHOLDER.as_bytes().to_vec())},
		None => return app.not_found(),
	};
	let mut response = Response::new(Body::from(body));
	*response.status_mut() = StatusCode::OK;
	response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(kind(&name)));
	response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
	response.headers_mut().insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
	response
}
