//! The OpenAPI 3.1 document of the admin API, built from the route table. It is committed as `openapi.json` next to the manifest, and a test fails when that file is not what this produces.
use crate::routes::{failure_schema, routes};
use schemars::generate::SchemaSettings;
use serde_json::{json, Map, Value};

pub fn openapi() -> String {
	let mut schemas = SchemaSettings::draft2020_12().with(|settings| (settings.definitions_path, settings.meta_schema) = ("/components/schemas".into(), None)).into_generator();
	let failure = failure_schema(&mut schemas);
	let mut paths = Map::new();
	for route in routes(&mut schemas) {
		let parameters: Vec<Value> = route.path.split('/').filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}')).map(|name| json!({"name": name, "in": "path", "required": true, "schema": {"type": if name == "sid" {"string"} else {"integer"}}})).collect();
		let mut operation = json!({"operationId": route.operation, "summary": route.summary, "parameters": parameters, "x-access": route.access.word(), "responses": {
			"200": {"description": "Done.", "content": {"application/json": {"schema": route.response}}},
			"400": {"description": "The request is malformed or breaks a rule.", "content": {"application/json": {"schema": failure}}},
			"401": {"description": "Not logged in, or the token is not valid.", "content": {"application/json": {"schema": failure}}},
			"403": {"description": "Not allowed: wrong scope, missing CSRF token or a re-authentication is due.", "content": {"application/json": {"schema": failure}}},
			"429": {"description": "Rate limited.", "content": {"application/json": {"schema": failure}}}
		}});
		if let Some(schema) = &route.body {operation["requestBody"] = json!({"required": true, "content": {"application/json": {"schema": schema}}})}
		paths.entry(route.path).or_insert_with(|| json!({}))[route.method.as_str().to_lowercase()] = operation;
	}
	let document = json!({
		"openapi": "3.1.0",
		"info": {"title": "Veilway panel API", "version": env!("CARGO_PKG_VERSION"), "description": "HTTP and JSON under the panel's path prefix. A browser logs in and sends the CSRF token on every change. An integration sends an API token as a Bearer header. The x-access member of an operation says what it needs: read, users or full are token scopes, session and session-reauth are for a logged-in admin only, and public needs nothing."},
		"servers": [{"url": "{prefix}/api", "variables": {"prefix": {"default": "/panel"}}}],
		"paths": paths,
		"components": {"schemas": schemas.take_definitions(true), "securitySchemes": {"session": {"type": "apiKey", "in": "cookie", "name": "vw_session"}, "token": {"type": "http", "scheme": "bearer"}}}
	});
	format!("{document:#}\n")
}
