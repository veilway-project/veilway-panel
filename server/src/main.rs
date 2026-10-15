use std::{env, net::SocketAddr, process::ExitCode};
use tracing_subscriber::EnvFilter;
use veilway_panel::{build, config::Config, openapi, router, spawn_upkeep};

#[tokio::main]
async fn main() -> ExitCode {
	tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))).init();
	let args: Vec<String> = env::args().skip(1).collect();
	match args.first().map(String::as_str) {
		Some("openapi") => {print!("{}", openapi::openapi()); ExitCode::SUCCESS}
		Some("run") => {
			let path = args.iter().position(|arg| arg == "--config").and_then(|at| args.get(at + 1)).map_or("panel.json", String::as_str);
			let result = async {
				let app = build(Config::load(path)?)?;
				spawn_upkeep(app.clone());
				let listener = tokio::net::TcpListener::bind(app.cfg.listen).await.map_err(|error| format!("{}: {error}", app.cfg.listen))?;
				tracing::info!("listening on {} under {}", app.cfg.listen, app.cfg.prefix);
				axum::serve(listener, router(app).into_make_service_with_connect_info::<SocketAddr>()).await.map_err(|error| error.to_string())
			}.await;
			match result {Ok(()) => ExitCode::SUCCESS, Err(error) => {eprintln!("veilway-panel: {error}"); ExitCode::FAILURE}}
		}
		_ => {eprintln!("usage: veilway-panel run [--config panel.json] | openapi"); ExitCode::from(2)}
	}
}
