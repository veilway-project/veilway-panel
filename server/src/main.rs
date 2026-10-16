use std::{env, net::SocketAddr, process::ExitCode, time::Duration};
use tracing_subscriber::EnvFilter;
use veilway_panel::{build, config::Config, openapi, router, spawn_upkeep, updater};

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
				updater::spawn_checks(app.clone());
				let listener = tokio::net::TcpListener::bind(app.cfg.listen).await.map_err(|error| format!("{}: {error}", app.cfg.listen))?;
				tracing::info!("listening on {} under {}", app.cfg.listen, app.cfg.prefix);
				let stop = app.clone();
				axum::serve(listener, router(app).into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(async move {
					stop.restart.notified().await;
					tracing::info!("a backup was restored: stopping so the service manager starts the panel on the restored files");
					tokio::spawn(async {tokio::time::sleep(Duration::from_secs(5)).await; std::process::exit(75)});
				}).await.map_err(|error| error.to_string())
			}.await;
			// The server only stops by itself after a restore, and a failure code is what an on-failure service restart answers to.
			match result {Ok(()) => ExitCode::from(75), Err(error) => {eprintln!("veilway-panel: {error}"); ExitCode::FAILURE}}
		}
		_ => {eprintln!("usage: veilway-panel run [--config panel.json] | openapi"); ExitCode::from(2)}
	}
}
