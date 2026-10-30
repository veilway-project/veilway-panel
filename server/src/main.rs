use std::{env, net::SocketAddr, process::ExitCode, time::Duration};
use tracing_subscriber::EnvFilter;
use veilway_panel::{admin, build, config::Config, db::Db, openapi, router, spawn_upkeep, updater};

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
		Some(command @ ("admins" | "reset-password")) => {
			let path = args.iter().position(|arg| arg == "--config").and_then(|at| args.get(at + 1)).map_or("panel.json", String::as_str);
			let result = (|| -> Result<(), String> {
				let cfg = Config::load(path)?;
				let db = Db::open(&cfg.database).map_err(|error| format!("{}: {error}", cfg.database.display()))?;
				if command == "admins" {
					for (name, used) in db.blocking(|connection| admin::console_admins(connection)).map_err(|error| error.to_string())?.map_err(|error| error.to_string())? {println!("{name}{}", if used || !cfg.two_step_on() {""} else {"  (has not signed in with an authenticator code yet)"})}
					return Ok(())
				}
				let name = args.get(1).filter(|arg| !arg.starts_with("--")).ok_or("usage: veilway-panel reset-password <username> [--config panel.json], with the new password on standard input")?.clone();
				let mut password = String::new();
				std::io::stdin().read_line(&mut password).map_err(|error| error.to_string())?;
				let password = password.trim_end_matches(['\r', '\n']).to_string();
				let ended = db.blocking(move |connection| admin::console_reset(connection, &name, &password)).map_err(|error| error.to_string())??;
				println!("the password is changed and {ended} sessions were signed out");
				Ok(())
			})();
			match result {Ok(()) => ExitCode::SUCCESS, Err(error) => {eprintln!("veilway-panel: {error}"); ExitCode::FAILURE}}
		}
		Some("first-run") => {
			let flag = |name: &str| args.iter().position(|arg| arg == name).and_then(|at| args.get(at + 1)).map_or("", String::as_str).to_string();
			let result = (|| -> Result<(), String> {
				let cfg = Config::load(args.iter().position(|arg| arg == "--config").and_then(|at| args.get(at + 1)).map_or("panel.json", String::as_str))?;
				let db = Db::open(&cfg.database).map_err(|error| format!("{}: {error}", cfg.database.display()))?;
				let (host, url, pin) = (flag("--node-host"), flag("--endpoint-url"), flag("--endpoint-pin"));
				println!("{}", db.blocking(move |connection| admin::console_first_run(connection, &host, &url, &pin)).map_err(|error| error.to_string())??);
				Ok(())
			})();
			match result {Ok(()) => ExitCode::SUCCESS, Err(error) => {eprintln!("veilway-panel: {error}"); ExitCode::FAILURE}}
		}
		_ => {eprintln!("usage: veilway-panel run [--config panel.json] | admins [--config panel.json] | reset-password <username> [--config panel.json] | first-run [--node-host H] [--endpoint-url U] [--endpoint-pin P] [--config panel.json] | openapi"); ExitCode::from(2)}
	}
}
