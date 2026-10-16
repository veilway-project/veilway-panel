// The web app is embedded from web/dist at compile time. Watching the folder rebuilds the binary when the app changes; a release sets VEILWAY_REQUIRE_WEB=1, so a missing app stops the build instead of shipping the placeholder page.
fn main() {
	println!("cargo:rerun-if-env-changed=VEILWAY_REQUIRE_WEB");
	println!("cargo:rerun-if-changed=../web/dist");
	if std::env::var("VEILWAY_REQUIRE_WEB").as_deref() == Ok("1") && !std::path::Path::new("../web/dist/index.html").exists() {panic!("VEILWAY_REQUIRE_WEB is set and web/dist has no index.html: build the web app first, npm run build in web/")}
}
