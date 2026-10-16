# Veilway panel

Rust server (`server/`, crate `veilway-panel`) and React app (`web/`, built into `web/dist`, embedded in the binary). Part of Veilway; the core repo `veilway` holds `PLAN.md`, `THREAT_MODEL.md` and the protocol spec, which are binding here. The server depends on `veilway-proto` by path (`../../veilway/crates/veilway-proto`) until the core publishes a version.

## Layout

- `server/src/routes.rs` is the one route table that builds the router and `openapi.json` (`openapi.rs`). Add a route there and run `cargo run -- openapi > openapi.json`; a test fails when the file is stale.
- `auth.rs` is the guard in front of every admin route: host and origin, rate limits, API tokens, sessions, CSRF, re-authentication. A route's `Access` decides who may call it; tokens never reach `Admin` or `AdminReauth` routes.
- `subs.rs` is the subscription endpoint, the link and the signed document. Use `veilway-proto` for links and the envelope, never reimplement them. `crypto.rs` holds the sealed-secret keys and TOTP.
- `node.rs` talks to the node's control API on its unix socket; `users.rs` and `admin.rs` hold the handlers.
- The database is one connection owned by a thread (`db.rs`). Async code reaches it only through `db.call(...)` or `db.audit(...)`, and never calls `app.settings()` inside a call. `db.blocking(...)` is for start-up and blocking tasks only. Schema changes are numbered `MIGRATIONS` steps in `db.rs`.

## Commands

Everything runs in Docker, not on the host:

```
docker run --rm --cpus 3 --memory 3g -v "$PWD":/w/veilway-panel -v "$PWD/../veilway":/w/veilway -v veilway-cargo:/usr/local/cargo/registry -v veilway-target-usage:/t -w /w/veilway-panel/server -e CARGO_TARGET_DIR=/t/target/panel rust:1 sh -c "cargo test"
```

## Code style

Match the core repo's Rust style: no blank lines inside function bodies, spaces after commas and around operators, double quotes, one-liners where they fit, no single-use helper functions, comments only for non-obvious context, no em dashes anywhere. American English in all text. Never run `rustfmt`, `cargo fmt` or prettier. Frontend work loads the `frontend-preferences` skill: no pill shapes, no uppercase eyebrow labels, no emoji.

## Rules

- No secrets, addresses, keys or passwords in the repo, its tests or commit messages. The audit log never holds a link, token or key.
- The project identity is set in this repo's local git config. Check it before committing, commit with `TZ=UTC`.
- Never push. Only the owner asks for a push, in that message.
