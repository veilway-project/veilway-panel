# Veilway panel

The admin panel of Veilway: a Rust server (axum and SQLite) with a React app embedded in the one binary. It runs on the node's host and changes users and config through the node's control API on its unix socket.

This repo holds part A, the server: admin login (Argon2id, TOTP, sessions, rate limits, audit log), users and devices, subscription links and the public subscription endpoint, API tokens and the admin API with its `openapi.json`. The web app in `web/` and the stats and config pages come next.

## Run

```
cd server
cargo run -- run --config panel.json   # prints a one-time setup token on first start
cargo run -- openapi > openapi.json    # after any change to a route or a type
cargo test
```

`panel.json` keys (all optional): `listen`, `prefix` (admin path, make it random), `sub_path` (the endpoint, forwarded by your web server), `database`, `keys`, `signing`, `node_socket`, `allowed_hosts`, `trusted_proxies`, `not_found` (status, headers and body copied from your web server's 404), `secure_cookies`.

First run: POST the printed token with a username and password to `{prefix}/api/setup`, and add the TOTP secret from the answer to an authenticator app. Then fill `PUT {prefix}/api/settings` (endpoint URL, pool, profiles) before making users.

## Secrets

Three files, kept apart and mode 600: the database holds no key; `panel.keys` holds the token lookup, copy and secret keys; `signing.keys` holds the subscription signing keys. Back up `panel.keys` on its own. Without it the endpoint answers like an unknown path and no secret opens.
