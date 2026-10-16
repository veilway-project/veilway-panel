<p align="center">
<img src=".github/icon.svg" width="96" height="96" alt="Veilway">
</p>

<h1 align="center">Veilway panel</h1>

<p align="center">
The admin panel of a Veilway node: users, devices, subscription links and an API.
</p>

<p align="center">
<b>English</b> | <a href="README.fa.md">فارسی</a>
</p>

<p align="center">
<a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

## What it is

Veilway is an open-source VPN platform for people on censored networks: a Rust core, a web panel and first-party apps. The panel is the admin side of a node. It is a Rust server with SQLite, and a React app that is built into the same binary. It runs on the node's host and changes users and settings through the node's control API on its unix socket.

- Admin sign-in with an Argon2id password, a TOTP code, sessions, rate limits and an audit log.
- Users and devices, and the subscription links they use.
- The public subscription endpoint, which your own web server forwards to the panel.
- An admin API with API tokens, described by `server/openapi.json`.

## Who it is for

Operators who run a Veilway node and want to manage its users from a browser or from scripts. Your web server stays in front of the panel. It forwards the admin path and the subscription endpoint, and it answers every other path with its own 404.

## Status

> **Early.** The server is built and tested. The web app in `web/` is still being built, so for now the admin work goes through the API.

## Quick start

There is no release yet, so build from source first (see below). Then, in `server/`:

1. Write `panel.json`. Every key is optional. Set `prefix` to a long random path: it is the admin path. Set `not_found` to the status, headers and body of your web server's 404, copied as they are.
2. Start the panel:

```
cargo run -- run --config panel.json
```

On the first start it prints a one-time setup token to the console. Keep it private.

3. Create the first admin account: send the token with a username and password to `{prefix}/api/setup`. The answer holds a TOTP secret. Add it to an authenticator app, then sign in with the code.
4. Before you add users, set the endpoint URL, the pool and the profiles with `PUT {prefix}/api/settings`.
5. Open `{prefix}` in a browser to sign in. The web app that serves this page is not in the repository yet.

## Build from source

Clone the core repository next to this one. The server reads `veilway-proto` from `../../veilway/crates`, so the folders must sit side by side:

```
git clone https://github.com/veilway-project/veilway
git clone https://github.com/veilway-project/veilway-panel
cd veilway-panel
```

Run the tests in Docker:

```
docker run --rm --cpus 3 --memory 3g -v "$PWD":/w/veilway-panel -v "$PWD/../veilway":/w/veilway -v veilway-cargo:/usr/local/cargo/registry -v veilway-target-usage:/t -w /w/veilway-panel/server -e CARGO_TARGET_DIR=/t/target/panel rust:1 sh -c "cargo test"
```

After a change to a route or a type, regenerate `server/openapi.json` with the same command, using `sh -c "cargo run -- openapi > openapi.json"` in place of `cargo test`. A test fails when the file is stale.

## Run with Docker

The install script is the recommended way; Docker is an option. Images for linux/amd64 and linux/arm64 are published to `ghcr.io/veilway-project/veilway-panel` on each `v*` tag. The image runs as a non-root user, and its config and data live in volumes. The panel listens on `127.0.0.1` only, so it needs a web server with TLS in front of it, and it needs the node's control socket.

Run the container with a restart policy, `--restart unless-stopped` or `restart: unless-stopped` in compose. After a restore from a backup the panel stops by itself with exit code 75 so that the restart policy starts it on the restored files. Without a policy it stays stopped. The update button does not work in a container: pull the new image instead.

[deploy/compose](https://github.com/veilway-project/veilway/tree/main/deploy/compose) in the core repo runs the node and the panel together, with the steps for the config, the socket volume and the web server.

## The API

The admin API sits under `{prefix}/api`. The route table in `server/src/routes.rs` builds both the router and `openapi.json`, so the file always describes the running code.

API tokens let a script call the admin API. A token never reaches the routes that need a full admin session or re-authentication.

## Security notes

- Admin sign-in asks for a TOTP code as well as the password. Passwords are hashed with Argon2id.
- The panel checks the host and origin of admin requests. `allowed_hosts` lists the host names it accepts.
- `trusted_proxies` lists the proxies whose forwarded address the panel believes. Keep it to your own web server.
- Three files, kept apart and readable only by their owner (mode 600): the database holds no key, `panel.keys` holds the token and secret keys, and `signing.keys` holds the subscription signing keys. Back up `panel.keys` on its own. Without it the subscription endpoint answers like an unknown path, and no secret opens.
- The subscription endpoint looks like your web server's own 404. The `not_found` setting copies that answer, so a stranger cannot tell the endpoint from any other missing path.
- The audit log never holds a link, token or key.

## Screenshots

Screenshots come with the web app.

## Repositories

- [veilway](https://github.com/veilway-project/veilway): the core, the control API and its TypeScript client, and the desktop app.
- [veilway-ui](https://github.com/veilway-project/veilway-ui): the design system and the translations shared by the panel and the apps.
- [veilway-docs](https://github.com/veilway-project/veilway-docs): protocol spec, config reference and manuals, in English and Persian. The site is at [veilway-project.github.io/veilway-docs](https://veilway-project.github.io/veilway-docs/).
- veilway-panel: this repository.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. A first pull request asks you to sign the [CLA](CLA.md) once. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The license does not cover the name: see [TRADEMARKS.md](TRADEMARKS.md).
