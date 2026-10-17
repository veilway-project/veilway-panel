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

## Screenshots

The dashboard in the dark theme.

![Dashboard with live speed, a day of traffic, users near their quota and exits](docs/screenshots/panel-dashboard-dark.png)

The users list with quotas, expiry and state.

![Users list with usage bars, groups, expiry and device counts](docs/screenshots/panel-users-dark.png)

One user: usage, devices and the subscription link.

![User page with usage, devices and the subscription link](docs/screenshots/panel-user-dark.png)

Traffic per user, inbound, exit and outbound.

![Traffic page with a chart and a usage table](docs/screenshots/panel-traffic-dark.png)

Inbounds, native and Xray.

![Inbounds page listing a Veilway, a WireGuard and an Xray inbound](docs/screenshots/panel-inbounds-dark.png)

The dashboard in the light theme.

![Dashboard in the light theme](docs/screenshots/panel-dashboard-light.png)

## What it is

Veilway is an open-source VPN platform for people on censored networks: a Rust core, a web panel and first-party apps. The panel is the admin side of a node. It is a Rust server with SQLite, and a React app that is built into the same binary. It runs on the node's host and changes users and settings through the node's control API on its unix socket.

- Users and devices: quotas per period, expiry, groups, enabling and disabling, device keys, usage resets, and subscription links and QR codes.
- Subscriptions and gateway keys: requests and answers are encrypted end to end to the panel's gateway key, so relay mirrors see nothing of their content. Links carry the gateway key, and the page for rotation, theft and loss of a key is in the panel. Named endpoints are reached at `sub_path/<name>`, can be assigned per user and per group, and a move between them is signed. An endpoint may be plain `http://`, and the panel warns when one is.
- Inbounds, exits and routing: native inbounds and the optional Xray add-on, a default exit with exits per user, and routing rules you reorder by drag and drop. A raw JSON editor checks each change against the schema.
- Node links and mirrors: guided setups for an entry node and a reverse tunnel, relays, and relay and static mirrors.
- Traffic, DNS, logs and notices: live and past traffic per user, inbound, exit and outbound, DNS settings, logs, and notices to every device.
- Admins and access: sign-in with a password and a TOTP code, sessions, rate limits, API tokens, and an audit log. The admin API is described by `server/openapi.json`.
- Operations: backup and restore, an update button for installs made with the install script, links to your own terms and privacy pages, a demo mode with two-step sign-in off (`"two_step": "off"` in `panel.json` only) that logs a warning, and English and Persian in light and dark themes.

## Who it is for

Operators who run a Veilway node and want to manage its users from a browser or from scripts. Your web server stays in front of the panel. It terminates TLS, forwards the admin path and the subscription path, and answers every other path with its own 404. The panel listens on loopback only and sets secure cookies.

## Status

> **Alpha.** The server and the web app are built and run against a real node in the alpha gate. This repository has no published release yet, and the panel has had no outside security review.

## Quick start

This repository has no published release yet, so build from source first (see below). Then, in `server/`:

1. Write `panel.json`. Every key is optional, but the panel refuses to start unless `trusted_proxies` lists your web server (or `direct` is `true` when no proxy is in front). Set `prefix` to a long random path: it is the admin path. Set `not_found` to the status, headers and body of your web server's 404, copied as they are.
2. Start the panel:

```
cargo run -- run --config panel.json
```

On the first start it prints a one-time setup token to the console. Keep it private.

3. Create the first admin account: send the token with a username, a password and `"accepted_terms": true` to `{prefix}/api/setup`. The panel requires accepting the Veilway terms at setup. The answer holds a TOTP secret. Add it to an authenticator app, then sign in with the code.
4. Before you add users, set the endpoint URL, the address pool and the profiles in the panel.
5. Open `{prefix}` in a browser to sign in.

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
- `gateway.keys` holds the gateway keys that open subscription requests, and the panel's backup includes it. The next key's private half goes to `gateway.next` once, for you to move off the server and keep.
- The panel has no TLS of its own: it refuses to start on a non-loopback `listen`, and its cookies are secure.
- The subscription endpoint looks like your web server's own 404. The `not_found` setting copies that answer, so a stranger cannot tell the endpoint from any other missing path.
- The audit log never holds a link, token or key.

## Screenshots

Screenshots will be added from the real web app.

## Repositories

- [veilway](https://github.com/veilway-project/veilway): the core, the control API and its TypeScript client, and the desktop and Android apps.
- [veilway-ui](https://github.com/veilway-project/veilway-ui): the design system and the translations shared by the panel and the apps.
- [veilway-docs](https://github.com/veilway-project/veilway-docs): protocol spec, config reference and manuals, in English and Persian. The site is at [veilway-project.github.io/veilway-docs](https://veilway-project.github.io/veilway-docs/).
- veilway-panel: this repository.

## Contributing and security

Questions and help with setup go to [GitHub Discussions](https://github.com/veilway-project/veilway/discussions), in English or Persian. Issues are for bugs and concrete feature requests.

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. A first pull request asks you to sign the [CLA](CLA.md) once. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). The license does not cover the name: see [TRADEMARKS.md](TRADEMARKS.md).
