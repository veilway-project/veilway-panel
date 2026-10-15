# Contributing to the Veilway panel

The general guide is [CONTRIBUTING.md in veilway](https://github.com/veilway-project/veilway/blob/main/CONTRIBUTING.md): ways to help, the contributor agreement (`CLA.md`, signed once on your first pull request in any Veilway repository), and how pull requests are reviewed. Security problems are never reported in public: see `SECURITY.md`.

What is different here:

- The server depends on `veilway-proto` by path, so clone `veilway` next to this repository. The commands are in `README.md`.
- Everything runs in containers. The commands are in `README.md` and `CLAUDE.md`.
- A new route goes in `server/src/routes.rs`. Run `cargo run -- openapi > openapi.json` after the change; a test fails when the file is stale.
- Never hold the database lock across an await. The audit log never holds a link, token or key.
- A visible change to the web app needs screenshots in dark and light, English and Persian.
- No pill shapes, no uppercase labels above headings, no emoji, small consistent corner radii.
- Code style: no blank lines inside function bodies, double quotes, one-liners where they fit, no single-use helpers, comments only where they add something the code does not say, and never a code formatter, since it adds blank lines and breaks one-liners.
