# @veilway/panel-sdk

A typed client for the admin API of the Veilway panel, for integrations that use an API token. It is generated from the panel's `server/openapi.json`, and it uses the `fetch` you pass in, so it has no runtime dependencies.

## Use

```ts
import {Client, VeilwayError} from "@veilway/panel-sdk";

const client = new Client(fetch, "https://panel.example.com/<prefix>/api", process.env.VEILWAY_TOKEN ?? "");
const [user] = await client.listUsers({q: "ana"});
try {
	if (user) await client.updateUser(user.id, {note: "renewed"});
} catch (e) {
	if (e instanceof VeilwayError) console.log(e.status, e.code, e.message);
}
```

The token's scope decides what it may call: `read` only reads, `users` also changes users and devices, and `full` also changes the config, the Xray add-on and the audit log. Routes that need a logged-in admin answer `unauthorized` to a token.

## Commands

Everything runs in Docker with the image `node:22`.

```
docker run --rm --cpus 2 --memory 2g -v "$PWD/../..:/w" -w /w/sdk node:22 sh -c "npm ci --ignore-scripts && npm run generate"
docker run --rm --cpus 2 --memory 2g -v "$PWD/../..:/w" -w /w/sdk node:22 sh -c "npm ci --ignore-scripts && npm run check && npm test"
```

- `npm run generate` writes `src/schema.ts` from `../server/openapi.json`. Run it after the panel's routes change.
- `npm run check` generates into a temporary file, fails if it differs from `src/schema.ts`, then type-checks.
- `npm test` compiles and runs the tests, which use a fake `fetch` and need no panel.
