import assert from "node:assert/strict";
import {test} from "node:test";
import {Client, VeilwayError, type Fetch} from "../src/index.js";

type Call = {url: string, method: string, headers: Record<string, string>, body?: string};

function panel(calls: Call[], status: number, text: string): Fetch {
	return async (url, init) => {
		calls.push({url, ...init});
		return {status, text: async () => text};
	};
}

test("lists users with the token as a Bearer header and the filter as a query", async () => {
	const calls: Call[] = [];
	const client = new Client(panel(calls, 200, JSON.stringify({users: []})), "https://panel.example/veilway/", "vwp_test");
	assert.deepEqual(await client.listUsers({q: "ana", enabled: true}), []);
	assert.equal(calls[0]?.url, "https://panel.example/veilway/users?q=ana&enabled=true");
	assert.equal(calls[0]?.method, "GET");
	assert.equal(calls[0]?.headers.authorization, "Bearer vwp_test");
	assert.equal(calls[0]?.body, undefined);
});

test("writes send JSON", async () => {
	const calls: Call[] = [];
	const client = new Client(panel(calls, 200, JSON.stringify({device: {}, node: {}, weaker: false})), "https://panel.example", "vwp_test");
	await client.createDevice(3, "laptop");
	assert.equal(calls[0]?.url, "https://panel.example/users/3/devices");
	assert.equal(calls[0]?.headers["content-type"], "application/json");
	assert.equal(calls[0]?.body, "{\"name\":\"laptop\"}");
});

test("an error document becomes a VeilwayError", async () => {
	const body = JSON.stringify({error: {code: "forbidden", message: "This token's scope does not allow that."}});
	const client = new Client(panel([], 403, body), "https://panel.example", "vwp_test");
	await assert.rejects(client.deleteUser(3), (e: unknown) => e instanceof VeilwayError && e.status === 403 && e.code === "forbidden");
});

test("an answer that is not an error document is bad_response", async () => {
	const client = new Client(panel([], 502, "<html>"), "https://panel.example", "vwp_test");
	await assert.rejects(client.getUser(1), (e: unknown) => e instanceof VeilwayError && e.status === 502 && e.code === "bad_response");
});

test("a success answer that is not JSON is bad_response", async () => {
	const client = new Client(panel([], 200, "no json"), "https://panel.example", "vwp_test");
	await assert.rejects(client.statsNow(), (e: unknown) => e instanceof VeilwayError && e.code === "bad_response");
});

test("usage and history name their kind in the query", async () => {
	const calls: Call[] = [];
	const client = new Client(panel(calls, 200, JSON.stringify({kind: "user", period: "week", since: 0, entries: []})), "https://panel.example", "vwp_test");
	await client.statsUsage("user", {period: "week"});
	await client.statsHistory("exit", "de-1", {resolution: "day"});
	assert.equal(calls[0]?.url, "https://panel.example/stats/usage?kind=user&period=week");
	assert.equal(calls[1]?.url, "https://panel.example/stats/history?kind=exit&name=de-1&resolution=day");
});
