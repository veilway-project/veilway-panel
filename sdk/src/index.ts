import type {components} from "./schema.js";

type Schemas = components["schemas"];
export type {components, paths, operations} from "./schema.js";
export type User = Schemas["UserOut"];
export type UserInput = Schemas["UserIn"];
export type UserPatch = Schemas["UserPatch"];
export type Created = Schemas["Created"];
export type Changed = Schemas["Changed"];
export type Deleted = Schemas["Deleted"];
export type Device = Schemas["DeviceOut"];
export type DeviceCreated = Schemas["DeviceCreated"];
export type Subscription = Schemas["SubscriptionInfo"];
export type LinkReset = Schemas["LinkReset"];
export type Live = Schemas["Live"];
export type Usage = Schemas["UsageOut"];
export type History = Schemas["HistoryOut"];
export type Settings = Schemas["Settings"];
export type ProfileOrder = Schemas["ProfileOrder"];
export type NodeInfo = Schemas["NodeInfo"];
export type NodeState = Schemas["NodeState"];
export type UpdateInfo = Schemas["UpdateInfo"];
export type Bulk = Schemas["Bulk"];
export type BulkResult = Schemas["BulkResult"];
export type Endpoints = Schemas["EndpointsOut"];
export type Move = Schemas["MoveIn"];
export type Moved = Schemas["MoveOut"];
export type Audit = Schemas["AuditOut"];
export type Xray = Schemas["XrayOut"];
export type LinkInbounds = Schemas["Inbounds"];
export type Upstreams = Schemas["Upstreams"];
export type Upstream = Schemas["Upstream"];
export type Retried = Schemas["Retried"];
/** One section of the node's config, such as `exits` or `routing`. The generated schema leaves `value` open, so it is `unknown` here. */
export interface ConfigSection {revision: string, generation: number, value: unknown}
/** The exits section of the node's config. */
export type ExitsSection = ConfigSection;
/** The part of a fetch response the client uses, so the global `fetch` and a test double both fit. */
export interface FetchResponse {
	status: number;
	text(): Promise<string>;
}
export type Fetch = (url: string, init: {method: string, headers: Record<string, string>, body?: string}) => Promise<FetchResponse>;

/** Every answer that is not a success, and an answer the client could not read. */
export class VeilwayError extends Error {
	constructor(readonly status: number, readonly code: string, message: string) {
		super(message);
		this.name = "VeilwayError";
	}
}

/** The query string of the params that are set, or "" when none is. */
function query(params: object): string {
	const search = new URLSearchParams(Object.entries(params).filter(([, value]) => value !== undefined).map(([key, value]) => [key, String(value)]));
	return search.size ? "?" + search : "";
}

export class Client {
	/** `base` is the panel's address with its admin prefix and `/api`, for example "https://panel.example.com/<prefix>/api". `token` is an API token, sent as a Bearer header. A route the token's scope does not allow answers `forbidden`, and a route only a logged-in admin may use answers `unauthorized`. */
	constructor(private readonly fetch: Fetch, private readonly base: string, private readonly token: string) {}

	private async send(method: string, path: string, body?: unknown): Promise<FetchResponse> {
		const headers: Record<string, string> = {accept: "application/json", authorization: "Bearer " + this.token};
		if (body !== undefined) headers["content-type"] = "application/json";
		const response = await this.fetch(this.base.replace(/\/+$/, "") + path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body)});
		if (response.status >= 200 && response.status < 300) return response;
		const text = await response.text().catch(() => "");
		let failure: {code?: unknown, message?: unknown} | undefined;
		try {failure = JSON.parse(text).error} catch {}
		if (failure && typeof failure.code === "string" && typeof failure.message === "string") throw new VeilwayError(response.status, failure.code, failure.message);
		throw new VeilwayError(response.status, "bad_response", "The panel answered " + response.status + " with a body that is not an error document.");
	}

	private async json<T>(method: string, path: string, body?: unknown): Promise<T> {
		const response = await this.send(method, path, body);
		try {return JSON.parse(await response.text()) as T} catch {throw new VeilwayError(response.status, "bad_response", "The panel answered with a body that is not JSON.")}
	}

	async listUsers(filter: {q?: string, group?: string, enabled?: boolean} = {}): Promise<User[]> {return (await this.json<{users: User[]}>("GET", "/users" + query(filter))).users}

	getUser(id: number): Promise<User> {return this.json("GET", "/users/" + id)}

	createUser(input: UserInput): Promise<Created> {return this.json("POST", "/users", input)}

	/** A field set to null clears it. */
	updateUser(id: number, patch: UserPatch): Promise<Changed> {return this.json("PATCH", "/users/" + id, patch)}

	deleteUser(id: number): Promise<Deleted> {return this.json("DELETE", "/users/" + id)}

	async listDevices(id: number): Promise<Device[]> {return (await this.json<{devices: Device[]}>("GET", "/users/" + id + "/devices")).devices}

	createDevice(id: number, name: string): Promise<DeviceCreated> {return this.json("POST", "/users/" + id + "/devices", {name})}

	removeDevice(id: number, device: number): Promise<Deleted> {return this.json("DELETE", "/users/" + id + "/devices/" + device)}

	/** The facts about the user's link. The link itself is not returned. */
	getSubscription(id: number): Promise<Subscription> {return this.json("GET", "/users/" + id + "/subscription")}

	/** Makes a new link, and the old one stops working. `removeDevices` also removes the devices that were enrolled with the old one. */
	resetSubscription(id: number, options: {removeDevices?: boolean} = {}): Promise<LinkReset> {return this.json("POST", "/users/" + id + "/subscription/reset", {remove_devices: options.removeDevices === true})}

	/** Starts the user's quota count over on the node. With `totals` the traffic goes back to zero as well. */
	resetUsage(id: number, options: {totals?: boolean} = {}): Promise<unknown> {return this.json("POST", "/users/" + id + "/usage/reset", {totals: options.totals === true})}

	getExits(): Promise<ExitsSection> {return this.json("GET", "/config/exits")}

	/** A section of the node's config, with the revision to send back with a change. */
	getConfigSection(section: string): Promise<ConfigSection> {return this.json("GET", "/config/" + encodeURIComponent(section))}

	/** Replaces a section of the node's config. `revision` is the one `getConfigSection` gave: a config that changed since answers `conflict`. Needs a token of scope full. */
	putConfigSection(section: string, value: unknown, revision: string): Promise<unknown> {return this.json("PUT", "/config/" + encodeURIComponent(section), {revision, value})}

	/** Checks a whole config document without applying it. Needs a token of scope full. */
	validateConfig(document: unknown): Promise<unknown> {return this.json("POST", "/config/validate", {document})}

	/** What applying a whole config document would change. Needs a token of scope full. */
	diffConfig(document: unknown): Promise<unknown> {return this.json("POST", "/config/diff", {document})}

	/** One change to many users at once: enable, disable, a group, a quota, an expiry, a device limit, exits, or a reset of usage or links. */
	bulkUsers(input: Bulk): Promise<BulkResult> {return this.json("POST", "/users/bulk", input)}

	getSettings(): Promise<Settings> {return this.json("GET", "/settings")}

	/** The node: whether it answers, its version and what the panel last sent it. */
	getNode(): Promise<NodeInfo> {return this.json("GET", "/node")}

	/** Sends the node the users and config the panel holds now. */
	syncNode(): Promise<NodeState> {return this.json("POST", "/node/sync")}

	/** Whether a newer panel or node is out. */
	getUpdate(): Promise<UpdateInfo> {return this.json("GET", "/update")}
	/** Checks GitHub for newer releases now, at most once a minute, and answers as `getUpdate`. */
	checkUpdates(): Promise<UpdateInfo> {return this.json("POST", "/update/check")}

	/** The profiles the panel makes from the node's inbounds, before overrides. */
	derivedProfiles(): Promise<unknown> {return this.json("GET", "/profiles/derived")}

	/** The global order of the profiles in subscriptions, and every profile of every node in the default order. */
	getProfileOrder(): Promise<ProfileOrder> {return this.json("GET", "/profiles/order")}

	/** Sets the global order of the profiles as profile ids across all nodes (at most 64, unknown ids ignored). Needs a token of scope full. */
	setProfileOrder(order: string[]): Promise<ProfileOrder> {return this.json("PUT", "/profiles/order", {order})}

	/** Sets the overrides of the profile of one inbound, such as `node_addresses`. An empty object removes them. Needs a token of scope full. */
	setProfileOverride(inbound: string, set: Record<string, unknown>): Promise<unknown> {return this.json("PUT", "/profiles/overrides/" + encodeURIComponent(inbound), {set})}

	getEndpoints(): Promise<Endpoints> {return this.json("GET", "/endpoints")}

	/** Moves users to another subscription endpoint, or with `dry_run` says what would move. */
	moveEndpoint(input: Move): Promise<Moved> {return this.json("POST", "/endpoints/move", input)}

	/** The node links and their state. */
	getLinks(): Promise<unknown> {return this.json("GET", "/links")}

	/** The inbounds a node link can use. */
	getLinkInbounds(): Promise<LinkInbounds> {return this.json("GET", "/links/inbounds")}

	/** The subscriptions of other providers that exits of the node use, with their state. No key, secret or link is in it. Adding, confirming and removing one need a person at the panel and are not available to a token. */
	async getUpstreams(): Promise<Upstream[]> {return (await this.json<Upstreams>("GET", "/upstreams")).upstreams}

	/** Asks an upstream to connect again now. Needs a token of scope full. */
	retryUpstream(tag: string): Promise<Retried> {return this.json("POST", "/upstreams/" + encodeURIComponent(tag) + "/retry")}

	/** The Xray add-on: whether it is installed and its inbounds. */
	getXray(): Promise<Xray> {return this.json("GET", "/xray")}

	/** The audit log. Needs a token of scope full. */
	getAudit(): Promise<Audit> {return this.json("GET", "/audit")}

	statsNow(): Promise<Live> {return this.json("GET", "/stats/now")}

	/** Bytes carried over a period (day, week, month or year) by `kind`: user, inbound, exit or outbound. */
	statsUsage(kind: string, options: {period?: string, name?: string} = {}): Promise<Usage> {return this.json("GET", "/stats/usage" + query({kind, ...options}))}

	statsHistory(kind: string, name: string, options: {resolution?: string, since?: number} = {}): Promise<History> {return this.json("GET", "/stats/history" + query({kind, name, ...options}))}
}
