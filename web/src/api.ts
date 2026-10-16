import type {components, paths} from "./schema.ts";

type Schemas = components["schemas"];
export type User = Schemas["UserOut"];
export type UserIn = Schemas["UserIn"];
export type UserPatch = Schemas["UserPatch"];
export type Device = Schemas["DeviceOut"];
export type LinkView = Schemas["LinkView"];
export type NodeState = Schemas["NodeState"];
export type Settings = Schemas["Settings"];
export type SigningKey = Schemas["KeyOut"];
export type Token = Schemas["TokenRow"];
export type SessionRow = Schemas["SessionRow"];
export type AuditRow = Schemas["AuditRow"];
export type Subscription = Schemas["SubscriptionInfo"];
export type Totp = Schemas["TotpEnrolled"];
export type Live = Schemas["Live"];
export type UsageEntry = Schemas["UsageEntry"];
export type Point = Schemas["Point"];
export type NotFound = Schemas["NotFound"];
export type XrayLink = Schemas["XrayLink"];
export type XrayInbound = Schemas["XrayInboundOut"];
export type AdminRow = Schemas["AdminRowOut"];
// The routes below hand on the node's own answers, which the schema leaves open. Only the fields the panel reads are named.
export type Problem = {path: string, message: string};
export type Report = {errors: Problem[], warnings: Problem[], more_errors: number, more_warnings: number};
export type Changes = {added: string[], changed: string[], removed: string[]};
export type Diff = {[kind in "inbounds" | "outbounds" | "exits" | "rules" | "users"]?: Changes} & {routing_default?: boolean, rules_reordered?: boolean, inbound_changes?: {tag: string, restart: boolean}[], user_changes?: {name: string, lost_access?: boolean}[]};
export type Running = {revision: string, generation: number, document: Record<string, unknown>};
export type Template = {inbound: string, profile: Record<string, unknown>, missing: string[], overridden: string[]};
export type Pairings = {offers: {id: string, name: string, direction: string, expires_at: number}[], answered: {id: string, name: string, direction: string, expires_at: number, fingerprint: string, tries: number, role: string}[]};
export type NodeLink = {tag: string, id: string, half: string, role: string, state: string, state_secs: number, flows: number, traffic: {up_bytes: number, down_bytes: number}};
export type Pasted = {id: string, name: string, direction: string, half: string, expires_at: number, expired: boolean, overlaps_pool: boolean, dials: {address: string, private: boolean}[], transports: {type: string}[], ws_warning: boolean};
/** What the node reports for a user. The schema leaves it open, so only the fields the panel reads are named. */
export type NodeUser = {used_bytes?: number, period_start?: number, denied?: "disabled" | "expired" | "quota" | null, traffic?: {up_bytes?: number, down_bytes?: number}, devices?: {public_key?: string, handshake_age_secs?: number | null}[]};

type Method = "get" | "post" | "put" | "patch" | "delete";
type Operation<P extends keyof paths, M extends Method> = NonNullable<paths[P][M]>;
export type Answer<P extends keyof paths, M extends Method> = Operation<P, M> extends {responses: {200: {content: {"application/json": infer R}}}} ? R : never;
type Input<P extends keyof paths, M extends Method> = Operation<P, M> extends {requestBody?: {content: {"application/json": infer B}}} ? B : never;
export type Call<P extends keyof paths, M extends Method> = {params?: Record<string, string | number>, query?: Record<string, string | number | undefined>, body?: Input<P, M>};

/** Set from the status answer before anyone signs in. False only when the panel's config file turns two-step sign-in off. */
export const flags = {twoStep: true};

/** Every answer that is not a success. code is the server's error code, or "network" when no answer came. */
export class ApiError extends Error {
	constructor(readonly status: number, readonly code: string, message: string) {
		super(message);
		this.name = "ApiError";
	}
}

// The page is always served at the prefix itself (routes live in the hash), so the API is one step below it whatever prefix the operator chose.
const base = location.pathname.replace(/\/+$/, "") + "/api";
let csrf = "", expired: () => void = () => {};

export const session = {
	set: (token: string) => { csrf = token; },
	onExpired: (handler: () => void) => { expired = handler; }
};

export async function api<P extends keyof paths, M extends Method>(method: M, path: P, call: Call<P, M> = {}): Promise<Answer<P, M>> {
	const query = Object.entries(call.query ?? {}).filter(([, value]) => value !== undefined && value !== "").map(([name, value]) => [name, String(value)]);
	const url = base + String(path).replace(/\{(\w+)\}/g, (_, name: string) => encodeURIComponent(String(call.params?.[name] ?? ""))) + (query.length ? "?" + new URLSearchParams(query) : "");
	const headers: Record<string, string> = {accept: "application/json"};
	if (call.body !== undefined) headers["content-type"] = "application/json";
	if (method !== "get" && csrf) headers["x-csrf-token"] = csrf;
	let response: Response;
	try {
		response = await fetch(url, {method: method.toUpperCase(), headers, body: call.body === undefined ? undefined : JSON.stringify(call.body), credentials: "same-origin", cache: "no-store"});
	} catch {
		throw new ApiError(0, "network", "");
	}
	const text = await response.text();
	let data: unknown = null;
	try { data = text ? JSON.parse(text) : null; } catch { data = null; }
	if (!response.ok) {
		const detail = (data as {error?: {code?: string, message?: string}} | null)?.error;
		const error = new ApiError(response.status, typeof detail?.code === "string" ? detail.code : "unknown", typeof detail?.message === "string" ? detail.message : "");
		if (error.status === 401 && path !== "/login" && path !== "/session") expired();
		throw error;
	}
	return data as Answer<P, M>;
}
