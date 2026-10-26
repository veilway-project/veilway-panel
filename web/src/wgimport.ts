import type {PanelKey} from "./locales/en.ts";

// Reads a wg-quick file in the browser. The pasted text is hostile input (threat model row 69): bounded, strict about what it takes, and never sent anywhere, only the fields it yields.
export type Note = {key: PanelKey, values?: Record<string, string | number>};
export type WgFile = {fields: Record<string, unknown>, dns: string[], notes: Note[], warnings: Note[]};
export const MAX_BYTES = 65536, MAX_LINES = 1000, MAX_LINE = 2048;
export const KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const NAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const TAKEN: Record<string, string[]> = {interface: ["privatekey", "address", "mtu", "dns"], peer: ["publickey", "presharedkey", "endpoint", "persistentkeepalive", "allowedips"]};
const REPEATABLE = ["address", "dns", "allowedips"];
export const isV4 = (text: string) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(text) && text.split(".").every(part => Number(part) <= 255 && String(Number(part)) === part);
export const isV6 = (text: string) => /^[0-9A-Fa-f:.]{2,45}$/.test(text) && text.includes(":") && URL.canParse(`http://[${text}]/`);
const whole = (text: string, low: number, high: number) => /^\d{1,5}$/.test(text) && Number(text) >= low && Number(text) <= high;

// Whether an address typed in the form is a host address of one family, with the /32 or /128 that wg-quick writes allowed.
export const hostAddress = (text: string) => { const [address, prefix, ...more] = text.split("/"); return address !== undefined && more.length === 0 && (isV4(address) ? prefix === undefined || prefix === "32" : isV6(address) && (prefix === undefined || prefix === "128")); };

// Splits host:port or [v6]:port.
export const hostPort = (text: string) => {
	const at = text.lastIndexOf(":"), host = text.slice(0, at), port = text.slice(at + 1), bracket = host.startsWith("[") && host.endsWith("]");
	if (at < 1 || !whole(port, 1, 65535) || (host.includes(":") && !bracket)) return null;
	const name = bracket ? host.slice(1, -1) : host;
	return bracket ? isV6(name) ? {host: name.toLowerCase(), port: Number(port)} : null : isV4(name) || NAME.test(name.toLowerCase()) && !/^[\d.]+$/.test(name) ? {host: name.toLowerCase(), port: Number(port)} : null;
};

export function parseWgQuick(text: string): WgFile | Note {
	if (new TextEncoder().encode(text).length > MAX_BYTES) return {key: "wg.err.big", values: {max: "64 KiB"}};
	const rows = text.split(/\r\n|\r|\n/);
	if (rows.length > MAX_LINES) return {key: "wg.err.lines", values: {max: MAX_LINES}};
	const seen: Record<string, string[]> = {}, values: Record<string, string> = {}, sections: string[] = [], ignored = new Set<string>(), warnings: Note[] = [], notes: Note[] = [];
	let at = "";
	for (const [index, row] of rows.entries()) {
		const line = row.replace(/#.*/, "").trim(), number = index + 1;
		if (row.length > MAX_LINE) return {key: "wg.err.long", values: {line: number}};
		if (!line) continue;
		const header = line.match(/^\[\s*([A-Za-z]{1,32})\s*\]$/);
		if (header) {
			at = header[1]!.toLowerCase();
			if (at !== "interface" && at !== "peer") { at = "other"; ignored.add(header[1]!); continue; }
			sections.push(at);
			if (at === "interface" && sections.filter(name => name === "interface").length > 1) return {key: "wg.err.twoInterfaces", values: {line: number}};
			if (at === "peer" && sections.filter(name => name === "peer").length > 1) return {key: "wg.err.twoPeers", values: {line: number}};
			continue;
		}
		const split = line.indexOf("=");
		if (split < 1) return {key: "wg.err.line", values: {line: number}};
		const name = line.slice(0, split).trim().toLowerCase(), value = line.slice(split + 1).trim();
		if (!at) return {key: "wg.err.outside", values: {line: number}};
		if (!/^[a-z0-9]{1,32}$/.test(name)) return {key: "wg.err.line", values: {line: number}};
		if (at === "other" || !TAKEN[at]!.includes(name)) { ignored.add(line.slice(0, split).trim().slice(0, 32)); continue; }
		const field = at + "." + name;
		if (REPEATABLE.includes(name)) { seen[field] = [...(seen[field] ?? []), ...value.split(",").map(part => part.trim()).filter(Boolean)]; continue; }
		if (field in values) return {key: "wg.err.twice", values: {line: number}};
		values[field] = value;
	}
	if (!sections.includes("interface")) return {key: "wg.err.noInterface"};
	if (!sections.includes("peer")) return {key: "wg.err.noPeer"};
	const fields: Record<string, unknown> = {};
	for (const [field, label] of [["interface.privatekey", "PrivateKey"], ["peer.publickey", "PublicKey"], ["peer.presharedkey", "PresharedKey"]] as const) {
		if (!(field in values)) { if (field !== "peer.presharedkey") return {key: "wg.err.missing", values: {name: label}}; continue; }
		if (!KEY.test(values[field]!)) return {key: "wg.err.key", values: {name: label}};
		fields[{"interface.privatekey": "private_key", "peer.publickey": "public_key", "peer.presharedkey": "preshared_key"}[field]!] = values[field];
	}
	const addresses = seen["interface.address"] ?? [];
	if (!addresses.length) return {key: "wg.err.missing", values: {name: "Address"}};
	if (!addresses.every(hostAddress)) return {key: "wg.err.address"};
	const kept = addresses.map(address => address.split("/")[0]!.toLowerCase());
	if (kept.length > 2 || kept.filter(isV4).length > 1 || kept.filter(isV6).length > 1) return {key: "wg.err.addressMany"};
	fields.addresses = kept;
	if (!("peer.endpoint" in values)) return {key: "wg.err.missing", values: {name: "Endpoint"}};
	const endpoint = hostPort(values["peer.endpoint"]!);
	if (!endpoint) return {key: "wg.err.endpoint"};
	fields.server = endpoint.host.includes(":") ? `[${endpoint.host}]:${endpoint.port}` : `${endpoint.host}:${endpoint.port}`;
	if ("interface.mtu" in values) { if (!whole(values["interface.mtu"]!, 1280, 1500)) return {key: "wg.err.mtu"}; fields.mtu = Number(values["interface.mtu"]); }
	if ("peer.persistentkeepalive" in values) {
		const keepalive = values["peer.persistentkeepalive"]!.toLowerCase();
		if (keepalive !== "off" && !whole(keepalive, 0, 3600)) return {key: "wg.err.keepalive"};
		fields.keepalive_secs = keepalive === "off" ? 0 : Number(keepalive);
	}
	const routes = (seen["peer.allowedips"] ?? []).map(route => route.toLowerCase());
	if (!routes.includes("0.0.0.0/0") || !routes.includes("::/0")) warnings.push({key: "wg.warn.allowed"});
	const dns = (seen["interface.dns"] ?? []).filter(item => isV4(item) || isV6(item) || NAME.test(item.toLowerCase())).slice(0, 4);
	if (dns.length) notes.push({key: "wg.note.dns", values: {servers: dns.join(", ")}});
	if (ignored.size) notes.push({key: "wg.note.ignored", values: {names: [...ignored].slice(0, 8).map(name => name.replace(/[^A-Za-z0-9 ]/g, "")).filter(Boolean).join(", ")}});
	return {fields, dns, notes, warnings};
}
