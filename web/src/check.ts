import type {PanelKey} from "./locales/en.ts";

// A reader for the part of JSON Schema that `veilway schema` uses, so an editor can point at a mistake before the node is asked. The node's own validation stays the authority. The panel's CSP forbids eval, which rules out a schema compiler.
export type Schema = boolean | {[key: string]: unknown};
export type Issue = {path: string, key: PanelKey, values?: Record<string, string>};

const kind = (value: unknown) => value === null ? "null" : Array.isArray(value) ? "array" : Number.isInteger(value) ? "integer" : typeof value;
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

function resolve(root: Schema, schema: Schema): Schema {
	const ref = typeof schema === "object" ? schema.$ref : undefined;
	if (typeof ref !== "string" || typeof root !== "object") return schema;
	return resolve(root, ref.replace(/^#\//, "").split("/").reduce<unknown>((at, part) => (at as Record<string, unknown> | undefined)?.[part], root) as Schema ?? true);
}

export function check(schema: Schema, value: unknown, root: Schema, path = ""): Issue[] {
	const s = resolve(root, schema);
	// The node shows every secret as its marker, and a marker sent back keeps the running value.
	if (typeof value === "string" && /^<redacted(:[0-9a-f]{8})?>$/.test(value)) return [];
	if (s === true || typeof s !== "object") return s === false ? [{path, key: "check.unknown", values: {name: path.split(".").pop() ?? ""}}] : [];
	const issues: Issue[] = [], type = kind(value), hint = typeof s.description === "string" ? s.description : "";
	const types = s.type === undefined ? null : ([] as unknown[]).concat(s.type);
	if (types && !types.some(want => want === type || (want === "number" && type === "integer"))) return [{path, key: "check.type", values: {expected: types.join(", ")}}];
	if ("const" in s && !same(s.const, value)) return [{path, key: "check.enum", values: {values: JSON.stringify(s.const)}}];
	if (Array.isArray(s.enum) && !s.enum.some(option => same(option, value))) return [{path, key: "check.enum", values: {values: s.enum.map(option => JSON.stringify(option)).join(", ")}}];
	if (s.not && check(s.not as Schema, value, root, path).length === 0) issues.push({path, key: "check.reserved"});
	for (const word of ["oneOf", "anyOf"] as const) {
		const options = s[word];
		if (!Array.isArray(options)) continue;
		const tried = options.map(option => check(option as Schema, value, root, path));
		if (tried.some(found => found.length === 0)) continue;
		// Objects told apart by their type say what is wrong inside the one their type names.
		const named = options.findIndex(option => { const o = resolve(root, option as Schema), kinds = typeof o === "object" ? resolve(root, (o.properties as Record<string, Schema> | undefined)?.type ?? true) : true; return typeof kinds === "object" && [kinds.const, ...((kinds.oneOf as {const?: unknown}[] | undefined) ?? []).map(one => one.const)].some(known => known !== undefined && same(known, (value as {type?: unknown} | null)?.type)); });
		issues.push(...(named >= 0 && type === "object" ? tried[named]! : [{path, key: "check.shape" as PanelKey, values: {hint}}]));
	}
	if (type === "string") {
		const text = value as string;
		if (typeof s.minLength === "number" && [...text].length < s.minLength) issues.push({path, key: "check.short", values: {min: String(s.minLength)}});
		if (typeof s.maxLength === "number" && [...text].length > s.maxLength) issues.push({path, key: "check.long", values: {max: String(s.maxLength)}});
		if (typeof s.pattern === "string" && !new RegExp(s.pattern, "u").test(text)) issues.push(hint ? {path, key: "check.form", values: {hint}} : {path, key: "check.pattern"});
	}
	if (type === "integer" || type === "number") {
		if (typeof s.minimum === "number" && (value as number) < s.minimum) issues.push({path, key: "check.small", values: {min: String(s.minimum)}});
		if (typeof s.maximum === "number" && (value as number) > s.maximum) issues.push({path, key: "check.big", values: {max: String(s.maximum)}});
	}
	if (type === "array") {
		const list = value as unknown[];
		if (typeof s.minItems === "number" && list.length < s.minItems) issues.push({path, key: "check.short", values: {min: String(s.minItems)}});
		if (typeof s.maxItems === "number" && list.length > s.maxItems) issues.push({path, key: "check.long", values: {max: String(s.maxItems)}});
		if (s.uniqueItems && new Set(list.map(item => JSON.stringify(item))).size < list.length) issues.push({path, key: "check.twice"});
		if (s.items !== undefined) list.forEach((item, i) => issues.push(...check(s.items as Schema, item, root, `${path}[${i}]`)));
	}
	if (type === "object") {
		const object = value as Record<string, unknown>, properties = (s.properties ?? {}) as Record<string, Schema>;
		for (const name of (s.required ?? []) as string[]) if (!(name in object)) issues.push({path, key: "check.required", values: {name}});
		for (const [name, needs] of Object.entries((s.dependentRequired ?? {}) as Record<string, string[]>)) for (const other of needs) if (name in object && !(other in object)) issues.push({path, key: "check.needs", values: {name, other}});
		for (const [name, item] of Object.entries(object)) {
			const at = path ? `${path}.${name}` : name;
			if (name in properties) issues.push(...check(properties[name]!, item, root, at));
			else if (s.additionalProperties === false) issues.push({path: at, key: "check.unknown", values: {name}});
			else if (typeof s.additionalProperties === "object") issues.push(...check(s.additionalProperties as Schema, item, root, at));
		}
	}
	return issues.slice(0, 50);
}
