import {NumberField, SelectField, Switch, TextField} from "@veilway/ui";
import {Mark, useP} from "./kit.tsx";
import type {PanelKey} from "./locales/en.ts";

type Item = Record<string, unknown>;
const str = (value: unknown) => typeof value === "string" ? value : "";

// The presets of a fronted-shaped transport as method, place of the data and downstream mode, and the bounds of up.limit by place with the node's default.
const SHAPE_PRESETS: Record<string, [string, string, string]> = {"post-stream": ["POST", "body", "sse"], "get-stream": ["GET", "query", "sse"], "put-poll": ["PUT", "body", "poll"], "get-poll": ["GET", "query", "poll"]};
const SHAPE_LIMITS: Record<string, [number, number, number]> = {body: [1024, 65536, 65536], query: [1024, 8000, 4000], path: [1024, 8000, 4000], header: [1024, 4096, 3000]};
// Header fields the client or a web server in front writes or reads. A shape may not name one of them, nor any Sec- or Proxy- field.
const SHAPE_HEADERS_REFUSED = ["host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "accept", "range", "expect", "te", "trailer", "user-agent", "origin", "referer", "accept-encoding", "accept-language", "cache-control", "pragma", "keep-alive", "x-forwarded-for", "forwarded", "via", "cookie", "authorization"];

// The free members of a preset are drawn near their defaults: the spec's full ranges would allow a 250 ms gather or an hour-long stream.
const between = (low: number, high: number) => low + Math.floor(Math.random() * (high - low + 1));
const within = (value: unknown, low: number, high: number) => Number.isInteger(value) && (value as number) >= low && (value as number) <= high;
export const drawPreset = (preset: string) => {
	const [method, place, mode] = SHAPE_PRESETS[preset]!, cap = SHAPE_LIMITS[place]![2], sse = mode === "sse";
	return {preset, shape: {up: {method, in: place, gather: [between(10, 30), between(40, 60)], limit: between(Math.floor(cap * 0.75), cap)}, down: {mode, ...(sse ? {gather: [between(0, 5), between(10, 20)], life: [between(120, 400), between(600, 900)]} : {})}}};
};
// The node's rules for a fronted-shaped transport, as messages for its fields. A preset's values pass; this catches what the custom members and the JSON view can write.
export function shapeProblems(shape: Item, header: string) {
	const up = (shape.up ?? {}) as Item, down = (shape.down ?? {}) as Item, sse = down.mode === "sse", method = str(up.method), place = str(up.in), name = str(up.name), found: PanelKey[] = [];
	const range = (value: unknown, low: number, high: number) => Array.isArray(value) && value.length === 2 && value.every(item => within(item, low, high)) && value[0] <= value[1];
	const places = method === "GET" ? ["query", "path", "header"] : ["POST", "PUT", "PATCH"].includes(method) ? ["body"] : ["body", "query", "path", "header"], [low, high] = SHAPE_LIMITS[place] ?? SHAPE_LIMITS.body!;
	if (!/^[A-Z]{3,16}$/.test(method) || ["CONNECT", "TRACE", "HEAD", "OPTIONS"].includes(method)) found.push("shape.err.method");
	if (!places.includes(place)) found.push("shape.err.place");
	if (place === "header" ? !/^[A-Za-z0-9-]{1,32}$/.test(name) : up.name !== undefined) found.push("shape.err.name");
	else if (name && (SHAPE_HEADERS_REFUSED.includes(name.toLowerCase()) || /^(sec|proxy)-/i.test(name))) found.push("shape.err.nameRefused");
	else if (name && name.toLowerCase() === header.toLowerCase()) found.push("shape.err.nameHeader");
	if (up.limit !== undefined && !within(up.limit, low, high)) found.push("shape.err.limit");
	if (up.inflight !== undefined && !(within(up.inflight, 1, 4) && (sse || up.inflight === 1))) found.push("shape.err.inflight");
	if (!["poll", "sse"].includes(str(down.mode))) found.push("shape.err.mode");
	if (up.gather !== undefined && !range(up.gather, 0, 250)) found.push("shape.err.range");
	if (down.gather !== undefined && !sse) found.push("shape.err.sse");
	else if (down.gather !== undefined && !range(down.gather, 0, 250)) found.push("shape.err.range");
	if (down.life !== undefined && !sse) found.push("shape.err.sse");
	else if (down.life !== undefined && !range(down.life, 30, 3600)) found.push("shape.err.range");
	if (down.fallback !== undefined && (!sse || typeof down.fallback !== "boolean")) found.push(sse ? "shape.err.fallback" : "shape.err.sse");
	return [...new Set(found)];
}

// Two whole numbers, low first. Each end has its own field, and a range with both ends empty is left out so the node keeps its default.
function RangeField({label, hint, unit, min, max, defaults, value, onChange}: {label: string, hint: string, unit: string, min: number, max: number, defaults: [number, number], value: unknown, onChange: (value: unknown) => void}) {
	const {t} = useP(), [low = "", high = ""] = Array.isArray(value) ? value : [], set = (next: unknown[]) => onChange(next.every(item => item === "") ? undefined : next);
	return <fieldset className="p-proxies">
		<legend className="vw-label">{label}</legend>
		<p className="vw-muted vw-small">{hint}</p>
		<div className="p-pair">
			<NumberField label={t("shape.from")} unit={unit} min={min} max={max} placeholder={String(defaults[0])} value={low} onChange={from => set([from, high])} optional/>
			<NumberField label={t("shape.to")} unit={unit} min={min} max={max} placeholder={String(defaults[1])} value={high} onChange={to => set([low, to])} optional/>
		</div>
	</fieldset>;
}

// The preset whose method, place and downstream mode the shape has, or custom.
export function presetOf(shape: Item) {
	const up = (shape.up ?? {}) as Item, down = (shape.down ?? {}) as Item;
	return Object.keys(SHAPE_PRESETS).find(name => SHAPE_PRESETS[name]!.join(" ") === [str(up.method), str(up.in), str(down.mode)].join(" ")) ?? "custom";
}

// The request shape of a fronted-shaped transport, as the node's config and a profile of a subscription both edit it. A preset sets every member, custom sets each one.
export function ShapeFields({preset, shape, problems, onChange}: {preset: string, shape: Item, problems: PanelKey[], onChange: (next: {preset: string, shape: Item}) => void}) {
	const {t} = useP(), shapeUp = (shape.up ?? {}) as Item, shapeDown = (shape.down ?? {}) as Item;
	const member = (part: "up" | "down", key: string, value: unknown) => { const sides = {up: {...shapeUp}, down: {...shapeDown}}; if (value === undefined || value === "") delete sides[part][key]; else sides[part][key] = value; if (sides.up.in !== "header") delete sides.up.name; if (sides.down.mode !== "sse") {delete sides.up.inflight; delete sides.down.gather; delete sides.down.life; delete sides.down.fallback;} onChange({preset, shape: sides}); };
	return <fieldset className="p-mirror">
		<legend className="vw-label">{t("shape.legend")}</legend>
		<p className="vw-muted vw-small">{t("shape.lead")}</p>
		<SelectField label={t("shape.preset")} hint={t("shape.presetHint")} value={preset} onChange={name => onChange(name === "custom" ? {preset: name, shape} : drawPreset(name))} options={[...Object.keys(SHAPE_PRESETS), "custom"].map(name => ({value: name, label: name, detail: t(`shape.preset.${name}` as PanelKey)}))}/>
		{preset !== "custom" ? <p className="vw-muted vw-small">{t("shape.drawn")}</p> : <>
			<TextField label={t("shape.method")} hint={t("shape.methodHint")} placeholder="POST" value={str(shapeUp.method)} onChange={value => member("up", "method", value.trim().toUpperCase())} technical/>
			<SelectField label={t("shape.in")} hint={t("shape.inHint")} value={str(shapeUp.in)} onChange={value => member("up", "in", value)} options={["body", "query", "path", "header"].map(place => ({value: place, label: t(`shape.in.${place}` as PanelKey)}))}/>
			{shapeUp.in === "header" && <TextField label={t("shape.name")} hint={t("shape.nameHint")} placeholder="X-Trace" value={str(shapeUp.name)} onChange={value => member("up", "name", value.trim())} technical/>}
			<NumberField label={t("shape.limit")} hint={t("shape.limitHint")} unit={t("config.bytes")} min={1024} max={SHAPE_LIMITS[str(shapeUp.in)]?.[1] ?? 65536} placeholder={String(SHAPE_LIMITS[str(shapeUp.in)]?.[2] ?? 65536)} value={typeof shapeUp.limit === "number" ? shapeUp.limit : ""} onChange={value => member("up", "limit", value)} optional/>
			{shapeDown.mode === "sse" && <NumberField label={t("shape.inflight")} hint={t("shape.inflightHint")} unit={t("unit.requests")} min={1} max={4} placeholder="2" value={typeof shapeUp.inflight === "number" ? shapeUp.inflight : ""} onChange={value => member("up", "inflight", value)} optional/>}
			<RangeField label={t("shape.gather")} hint={t("shape.gatherHint")} unit={t("unit.milliseconds")} min={0} max={250} defaults={[10, 60]} value={shapeUp.gather} onChange={value => member("up", "gather", value)}/>
			<SelectField label={t("shape.mode")} value={str(shapeDown.mode)} onChange={value => member("down", "mode", value)} options={["poll", "sse"].map(mode => ({value: mode, label: mode, detail: t(`shape.mode.${mode}` as PanelKey)}))}/>
			{shapeDown.mode === "sse" && <>
				<RangeField label={t("shape.downGather")} hint={t("shape.downGatherHint")} unit={t("unit.milliseconds")} min={0} max={250} defaults={[0, 20]} value={shapeDown.gather} onChange={value => member("down", "gather", value)}/>
				<RangeField label={t("shape.life")} hint={t("shape.lifeHint")} unit={t("unit.seconds")} min={30} max={3600} defaults={[120, 900]} value={shapeDown.life} onChange={value => member("down", "life", value)}/>
				<Switch label={t("shape.fallback")} hint={t("shape.fallbackHint")} checked={shapeDown.fallback !== false} onChange={on => member("down", "fallback", on ? undefined : false)}/>
			</>}
		</>}
		{problems.map(key => <Mark key={key} tone="danger">{t(key)}</Mark>)}
		<p className="vw-muted vw-small">{t("shape.oldApps")}</p>
	</fieldset>;
}
