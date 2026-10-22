import {Banner, Button, Checkbox, DataTable, Dialog, Field, Glass, Icon, IconButton, NumberField, RadioGroup, SecretField, Segmented, SelectField, StateBlock, Switch, Tabs, TextField, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, ApiError, type Diff, type Report, type Running} from "../api.ts";
import {check, type Issue, type Schema} from "../check.ts";
import {Copyable, dnsName, ErrorNote, Issues, lines, LinesField, Mark, moved, PageHead, useGuard, useLoad, useP, useReorder, useSay} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {drawPreset, presetOf, ShapeFields, shapeProblems} from "../shape.tsx";
import {UpstreamsTab} from "./upstreams.tsx";
import {XrayForm, XraySheet} from "./xray.tsx";

type Section = "inbounds" | "outbounds" | "exits" | "routing";
type Item = Record<string, unknown>;
type Row = {type: string, listen: string, path: string, at: number, cert: "self" | "files", name: string, certFile: string, keyFile: string, origin: string, proxyProtocol: boolean, http2: boolean, proxies: string[], header: string, preset: string, shape: Item, limits: Record<string, number | "">, siteHost: string, siteNames: string[], sitePort: number | "", siteAddress: string, acknowledged: boolean, siteKey: string, keys: string[]};
type BorrowedErrors = Partial<Record<"listen" | "host" | "names" | "port" | "address" | "ack" | "key", PanelKey>>;
type StreamErrors = Partial<Record<"path" | "origin" | "certFile" | "keyFile" | "name" | "proxies" | "header", PanelKey>>;
type Cond = {key: string, values: string};
type Listed = {kind: "veilway" | "wireguard" | "xray", tag: string, index: number, item?: Item, xray?: XrayRow};
type XrayRow = {tag: string, protocol: string, listen: string, port: number, security: string, clients: number, host: string, managed: boolean, certificate_missing: boolean};
const TABS = ["exits", "routing", "outbounds", "upstreams"] as const;
const TRANSPORTS = ["udp", "udp-obfs", "tls", "ws", "ws-plain", "fronted", "fronted-shaped", "faketls"];
const PATHED = ["tls", "ws", "ws-plain", "fronted", "fronted-shaped"];
const CONDITIONS = ["user", "group", "inbound", "link", "ip", "domain", "protocol", "port", "icmp_type", "icmp_code"];
const NUMERIC = ["protocol", "port", "icmp_type", "icmp_code"];
const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/, RESERVED = ["all", "any", "block", "reject", "drop", "local", "direct", "user", "users"], KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
// Loopback, private and link-local hosts, the ones the node's validator does not warn about. A host may come with brackets or a prefix length.
// Each pool of a listener with its bounds, default and unit from the schema, and the pools each transport has: udp-obfs only sessions, tls no pools of the proxy path.
const LIMITS: Record<string, [number, number, number, "sessions" | "connections" | "requests"]> = {sessions: [1, 1048576, 16384, "sessions"], undecided: [1, 65536, 512, "connections"], undecided_per_source: [1, 65536, 64, "connections"], relayed: [1, 65536, 1024, "connections"], proxy_connections: [2, 65536, 2048, "connections"], decoy_requests_per_source: [1, 65536, 16, "requests"], fronted_sessions: [1, 65536, 1024, "sessions"], shaped_sessions: [1, 65536, 256, "sessions"], site_rate: [1, 1024, 16, "connections"]};
const POOLS: Record<string, string[]> = {"udp-obfs": ["sessions"], tls: ["sessions", "undecided", "undecided_per_source", "relayed"], ws: ["sessions", "undecided", "undecided_per_source", "relayed", "proxy_connections", "decoy_requests_per_source"], fronted: ["sessions", "undecided", "undecided_per_source", "relayed", "proxy_connections", "decoy_requests_per_source", "fronted_sessions"], "fronted-shaped": ["sessions", "undecided", "undecided_per_source", "relayed", "proxy_connections", "decoy_requests_per_source", "fronted_sessions", "shaped_sessions"], "ws-plain": ["sessions", "undecided", "undecided_per_source", "relayed", "proxy_connections", "decoy_requests_per_source"], faketls: ["relayed", "site_rate"]};
const REFUSED_HEADERS = ["upgrade", "connection", "sec-websocket-accept", "set-cookie", "content-length", "transfer-encoding", "content-type", "content-encoding", "trailer", "keep-alive"];
// What an exit does with traffic its outbound cannot carry, and the default of each kind. Only ping may be answered by the node, and only UDP may leave from the node's own address.
const POLICIES: Record<string, string[]> = {icmp_echo: ["local", "reject", "drop", "direct", "via"], udp: ["reject", "drop", "direct", "via"], other: ["reject", "drop", "via"]};
const PICKED = ["user", "group", "inbound", "link"];
const loopback = (host: string) => /^\[?(127\.|::1(\]|\/|$))/.test(host);
const local = (host: string) => loopback(host) || /^\[?(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|f[cd][0-9a-f]{0,2}:|fe[89ab][0-9a-f]?:)/i.test(host);
const BLANK: Record<Exclude<Section, "routing">, Item> = {inbounds: {tag: "", type: "veilway", address: [], transports: [{type: "udp-obfs", listen: ""}]}, outbounds: {tag: "", type: "direct"}, exits: {tag: "", backend: {type: "netstack", outbound: ""}}};
let schemaCache: Promise<Schema> | null = null;

// The schema does not change while the panel runs, so every editor shares one copy.
export const loadSchema = () => schemaCache ??= api("get", "/config/schema").then(schema => schema as Schema, error => { schemaCache = null; throw error; });
export const loadRunning = () => api("get", "/config") as Promise<Running>;
const str = (value: unknown) => typeof value === "string" ? value : "";
const list = (value: unknown) => Array.isArray(value) ? value as Item[] : [];
// The reason a Through choice cannot be saved, read from the outbounds as they would be saved. `from` is the outbound that goes through, or empty for a link, which nothing can go back to. Mirrors `server/src/via.rs`.
export function viaProblem(from: string, via: string, outbounds: Item[]): PanelKey | undefined {
	const seen = new Set([from]);
	let at = via, hops = 1;
	while (true) {
		const item = outbounds.find(other => str(other.tag) === at);
		if (item?.type !== "socks5") return "via.notSocks";
		if (seen.has(at)) return "via.loop";
		seen.add(at);
		if (!str(item.via)) return undefined;
		if (++hops > 8) return "via.hops";
		at = str(item.via);
	}
}

// The outbounds that dial through another one, which an exit may not send UDP around. Mirrors `server/src/via.rs`.
export function viaChained(document: Item): string[] {
	return list(document.outbounds).filter(item => str(item.via)).map(item => str(item.tag));
}

// Says what a check found in the reader's language. The node's own reports are English only and are shown as they come.
export function useIssueText() {
	const {t} = useP();
	return (issues: Issue[]) => issues.map(issue => ({path: issue.path, text: t(issue.key, issue.values)}));
}

// Where devices connect: the node's own inbounds and the Xray add-on's, in one list. Each row says its type (what apps speak) apart from its transports (how the bytes travel).
export function InboundsPage() {
	const {t, number} = useP(), say = useSay(), toast = useToast(), config = useLoad(loadRunning, []), schema = useLoad(loadSchema, []), xray = useLoad(() => api("get", "/xray"), []);
	const [kind, setKind] = useState("all"), [json, setJson] = useState(false), [proposed, setProposed] = useState<unknown>(undefined), [editing, setEditing] = useState<{index: number | null} | null>(null), [adding, setAdding] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [moves, setMoves] = useState<string[]>([]);
	useEffect(() => { if (adding) document.getElementById("xray-form-title")?.scrollIntoView({block: "nearest"}); }, [adding]);
	if (config.error && !config.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={config.reload}>{t("action.retry")}</Button>}>{say(config.error)}</StateBlock>;
	if (!config.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const running = config.data, items = list(running.document.inbounds), outbounds = list(running.document.outbounds).map(item => str(item.tag)).filter(Boolean);
	const rows: Listed[] = [...items.map((item, index) => ({kind: item.type === "wireguard" ? "wireguard" as const : "veilway" as const, tag: str(item.tag), index, item})), ...(xray.data?.inbounds ?? []).map((row, index) => ({kind: "xray" as const, tag: row.tag, index, xray: row as XrayRow}))];
	const shown = kind === "all" ? rows : rows.filter(row => row.kind === kind), count = (of: string) => rows.filter(row => row.kind === of).length;
	const propose = (next: unknown, notes: string[] = []) => { setMoves(notes); setProposed(next); };
	const removeXray = (tag: string) => { setBusy(true); setError(null); void api("delete", "/xray/inbounds/{tag}", {params: {tag}}).then(() => { toast({tone: "success", title: t("xray.removed", {tag})}); xray.reload(); }, setError).finally(() => setBusy(false)); };
	const port = (listen: string) => listen.slice(listen.lastIndexOf(":") + 1);
	return <>
		<PageHead title={t("nav.inbounds")} lead={t("inbounds.lead")}>
			<Button onClick={() => setJson(!json)}>{t(json ? "inbounds.asList" : "inbounds.asJson")}</Button>
			<Button variant="primary" icon="plus" onClick={() => setEditing({index: null})}>{t("config.add.inbounds")}</Button>
		</PageHead>
		<div className={adding ? "p-grid-main" : "p-stack"}>
			<div className="p-stack">
				{json ? <JsonEditor key={running.revision} section="inbounds" value={running.document.inbounds ?? []} schema={schema.data} onReview={propose}/> : <Glass className="p-panel">
					<Segmented label={t("inbounds.kind")} value={kind} onChange={setKind} options={(["all", "veilway", "wireguard", "xray"] as const).map(of => ({value: of, label: t(`inbounds.kind.${of}`) + " " + number(of === "all" ? rows.length : count(of))}))}/>
					<DataTable caption={t("nav.inbounds")} rows={shown} rowKey={row => row.kind + row.tag + row.index} empty={<StateBlock kind="empty" title={t("config.empty.inbounds")} action={<Button variant="primary" icon="plus" onClick={() => setEditing({index: null})}>{t("config.add.inbounds")}</Button>}>{t("config.emptyBody.inbounds")}</StateBlock>} columns={[
						{id: "tag", header: t("config.col.tag"), cell: row => <span className="vw-code p-name">{row.tag}</span>},
						{id: "type", header: t("inbounds.col.type"), cell: row => row.xray ? t("inbounds.type.xray", {protocol: t(`xray.name.${["vless", "trojan", "shadowsocks"].includes(row.xray.protocol) ? row.xray.protocol as "vless" : "vless"}`)}) : t(`inbounds.type.${row.kind as "veilway"}`)},
						{id: "at", header: t("inbounds.col.at"), cell: row => row.xray ? <span className="p-user"><span className="vw-code" dir="ltr">{row.xray.host ? `${row.xray.host}:${row.xray.port}` : row.xray.listen}</span>{row.xray.certificate_missing ? <Mark tone="warning">{t("xray.noCertificate")}</Mark> : !row.xray.managed ? <Mark tone="warning" title={t("xray.unmanagedHint")}>{t("xray.unmanaged")}</Mark> : <span>{t("inbounds.users", {count: row.xray.clients})}</span>}</span> : <span className="p-user"><span className="vw-code" dir="ltr">{(row.item!.address as string[] | undefined)?.join(", ")}</span>{typeof row.item!.mtu === "number" && <span>{t("inbounds.mtu", {mtu: number(row.item!.mtu as number, {useGrouping: false})})}</span>}</span>},
						{id: "transports", header: t("config.col.transports"), cell: row => <span className="p-tags">{row.xray ? <><span className="p-tag vw-code" title={row.xray.listen}>{(row.xray.protocol === "shadowsocks" ? "tcp+udp " : "tcp ") + row.xray.port}</span>{row.xray.security === "tls" && <span className="p-tag vw-code">tls</span>}</> : list(row.item!.transports).map((tr, i) => <span key={i} className="p-tag vw-code" title={str(tr.listen)}>{str(tr.type) + " " + (str(tr.path) || port(str(tr.listen)))}</span>)}</span>},
						{id: "edit", header: "", align: "end", cell: row => <div className="p-cluster p-end">{row.item && <Button size="sm" variant="quiet" aria-label={t("config.editName", {name: row.tag})} onClick={() => setEditing({index: row.index})}>{t("user.edit")}</Button>}<Button size="sm" variant="quiet" disabled={busy} aria-label={t("config.removeName", {name: row.tag})} onClick={() => row.item ? propose(items.filter((_, i) => i !== row.index)) : removeXray(row.tag)}>{t("common.remove")}</Button></div>}
					]}/>
					<ErrorNote error={error}/>
					<div className="vw-well p-note"><Icon name="info"/><p className="vw-small">{t("inbounds.rating")}</p></div>
				</Glass>}
				<p className="vw-muted vw-small">{t("config.reviewNote")}</p>
				{xray.data && <XraySheet xray={xray.data} onAdd={() => setAdding(true)} onChanged={xray.reload}/>}
			</div>
			{adding && <XrayForm onClose={() => setAdding(false)} onDone={() => { setAdding(false); xray.reload(); }}/>}
		</div>
		{editing && <ItemForm section="inbounds" xray={xray.data?.installed === true} onXray={() => { setEditing(null); setAdding(true); }} hidden={proposed !== undefined} item={editing.index === null ? null : items[editing.index]!} taken={[...items.filter((_, i) => i !== editing.index).map(item => str(item.tag)), ...(xray.data?.inbounds ?? []).map(row => row.tag)]} outbounds={outbounds} schema={schema.data} onSave={(item, notes) => propose(editing.index === null ? [...items, item] : items.map((old, i) => i === editing.index ? item : old), notes)} onClose={() => setEditing(null)}/>}
		{proposed !== undefined && <Review section="inbounds" running={running} value={proposed} moves={moves} show={{kind: "inbounds", count: items.length, go: index => { setJson(false); setKind("all"); setProposed(undefined); requestAnimationFrame(() => { const row = document.querySelectorAll<HTMLElement>(".p-panel tbody tr")[index]; row?.scrollIntoView({block: "center"}); row?.querySelector<HTMLElement>("td:last-child button")?.focus(); }); }}} onClose={() => setProposed(undefined)} onDone={() => { setProposed(undefined); setEditing(null); config.reload(); }}/>}
	</>;
}

// Where traffic leaves and the rules that pick the way, one tab each.
export function RoutingPage({tab}: {tab: string}) {
	const {t} = useP(), current = (TABS as readonly string[]).includes(tab) ? tab : "exits";
	// On a phone the tab row scrolls, and a tab opened by its address can sit out of view.
	useEffect(() => { document.querySelector(".vw-tab[data-state=active]")?.scrollIntoView({block: "nearest", inline: "nearest"}); }, [current]);
	return <>
		<PageHead title={t("nav.routing")} lead={t("routing.lead")}/>
		<Tabs label={t("nav.routing")} value={current} onChange={id => { location.hash = "#/routing/" + id; }} items={TABS.map(id => ({id, label: t(`node.tab.${id}`), content: id === "upstreams" ? <UpstreamsTab/> : <SectionTab section={id}/>}))}/>
	</>;
}

function SectionTab({section}: {section: Exclude<Section, "inbounds">}) {
	const {t} = useP(), say = useSay(), config = useLoad(loadRunning, []), schema = useLoad(loadSchema, []), [json, setJson] = useState(false), [proposed, setProposed] = useState<unknown>(undefined), [editing, setEditing] = useState<{index: number | null} | null>(null), [moves, setMoves] = useState<string[]>([]);
	if (config.error && !config.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={config.reload}>{t("action.retry")}</Button>}>{say(config.error)}</StateBlock>;
	if (!config.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const running = config.data, value = running.document[section] ?? (section === "routing" ? {default: ""} : []), items = list(value), document = running.document;
	const tags = (name: string) => list(document[name]).map(item => str(item.tag)).filter(Boolean);
	const propose = (next: unknown, notes: string[] = []) => { setMoves(notes); setProposed(next); };
	const remove = (index: number) => propose(items.filter((_, i) => i !== index));
	const edit = (index: number | null) => setEditing({index});
	return <div className="p-stack">
		<div className="p-row"><p className="vw-muted p-lead">{t(`config.lead.${section}`)}</p><Segmented label={t("config.view")} value={json ? "json" : "list"} onChange={view => setJson(view === "json")} options={[{value: "list", label: t("config.view.list")}, {value: "json", label: t("config.view.json")}]}/></div>
		{json ? <JsonEditor key={running.revision} section={section} value={value} schema={schema.data} onReview={propose}/>
		: section === "routing" ? <Routing key={running.revision} reviewing={proposed !== undefined} routing={value as Item} exits={list(document.exits).filter(item => str(item.tag))} inbounds={tags("inbounds")} links={tags("links")} onPropose={propose}/>
		: <Glass className="p-panel">
			<div className="p-row p-table-head"><span className="vw-muted vw-small">{t("config.count", {count: items.length})}</span><Button size="sm" icon="plus" onClick={() => edit(null)}>{t(`config.add.${section}`)}</Button></div>
			<DataTable caption={t(`node.tab.${section}`)} rows={items.map((item, index) => ({item, index}))} rowKey={row => str(row.item.tag) || String(row.index)} empty={<StateBlock kind="empty" title={t(`config.empty.${section}`)} action={<Button variant="primary" icon="plus" onClick={() => edit(null)}>{t(`config.add.${section}`)}</Button>}>{t(`config.emptyBody.${section}`)}</StateBlock>} columns={[
				{id: "tag", header: t("config.col.tag"), cell: ({item}) => <span className="p-user"><span className="vw-code">{str(item.tag)}</span><span className="vw-muted vw-small">{section === "exits" ? [str(item.name), str(item.country)].filter(Boolean).join(", ") : str(item.type)}</span></span>},
				...(section === "outbounds" ? [
					{id: "target", header: t("config.col.target"), cell: ({item}: {item: Item}) => item.type === "socks5" ? <span className="p-user"><span className="vw-code">{str(item.server)}</span>{str(item.via) && <span className="vw-muted vw-small">{t("config.viaName", {outbound: str(item.via)})}</span>}</span> : <span className="vw-muted">{(item.bind ? t("config.bind", {address: str(item.bind)}) : t("config.fromNode")) + (item.interface ? t("config.onInterface", {name: str(item.interface)}) : "")}</span>}
				] : [
					{id: "backend", header: t("config.col.backend"), cell: ({item}: {item: Item}) => { const backend = (item.backend ?? {}) as Item; return backend.type === "netstack" ? t("config.backend.netstackVia", {outbound: str(backend.outbound)}) : backend.type === "chain" ? t("config.backend.chainVia", {links: (backend.links as string[] | undefined ?? []).join(", ")}) : backend.type === "upstream" ? t("config.backend.upstreamVia", {upstream: str(backend.upstream)}) : t(`config.backend.${backend.type === "l3" ? "l3" : "block"}`); }}
				]),
				{id: "edit", header: "", align: "end", cell: ({item, index}) => <div className="p-cluster p-end"><Button size="sm" variant="quiet" aria-label={t("config.editName", {name: str(item.tag)})} onClick={() => edit(index)}>{t("user.edit")}</Button><Button size="sm" variant="quiet" aria-label={t("config.removeName", {name: str(item.tag)})} onClick={() => remove(index)}>{t("common.remove")}</Button></div>}
			]}/>
		</Glass>}
		{section !== "routing" && <p className="vw-muted vw-small">{t("config.reviewNote")}</p>}
		{editing && section !== "routing" && <ItemForm section={section} hidden={proposed !== undefined} socks={list(document.outbounds).filter(item => item.type === "socks5").map(item => str(item.tag))} exits={list(document.exits)} chain={list(document.outbounds)} chained={viaChained(document)} item={editing.index === null ? null : items[editing.index]!} taken={items.filter((_, i) => i !== editing.index).map(item => str(item.tag))} outbounds={tags("outbounds")} schema={schema.data} onSave={item => propose(editing.index === null ? [...items, item] : items.map((old, i) => i === editing.index ? item : old))} onClose={() => setEditing(null)}/>}
		{proposed !== undefined && <Review section={section} running={running} value={proposed} moves={moves} show={{kind: section === "routing" ? "rules" : section, count: section === "routing" ? list((value as Item).rules).length : items.length, go: index => { setJson(false); setProposed(undefined); requestAnimationFrame(() => { const row = window.document.querySelectorAll<HTMLElement>(".p-panel tbody tr")[index]; row?.scrollIntoView({block: "center"}); row?.querySelector<HTMLElement>("td:last-child button:last-child")?.focus(); }); }}} onClose={() => setProposed(undefined)} onDone={() => { setProposed(undefined); setEditing(null); config.reload(); }}/>}
	</div>;
}

function JsonEditor({section, value, schema, onReview}: {section: Section, value: unknown, schema: Schema | null, onReview: (value: unknown) => void}) {
	const {t} = useP(), say = useIssueText(), first = JSON.stringify(value, null, 2), [text, setText] = useState(first);
	let parsed: unknown = undefined, issues: {path: string, text: string}[] = [];
	try { parsed = JSON.parse(text); } catch (failure) { issues = [{path: "", text: t("error.json", {message: (failure as Error).message})}]; }
	if (parsed !== undefined && schema && typeof schema === "object") issues = say(check((schema.properties as Record<string, Schema>)[section] ?? true, parsed, schema, section));
	return <Glass className="p-panel">
		<label className="vw-label" htmlFor={"json-" + section}>{t("config.jsonLabel", {section})}</label>
		<textarea id={"json-" + section} className="vw-input vw-code p-textarea p-json" dir="ltr" spellCheck={false} rows={18} value={text} onChange={event => setText(event.target.value)} aria-describedby={"json-" + section + "-note"}/>
		<p className="vw-note" id={"json-" + section + "-note"}>{!schema ? t("config.noSchema") : issues.length ? t("config.issues", {count: issues.length}) : t("config.clean")}</p>
		<Issues issues={issues}/>
		<div className="p-cluster"><Button variant="primary" disabled={issues.length > 0 || text === first} onClick={() => onReview(parsed)}>{t("config.review")}</Button>{text !== first && <Button variant="quiet" onClick={() => setText(first)}>{t("config.undo")}</Button>}</div>
	</Glass>;
}

// A dry run on the node first, then the apply on the revision this page read. A revision that moved means another admin or the node's file changed it in between.
function Review({section, running, value, moves, show, onClose, onDone}: {section: Section, running: Running, value: unknown, moves: string[], show?: {kind: string, count: number, go: (index: number) => void}, onClose: () => void, onDone: () => void}) {
	const {t, number} = useP(), guard = useGuard(), toast = useToast(), [answer, setAnswer] = useState<{valid: boolean, report: Report, diff: Diff | null} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [stale, setStale] = useState(false), [refused, setRefused] = useState<Report | null>(null);
	useEffect(() => { api("post", "/config/diff", {body: {document: {...running.document, [section]: value}}}).then(found => setAnswer(found as typeof answer), setError); }, []);
	const apply = async () => {
		setBusy(true);
		setError(null);
		try {
			const done = await guard(() => api("put", "/config/{section}", {params: {section}, body: {revision: running.revision, value}})) as {generation?: number};
			toast({tone: "success", title: t("config.applied", {generation: done.generation ?? running.generation + 1})});
			onDone();
		} catch (failure) {
			if (failure instanceof ApiError && failure.status === 409) setStale(true);
			else if (failure instanceof ApiError && failure.code === "invalid_config") { try { setRefused((JSON.parse(failure.message) as {report: Report}).report); } catch { setError(failure); } }
			else setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const report = refused ?? answer?.report, diff = answer?.diff, doc = {...running.document, [section]: value} as Record<string, unknown>;
	// The node's paths in the reader's words for the items the panel has a form for, with a way to the item when the page lists it. Other paths stay as the node wrote them; the raw path stays beside the words.
	const word = (issue: {path: string, message: string}) => {
		const at = issue.path.match(/^(routing\.rules|inbounds|outbounds|exits)\[(\d+)\](?:\.transports\[(\d+)\])?/), missing = issue.message.match(/^missing required key `(.+)`$/);
		if (!at) return {path: issue.path, text: issue.message};
		const kind = at[1] === "routing.rules" ? "rules" : at[1]!, index = Number(at[2]), item = (kind === "rules" ? list((doc.routing as Item | undefined)?.rules) : list(doc[kind]))[index] ?? {}, tag = str(item.tag);
		const who = kind === "rules" ? t(tag ? "issue.ruleNamed" : "issue.rule", {number: number(index + 1), name: tag}) : t(`issue.${kind as "exits"}`, {name: tag || number(index + 1)}), where = at[3] ? t("issue.transport", {who, number: number(Number(at[3]) + 1)}) : who;
		const text = missing ? missing[1] === "tag" ? t("issue.needsName") : t("issue.needsKey", {key: missing[1]!}) : issue.message.includes("found a tag no exit has") ? t("issue.noExit", {exit: str(((item.action ?? {}) as Item).exit)}) : issue.message;
		return {path: issue.path, text: where + ": " + text, action: show?.kind === kind && index < show.count ? <Button size="sm" variant="quiet" onClick={() => show.go(index)}>{t("issue.show")}</Button> : undefined};
	};
	const changes = diff ? (["inbounds", "outbounds", "exits", "rules", "users"] as const).flatMap(kind => (["added", "changed", "removed"] as const).filter(verb => diff[kind]?.[verb]?.length).map(verb => ({kind, verb, names: diff[kind]![verb]}))) : [];
	const restarts = diff?.inbound_changes?.filter(change => change.restart).map(change => change.tag) ?? [], lost = diff?.user_changes?.filter(change => change.lost_access).map(change => change.name) ?? [];
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("review.title")} description={t("review.body")}>
		<div className="p-stack">
			{!answer && !error && <StateBlock kind="loading" title={t("review.asking")}/>}
			{stale && <Banner tone="warning" title={t("review.stale")} action={<Button size="sm" icon="refresh" onClick={onDone}>{t("review.reload")}</Button>}>{t("review.staleBody")}</Banner>}
			{report && report.errors.length > 0 && <><Banner tone="danger" title={t("review.invalid")}>{t("review.invalidBody")}</Banner><Issues issues={report.errors.map(word)}/></>}
			{answer?.valid && !refused && <>
				{changes.length || diff?.routing_default || diff?.rules_reordered || moves.length ? <ul className="p-changes">
					{changes.map(change => <li key={change.kind + change.verb}><Mark tone={change.verb === "removed" ? "danger" : change.verb === "added" ? "success" : "info"}>{t(`review.${change.verb}`)}</Mark><span>{t(`review.kind.${change.kind}`)}</span><span className="vw-code">{change.names.join(", ")}</span></li>)}
					{diff?.routing_default && <li><Mark tone="info">{t("review.changed")}</Mark><span>{t("review.default")}</span></li>}
					{moves.map(move => <li key={move}><Mark tone="info">{t("review.moved")}</Mark><span>{move}</span></li>)}
					{diff?.rules_reordered && !moves.length && <li><Mark tone="info">{t("review.changed")}</Mark><span>{t("review.order")}</span></li>}
				</ul> : <p className="vw-muted">{t("review.nothing")}</p>}
				{restarts.length > 0 && <Banner tone="warning" title={t("review.restart", {tags: restarts.join(", ")})}>{t("review.restartBody")}</Banner>}
				{lost.length > 0 && <Banner tone="danger" title={t("review.lost", {count: lost.length})}>{lost.join(", ")}</Banner>}
			</>}
			{report && report.warnings.length > 0 && <><p className="vw-label">{t("review.warnings")}</p><Issues issues={report.warnings.map(word)}/></>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy || !answer?.valid || stale || refused !== null} onClick={() => void apply()}>{t("review.apply")}</Button></div>
		</div>
	</Dialog>;
}

const ceiling = (row: Row, key: string) => key === "undecided_per_source" ? Math.min(Number(row.limits.undecided) || 512, 65536) : LIMITS[key]![1];
const outside = (row: Row, key: string) => typeof row.limits[key] === "number" && ((row.limits[key] as number) < LIMITS[key]![0] || (row.limits[key] as number) > ceiling(row, key));
// A key from the browser's random source, as veilway genkey makes one: an inbound key is clamped for X25519, a transport key is 32 random bytes.
const newKey = (clamped: boolean) => { const key = crypto.getRandomValues(new Uint8Array(32)); if (clamped) { key[0] = key[0]! & 248; key[31] = (key[31]! & 127) | 64; } return btoa(String.fromCharCode(...key)); };

const toRow = (tr: Item, at: number): Row => { const tls = (tr.tls ?? {}) as Item, site = (tr.site ?? {}) as Item, shape = (tr.shape ?? {}) as Item; return {limits: {...((tr.limits ?? {}) as Record<string, number>)}, proxyProtocol: ((tr.decoy ?? {}) as Item).proxy_protocol === true, http2: tr.http2 === "on", type: str(tr.type), listen: str(tr.listen), path: str(tr.path), at, cert: tls.cert !== undefined ? "files" : "self", name: str(tls.name), certFile: str(tls.cert), keyFile: str(tls.key), origin: str(((tr.decoy ?? {}) as Item).origin), proxies: Array.isArray(tr.trusted_proxies) && tr.trusted_proxies.length ? tr.trusted_proxies as string[] : [""], header: str(tr.client_address_header), preset: presetOf(shape), shape, siteHost: str(site.host), siteNames: Array.isArray(site.names) ? site.names.map(str) : [], sitePort: typeof site.port === "number" ? site.port : "", siteAddress: str(site.address), acknowledged: site.acknowledged === true, siteKey: str(tr.transport_key), keys: Array.isArray(tr.transport_keys) ? tr.transport_keys.map(str) : []}; };

// The lines a transport behind the operator's web server needs in its site file. handle, never handle_path: the node wants the path kept.
function WebLines({row}: {row: Row}) {
	const {t} = useP(), listen = row.listen.trim().replace(/^0\.0\.0\.0:/, "127.0.0.1:").replace(/^\[::\]:/, "[::1]:"), path = row.path.trim(), proxies = row.proxies.map(proxy => proxy.trim()).filter(Boolean), fronted = row.type !== "ws";
	const caddy = `handle ${path}* {\n\treverse_proxy ${listen}\n}`, nginx = `location ${path} {\n\tproxy_pass http://${listen};\n\tproxy_http_version 1.1;\n\tproxy_set_header Upgrade $http_upgrade;\n\tproxy_set_header Connection "upgrade";\n\tproxy_set_header Host $host;\n\tproxy_set_header X-Forwarded-For $remote_addr;${fronted ? "\n\tproxy_buffering off;\n\tproxy_read_timeout 1h;" : ""}\n}`;
	return <details className="p-details p-wide" open>
		<summary>{t("web.title")}</summary>
		<p className="vw-muted vw-small">{t("web.lead")}</p>
		<Copyable label={t("web.caddy")} value={caddy} multiline/>
		<Copyable label={t("web.nginx")} value={nginx} multiline/>
		<p className="vw-muted vw-small">{t("web.where")}</p>
		<p className="vw-muted vw-small">{t("web.decoy")}</p>
		{!loopback(listen) && <Mark tone="warning">{t("web.warnListen")}</Mark>}
		{proxies.length > 0 && !proxies.some(proxy => loopback(proxy)) && <Mark tone="warning">{t("web.warnProxy")}</Mark>}
	</details>;
}

// The checks the node's validator runs on a tls, ws or fronted transport of a veilway inbound, so a mistake shows at its field before the review. Errors stop the review; warnings repeat the node's own.
function streamProblems(row: Row, rows: Row[]) {
	const errors: StreamErrors = {}, warnings: PanelKey[] = [], proxies = row.proxies.map(proxy => proxy.trim()).filter(Boolean), host = row.listen.trim().slice(0, row.listen.trim().lastIndexOf(":")), origin = row.origin.trim().replace(/^http:\/\//, "").replace(/\/$/, "").replace(/:\d+$/, "");
	const file = (path: string) => path.trim() !== "" && !/^[/\\]/.test(path.trim()) && path.trim()[1] !== ":" && !path.trim().split(/[/\\]/).includes("..");
	if (!/^\/[A-Za-z0-9._~/-]{11,255}$/.test(row.path.trim()) || row.path.split("/").includes("..")) errors.path = "stream.err.path";
	else if (row.type === "fronted-shaped" && rows.some(other => other !== row && other.listen.trim() === row.listen.trim() && other.path.trim().startsWith(row.path.trim()))) errors.path = "stream.err.prefix";
	else if (row.type === "ws-plain" && rows.some(other => other !== row && other.type !== "ws-plain" && PATHED.includes(other.type) && other.path.trim() === row.path.trim())) errors.path = "stream.err.plainPath";
	if (!/^http:\/\/([a-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]+\])(:[1-9][0-9]{0,4})?\/?$/.test(row.origin.trim())) errors.origin = "stream.err.origin";
	else if (!local(origin)) warnings.push("stream.warn.origin");
	if (row.type === "tls") {
		if (row.cert === "files" && !file(row.certFile)) errors.certFile = "stream.err.file";
		if (row.cert === "files" && !file(row.keyFile)) errors.keyFile = "stream.err.file";
		if (row.cert === "self" && row.name && !(row.name.length <= 64 && /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(row.name))) errors.name = "stream.err.name";
		if (row.cert === "self" && !loopback(host)) warnings.push("stream.warn.selfSigned");
		return {errors, warnings, shape: []};
	}
	if (!proxies.length) errors.proxies = "stream.err.proxies";
	else if (proxies.some(proxy => !/^[0-9A-Fa-f:.]+(\/(0|[1-9][0-9]{0,2}))?$/.test(proxy))) errors.proxies = "stream.err.proxy";
	else if (proxies.some(proxy => proxy.endsWith("/0"))) errors.proxies = "stream.err.proxyAll";
	else if (new Set(proxies).size !== proxies.length) errors.proxies = "stream.err.proxyTwice";
	else if (proxies.some(proxy => !local(proxy))) warnings.push("stream.warn.proxy");
	if (row.header && !/^[A-Za-z0-9-]{1,64}$/.test(row.header)) errors.header = "stream.err.header";
	if (!row.header) warnings.push("stream.warn.header");
	if (!loopback(host)) warnings.push("stream.warn.listen");
	return {errors, warnings, shape: row.type === "fronted-shaped" ? shapeProblems(row.shape, row.header) : []};
}

// The node's rules for a faketls transport, as messages for its fields. The site is a third party, so its names are held to the node's own rule for a DNS name, and the form asks for the acknowledgment the node refuses to run without.
const wild = (host: string) => /^\[?(0\.0\.0\.0|::)\]?$/.test(host);
const hostPort = (address: string) => ({host: address.slice(0, address.lastIndexOf(":")), port: address.slice(address.lastIndexOf(":") + 1)});
function borrowedProblems(row: Row, rows: Row[], held: string[]) {
	const errors: BorrowedErrors = {}, names = row.siteNames.map(name => name.trim()).filter(Boolean), address = row.siteAddress.trim(), here = hostPort(row.listen.trim()), there = hostPort(address), key = row.siteKey.trim();
	const sharing = rows.find(other => other !== row && other.type !== "udp" && other.type !== "udp-obfs" && hostPort(other.listen.trim()).port === here.port && (hostPort(other.listen.trim()).host === here.host || wild(hostPort(other.listen.trim()).host) || wild(here.host)));
	if (sharing) errors.listen = "borrowed.err.listen";
	if (!dnsName(row.siteHost.trim())) errors.host = "borrowed.err.host";
	if (names.length > 4 || names.some((name, i) => !dnsName(name) || name === row.siteHost.trim() || names.indexOf(name) !== i)) errors.names = "borrowed.err.names";
	if (row.sitePort !== "" && !(Number.isInteger(row.sitePort) && row.sitePort >= 1 && row.sitePort <= 65535)) errors.port = "borrowed.err.port";
	if (address && !(/^(\d{1,3}(\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]):[1-9]\d{0,4}$/.test(address) && Number(there.port) <= 65535)) errors.address = "borrowed.err.address";
	else if (address && rows.some(other => other.type !== "udp" && other.type !== "udp-obfs" && hostPort(other.listen.trim()).port === there.port && (hostPort(other.listen.trim()).host === there.host || (wild(hostPort(other.listen.trim()).host) && (loopback(there.host) || wild(there.host))) || (wild(there.host) && loopback(hostPort(other.listen.trim()).host))))) errors.address = "borrowed.err.loop";
	if (!row.acknowledged) errors.ack = "borrowed.err.ack";
	if (!(KEY.test(key) || key.startsWith("<redacted"))) errors.key = "borrowed.err.key";
	else if (held.includes(key)) errors.key = "borrowed.err.keyShared";
	return errors;
}

// The item's own object beside the form fields. It opens on the form's state, and every edit that parses goes back into the fields, so either side shows the other's change.
function ItemJson({value, onChange}: {value: Item, onChange: (item: Item | null, error: string) => void}) {
	const {t} = useP(), [text, setText] = useState(() => JSON.stringify(value, null, 2)), [wrong, setWrong] = useState("");
	const edit = (next: string) => {
		let parsed: unknown, error = "";
		setText(next);
		try { parsed = JSON.parse(next); if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) error = t("config.jsonObject"); } catch (failure) { error = t("error.json", {message: (failure as Error).message}); }
		setWrong(error);
		onChange(error ? null : parsed as Item, error);
	};
	return <Field label={t("config.itemJson")} hint={t("config.itemJsonHint")} error={wrong || undefined}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea p-json" dir="ltr" spellCheck={false} rows={14} value={text} onChange={event => edit(event.target.value)}/>}</Field>;
}

function ItemForm({section, hidden, item, taken, outbounds, socks = [], exits = [], chain = [], chained = [], xray = false, onXray, schema, onSave, onClose}: {section: Exclude<Section, "routing">, hidden: boolean, item: Item | null, taken: string[], outbounds: string[], socks?: string[], exits?: Item[], chain?: Item[], chained?: string[], xray?: boolean, onXray?: () => void, schema: Schema | null, onSave: (item: Item, notes: string[]) => void, onClose: () => void}) {
	const {t, number} = useP(), say = useIssueText(), read = (from: Item) => ({draft: from, addresses: ((from.address as string[] | undefined) ?? []).join("\n"), links: ((((from.backend ?? {}) as Item).links as string[] | undefined) ?? []).join("\n"), rows: list(from.transports).map(toRow), headers: ((from.upgrade_headers as string[] | undefined) ?? []).join("\n")});
	const [form, setForm] = useState(() => read(item ?? BLANK[section])), [json, setJson] = useState<string | null>(null), [issues, setIssues] = useState<{path: string, text: string}[]>([]), [tried, setTried] = useState(false);
	const {draft, rows} = form, patch = (change: Partial<typeof form>) => setForm({...form, ...change}), setRows = (next: Row[]) => patch({rows: next});
	const set = (key: string, next: unknown) => { const copy = {...draft}; if (next === undefined || next === "") delete copy[key]; else copy[key] = next; patch({draft: copy}); };
	const setBackend = (key: string, next: unknown) => { const copy = {...(draft.backend as Item)}; if (next === undefined || next === "") delete copy[key]; else copy[key] = next; set("backend", copy); };
	const reorder = useReorder(rows.length, index => t("config.transport", {number: index + 1}), (from, to) => { const next = rows.filter((_, i) => i !== from); next.splice(to, 0, rows[from]!); setRows(next); });
	const kind = str(draft.type), back = (draft.backend ?? {}) as Item, tag = str(draft.tag), clash = taken.includes(tag), veilway = section === "inbounds" && kind === "veilway";
	const problems = rows.map(row => veilway && PATHED.includes(row.type) ? streamProblems(row, rows) : null), proved = problems.some((problem, i) => problem && rows[i]!.type !== "ws-plain"), upgraded = veilway && rows.some(row => row.type === "tls" || row.type === "ws"), cookied = upgraded || (veilway && rows.some(row => row.type === "ws-plain")), plainWrong = veilway && rows.some(row => row.type === "ws-plain" && !(KEY.test(row.keys[0] ?? "") || (row.keys[0] ?? "").startsWith("<redacted")));
	const padding = (draft.padding ?? {}) as Item, headers = lines(form.headers), headersWrong = headers.length > 16 ? "stream.err.headersMany" : headers.some(name => !/^[A-Za-z0-9-]{1,64}$/.test(name)) ? "stream.err.header" : headers.some(name => REFUSED_HEADERS.includes(name.toLowerCase())) ? "stream.err.headerRefused" : null;
	const paddingWrong = (key: "normal" | "wide") => typeof padding[key] === "number" && !(key === "normal" ? (padding[key] as number) >= 64 && (padding[key] as number) <= 255 : (padding[key] as number) >= 512 && (padding[key] as number) <= 1023);
	const un = (back.unsupported ?? {}) as Item, policy = (key: string) => typeof un[key] === "object" && un[key] ? "via" : str(un[key]) || (key === "icmp_echo" ? "local" : "reject"), viaOf = (key: string) => str(((un[key] ?? {}) as Item).via), proxied = socks.includes(str(back.outbound)), direct = back.type === "netstack" && !proxied;
	const targets = (key: string) => exits.filter(exit => exit.tag !== draft.tag && (((exit.backend ?? {}) as Item).type === "l3" || (key === "udp" && ((exit.backend ?? {}) as Item).type === "netstack"))).map(exit => str(exit.tag));
	const around = back.type === "netstack" && ["icmp_echo", "udp", "other"].some(key => (policy(key) === "direct" || policy(key) === "via") && !(key === "udp" && direct)) && proxied && back.proxy_only !== false;
	const idleWrong = (key: "tcp_idle_secs" | "udp_idle_secs") => typeof back[key] === "number" && !(key === "tcp_idle_secs" ? (back[key] as number) >= 10 && (back[key] as number) <= 86400 : (back[key] as number) >= 5 && (back[key] as number) <= 3600);
	const setPolicy = (key: string, value: string, via = "") => { const next = {...un}; if (value === "via") next[key] = {via: via || targets(key)[0] || ""}; else if (value === (key === "icmp_echo" ? "local" : "reject")) delete next[key]; else next[key] = value; setBackend("unsupported", Object.keys(next).length ? next : undefined); };
	const keys = Array.isArray(draft.transport_keys) ? draft.transport_keys as string[] : [], keyWrong = proved && !(KEY.test(keys[0] ?? "") || (keys[0] ?? "").startsWith("<redacted")), cookieWrong = cookied && !/^[A-Za-z0-9_-]{1,32}$/.test(str(draft.upgrade_cookie));
	const borrowed = rows.map((row, i) => veilway && row.type === "faketls" ? borrowedProblems(row, rows, [...keys, ...rows.filter((other, j) => j !== i && other.type === "faketls").map(other => other.siteKey.trim())].filter(Boolean)) : null), borrowedWrong = borrowed.some(problem => problem && Object.keys(problem).length > 0);
	const others = chain.filter(other => str(other.tag) !== str(item?.tag)), through = others.filter(other => other.type === "socks5" && str(other.tag) !== tag).map(other => str(other.tag)), viaWrong = section === "outbounds" && kind === "socks5" && str(draft.via) ? viaProblem(tag, str(draft.via), [...others, draft]) : undefined;
	const udpChained = section === "exits" && back.type === "netstack" && chained.includes(str(back.outbound));
	// The form writes the keys it shows and keeps every other key of the item and of each transport as it was.
	const build = (): Item => section === "exits" ? back.type === "chain" ? {...draft, backend: {...back, links: lines(form.links)}} : draft : section === "outbounds" ? draft : {...Object.fromEntries(Object.entries(draft).filter(([key]) => key !== "upgrade_headers")), ...(headers.length ? {upgrade_headers: headers} : {}), address: lines(form.addresses), transports: rows.map(row => {
		const was = list(draft.transports)[row.at], made: Item = {...(was?.type === row.type ? was : {}), type: row.type, listen: row.listen.trim()}, proxies = row.proxies.map(proxy => proxy.trim()).filter(Boolean);
		const limits = Object.fromEntries(Object.entries(row.limits).filter(([key, value]) => value !== "" && (POOLS[row.type] ?? []).includes(key)));
		if (row.path.trim()) made.path = row.path.trim(); else delete made.path;
		if (Object.keys(limits).length && veilway) made.limits = limits; else delete made.limits;
		if (row.type === "faketls" && veilway) {
			for (const key of ["decoy", "tls", "trusted_proxies", "client_address_header", "shape", "http2"]) delete made[key];
			const names = row.siteNames.map(name => name.trim()).filter(Boolean);
			return {...made, site: {host: row.siteHost.trim(), ...(names.length ? {names} : {}), ...(row.sitePort !== "" ? {port: row.sitePort} : {}), ...(row.siteAddress.trim() ? {address: row.siteAddress.trim()} : {}), acknowledged: row.acknowledged}, transport_key: row.siteKey.trim()};
		}
		if (!veilway || !PATHED.includes(row.type)) return made;
		made.decoy = {...Object.fromEntries(Object.entries((made.decoy ?? {}) as Item).filter(([key]) => key !== "proxy_protocol")), origin: row.origin.trim(), ...(row.proxyProtocol ? {proxy_protocol: true} : {})};
		if (row.type === "tls") {if (row.http2) made.http2 = "on"; else delete made.http2}
		if (row.type === "tls") return {...made, tls: row.cert === "files" ? {cert: row.certFile.trim(), key: row.keyFile.trim()} : {self_signed: true, ...(row.name ? {name: row.name} : {})}};
		if (row.header) made.client_address_header = row.header; else delete made.client_address_header;
		return {...made, trusted_proxies: proxies, ...(row.type === "fronted-shaped" ? {shape: row.shape} : {}), ...(row.type === "ws-plain" ? {transport_keys: row.keys.filter(Boolean)} : {})};
	})};
	const save = () => {
		setTried(true);
		if (json !== null && issues.length && issues[0]!.path === "json") return;
		if (problems.some(problem => problem && (Object.keys(problem.errors).length || problem.shape.length)) || borrowedWrong || keyWrong || plainWrong || cookieWrong || headersWrong || paddingWrong("normal") || paddingWrong("wide") || rows.some(row => (POOLS[row.type] ?? []).some(key => outside(row, key))) || around || viaWrong || (udpChained && policy("udp") === "direct") || idleWrong("tcp_idle_secs") || idleWrong("udp_idle_secs") || (back.type === "netstack" && ["icmp_echo", "udp", "other"].some(key => policy(key) === "via" && !targets(key).includes(viaOf(key))))) return;
		const made = build(), found = schema && typeof schema === "object" ? say(check(((schema.properties as Record<string, Item>)[section]?.items ?? true) as Schema, made, schema, section)) : [];
		setIssues(clash ? [{path: "tag", text: t("config.tagTaken")}, ...found] : found);
		if (!clash && !found.length) onSave(made, section === "inbounds" ? moved(rows.map(row => row.at)).map(move => t("review.moveTransport", {name: rows[move.to]!.type + " " + (rows[move.to]!.path || rows[move.to]!.listen), inbound: tag, from: number(move.from + 1), to: number(move.to + 1)})) : []);
	};
	// While the review is open the form stays mounted behind it, so closing the review comes back to the same edit.
	return <Dialog open={!hidden} onOpenChange={open => { if (!open) onClose(); }} title={t(item ? "config.editName" : `config.add.${section}`, {name: str(item?.tag)})}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); save(); }} noValidate>
			<Segmented label={t("config.view")} value={json === null ? "form" : "json"} onChange={view => { setIssues([]); setJson(view === "json" ? JSON.stringify(build(), null, 2) : null); }} options={[{value: "form", label: t("config.view.form")}, {value: "json", label: t("config.view.json")}]}/>
			{json !== null ? <ItemJson value={JSON.parse(json) as Item} onChange={(next, error) => { if (next) setForm(read(next)); setIssues(error ? [{path: "json", text: error}] : []); }}/> : <>
			<TextField label={t("config.col.tag")} hint={t("config.tagHint")} value={tag} onChange={value => set("tag", value.toLowerCase())} error={clash ? t("config.tagTaken") : undefined} technical required autoFocus/>
			{section === "inbounds" && <>
				<SelectField label={t("inbounds.col.type")} hint={t("inbounds.typeHint")} value={kind} onChange={value => { if (value !== "xray") set("type", value); else if (xray) onXray?.(); }} options={[{value: "veilway", label: t("config.inbound.veilway"), detail: t("config.inbound.veilwayDetail")}, {value: "wireguard", label: t("config.inbound.wireguard"), detail: t("config.inbound.wireguardDetail")}, ...(item ? [] : [{value: "xray", label: t("config.inbound.xray"), detail: t(xray ? "config.inbound.xrayDetail" : "config.inbound.xrayMissing")}])]}/>
				<div className="p-proxy">
					<SecretField label={t("config.privateKey")} hint={t(item ? "config.privateKeyKeep" : "config.privateKeyNew")} value={str(draft.private_key)} onChange={value => set("private_key", value.trim())} autoComplete="off"/>
					{!str(draft.private_key).startsWith("<redacted") && <Button onClick={() => set("private_key", newKey(true))}>{t("config.keyMake")}</Button>}
				</div>
				<LinesField label={t("config.addresses")} hint={t("config.addressesHint")} value={form.addresses} onChange={addresses => patch({addresses})} rows={2}/>
				<NumberField label={t("config.mtu")} hint={t("config.mtuHint")} unit={t("config.bytes")} min={1280} max={1500} value={typeof draft.mtu === "number" ? draft.mtu : ""} onChange={value => set("mtu", value === "" ? undefined : value)} optional/>
				<fieldset className="p-mirror">
					<legend className="vw-label">{t("config.col.transports")}</legend>
					<p className="vw-muted vw-small">{t("inbounds.transportHint")}</p>
					{rows.map((row, i) => {
						// A name only goes with the header place, and the downstream members only with event streams, so the shape keeps only what the node reads.
						const problem = problems[i], bproblem = borrowed[i], shownBorrowed = (field: keyof BorrowedErrors, value: string) => bproblem?.[field] && (tried || value.trim()) ? t(bproblem[field]!) : undefined, up = (change: Partial<Row>) => setRows(rows.map((r, j) => j === i ? {...r, ...change} : r)), shown = (field: keyof StreamErrors, value: string) => problem?.errors[field] && (tried || value.trim()) ? t(problem.errors[field]!) : undefined;
						return <div key={i} className="p-transport-row" data-order-row>
							{rows.length > 1 && <div className="p-row-tools">{reorder.handle(i)}<div className="p-cluster">{reorder.steps(i)}<IconButton icon="close" label={t("config.removeTransport", {number: i + 1})} onClick={() => setRows(rows.filter((_, j) => j !== i))}/></div></div>}
							<SelectField label={t("config.transport", {number: i + 1})} value={row.type} onChange={type => up(type === "fronted-shaped" && type !== row.type ? {type, ...drawPreset("post-stream")} : type === "ws-plain" && !row.keys.length ? {type, keys: [newKey(false)]} : {type})} options={(kind === "wireguard" ? ["udp", "ws"] : TRANSPORTS).map(type => ({value: type, label: type === "faketls" ? t("borrowed.name") : type, detail: t(`config.transport.${type}` as PanelKey)}))}/>
							<TextField label={t("config.listen")} placeholder={problem && row.type !== "tls" ? "127.0.0.1:8081" : "0.0.0.0:443"} value={row.listen} onChange={listen => up({listen})} technical/>
							{row.type === "faketls" && veilway && <div className="p-stream">
								<Banner tone="warning" title={t("borrowed.title")}>{t("borrowed.warning")}</Banner>
								{bproblem?.listen && <Mark tone="danger">{t(bproblem.listen)}</Mark>}
								<TextField label={t("borrowed.host")} hint={t("borrowed.hostHint")} placeholder="www.example.com" value={row.siteHost} onChange={siteHost => up({siteHost: siteHost.toLowerCase().trim()})} error={shownBorrowed("host", row.siteHost)} technical/>
								<fieldset className="p-proxies">
									<legend className="vw-label">{t("borrowed.names")}</legend>
									<p className="vw-muted vw-small">{t("borrowed.namesHint")}</p>
									{row.siteNames.map((name, k) => <div key={k} className="p-proxy"><TextField label={t("borrowed.nameN", {number: k + 1})} placeholder="example.com" value={name} onChange={value => up({siteNames: row.siteNames.map((n, m) => m === k ? value.toLowerCase().trim() : n)})} technical/><IconButton icon="close" label={t("borrowed.removeName", {number: k + 1})} onClick={() => up({siteNames: row.siteNames.filter((_, m) => m !== k)})}/></div>)}
									{bproblem?.names && (tried || row.siteNames.some(name => name.trim())) && <Mark tone="danger">{t(bproblem.names)}</Mark>}
									{row.siteNames.length < 4 && <div><Button size="sm" icon="plus" onClick={() => up({siteNames: [...row.siteNames, ""]})}>{t("borrowed.addName")}</Button></div>}
								</fieldset>
								<div className="p-pair">
									<NumberField label={t("borrowed.port")} hint={t("borrowed.portHint")} unit="TCP" min={1} max={65535} placeholder="443" value={row.sitePort} onChange={sitePort => up({sitePort})} error={bproblem?.port ? t(bproblem.port) : undefined} optional/>
									<TextField label={t("borrowed.address")} hint={t("borrowed.addressHint")} placeholder="192.0.2.10:443" value={row.siteAddress} onChange={siteAddress => up({siteAddress: siteAddress.trim()})} error={shownBorrowed("address", row.siteAddress)} technical optional/>
								</div>
								<div className="p-proxy">
									<SecretField label={t("borrowed.key")} hint={t(row.siteKey.startsWith("<redacted") ? "borrowed.keyKeep" : "borrowed.keyNew")} value={row.siteKey} onChange={value => up({siteKey: value.trim()})} error={shownBorrowed("key", row.siteKey)} autoComplete="off"/>
									<Button onClick={() => up({siteKey: newKey(false)})}>{t("borrowed.keyPick")}</Button>
								</div>
								<Checkbox label={t("borrowed.acknowledge")} checked={row.acknowledged} onChange={acknowledged => up({acknowledged})}/>
								{bproblem?.ack && tried && <Mark tone="danger">{t(bproblem.ack)}</Mark>}
							</div>}
							{PATHED.includes(row.type) && !problem && <TextField label={t("config.path")} placeholder="/a-long-random-path" value={row.path} onChange={path => up({path})} technical/>}
							{problem && <div className="p-stream">
								<TextField label={t("config.path")} hint={t("stream.pathHint")} placeholder="/a-long-random-path" value={row.path} onChange={path => up({path})} error={shown("path", row.path)} technical/>
								{row.type === "fronted-shaped" && <ShapeFields preset={row.preset} shape={row.shape} problems={problem.shape} onChange={up}/>}
								{row.type === "tls" && <>
									<RadioGroup label={t("stream.cert")} value={row.cert} onChange={cert => up({cert: cert === "files" ? "files" : "self"})} options={[{value: "self", label: t("stream.cert.self"), detail: t("stream.cert.selfDetail")}, {value: "files", label: t("stream.cert.files"), detail: t("stream.cert.filesDetail")}]}/>
									{row.cert === "self" ? <TextField label={t("stream.certName")} hint={t("stream.certNameHint")} placeholder="www.example.com" value={row.name} onChange={name => up({name: name.toLowerCase().trim()})} error={shown("name", row.name)} technical optional/> : <div className="p-pair">
										<TextField label={t("stream.certFile")} hint={t("stream.fileHint")} placeholder="certs/fullchain.pem" value={row.certFile} onChange={certFile => up({certFile})} error={shown("certFile", row.certFile)} technical/>
										<TextField label={t("stream.keyFile")} hint={t("stream.fileHint")} placeholder="certs/privkey.pem" value={row.keyFile} onChange={keyFile => up({keyFile})} error={shown("keyFile", row.keyFile)} technical/>
									</div>}
								</>}
								<TextField label={t("stream.origin")} hint={t("stream.originHint")} placeholder="http://127.0.0.1:8080" value={row.origin} onChange={origin => up({origin: origin.trim()})} error={shown("origin", row.origin)} technical/>
								<Switch label={t("stream.proxyProtocol")} hint={t("stream.proxyProtocolHint")} checked={row.proxyProtocol} onChange={proxyProtocol => up({proxyProtocol})}/>
								{row.type === "tls" && <Switch label={t("stream.http2")} hint={t("stream.http2Hint")} checked={row.http2} onChange={http2 => up({http2})}/>}
								{row.type !== "tls" && <>
									<fieldset className="p-proxies">
										<legend className="vw-label">{t("stream.proxies")}</legend>
										<p className="vw-muted vw-small">{t("stream.proxiesHint")}</p>
										{row.proxies.map((proxy, k) => <div key={k} className="p-proxy"><TextField label={t("stream.proxy", {number: k + 1})} placeholder="127.0.0.1" value={proxy} onChange={value => up({proxies: row.proxies.map((p, m) => m === k ? value.trim() : p)})} technical/>{row.proxies.length > 1 && <IconButton icon="close" label={t("stream.removeProxy", {number: k + 1})} onClick={() => up({proxies: row.proxies.filter((_, m) => m !== k)})}/>}</div>)}
										{problem.errors.proxies && (tried || row.proxies.some(proxy => proxy.trim())) && <Mark tone="danger">{t(problem.errors.proxies)}</Mark>}
										{row.proxies.length < 64 && <div><Button size="sm" icon="plus" onClick={() => up({proxies: [...row.proxies, ""]})}>{t("stream.addProxy")}</Button></div>}
									</fieldset>
									<TextField label={t("stream.header")} hint={t("stream.headerHint")} placeholder="X-Forwarded-For" value={row.header} onChange={header => up({header: header.trim()})} error={shown("header", row.header)} technical optional/>
								</>}
								{row.type === "ws-plain" && <>
									<Mark tone="warning">{t("stream.plainWarn")}</Mark>
									<div className="p-proxy">
										<SecretField label={t("stream.plainKey")} hint={t((row.keys[0] ?? "").startsWith("<redacted") ? "stream.keyKeep" : "stream.plainKeyHint")} value={row.keys[0] ?? ""} onChange={value => up({keys: [value.trim(), ...row.keys.slice(1)]})} error={plainWrong && !(KEY.test(row.keys[0] ?? "") || (row.keys[0] ?? "").startsWith("<redacted")) && (tried || row.keys[0]) ? t("stream.err.key") : undefined} autoComplete="off"/>
										{!(row.keys[0] ?? "").startsWith("<redacted") && <Button onClick={() => up({keys: [newKey(false), ...row.keys.slice(1)]})}>{t("config.keyMake")}</Button>}
									</div>
									{row.keys.length > 1 && <p className="vw-muted vw-small">{t("stream.keyRotating")}</p>}
									<p className="vw-muted vw-small">{t("stream.plainCookie")}</p>
								</>}
								{["ws", "fronted", "fronted-shaped"].includes(row.type) && !problem.errors.path && /^(\[[0-9A-Fa-f:.]+\]|[0-9A-Za-z.-]+):[1-9][0-9]{0,4}$/.test(row.listen.trim()) && <WebLines row={row}/>}
								{problem.warnings.map(key => <Mark key={key} tone="warning">{t(key)}</Mark>)}
							</div>}
							{veilway && POOLS[row.type] && <details className="p-details p-wide" open={(POOLS[row.type] ?? []).some(key => outside(row, key)) || undefined}>
								<summary>{t("config.advancedLimits")}</summary>
								<p className="vw-muted vw-small">{t("limit.lead")}</p>
								<div className="p-pair">{POOLS[row.type]!.map(key => <NumberField key={key} label={t((row.type === "faketls" && key === "relayed" ? "limit.relayedSite" : `limit.${key}`) as PanelKey)} unit={t(`unit.${LIMITS[key]![3]}`)} min={LIMITS[key]![0]} max={ceiling(row, key)} placeholder={String(key === "proxy_connections" ? 2 * (Number(row.limits.fronted_sessions) || 1024) : row.type === "faketls" && key === "relayed" ? 256 : key === "undecided_per_source" ? Math.min(64, ceiling(row, key)) : LIMITS[key]![2])} value={row.limits[key] ?? ""} onChange={value => up({limits: {...row.limits, [key]: value}})} error={outside(row, key) ? t("limit.range", {min: number(LIMITS[key]![0]), max: number(ceiling(row, key))}) : undefined} optional/>)}</div>
							</details>}
						</div>;
					})}
					{reorder.live}
					{rows.length < 8 && <div><Button size="sm" icon="plus" onClick={() => setRows([...rows, toRow({type: "udp-obfs"}, -1)])}>{t("config.addTransport")}</Button></div>}
					<p className="vw-muted vw-small">{t("inbounds.rating")}</p>
				</fieldset>
				{(proved || cookied) && <fieldset className="p-mirror">
					<legend className="vw-label">{t("stream.keys")}</legend>
					{proved && <div className="p-proxy">
						<SecretField label={t("stream.key")} hint={t((keys[0] ?? "").startsWith("<redacted") ? "stream.keyKeep" : "stream.keyNew")} value={keys[0] ?? ""} onChange={value => set("transport_keys", [value.trim(), ...keys.slice(1)])} error={keyWrong && (tried || keys[0]) ? t("stream.err.key") : undefined} autoComplete="off"/>
						{!(keys[0] ?? "").startsWith("<redacted") && <Button onClick={() => set("transport_keys", [newKey(false), ...keys.slice(1)])}>{t("config.keyMake")}</Button>}
					</div>}
					{proved && keys.length > 1 && <p className="vw-muted vw-small">{t("stream.keyRotating")}</p>}
					{cookied && <div className="p-proxy">
						<TextField label={t("stream.cookie")} hint={t("stream.cookieHint")} value={str(draft.upgrade_cookie)} onChange={value => set("upgrade_cookie", value.trim())} error={cookieWrong && (tried || draft.upgrade_cookie) ? t("stream.err.cookie") : undefined} technical/>
						<Button onClick={() => { const bytes = crypto.getRandomValues(new Uint8Array(17)); set("upgrade_cookie", Array.from(bytes.slice(1, 9 + bytes[0]! % 9), b => "abcdefghijklmnopqrstuvwxyz0123456789_-"[b % 38]).join("")); }}>{t("stream.cookiePick")}</Button>
					</div>}
				</fieldset>}
				{veilway && <details className="p-details">
					<summary>{t("config.advancedDisguise")}</summary>
					<div className="p-stack">
						<p className="vw-muted vw-small">{t("disguise.lead")}</p>
						<div className="p-pair">
							<NumberField label={t("disguise.normal")} hint={t("disguise.normalHint")} unit={t("config.bytes")} min={64} max={255} placeholder="255" value={typeof padding.normal === "number" ? padding.normal : ""} onChange={value => { const next = {...padding}; if (value === "") delete next.normal; else next.normal = value; set("padding", Object.keys(next).length ? next : undefined); }} error={paddingWrong("normal") ? t("limit.range", {min: number(64), max: number(255)}) : undefined} optional/>
							<NumberField label={t("disguise.wide")} hint={t("disguise.wideHint")} unit={t("config.bytes")} min={512} max={1023} placeholder="1023" value={typeof padding.wide === "number" ? padding.wide : ""} onChange={value => { const next = {...padding}; if (value === "") delete next.wide; else next.wide = value; set("padding", Object.keys(next).length ? next : undefined); }} error={paddingWrong("wide") ? t("limit.range", {min: number(512), max: number(1023)}) : undefined} optional/>
						</div>
						{upgraded && <Field label={t("disguise.headers")} hint={t("disguise.headersHint")} error={headersWrong ? t(headersWrong) : undefined} optional>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={3} placeholder={rows.some(row => row.type === "tls") ? "Server\nDate" : ""} value={form.headers} onChange={event => patch({headers: event.target.value})}/>}</Field>}
					</div>
				</details>}
			</>}
			{section === "outbounds" && <>
				<SelectField label={t("config.type")} value={kind} onChange={value => { const copy: Item = {...draft, type: value}; if (value === "direct") delete copy.via; patch({draft: copy}); }} options={[{value: "direct", label: t("config.outbound.direct"), detail: t("config.outbound.directDetail")}, {value: "socks5", label: t("config.outbound.socks5"), detail: t("config.outbound.socks5Detail")}]}/>
				{kind === "socks5" ? <>
					<TextField label={t("config.server")} hint={t("config.serverHint")} placeholder="192.0.2.10:1080" value={str(draft.server)} onChange={value => set("server", value.trim())} technical/>
					<div className="p-pair">
						<SecretField label={t("config.username")} value={str(draft.username)} onChange={value => set("username", value)} autoComplete="off" optional/>
						<SecretField label={t("config.password")} value={str(draft.password)} onChange={value => set("password", value)} autoComplete="off" optional/>
					</div>
					<SelectField label={t("config.via")} hint={t("config.viaHint") + " " + t("via.plain")} value={str(draft.via)} onChange={value => set("via", value)} error={viaWrong ? t(viaWrong) : undefined} options={[{value: "", label: t("config.viaDirect")}, ...[...through, ...(str(draft.via) && !through.includes(str(draft.via)) ? [str(draft.via)] : [])].map(tag => ({value: tag, label: tag}))]}/>
				</> : <>
					<TextField label={t("config.bindLabel")} hint={t("config.bindHint")} value={str(draft.bind)} onChange={value => set("bind", value.trim())} technical optional/>
					<TextField label={t("config.outInterface")} hint={t("config.outInterfaceHint")} placeholder="eth1" value={str(draft.interface)} onChange={value => set("interface", value.trim())} maxLength={15} technical optional/>
				</>}
			</>}
			{section === "exits" && <>
				<div className="p-pair">
					<TextField label={t("config.exitName")} hint={t("config.exitNameHint")} value={str(draft.name)} onChange={value => set("name", value)} maxLength={64} optional/>
					<TextField label={t("config.country")} hint={t("config.countryHint")} value={str(draft.country)} onChange={value => set("country", value.toUpperCase())} maxLength={2} technical optional/>
				</div>
				<SelectField label={t("config.col.backend")} value={str(back.type)} onChange={type => set("backend", type === "netstack" ? {type, outbound: outbounds[0] ?? ""} : type === "chain" ? {type, links: []} : {type})} options={["netstack", "l3", "block", "chain", ...(back.type === "upstream" ? ["upstream"] : [])].map(type => ({value: type, label: t(`config.backend.${type}` as PanelKey), detail: t(`config.backend.${type}Detail` as PanelKey)}))}/>
				{back.type === "netstack" && <SelectField label={t("config.outboundLabel")} value={str(back.outbound)} onChange={value => setBackend("outbound", value)} options={outbounds.map(tag => ({value: tag, label: tag}))}/>}
				{back.type === "netstack" && <fieldset className="p-mirror">
					<legend className="vw-label">{t("exit.unsupported")}</legend>
					<p className="vw-muted vw-small">{t("exit.unsupportedLead")}</p>
					{["icmp_echo", "udp", "other"].filter(key => !(key === "udp" && direct)).map(key => <div key={key} className="p-stack">
						<SelectField label={t(`exit.kind.${key}` as PanelKey)} value={policy(key)} onChange={value => setPolicy(key, value)} options={POLICIES[key]!.filter(word => (word !== "via" || targets(key).length || policy(key) === "via") && (word !== "direct" || key !== "udp" || !udpChained || policy(key) === "direct")).map(word => ({value: word, label: t(`exit.policy.${word}` as PanelKey), detail: t(`exit.policy.${word}Detail` as PanelKey)}))} error={key === "udp" && udpChained && policy(key) === "direct" ? t("exit.err.chainedUdp") : undefined}/>
						{policy(key) === "via" && <SelectField label={t("exit.via")} hint={t(key === "udp" ? "exit.viaUdpHint" : "exit.viaL3Hint")} value={viaOf(key)} onChange={value => setPolicy(key, "via", value)} error={targets(key).includes(viaOf(key)) ? undefined : t("exit.viaMissing")} options={[...(targets(key).includes(viaOf(key)) || !viaOf(key) ? [] : [{value: viaOf(key), label: viaOf(key)}]), ...targets(key).map(tag => ({value: tag, label: tag}))]}/>}
						{policy(key) === "direct" && <Mark tone="warning">{t("exit.warn.direct")}</Mark>}
					</div>)}
					{direct && <p className="vw-muted vw-small">{t("exit.udpDirect")}</p>}
					{around && <Mark tone="danger">{t("exit.err.proxyOnly")}</Mark>}
				</fieldset>}
				{back.type === "l3" && <TextField label={t("config.interface")} hint={t("config.interfaceHint")} value={str(back.interface)} onChange={value => setBackend("interface", value.trim())} technical optional/>}
				{(back.type === "netstack" || back.type === "l3") && <details className="p-details" open={around || idleWrong("tcp_idle_secs") || idleWrong("udp_idle_secs") || undefined}>
					<summary>{t("config.advanced")}</summary>
					<div className="p-stack">
						{back.type === "l3" ? <Switch label={t("exit.masquerade")} hint={t("exit.masqueradeHint")} checked={back.masquerade !== false} onChange={on => setBackend("masquerade", on ? undefined : false)}/> : <>
							{proxied && <Switch label={t("exit.proxyOnly")} hint={t("exit.proxyOnlyHint")} checked={back.proxy_only !== false} onChange={on => setBackend("proxy_only", on ? undefined : false)}/>}
							<div className="p-pair">
								<NumberField label={t("exit.tcpIdle")} hint={t("exit.tcpIdleHint")} unit={t("unit.seconds")} min={10} max={86400} placeholder="7200" value={typeof back.tcp_idle_secs === "number" ? back.tcp_idle_secs : ""} onChange={value => setBackend("tcp_idle_secs", value === "" ? undefined : value)} error={idleWrong("tcp_idle_secs") ? t("limit.range", {min: number(10), max: number(86400)}) : undefined} optional/>
								<NumberField label={t("exit.udpIdle")} hint={t("exit.udpIdleHint")} unit={t("unit.seconds")} min={5} max={3600} placeholder="60" value={typeof back.udp_idle_secs === "number" ? back.udp_idle_secs : ""} onChange={value => setBackend("udp_idle_secs", value === "" ? undefined : value)} error={idleWrong("udp_idle_secs") ? t("limit.range", {min: number(5), max: number(3600)}) : undefined} optional/>
							</div>
						</>}
					</div>
				</details>}
				{back.type === "chain" && <LinesField label={t("config.links")} hint={t("config.linksHint")} value={form.links} onChange={links => patch({links})} rows={2}/>}
			</>}
			</>}
			<Issues issues={issues.filter(issue => issue.path !== "json")}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t("config.review")}</Button></div>
		</form>
	</Dialog>;
}

// The table shows the draft order: a drag or a move button changes it here, and it reaches the node only through the review, along with any other edit made meanwhile.
function Routing({routing, reviewing, exits: items, inbounds, links, onPropose}: {routing: Item, reviewing: boolean, exits: Item[], inbounds: string[], links: string[], onPropose: (routing: Item, notes?: string[]) => void}) {
	const users = useLoad(() => api("get", "/users"), []), people = users.data?.users ?? null;
	const exits = items.map(item => str(item.tag)), named = (tag: string) => str(items.find(item => item.tag === tag)?.name) || tag;
	const {t, number} = useP(), saved = list(routing.rules), [order, setOrder] = useState(() => saved.map((_, i) => i)), rules = order.map(i => saved[i]!), [fallback, setFallback] = useState(str(routing.default)), savedSpare = list(routing.fallback).map(str), [spare, setSpare] = useState(savedSpare), [editing, setEditing] = useState<number | null | undefined>(undefined);
	// The exits Automatic may switch to, in the order of the exits. A block exit carries nothing and is not offered.
	const spares = items.filter(item => (item.backend as Item | undefined)?.type !== "block").map(item => str(item.tag)), spareChanged = spare.join(",") !== savedSpare.join(",");
	// A rule can name an exit that a later edit removed. The node refuses such a config in the review; the list says so before that.
	const action = (rule: Item) => { const exit = typeof rule.action === "object" && rule.action ? str((rule.action as Item).exit) : null; return exit === null ? t(`rule.action.${rule.action === "block" || rule.action === "reject" ? rule.action : "user"}`) : exits.includes(exit) ? <span title={exit}>{t("rule.toExit", {exit: named(exit)})}</span> : <Mark tone="danger">{t("rule.missingExit", {exit})}</Mark>; };
	const when = (rule: Item) => CONDITIONS.filter(key => Array.isArray(rule[key])).map(key => t(`rule.cond.${key}` as PanelKey) + ": " + (rule[key] as unknown[]).join(", ")).join("; ");
	const shifts = moved(order), shifted = new Set(shifts.map(move => move.to)), notes = shifts.map(move => t("review.moveRule", {name: str(saved[move.from]!.tag) || when(saved[move.from]!), from: number(move.from + 1), to: number(move.to + 1)}));
	const withRules = (next: Item[]) => onPropose({...routing, rules: next}, notes);
	const reorder = useReorder(rules.length, index => t("order.rule", {number: number(index + 1)}), (from, to) => { const next = order.filter((_, i) => i !== from); next.splice(to, 0, order[from]!); setOrder(next); });
	return <>
		<Glass className="p-panel p-form">
			<SelectField label={t("rule.default")} hint={t("rule.defaultHint")} value={fallback} onChange={setFallback} options={exits.map(tag => ({value: tag, label: tag}))}/>
			<Field label={t("rule.spare")} hint={t("rule.spareHint")}>
				{ids => <div {...ids} role="group" className="p-pick-list">{spares.map(tag => <div key={tag} className="p-pick-row"><Checkbox label={named(tag)} checked={spare.includes(tag)} onChange={on => setSpare(spares.filter(other => other === tag ? on : spare.includes(other)))}/></div>)}</div>}
			</Field>
			{(fallback !== str(routing.default) || spareChanged) && <div><Button variant="primary" onClick={() => { const next: Item = {...routing, ...(notes.length ? {rules} : {}), default: fallback}; if (spare.length) next.fallback = spare; else delete next.fallback; onPropose(next, notes); }}>{t("config.review")}</Button></div>}
		</Glass>
		<Glass className="p-panel">
			<div className="p-row p-table-head"><span className="vw-muted vw-small">{t("rule.lead")}</span><Button size="sm" icon="plus" onClick={() => setEditing(null)}>{t("rule.add")}</Button></div>
			<DataTable caption={t("node.tab.routing")} rows={rules.map((rule, index) => ({rule, index}))} rowKey={row => String(row.index)} empty={<StateBlock kind="empty" title={t("rule.empty")} action={<Button icon="plus" onClick={() => setEditing(null)}>{t("rule.add")}</Button>}>{t("rule.emptyBody", {exit: str(routing.default)})}</StateBlock>} columns={[
				{id: "order", header: t("rule.col.order"), cell: ({index}) => <span className="p-order">{reorder.handle(index)}<span className="vw-num" data-moved={shifted.has(index) || undefined}>{index + 1}</span></span>},
				{id: "when", header: t("rule.col.when"), cell: ({rule}) => <span className="p-user"><span className="vw-code">{when(rule)}</span><span className="vw-muted vw-small">{[str(rule.tag), rule.enabled === false ? t("rule.off") : ""].filter(Boolean).join(", ")}</span></span>},
				{id: "then", header: t("rule.col.then"), cell: ({rule}) => action(rule)},
				{id: "edit", header: "", align: "end", cell: ({index}) => <div className="p-cluster p-end">{reorder.steps(index)}<Button size="sm" variant="quiet" aria-label={t("rule.editNumber", {number: index + 1})} onClick={() => setEditing(index)}>{t("user.edit")}</Button></div>}
			]}/>
			{notes.length > 0 && <div className="p-row p-order-bar"><span>{t("order.pending")}</span><div className="p-cluster"><Button variant="quiet" onClick={() => setOrder(saved.map((_, i) => i))}>{t("order.undo")}</Button><Button variant="primary" onClick={() => withRules(rules)}>{t("order.review")}</Button></div></div>}
			{reorder.live}
		</Glass>
		{editing !== undefined && <RuleForm hidden={reviewing} rule={editing === null ? null : rules[editing]!} position={editing === null ? rules.length + 1 : editing + 1} count={rules.length} exits={exits} known={{user: people && people.map(user => user.name), group: people && [...new Set(people.flatMap(user => user.groups))].sort(), inbound: inbounds, link: links}} taken={rules.filter((_, i) => i !== editing).map(rule => str(rule.tag)).filter(Boolean)} named={named} onClose={() => setEditing(undefined)} onRemove={() => withRules(rules.filter((_, i) => i !== editing))} onSave={(rule, position) => { const rest = editing === null ? rules : rules.filter((_, i) => i !== editing); withRules([...rest.slice(0, position - 1), rule, ...rest.slice(position - 1)]); }}/>}
	</>;
}

// Users, groups, inbounds and node links are picked from what the node has, and a value it does not have shows as unknown. Networks, domains, protocols, ports and ICMP numbers stay typed.
function RuleForm({hidden, rule, position, count, exits, known, taken, named, onSave, onRemove, onClose}: {hidden: boolean, rule: Item | null, position: number, count: number, exits: string[], known: Record<string, string[] | null>, taken: string[], named: (tag: string) => string, onSave: (rule: Item, position: number) => void, onRemove: () => void, onClose: () => void}) {
	const {t} = useP(), read = (from: Item) => { const found = CONDITIONS.filter(key => Array.isArray(from[key])).map(key => ({key, values: (from[key] as unknown[]).join(", ")})), exit = typeof from.action === "object" && from.action ? str((from.action as Item).exit) : null; return {base: from, name: str(from.tag), named: Boolean(from.tag), conds: found.length ? found : [{key: "user", values: ""}], then: exit === null ? str(from.action) || "user" : "exit", exit: exit ?? exits[0] ?? "", enabled: from.enabled !== false}; };
	const [form, setForm] = useState(() => read(rule ?? {action: {exit: exits[0] ?? ""}})), [json, setJson] = useState<string | null>(null), [jsonWrong, setJsonWrong] = useState(false), [at, setAt] = useState<number | "">(position), [tried, setTried] = useState(false), [finding, setFinding] = useState<Record<number, string>>({});
	const {conds, then, exit} = form, patch = (change: Partial<typeof form>) => setForm({...form, ...change}), setConds = (next: Cond[]) => patch({conds: next});
	const parsed = conds.map(cond => ({key: cond.key, values: cond.values.split(/[,\n]/).map(value => value.trim()).filter(Boolean).map(value => NUMERIC.includes(cond.key) && /^\d+$/.test(value) ? Number(value) : value)}));
	// Until the name is typed, it follows what the rule does: the first value and where it sends traffic, such as block-ads or streaming-germany, made unique among the other rules.
	const slug = (text: string) => text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30), first = slug(String(parsed[0]?.values[0] ?? "")), where = then === "exit" ? slug(named(exit)) : then === "user" ? "user-exit" : then;
	let name = form.named ? form.name : (then === "block" || then === "reject" ? [where, first] : [first, where]).filter(Boolean).join("-");
	if (!form.named && (!TAG.test(name) || RESERVED.includes(name))) name = "rule-" + position;
	for (let n = 2, root = name; !form.named && taken.includes(name); n++) name = root + "-" + n;
	const strange = (key: string, value: string) => PICKED.includes(key) && known[key] !== null && known[key] !== undefined && !known[key]!.includes(value), unknown = parsed.some(cond => cond.values.some(value => strange(cond.key, String(value))));
	const empty = parsed.some(cond => !cond.values.length), lost = then === "exit" && !exits.includes(exit), last = rule ? count : count + 1;
	const nameWrong = !name ? "rule.nameMissing" : !TAG.test(name) || RESERVED.includes(name) ? "rule.nameWrong" : taken.includes(name) ? "config.tagTaken" : null;
	const build = (): Item => ({...Object.fromEntries(Object.entries(form.base).filter(([key]) => !CONDITIONS.includes(key) && !["tag", "action", "enabled"].includes(key))), tag: name, ...Object.fromEntries(parsed.map(cond => [cond.key, cond.values])), action: then === "exit" ? {exit} : then, ...(form.enabled ? {} : {enabled: false})});
	const save = () => {
		setTried(true);
		if (jsonWrong || empty || lost || nameWrong || unknown) return;
		onSave(build(), Math.min(last, Math.max(1, at === "" ? last : at)));
	};
	return <Dialog open={!hidden} onOpenChange={open => { if (!open) onClose(); }} title={rule ? t("rule.editNumber", {number: position}) : t("rule.add")} description={t("rule.formBody")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); save(); }} noValidate>
			<Segmented label={t("config.view")} value={json === null ? "form" : "json"} onChange={view => { setJsonWrong(false); setJson(view === "json" ? JSON.stringify(build(), null, 2) : null); }} options={[{value: "form", label: t("config.view.form")}, {value: "json", label: t("config.view.json")}]}/>
			{json !== null ? <ItemJson value={JSON.parse(json) as Item} onChange={(next, error) => { if (next) setForm(read(next)); setJsonWrong(Boolean(error)); }}/> : <>
				<TextField label={t("rule.name")} hint={t("rule.nameHint")} value={name} onChange={value => patch({name: value.toLowerCase(), named: true})} error={nameWrong && (tried || form.named) ? t(nameWrong) : undefined} technical required/>
				{conds.map((cond, i) => <div key={i} className="p-cond">
					<SelectField label={t("rule.when")} value={cond.key} onChange={key => setConds(conds.map((c, j) => j === i ? {...c, key} : c))} options={CONDITIONS.filter(key => key === cond.key || !conds.some(c => c.key === key)).map(key => ({value: key, label: t(`rule.cond.${key}` as PanelKey)}))}/>
					{PICKED.includes(cond.key) && known[cond.key] ? <fieldset className="p-picks">
						<legend className="vw-label">{t("rule.values")}</legend>
						{known[cond.key]!.length > 10 && <TextField label={t("rule.find")} value={finding[i] ?? ""} onChange={text => setFinding({...finding, [i]: text})} technical optional/>}
						<div className="p-pick-list">{[...parsed[i]!.values.map(String).filter(value => strange(cond.key, value)), ...known[cond.key]!.filter(value => !finding[i] || value.includes(finding[i]!.toLowerCase()) || parsed[i]!.values.map(String).includes(value))].map(value => <div key={value} className="p-pick-row"><Checkbox label={value} checked={parsed[i]!.values.map(String).includes(value)} onChange={on => setConds(conds.map((c, j) => j === i ? {...c, values: (on ? [...parsed[i]!.values.map(String), value] : parsed[i]!.values.map(String).filter(old => old !== value)).join(", ")} : c))}/>{strange(cond.key, value) && <Mark tone="danger">{t("rule.unknown")}</Mark>}</div>)}</div>
						{!known[cond.key]!.length && <p className="vw-muted vw-small">{t(`rule.none.${cond.key}` as PanelKey)}</p>}
						{tried && !parsed[i]!.values.length && <Mark tone="danger">{t("rule.valuesMissing")}</Mark>}
					</fieldset> : <TextField label={t("rule.values")} hint={t(`rule.hint.${cond.key}` as PanelKey)} value={cond.values} onChange={values => setConds(conds.map((c, j) => j === i ? {...c, values} : c))} error={tried && !parsed[i]!.values.length ? t("rule.valuesMissing") : undefined} technical/>}
					{conds.length > 1 && <IconButton icon="close" label={t("rule.removeCond")} onClick={() => setConds(conds.filter((_, j) => j !== i))}/>}
				</div>)}
				{conds.length < CONDITIONS.length && <div><Button size="sm" icon="plus" onClick={() => setConds([...conds, {key: CONDITIONS.find(key => !conds.some(c => c.key === key))!, values: ""}])}>{t("rule.addCond")}</Button></div>}
				<SelectField label={t("rule.then")} value={then} onChange={value => patch({then: value})} options={(["exit", "user", "block", "reject"] as const).map(word => ({value: word, label: t(`rule.action.${word}`), detail: t(`rule.action.${word}Detail`)}))}/>
				{then === "exit" && <SelectField label={t("rule.exit")} value={exit} onChange={value => patch({exit: value})} error={tried && lost ? t(exit ? "rule.missingExit" : "rule.exitMissing", {exit}) : undefined} options={[...(exits.includes(exit) || !exit ? [] : [{value: exit, label: exit}]), ...exits.map(tag => ({value: tag, label: named(tag), detail: named(tag) === tag ? undefined : tag}))]}/>}
				<div className="p-pair">
					<NumberField label={t("rule.position")} hint={t("rule.positionHint")} unit={t("rule.positionUnit", {count: last})} min={1} max={last} value={at} onChange={setAt}/>
					<Switch label={t("rule.enabled")} hint={t("rule.enabledHint")} checked={form.enabled} onChange={enabled => patch({enabled})}/>
				</div>
			</>}
			{json !== null && tried && (nameWrong || empty || lost || unknown) && <Mark tone="danger">{t("rule.fixInForm")}</Mark>}
			<div className="vw-dialog-foot">{rule && <Button variant="danger" onClick={onRemove}>{t("rule.remove")}</Button>}<Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t("config.review")}</Button></div>
		</form>
	</Dialog>;
}
