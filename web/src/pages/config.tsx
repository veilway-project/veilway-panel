import {Banner, Button, DataTable, Dialog, Glass, IconButton, NumberField, SecretField, Segmented, SelectField, StateBlock, Switch, Tabs, TextField, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, ApiError, type Diff, type Report, type Running} from "../api.ts";
import {check, type Issue, type Schema} from "../check.ts";
import {ErrorNote, Issues, lines, LinesField, Mark, PageHead, Rating, useLoad, useP, useSay} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {LinksTab} from "./links.tsx";
import {ProfilesTab} from "./profiles.tsx";

type Section = "inbounds" | "outbounds" | "exits" | "routing";
type Item = Record<string, unknown>;
type Row = {type: string, listen: string, path: string};
type Cond = {key: string, values: string};
const TABS = ["inbounds", "outbounds", "exits", "routing", "profiles", "links"] as const;
const TRANSPORTS = ["udp", "udp-obfs", "tls", "ws", "fronted"];
const PATHED = ["tls", "ws", "fronted"];
const CONDITIONS = ["user", "group", "inbound", "link", "ip", "domain", "protocol", "port", "icmp_type", "icmp_code"];
const NUMERIC = ["protocol", "port", "icmp_type", "icmp_code"];
const BLANK: Record<Exclude<Section, "routing">, Item> = {inbounds: {tag: "", type: "veilway", address: [], transports: [{type: "udp-obfs", listen: ""}]}, outbounds: {tag: "", type: "direct"}, exits: {tag: "", backend: {type: "netstack", outbound: ""}}};
let schemaCache: Promise<Schema> | null = null;

// The schema does not change while the panel runs, so every editor shares one copy.
export const loadSchema = () => schemaCache ??= api("get", "/config/schema").then(schema => schema as Schema, error => { schemaCache = null; throw error; });
export const loadRunning = () => api("get", "/config") as Promise<Running>;
const str = (value: unknown) => typeof value === "string" ? value : "";
const list = (value: unknown) => Array.isArray(value) ? value as Item[] : [];

export function NodePage({tab}: {tab: string}) {
	const {t} = useP(), current = (TABS as readonly string[]).includes(tab) ? tab : "inbounds";
	// On a phone the tab row scrolls, and a tab opened by its address can sit out of view.
	useEffect(() => { document.querySelector(".vw-tab[data-state=active]")?.scrollIntoView({block: "nearest", inline: "nearest"}); }, [current]);
	return <>
		<PageHead title={t("node.title")} lead={t("node.lead")}/>
		<Tabs label={t("node.title")} value={current} onChange={id => { location.hash = "#/node/" + id; }} items={TABS.map(id => ({id, label: t(`node.tab.${id}`), content: id === "profiles" ? <ProfilesTab/> : id === "links" ? <LinksTab/> : <SectionTab section={id}/>}))}/>
	</>;
}

// Says what a check found in the reader's language. The node's own reports are English only and are shown as they come.
export function useIssueText() {
	const {t} = useP();
	return (issues: Issue[]) => issues.map(issue => ({path: issue.path, text: t(issue.key, issue.values)}));
}

function SectionTab({section}: {section: Section}) {
	const {t} = useP(), say = useSay(), config = useLoad(loadRunning, []), schema = useLoad(loadSchema, []), [json, setJson] = useState(false), [proposed, setProposed] = useState<unknown>(undefined), [editing, setEditing] = useState<{index: number | null} | null>(null);
	if (config.error && !config.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={config.reload}>{t("action.retry")}</Button>}>{say(config.error)}</StateBlock>;
	if (!config.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const running = config.data, value = running.document[section] ?? (section === "routing" ? {default: ""} : []), items = list(value), document = running.document;
	const tags = (name: string) => list(document[name]).map(item => str(item.tag)).filter(Boolean);
	const propose = (next: unknown) => { setEditing(null); setProposed(next); };
	const remove = (index: number) => propose(items.filter((_, i) => i !== index));
	const edit = (index: number | null) => setEditing({index});
	return <div className="p-stack">
		<div className="p-row"><p className="vw-muted p-lead">{t(`config.lead.${section}`)}</p><Segmented label={t("config.view")} value={json ? "json" : "list"} onChange={view => setJson(view === "json")} options={[{value: "list", label: t("config.view.list")}, {value: "json", label: t("config.view.json")}]}/></div>
		{json ? <JsonEditor key={running.revision} section={section} value={value} schema={schema.data} onReview={propose}/>
		: section === "routing" ? <Routing routing={value as Item} exits={tags("exits")} onPropose={propose}/>
		: <Glass className="p-pad p-stack">
			<div className="p-row p-table-head"><span className="vw-muted vw-small">{t("config.count", {count: items.length})}</span><Button size="sm" icon="plus" onClick={() => edit(null)}>{t(`config.add.${section}`)}</Button></div>
			<DataTable caption={t(`node.tab.${section}`)} rows={items.map((item, index) => ({item, index}))} rowKey={row => str(row.item.tag) || String(row.index)} empty={<StateBlock kind="empty" title={t(`config.empty.${section}`)} action={<Button variant="primary" icon="plus" onClick={() => edit(null)}>{t(`config.add.${section}`)}</Button>}>{t(`config.emptyBody.${section}`)}</StateBlock>} columns={[
				{id: "tag", header: t("config.col.tag"), cell: ({item}) => <span className="p-user"><span className="vw-code">{str(item.tag)}</span><span className="vw-muted vw-small">{section === "exits" ? [str(item.name), str(item.country)].filter(Boolean).join(", ") : str(item.type)}</span></span>},
				...(section === "inbounds" ? [
					{id: "address", header: t("config.col.address"), cell: ({item}: {item: Item}) => <span className="vw-code">{(item.address as string[] | undefined)?.join(", ")}</span>},
					{id: "transports", header: t("config.col.transports"), cell: ({item}: {item: Item}) => <ul className="p-transports">{list(item.transports).map((tr, i) => <li key={i}><span className="vw-code">{str(tr.type)} {str(tr.listen)}</span><Rating/></li>)}</ul>}
				] : section === "outbounds" ? [
					{id: "target", header: t("config.col.target"), cell: ({item}: {item: Item}) => item.type === "socks5" ? <span className="vw-code">{str(item.server)}</span> : <span className="vw-muted">{item.bind ? t("config.bind", {address: str(item.bind)}) : t("config.fromNode")}</span>}
				] : [
					{id: "backend", header: t("config.col.backend"), cell: ({item}: {item: Item}) => { const backend = (item.backend ?? {}) as Item; return backend.type === "netstack" ? t("config.backend.netstackVia", {outbound: str(backend.outbound)}) : backend.type === "chain" ? t("config.backend.chainVia", {links: (backend.links as string[] | undefined ?? []).join(", ")}) : t(`config.backend.${backend.type === "l3" ? "l3" : "block"}`); }}
				]),
				{id: "edit", header: "", align: "end", cell: ({item, index}) => <div className="p-cluster p-end"><Button size="sm" variant="quiet" aria-label={t("config.editName", {name: str(item.tag)})} onClick={() => edit(index)}>{t("user.edit")}</Button><Button size="sm" variant="quiet" aria-label={t("config.removeName", {name: str(item.tag)})} onClick={() => remove(index)}>{t("common.remove")}</Button></div>}
			]}/>
		</Glass>}
		{section !== "routing" && <p className="vw-muted vw-small">{t("config.reviewNote")}</p>}
		{editing && section !== "routing" && <ItemForm section={section} item={editing.index === null ? null : items[editing.index]!} taken={items.filter((_, i) => i !== editing.index).map(item => str(item.tag))} outbounds={tags("outbounds")} schema={schema.data} onSave={item => propose(editing.index === null ? [...items, item] : items.map((old, i) => i === editing.index ? item : old))} onClose={() => setEditing(null)}/>}
		{proposed !== undefined && <Review section={section} running={running} value={proposed} onClose={() => setProposed(undefined)} onDone={() => { setProposed(undefined); config.reload(); }}/>}
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
function Review({section, running, value, onClose, onDone}: {section: Section, running: Running, value: unknown, onClose: () => void, onDone: () => void}) {
	const {t} = useP(), toast = useToast(), [answer, setAnswer] = useState<{valid: boolean, report: Report, diff: Diff | null} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [stale, setStale] = useState(false), [refused, setRefused] = useState<Report | null>(null);
	useEffect(() => { api("post", "/config/diff", {body: {document: {...running.document, [section]: value}}}).then(found => setAnswer(found as typeof answer), setError); }, []);
	const apply = async () => {
		setBusy(true);
		setError(null);
		try {
			const done = await api("put", "/config/{section}", {params: {section}, body: {revision: running.revision, value}}) as {generation?: number};
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
	const report = refused ?? answer?.report, diff = answer?.diff;
	const changes = diff ? (["inbounds", "outbounds", "exits", "rules", "users"] as const).flatMap(kind => (["added", "changed", "removed"] as const).filter(verb => diff[kind]?.[verb]?.length).map(verb => ({kind, verb, names: diff[kind]![verb]}))) : [];
	const restarts = diff?.inbound_changes?.filter(change => change.restart).map(change => change.tag) ?? [], lost = diff?.user_changes?.filter(change => change.lost_access).map(change => change.name) ?? [];
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("review.title")} description={t("review.body")}>
		<div className="p-stack">
			{!answer && !error && <StateBlock kind="loading" title={t("review.asking")}/>}
			{stale && <Banner tone="warning" title={t("review.stale")} action={<Button size="sm" icon="refresh" onClick={onDone}>{t("review.reload")}</Button>}>{t("review.staleBody")}</Banner>}
			{report && report.errors.length > 0 && <><Banner tone="danger" title={t("review.invalid")}>{t("review.invalidBody")}</Banner><Issues issues={report.errors.map(p => ({path: p.path, text: p.message}))}/></>}
			{answer?.valid && !refused && <>
				{changes.length || diff?.routing_default || diff?.rules_reordered ? <ul className="p-changes">
					{changes.map(change => <li key={change.kind + change.verb}><Mark tone={change.verb === "removed" ? "danger" : change.verb === "added" ? "success" : "info"}>{t(`review.${change.verb}`)}</Mark><span>{t(`review.kind.${change.kind}`)}</span><span className="vw-code">{change.names.join(", ")}</span></li>)}
					{diff?.routing_default && <li><Mark tone="info">{t("review.changed")}</Mark><span>{t("review.default")}</span></li>}
					{diff?.rules_reordered && <li><Mark tone="info">{t("review.changed")}</Mark><span>{t("review.order")}</span></li>}
				</ul> : <p className="vw-muted">{t("review.nothing")}</p>}
				{restarts.length > 0 && <Banner tone="warning" title={t("review.restart", {tags: restarts.join(", ")})}>{t("review.restartBody")}</Banner>}
				{lost.length > 0 && <Banner tone="danger" title={t("review.lost", {count: lost.length})}>{lost.join(", ")}</Banner>}
			</>}
			{report && report.warnings.length > 0 && <><p className="vw-label">{t("review.warnings")}</p><Issues issues={report.warnings.map(p => ({path: p.path, text: p.message}))}/></>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy || !answer?.valid || stale || refused !== null} onClick={() => void apply()}>{t("review.apply")}</Button></div>
		</div>
	</Dialog>;
}

function ItemForm({section, item, taken, outbounds, schema, onSave, onClose}: {section: Exclude<Section, "routing">, item: Item | null, taken: string[], outbounds: string[], schema: Schema | null, onSave: (item: Item) => void, onClose: () => void}) {
	const {t} = useP(), say = useIssueText(), start = item ?? BLANK[section], backend = (start.backend ?? {}) as Item;
	const [draft, setDraft] = useState<Item>(start), [addresses, setAddresses] = useState(((start.address as string[] | undefined) ?? []).join("\n")), [links, setLinks] = useState(((backend.links as string[] | undefined) ?? []).join("\n"));
	const [rows, setRows] = useState<Row[]>(list(start.transports).map(tr => ({type: str(tr.type), listen: str(tr.listen), path: str(tr.path)}))), [issues, setIssues] = useState<{path: string, text: string}[]>([]);
	const set = (key: string, next: unknown) => { const copy = {...draft}; if (next === undefined || next === "") delete copy[key]; else copy[key] = next; setDraft(copy); };
	const setBackend = (key: string, next: unknown) => { const copy = {...(draft.backend as Item)}; if (next === undefined || next === "") delete copy[key]; else copy[key] = next; set("backend", copy); };
	const kind = str(draft.type), back = (draft.backend ?? {}) as Item, tag = str(draft.tag), clash = taken.includes(tag);
	const save = () => {
		const old = list(start.transports), made: Item = section === "inbounds" ? {...draft, address: lines(addresses), transports: rows.map((row, i) => ({...(old[i]?.type === row.type ? old[i] : {}), type: row.type, listen: row.listen.trim(), ...(row.path.trim() ? {path: row.path.trim()} : {})}))} : section === "exits" && back.type === "chain" ? {...draft, backend: {...back, links: lines(links)}} : draft;
		const found = schema && typeof schema === "object" ? say(check(((schema.properties as Record<string, Item>)[section]?.items ?? true) as Schema, made, schema, section)) : [];
		setIssues(clash ? [{path: "tag", text: t("config.tagTaken")}, ...found] : found);
		if (!clash && !found.length) onSave(made);
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t(item ? "config.editName" : `config.add.${section}`, {name: str(item?.tag)})}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); save(); }} noValidate>
			<TextField label={t("config.col.tag")} hint={t("config.tagHint")} value={tag} onChange={value => set("tag", value.toLowerCase())} error={clash ? t("config.tagTaken") : undefined} technical required autoFocus/>
			{section === "inbounds" && <>
				<SelectField label={t("config.type")} value={kind} onChange={value => set("type", value)} options={[{value: "veilway", label: t("config.inbound.veilway"), detail: t("config.inbound.veilwayDetail")}, {value: "wireguard", label: t("config.inbound.wireguard"), detail: t("config.inbound.wireguardDetail")}]}/>
				<SecretField label={t("config.privateKey")} hint={t(item ? "config.privateKeyKeep" : "config.privateKeyNew")} value={str(draft.private_key)} onChange={value => set("private_key", value.trim())} autoComplete="off"/>
				<LinesField label={t("config.addresses")} hint={t("config.addressesHint")} value={addresses} onChange={setAddresses} rows={2}/>
				<NumberField label={t("config.mtu")} hint={t("config.mtuHint")} unit={t("config.bytes")} min={1280} max={1500} value={typeof draft.mtu === "number" ? draft.mtu : ""} onChange={value => set("mtu", value === "" ? undefined : value)} optional/>
				<fieldset className="p-mirror">
					<legend className="vw-label">{t("config.col.transports")}</legend>
					{rows.map((row, i) => <div key={i} className="p-transport-row">
						<SelectField label={t("config.transport", {number: i + 1})} value={row.type} onChange={type => setRows(rows.map((r, j) => j === i ? {...r, type} : r))} options={(kind === "wireguard" ? ["udp", "ws"] : TRANSPORTS).map(type => ({value: type, label: type, detail: t(`config.transport.${type}` as PanelKey)}))}/>
						<TextField label={t("config.listen")} placeholder="0.0.0.0:443" value={row.listen} onChange={listen => setRows(rows.map((r, j) => j === i ? {...r, listen} : r))} technical/>
						{(PATHED.includes(row.type)) && <TextField label={t("config.path")} placeholder="/a-long-random-path" value={row.path} onChange={path => setRows(rows.map((r, j) => j === i ? {...r, path} : r))} technical/>}
						<div className="p-cluster"><Rating/>{rows.length > 1 && <IconButton icon="close" label={t("config.removeTransport", {number: i + 1})} onClick={() => setRows(rows.filter((_, j) => j !== i))}/>}</div>
					</div>)}
					{rows.length < 8 && <div><Button size="sm" icon="plus" onClick={() => setRows([...rows, {type: "udp-obfs", listen: "", path: ""}])}>{t("config.addTransport")}</Button></div>}
					<p className="vw-muted vw-small">{t("rating.detectableBody")}</p>
				</fieldset>
				{rows.some(row => PATHED.includes(row.type)) && <Banner tone="info" title={t("config.streamNote")}>{t("config.streamNoteBody")}</Banner>}
			</>}
			{section === "outbounds" && <>
				<SelectField label={t("config.type")} value={kind} onChange={value => set("type", value)} options={[{value: "direct", label: t("config.outbound.direct"), detail: t("config.outbound.directDetail")}, {value: "socks5", label: t("config.outbound.socks5"), detail: t("config.outbound.socks5Detail")}]}/>
				{kind === "socks5" ? <>
					<TextField label={t("config.server")} hint={t("config.serverHint")} placeholder="192.0.2.10:1080" value={str(draft.server)} onChange={value => set("server", value.trim())} technical/>
					<div className="p-pair">
						<SecretField label={t("config.username")} value={str(draft.username)} onChange={value => set("username", value)} autoComplete="off" optional/>
						<SecretField label={t("config.password")} value={str(draft.password)} onChange={value => set("password", value)} autoComplete="off" optional/>
					</div>
				</> : <TextField label={t("config.bindLabel")} hint={t("config.bindHint")} value={str(draft.bind)} onChange={value => set("bind", value.trim())} technical optional/>}
			</>}
			{section === "exits" && <>
				<div className="p-pair">
					<TextField label={t("config.exitName")} hint={t("config.exitNameHint")} value={str(draft.name)} onChange={value => set("name", value)} maxLength={64} optional/>
					<TextField label={t("config.country")} hint={t("config.countryHint")} value={str(draft.country)} onChange={value => set("country", value.toUpperCase())} maxLength={2} technical optional/>
				</div>
				<SelectField label={t("config.col.backend")} value={str(back.type)} onChange={type => set("backend", type === "netstack" ? {type, outbound: outbounds[0] ?? ""} : type === "chain" ? {type, links: []} : {type})} options={["netstack", "l3", "block", "chain"].map(type => ({value: type, label: t(`config.backend.${type}` as PanelKey), detail: t(`config.backend.${type}Detail` as PanelKey)}))}/>
				{back.type === "netstack" && <SelectField label={t("config.outboundLabel")} value={str(back.outbound)} onChange={value => setBackend("outbound", value)} options={outbounds.map(tag => ({value: tag, label: tag}))}/>}
				{back.type === "l3" && <TextField label={t("config.interface")} hint={t("config.interfaceHint")} value={str(back.interface)} onChange={value => setBackend("interface", value.trim())} technical optional/>}
				{back.type === "chain" && <LinesField label={t("config.links")} hint={t("config.linksHint")} value={links} onChange={setLinks} rows={2}/>}
				<p className="vw-muted vw-small">{t("config.moreInJson")}</p>
			</>}
			<Issues issues={issues}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t("config.review")}</Button></div>
		</form>
	</Dialog>;
}

function Routing({routing, exits, onPropose}: {routing: Item, exits: string[], onPropose: (routing: Item) => void}) {
	const {t} = useP(), rules = list(routing.rules), [fallback, setFallback] = useState(str(routing.default)), [editing, setEditing] = useState<number | null | undefined>(undefined);
	const action = (rule: Item) => typeof rule.action === "object" && rule.action ? t("rule.toExit", {exit: str((rule.action as Item).exit)}) : t(`rule.action.${rule.action === "block" || rule.action === "reject" ? rule.action : "user"}`);
	const when = (rule: Item) => CONDITIONS.filter(key => Array.isArray(rule[key])).map(key => t(`rule.cond.${key}` as PanelKey) + ": " + (rule[key] as unknown[]).join(", ")).join("; ");
	const withRules = (next: Item[]) => onPropose({...routing, rules: next});
	return <>
		<Glass className="p-panel p-form">
			<SelectField label={t("rule.default")} hint={t("rule.defaultHint")} value={fallback} onChange={setFallback} options={exits.map(tag => ({value: tag, label: tag}))}/>
			{fallback !== str(routing.default) && <div><Button variant="primary" onClick={() => onPropose({...routing, default: fallback})}>{t("config.review")}</Button></div>}
		</Glass>
		<Glass className="p-pad p-stack">
			<div className="p-row p-table-head"><span className="vw-muted vw-small">{t("rule.lead")}</span><Button size="sm" icon="plus" onClick={() => setEditing(null)}>{t("rule.add")}</Button></div>
			<DataTable caption={t("node.tab.routing")} rows={rules.map((rule, index) => ({rule, index}))} rowKey={row => String(row.index)} empty={<StateBlock kind="empty" title={t("rule.empty")} action={<Button icon="plus" onClick={() => setEditing(null)}>{t("rule.add")}</Button>}>{t("rule.emptyBody", {exit: str(routing.default)})}</StateBlock>} columns={[
				{id: "order", header: t("rule.col.order"), cell: ({index}) => <span className="vw-num">{index + 1}</span>},
				{id: "when", header: t("rule.col.when"), cell: ({rule}) => <span className="p-user"><span className="vw-code">{when(rule)}</span>{rule.enabled === false && <span className="vw-muted vw-small">{t("rule.off")}</span>}</span>},
				{id: "then", header: t("rule.col.then"), cell: ({rule}) => action(rule)},
				{id: "edit", header: "", align: "end", cell: ({index}) => <Button size="sm" variant="quiet" aria-label={t("rule.editNumber", {number: index + 1})} onClick={() => setEditing(index)}>{t("user.edit")}</Button>}
			]}/>
		</Glass>
		{editing !== undefined && <RuleForm rule={editing === null ? null : rules[editing]!} position={editing === null ? rules.length + 1 : editing + 1} count={rules.length} exits={exits} onClose={() => setEditing(undefined)} onRemove={() => withRules(rules.filter((_, i) => i !== editing))} onSave={(rule, position) => { const rest = editing === null ? rules : rules.filter((_, i) => i !== editing); withRules([...rest.slice(0, position - 1), rule, ...rest.slice(position - 1)]); }}/>}
	</>;
}

function RuleForm({rule, position, count, exits, onSave, onRemove, onClose}: {rule: Item | null, position: number, count: number, exits: string[], onSave: (rule: Item, position: number) => void, onRemove: () => void, onClose: () => void}) {
	const {t} = useP(), start = rule ?? {action: {exit: exits[0] ?? ""}};
	const [conds, setConds] = useState<Cond[]>(() => { const found = CONDITIONS.filter(key => Array.isArray(start[key])).map(key => ({key, values: (start[key] as unknown[]).join(", ")})); return found.length ? found : [{key: "user", values: ""}]; });
	const [then, setThen] = useState(typeof start.action === "object" && start.action ? "exit:" + str((start.action as Item).exit) : str(start.action)), [enabled, setEnabled] = useState(start.enabled !== false), [at, setAt] = useState<number | "">(position), [tried, setTried] = useState(false);
	const parsed = conds.map(cond => ({key: cond.key, values: cond.values.split(/[,\n]/).map(value => value.trim()).filter(Boolean).map(value => NUMERIC.includes(cond.key) && /^\d+$/.test(value) ? Number(value) : value)}));
	const empty = parsed.some(cond => !cond.values.length), last = rule ? count : count + 1;
	const save = () => {
		setTried(true);
		if (empty) return;
		const made: Item = {...(rule?.tag ? {tag: rule.tag} : {}), ...Object.fromEntries(parsed.map(cond => [cond.key, cond.values])), action: then.startsWith("exit:") ? {exit: then.slice(5)} : then, ...(enabled ? {} : {enabled: false})};
		onSave(made, Math.min(last, Math.max(1, at === "" ? last : at)));
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={rule ? t("rule.editNumber", {number: position}) : t("rule.add")} description={t("rule.formBody")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); save(); }} noValidate>
			{conds.map((cond, i) => <div key={i} className="p-cond">
				<SelectField label={t("rule.when")} value={cond.key} onChange={key => setConds(conds.map((c, j) => j === i ? {...c, key} : c))} options={CONDITIONS.filter(key => key === cond.key || !conds.some(c => c.key === key)).map(key => ({value: key, label: t(`rule.cond.${key}` as PanelKey)}))}/>
				<TextField label={t("rule.values")} hint={t(`rule.hint.${cond.key}` as PanelKey)} value={cond.values} onChange={values => setConds(conds.map((c, j) => j === i ? {...c, values} : c))} error={tried && !parsed[i]!.values.length ? t("rule.valuesMissing") : undefined} technical/>
				{conds.length > 1 && <IconButton icon="close" label={t("rule.removeCond")} onClick={() => setConds(conds.filter((_, j) => j !== i))}/>}
			</div>)}
			{conds.length < CONDITIONS.length && <div><Button size="sm" icon="plus" onClick={() => setConds([...conds, {key: CONDITIONS.find(key => !conds.some(c => c.key === key))!, values: ""}])}>{t("rule.addCond")}</Button></div>}
			<SelectField label={t("rule.then")} value={then} onChange={setThen} options={[...exits.map(tag => ({value: "exit:" + tag, label: t("rule.toExit", {exit: tag})})), ...(["user", "block", "reject"] as const).map(word => ({value: word, label: t(`rule.action.${word}`), detail: t(`rule.action.${word}Detail`)}))]}/>
			<div className="p-pair">
				<NumberField label={t("rule.position")} hint={t("rule.positionHint")} unit={t("rule.positionUnit", {count: last})} min={1} max={last} value={at} onChange={setAt}/>
				<Switch label={t("rule.enabled")} hint={t("rule.enabledHint")} checked={enabled} onChange={setEnabled}/>
			</div>
			<div className="vw-dialog-foot">{rule && <Button variant="danger" onClick={onRemove}>{t("rule.remove")}</Button>}<Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t("config.review")}</Button></div>
		</form>
	</Dialog>;
}
