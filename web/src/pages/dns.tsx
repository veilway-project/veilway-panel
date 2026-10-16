import {Banner, Button, Dialog, Glass, IconButton, List, ListRow, NumberField, SelectField, StateBlock, Switch, TextField} from "@veilway/ui";
import {useState} from "react";
import type {Running} from "../api.ts";
import {lines, LinesField, Mark, PageHead, useP, useSay} from "../kit.tsx";
import {SectionReview, useRunning, type NodeSection} from "./apply.tsx";

type DnsSet = {tag: string, servers: string[], users?: string[], groups?: string[], inbounds?: string[]};
type Dns = {servers: string[], hijack?: boolean, sets?: DnsSet[]};
type Log = {level?: string, destinations?: boolean};
type Replay = {cache?: number, per_source?: {burst: number, rate: number}};
const LEVELS = ["error", "warn", "info", "debug", "trace"] as const;
const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const words = (text: string) => text.split(",").map(word => word.trim().toLowerCase()).filter(Boolean);

// The node's own settings that are not about where traffic goes: its resolvers, its log and its replay memory. Each panel applies on its own.
export function DnsPage() {
	const {t} = useP(), say = useSay(), running = useRunning();
	return <>
		<PageHead title={t("nav.dns")} lead={t("dns.pageLead")}/>
		{running.error && !running.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={running.reload}>{t("action.retry")}</Button>}>{say(running.error)}</StateBlock>
		: !running.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <div className="p-stack">
			<DnsPanel key={running.data.revision + "dns"} running={running.data} onDone={running.reload}/>
			<LogPanel key={running.data.revision + "log"} running={running.data} onDone={running.reload}/>
			<ReplayPanel key={running.data.revision + "replay"} running={running.data} onDone={running.reload}/>
		</div>}
	</>;
}

// Undo and review, shown once a panel holds a change.
function Foot({changed, onUndo, onReview}: {changed: boolean, onUndo: () => void, onReview: () => void}) {
	const {t} = useP();
	return changed ? <div className="p-form-foot"><Button variant="quiet" onClick={onUndo}>{t("config.undo")}</Button><Button variant="primary" onClick={onReview}>{t("config.review")}</Button></div> : null;
}

function Apply({section, running, value, summary, open, onClose, onDone}: {section: NodeSection, running: Running, value: unknown, summary: string, open: boolean, onClose: () => void, onDone: () => void}) {
	return open ? <SectionReview section={section} running={running} value={value} summary={<p>{summary}</p>} onClose={onClose} onDone={onDone}/> : null;
}

function DnsPanel({running, onDone}: {running: Running, onDone: () => void}) {
	const {t} = useP(), live = (running.document.dns ?? {servers: []}) as Dns, [draft, setDraft] = useState<Dns>(live), [servers, setServers] = useState(live.servers.join("\n")), [editing, setEditing] = useState<number | null>(null), [review, setReview] = useState(false);
	const value: Dns = {...draft, servers: lines(servers)}, sets = draft.sets ?? [], hijack = draft.hijack ?? true, changed = JSON.stringify(value) !== JSON.stringify(live);
	const inbounds = ((running.document.inbounds ?? []) as {tag: string}[]).map(inbound => inbound.tag);
	return <Glass className="p-panel">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t("dns.title")}</h2><p>{t("dns.lead")}</p></div></div>
		<LinesField label={t("dns.servers")} hint={t("dns.serversHint")} value={servers} onChange={setServers} rows={3} optional={false}/>
		<Switch label={t("dns.hijack")} hint={t("dns.hijackHint")} checked={hijack} onChange={on => setDraft({...draft, hijack: on})}/>
		<div className="p-sheet-head">
			<div><h3 className="vw-h3">{t("dns.sets")}</h3><p>{t("dns.setsLead")}</p></div>
			<Button size="sm" icon="plus" disabled={sets.length >= 32 || !hijack} onClick={() => setEditing(sets.length)}>{t("dns.addSet")}</Button>
		</div>
		{!hijack && sets.length > 0 && <Banner tone="warning" title={t("dns.setsNeedHijack")}/>}
		{sets.length === 0 ? <p className="vw-muted vw-small">{t(hijack ? "dns.noSets" : "dns.noSetsHijack")}</p> : <List label={t("dns.sets")}>
			{sets.map((set, i) => <ListRow key={set.tag + i} title={set.tag} detail={[set.users?.length && t("dns.forUsers", {names: set.users.join(", ")}), set.groups?.length && t("dns.forGroups", {names: set.groups.join(", ")}), set.inbounds?.length && t("dns.forInbounds", {names: set.inbounds.join(", ")})].filter(Boolean).join(". ") + ". " + t("dns.asks", {servers: set.servers.join(", ")})} trailing={<><Button size="sm" variant="quiet" onClick={() => setEditing(i)}>{t("user.edit")}</Button><IconButton icon="close" label={t("config.removeName", {name: set.tag})} onClick={() => setDraft({...draft, sets: sets.filter((_, j) => j !== i)})}/></>}/>)}
		</List>}
		<Foot changed={changed} onUndo={() => { setDraft(live); setServers(live.servers.join("\n")); }} onReview={() => setReview(true)}/>
		{editing !== null && <SetDialog set={sets[editing] ?? null} taken={sets.filter((_, i) => i !== editing).map(set => set.tag)} inbounds={inbounds} onClose={() => setEditing(null)} onSave={set => { setDraft({...draft, sets: sets.length > editing ? sets.map((old, i) => i === editing ? set : old) : [...sets, set]}); setEditing(null); }}/>}
		<Apply section="dns" running={running} value={value} summary={t("dns.summary", {servers: value.servers.length, sets: sets.length})} open={review} onClose={() => setReview(false)} onDone={onDone}/>
	</Glass>;
}

function SetDialog({set, taken, inbounds, onClose, onSave}: {set: DnsSet | null, taken: string[], inbounds: string[], onClose: () => void, onSave: (set: DnsSet) => void}) {
	const {t} = useP(), [tag, setTag] = useState(set?.tag ?? ""), [servers, setServers] = useState((set?.servers ?? []).join("\n")), [users, setUsers] = useState((set?.users ?? []).join(", ")), [groups, setGroups] = useState((set?.groups ?? []).join(", ")), [chosen, setChosen] = useState(set?.inbounds ?? []), [tried, setTried] = useState(false);
	const made: DnsSet = {tag, servers: lines(servers), ...(words(users).length ? {users: words(users)} : {}), ...(words(groups).length ? {groups: words(groups)} : {}), ...(chosen.length ? {inbounds: chosen} : {})};
	const problems = {tag: !TAG.test(tag) ? t("dns.tagRule") : taken.includes(tag) ? t("config.tagTaken") : undefined, servers: made.servers.length < 1 || made.servers.length > 4 ? t("dns.serversCount") : undefined, who: !made.users && !made.groups && !made.inbounds ? t("dns.who") : undefined};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t(set ? "dns.editSet" : "dns.addSet")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); setTried(true); if (!problems.tag && !problems.servers && !problems.who) onSave(made); }} noValidate>
			<TextField label={t("config.col.tag")} hint={t("dns.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase().trim())} error={tried ? problems.tag : undefined} technical required autoFocus/>
			<LinesField label={t("dns.servers")} hint={t("dns.serversHint")} value={servers} onChange={setServers} rows={2} optional={false}/>
			{tried && problems.servers && <p className="vw-note p-exit-problem" role="alert">{problems.servers}</p>}
			<TextField label={t("dns.users")} hint={t("dns.listHint")} value={users} onChange={setUsers} optional technical/>
			<TextField label={t("form.groups")} hint={t("dns.listHint")} value={groups} onChange={setGroups} optional technical/>
			{inbounds.length > 0 && <div className="vw-field"><span className="vw-label">{t("dns.inbounds")}</span><ul className="p-row-list p-exit-list">{inbounds.map(inbound => <li key={inbound}><label className="p-exit"><input type="checkbox" className="p-check" checked={chosen.includes(inbound)} onChange={event => setChosen(event.target.checked ? [...chosen, inbound] : chosen.filter(held => held !== inbound))}/><span className="p-row-text"><strong className="vw-code">{inbound}</strong></span><span/></label></li>)}</ul></div>}
			{tried && problems.who && <p className="vw-note p-exit-problem" role="alert">{problems.who}</p>}
			<p className="vw-small vw-muted">{t("dns.order")}</p>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t("notices.keep")}</Button></div>
		</form>
	</Dialog>;
}

function LogPanel({running, onDone}: {running: Running, onDone: () => void}) {
	const {t} = useP(), live = (running.document.log ?? {}) as Log, [draft, setDraft] = useState<Log>(live), [review, setReview] = useState(false);
	const level = draft.level ?? "info", destinations = draft.destinations ?? false, value: Log = {level, destinations}, changed = level !== (live.level ?? "info") || destinations !== (live.destinations ?? false);
	return <Glass className="p-panel">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t("log.title")}</h2><p>{t("log.lead")}</p></div></div>
		<SelectField label={t("log.level")} hint={t(`log.level.${level as "info"}Hint`)} value={level} onChange={next => setDraft({...draft, level: next})} options={LEVELS.map(l => ({value: l, label: t(`log.level.${l}`)}))}/>
		<Switch label={t("log.destinations")} hint={t("log.destinationsHint")} checked={destinations} onChange={on => setDraft({...draft, destinations: on})}/>
		{destinations && <Banner tone="danger" title={t("log.destinationsWarn")}>{t("log.destinationsWarnBody")}</Banner>}
		<Foot changed={changed} onUndo={() => setDraft(live)} onReview={() => setReview(true)}/>
		<Apply section="log" running={running} value={value} summary={t("log.summary", {level: t(`log.level.${level as "info"}`), destinations: String(destinations)})} open={review} onClose={() => setReview(false)} onDone={onDone}/>
	</Glass>;
}

function ReplayPanel({running, onDone}: {running: Running, onDone: () => void}) {
	const {t} = useP(), live = (running.document.replay ?? {}) as Replay, [cache, setCache] = useState<number | "">(live.cache ?? ""), [burst, setBurst] = useState<number | "">(live.per_source?.burst ?? ""), [rate, setRate] = useState<number | "">(live.per_source?.rate ?? ""), [review, setReview] = useState(false);
	const obfuscated = ((running.document.inbounds ?? []) as {transports?: {type: string}[]}[]).some(inbound => (inbound.transports ?? []).some(transport => ["udp-obfs", "tls"].includes(transport.type) || transport.type === "ws" && "decoy" in transport));
	const value: Replay = {...(cache === "" ? {} : {cache}), ...(burst === "" || rate === "" ? {} : {per_source: {burst, rate}})}, changed = JSON.stringify(value) !== JSON.stringify(live), half = (burst === "") !== (rate === "");
	return <Glass className="p-panel">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t("replay.title")}</h2><p>{t("replay.lead")}</p></div></div>
		{!obfuscated && <p className="vw-small vw-muted">{t("replay.none")}</p>}
		<div className="p-pair">
			<div className="p-stack"><NumberField label={t("replay.cache")} hint={t("replay.cacheHint")} unit={t("replay.unitProofs")} min={1024} max={1048576} value={cache} onChange={setCache} optional/><span><Mark tone="warning">{t("replay.restart")}</Mark></span></div>
			<div className="p-pair">
				<NumberField label={t("replay.burst")} hint={t("replay.burstHint")} unit={t("replay.unitProofs")} min={1} max={65536} value={burst} onChange={setBurst} optional/>
				<NumberField label={t("replay.rate")} hint={t("replay.rateHint")} unit={t("replay.unitRate")} min={1} max={65536} value={rate} onChange={setRate} optional/>
			</div>
		</div>
		{half && <p className="vw-note p-exit-problem" role="alert">{t("replay.both")}</p>}
		{!half && <Foot changed={changed} onUndo={() => { setCache(live.cache ?? ""); setBurst(live.per_source?.burst ?? ""); setRate(live.per_source?.rate ?? ""); }} onReview={() => setReview(true)}/>}
		<Apply section="replay" running={running} value={value} summary={t(value.cache !== live.cache ? "replay.summaryRestart" : "replay.summary")} open={review} onClose={() => setReview(false)} onDone={onDone}/>
	</Glass>;
}
