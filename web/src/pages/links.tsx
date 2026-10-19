import {Banner, Button, Checkbox, ConfirmDialog, Dialog, Field, Glass, Icon, IconButton, List, ListRow, NumberField, RadioGroup, SelectField, StateBlock, Switch, TextField, useToast} from "@veilway/ui";
import {useRef, useState} from "react";
import {api, ApiError, type NodeLink, type Pairings, type Pasted, type Running, type Template, type User, type UserPatch} from "../api.ts";
import {ago, Copyable, DayField, ErrorNote, lines, LinesField, Mark, PageHead, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {SectionReview, useRunning} from "./apply.tsx";
import {loadRunning, viaProblem} from "./config.tsx";
import {TunnelCards, TunnelPreset} from "./tunnels.tsx";

type Compare = {id: string, fingerprint: string, name: string};
type Side = "entry" | "exit";
// A link as the config holds it. Keys, secrets and transports are the pairing's and are kept as they are.
type LinkConfig = {tag: string, direction: string, inbound?: string, peer?: unknown, enabled?: boolean, exit?: string, exits?: string[], allow_private?: boolean, max_flows?: number, quota_bytes?: number, quota_period?: string, expires_at?: string, mtu?: number, [key: string]: unknown};
const GB = 1024 ** 3;
const STATE_TONE: Record<string, "success" | "info" | "warning" | "danger" | undefined> = {up: "success", connecting: "warning", unreachable: "danger", refused: "danger"};

// This node and every node it is linked to, one card each, with the pairing steps for a new link.
export function NodesPage({status, reachable, online}: {status: {version?: string, generation?: number, uptime_secs?: number, public_addresses?: string[]} | null, reachable: boolean, online: number | undefined}) {
	const {t, bytes, time, number} = useP(), say = useSay(), toast = useToast(), links = useLoad(() => api("get", "/links") as Promise<{links: NodeLink[] | null}>, []), pairings = useLoad(() => api("get", "/links/pairings") as Promise<Pairings>, []);
	const [flow, setFlow] = useState<"offer" | "paste" | null>(null), [preset, setPreset] = useState<{side: Side | null, direction: string} | null>(null), [tunnelPreset, setTunnelPreset] = useState<"tcp" | "udp" | null>(null), [compare, setCompare] = useState<Compare | null>(null), [answering, setAnswering] = useState<string | null>(null);
	const running = useRunning(), configured = (running.data?.document.links ?? []) as LinkConfig[], [editing, setEditing] = useState<LinkConfig | null>(null), [removing, setRemoving] = useState<LinkConfig | null>(null), [proposed, setProposed] = useState<{value: LinkConfig[], summary: string} | null>(null);
	const manage = (tag: string) => { const found = configured.find(link => link.tag === tag); return found && <span className="p-cluster"><Button size="sm" variant="quiet" onClick={() => setEditing(found)}>{t("links.manage")}</Button><Button size="sm" variant="quiet" onClick={() => setRemoving(found)}>{t("common.remove")}</Button></span>; };
	const idle = configured.filter(link => !(links.data?.links ?? []).some(l => l.tag === link.tag));
	const refresh = () => { links.reload(); pairings.reload(); };
	const toCompare = (next: Compare) => { setFlow(null); setAnswering(null); setCompare(next); pairings.reload(); };
	const drop = (id: string) => void api("delete", "/links/pairings/{id}", {params: {id}}).then(() => { toast({tone: "success", title: t("links.dropped")}); pairings.reload(); }, failure => toast({tone: "danger", title: say(failure)}));
	const waiting = pairings.data ? pairings.data.offers.length + pairings.data.answered.length : 0, span = (seconds: number) => { const found = ago(seconds); return t(found.key, {count: found.count}); };
	if (compare) return <><PageHead title={t("nav.nodes")}/><Fingerprints pairing={compare} onClose={() => { setCompare(null); refresh(); }}/></>;
	if (preset) return <><PageHead title={t("nav.nodes")}/><Preset start={preset} onClose={() => { setPreset(null); running.reload(); refresh(); }}/></>;
	if (tunnelPreset && running.data) return <><PageHead title={t("nav.nodes")}/><TunnelPreset protocol={tunnelPreset} running={running.data} onClose={() => { setTunnelPreset(null); running.reload(); }}/></>;
	return <>
		<PageHead title={t("nav.nodes")} lead={t("links.lead")}>
			<Button variant={flow === "paste" ? "primary" : "secondary"} onClick={() => setFlow(flow === "paste" ? null : "paste")}>{t("links.paste")}</Button>
			<Button variant={flow === "offer" ? "secondary" : "primary"} icon="plus" onClick={() => setFlow(flow === "offer" ? null : "offer")}>{t("links.offer")}</Button>
		</PageHead>
		{flow === "offer" && <OfferFlow onCompare={toCompare} onClose={() => { setFlow(null); pairings.reload(); }}/>}
		{flow === "paste" && <PasteFlow onCompare={toCompare} onClose={() => setFlow(null)}/>}
		{answering && <AnswerStep id={answering} onCompare={toCompare} onClose={() => setAnswering(null)}/>}
		{!flow && !answering && <Glass className="p-panel">
			<div className="p-sheet-head"><div><h2 className="vw-h2">{t("preset.title")}</h2><p>{t("preset.lead")}</p></div></div>
			<div className="p-presets">
				<button type="button" className="p-preset" onClick={() => setPreset({side: "entry", direction: "forward"})}><strong>{t("preset.entry")}</strong><span>{t("preset.entryDetail")}</span></button>
				<button type="button" className="p-preset" onClick={() => setPreset({side: "exit", direction: "forward"})}><strong>{t("preset.exit")}</strong><span>{t("preset.exitDetail")}</span></button>
				<button type="button" className="p-preset" onClick={() => setPreset({side: null, direction: "reverse"})}><strong>{t("preset.reverse")}</strong><span>{t("preset.reverseDetail")}</span></button>
				<button type="button" className="p-preset" onClick={() => setTunnelPreset("tcp")}><strong>{t("preset.tunnel")}</strong><span>{t("preset.tunnelDetail")}</span></button>
				<button type="button" className="p-preset" onClick={() => setTunnelPreset("udp")}><strong>{t("preset.tunnelUdp")}</strong><span>{t("preset.tunnelUdpDetail")}</span></button>
			</div>
		</Glass>}
		{links.error && !links.data && <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={links.reload}>{t("action.retry")}</Button>}>{say(links.error)}</StateBlock>}
		<div className="p-columns p-node-cards">
			<Glass className="p-node-card p-sheet-new">
				<div className="p-sheet-head"><div><strong className="vw-code vw-h3">{status?.public_addresses?.[0] ?? t("side.thisNode")}</strong><span className="vw-small vw-muted">{t("nodes.this")}</span></div><Mark tone={reachable ? "success" : "danger"}>{reachable ? t("side.running") : t("side.unreachable")}</Mark></div>
				<dl>
					<div><dt>{t("nodes.online")}</dt><dd className="vw-num">{online === undefined ? t("users.usageUnknown") : number(online)}</dd></div>
					{status?.generation !== undefined && <div><dt>{t("side.config")}</dt><dd className="vw-num">{t("side.configNo", {generation: number(status.generation)})}</dd></div>}
					{status?.uptime_secs !== undefined && <div><dt>{t("side.uptime")}</dt><dd className="vw-num">{span(status.uptime_secs)}</dd></div>}
					{status?.version && <div><dt>{t("nodes.version")}</dt><dd className="vw-code">{status.version}</dd></div>}
				</dl>
			</Glass>
			{(links.data?.links ?? []).map(l => <Glass key={l.id} className="p-node-card">
				<div className="p-sheet-head"><div><strong className="vw-code vw-h3">{l.tag}</strong><span className="vw-small vw-muted" title={t(l.half === "exit" ? "links.half.exit" : "links.half.entry")}>{t(l.half === "exit" ? "nodes.half.exit" : "nodes.half.entry")}</span></div><Mark tone={STATE_TONE[l.state]}>{["up", "connecting", "unreachable", "refused", "ended"].includes(l.state) ? t(`links.state.${l.state as "up"}`) : l.state}</Mark></div>
				<dl>
					<div><dt>{t(l.state === "up" ? "nodes.upFor" : "nodes.stateFor")}</dt><dd className="vw-num">{span(l.state_secs)}</dd></div>
					<div><dt>{t("links.col.traffic")}</dt><dd className="vw-num">{bytes(l.traffic.up_bytes + l.traffic.down_bytes).text}</dd></div>
					<div><dt>{t("nodes.flows")}</dt><dd className="vw-num">{number(l.flows)}</dd></div>
				</dl>
				{manage(l.tag)}
			</Glass>)}
			{links.data && idle.map(link => <Glass key={link.tag} className="p-node-card">
				<div className="p-sheet-head"><div><strong className="vw-code vw-h3">{link.tag}</strong><span className="vw-small vw-muted">{t(exitHalf(link) ? "nodes.half.exit" : "nodes.half.entry")}</span></div><Mark tone="muted">{t(link.enabled === false ? "links.off" : "links.notRunning")}</Mark></div>
				{manage(link.tag)}
			</Glass>)}
		</div>
		{running.data && !flow && !answering && <TunnelCards running={running.data} onChanged={running.reload} onAdd={() => setTunnelPreset("tcp")}/>}
		{links.data && !(links.data.links ?? []).length && !flow && <Glass className="p-panel"><StateBlock kind="empty" title={t("links.empty")} action={<Button variant="primary" icon="plus" onClick={() => setFlow("offer")}>{t("links.offer")}</Button>}>{t("links.emptyBody")}</StateBlock></Glass>}
		{editing && <LinkDialog link={editing} exits={((running.data?.document.exits ?? []) as {tag: string, backend?: {type?: string}}[]).filter(exit => exit.backend?.type !== "chain").map(exit => exit.tag)} outbounds={(running.data?.document.outbounds ?? []) as Record<string, unknown>[]} onClose={() => setEditing(null)} onSave={changed => { setEditing(null); setProposed({value: configured.map(link => link.tag === changed.tag ? changed : link), summary: t("links.summaryEdit", {name: changed.tag})}); }}/>}
		<ConfirmDialog open={removing !== null} onOpenChange={open => { if (!open) setRemoving(null); }} danger title={t("links.removeTitle", {name: removing?.tag ?? ""})} body={t("links.removeBody", {name: removing?.tag ?? ""})} confirmLabel={t("links.removeConfirm")} onConfirm={() => { const gone = removing!; setRemoving(null); setProposed({value: configured.filter(link => link.tag !== gone.tag), summary: t("links.summaryRemove", {name: gone.tag})}); }}/>
		{proposed && running.data && <SectionReview section="links" running={running.data} value={proposed.value} summary={<p>{proposed.summary}</p>} onClose={() => setProposed(null)} onDone={() => { setProposed(null); running.reload(); refresh(); }}/>}
		{pairings.data && waiting > 0 && <Glass className="p-panel">
			<div className="p-sheet-head"><div><h2 className="vw-h2">{t("links.waiting")}</h2><p>{t("print.channel")}</p></div></div>
			<List label={t("links.waiting")}>
				{pairings.data.answered.map(p => <ListRow key={p.id} title={p.name} detail={t("links.answeredDetail", {time: time(new Date(p.expires_at * 1000)), tries: 5 - p.tries})} trailing={<><Button size="sm" variant="primary" onClick={() => toCompare({id: p.id, fingerprint: p.fingerprint, name: p.name})}>{t("links.compare")}</Button><IconButton icon="close" label={t("links.drop", {name: p.name})} onClick={() => drop(p.id)}/></>}/>)}
				{pairings.data.offers.map(p => <ListRow key={p.id} title={p.name} detail={t("links.offerDetail", {time: time(new Date(p.expires_at * 1000))})} trailing={<><Button size="sm" onClick={() => setAnswering(p.id)}>{t("links.pasteAnswer")}</Button><IconButton icon="close" label={t("links.drop", {name: p.name})} onClick={() => drop(p.id)}/></>}/>)}
			</List>
		</Glass>}
	</>;
}

// The exit half is the node that is dialled in a forward link, or that dials in a reverse one.
const exitHalf = (link: LinkConfig) => (link.inbound !== undefined) === (link.direction === "forward");

// What can change on a link after pairing: whether it runs, and on the exit half what it may use. The keys and the transports stay as the pairing made them.
function LinkDialog({link, exits, outbounds, onClose, onSave}: {link: LinkConfig, exits: string[], outbounds: Record<string, unknown>[], onClose: () => void, onSave: (link: LinkConfig) => void}) {
	const {t} = useP(), exitSide = exitHalf(link), [enabled, setEnabled] = useState(link.enabled ?? true), [exit, setExit] = useState(link.exit ?? ""), [allowed, setAllowed] = useState(link.exits ?? []), [allowPrivate, setAllowPrivate] = useState(link.allow_private ?? false);
	const [flows, setFlows] = useState<number | "">(link.max_flows ?? ""), [quota, setQuota] = useState<number | "">(link.quota_bytes ? Math.round(link.quota_bytes / GB * 100) / 100 : ""), [period, setPeriod] = useState(link.quota_period ?? "none"), [day, setDay] = useState(link.expires_at ? link.expires_at.slice(0, 10) : ""), [mtu, setMtu] = useState<number | "">(link.mtu ?? "");
	const [through, setThrough] = useState((link.via as string | undefined) ?? ""), dials = link.peer !== undefined, socks = outbounds.filter(item => item.type === "socks5").map(item => String(item.tag)), viaWrong = dials && through ? viaProblem("", through, outbounds) : undefined;
	const save = () => {
		if (viaWrong) return;
		const made: LinkConfig = {...link};
		for (const key of ["enabled", "exit", "exits", "allow_private", "max_flows", "quota_bytes", "quota_period", "expires_at", "mtu", "via"]) delete made[key];
		if (dials && through) made.via = through;
		if (!enabled) made.enabled = false;
		if (exitSide && exit) made.exit = exit;
		if (exitSide && allowed.length) made.exits = allowed;
		if (exitSide && allowPrivate) made.allow_private = true;
		if (exitSide && flows !== "") made.max_flows = flows;
		if (exitSide && quota !== "") made.quota_bytes = Math.round(quota * GB);
		if (exitSide && quota !== "" && period !== "none") made.quota_period = period;
		if (day) made.expires_at = day + "T23:59:59Z";
		if (mtu !== "") made.mtu = mtu;
		onSave(made);
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("links.manageTitle", {name: link.tag})} description={t(exitSide ? "links.manageExit" : "links.manageEntry")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); save(); }} noValidate>
			<Switch label={t("links.enabled")} hint={t("links.enabledHint")} checked={enabled} onChange={setEnabled}/>
			{dials && <SelectField label={t("links.via")} hint={t("links.viaHint") + " " + t("via.plain")} value={through} onChange={setThrough} error={viaWrong ? t(viaWrong) : undefined} options={[{value: "", label: t("config.viaDirect")}, ...[...socks, ...(through && !socks.includes(through) ? [through] : [])].map(tag => ({value: tag, label: tag}))]}/>}
			{exitSide && <>
				<SelectField label={t("links.exit")} hint={t("links.exitHint")} value={exit} onChange={setExit} options={[{value: "", label: t("links.exitDefault")}, ...exits.map(tag => ({value: tag, label: tag}))]}/>
				<div className="vw-field"><span className="vw-label">{t("links.exits")}</span><p className="vw-note">{t("links.exitsHint")}</p><ul className="p-row-list p-exit-list">{exits.map(tag => <li key={tag}><label className="p-exit"><input type="checkbox" className="p-check" checked={allowed.includes(tag)} onChange={event => setAllowed(event.target.checked ? [...allowed, tag] : allowed.filter(held => held !== tag))}/><span className="p-row-text"><strong className="vw-code">{tag}</strong></span><span/></label></li>)}</ul></div>
				<Switch label={t("links.privateRules")} hint={t("links.privateHint")} checked={allowPrivate} onChange={setAllowPrivate}/>
				<NumberField label={t("links.flows")} hint={t("links.flowsHint")} unit={t("links.unitFlows")} min={1} max={65536} value={flows} onChange={setFlows} optional/>
				<div className="p-pair">
					<NumberField label={t("form.quota")} hint={t("form.quotaHint")} unit={t("unit.gb")} min={0} step="any" value={quota} onChange={setQuota} optional/>
					<SelectField label={t("form.period")} value={quota === "" ? "none" : period} onChange={setPeriod} disabled={quota === ""} options={(["none", "daily", "weekly", "monthly"] as const).map(p => ({value: p, label: t(`form.period.${p}`)}))}/>
				</div>
			</>}
			<div className="p-pair">
				<DayField label={t("form.expiry")} hint={t("links.expiryHint")} value={day} onChange={setDay} optional/>
				<NumberField label={t("links.mtu")} hint={t("links.mtuHint")} unit={t("links.unitBytes")} min={1280} max={1500} value={mtu} onChange={setMtu} optional/>
			</div>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t("config.review")}</Button></div>
		</form>
	</Dialog>;
}

// Step 1 on the node that offers: the terms the other node will see, made into a code that holds no secret.
function OfferFlow({onCompare, onClose, fixed}: {onCompare: (pairing: Compare) => void, onClose: () => void, fixed?: string}) {
	const {t, time} = useP(), guard = useGuard(), running = useLoad(loadRunning, []), derived = useLoad(() => api("get", "/profiles/derived") as Promise<{templates: Template[]}>, []), nodeInbounds = useLoad(() => api("get", "/links/inbounds") as Promise<{inbounds: {tag: string, public_key: string, transport_public_key: string | null}[]}>, []);
	const inbounds = ((running.data?.document.inbounds ?? []) as {tag: string, type: string}[]).filter(inbound => inbound.type === "veilway").map(inbound => inbound.tag);
	const [inbound, setInbound] = useState(""), [tag, setTag] = useState(""), [name, setName] = useState(""), [direction, setDirection] = useState(fixed ?? "forward"), [key, setKey] = useState(""), [transportKey, setTransportKey] = useState(""), [dialler, setDialler] = useState(""), [listener, setListener] = useState(""), [transports, setTransports] = useState(""), [minutes, setMinutes] = useState<number | "">(10);
	const [made, setMade] = useState<{id: string, code: string, expires_at: number} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const reportedOf = (tagOf: string) => nodeInbounds.data?.inbounds.find(found => found.tag === tagOf);
	const pick = (tagOf: string) => { const profile = derived.data?.templates.find(template => template.inbound === tagOf)?.profile, reported = reportedOf(tagOf); setInbound(tagOf); setKey(reported?.public_key ?? ""); setTransportKey(reported?.transport_public_key ?? ""); if (profile) { setTransports(JSON.stringify(profile.transports ?? [], null, 2)); } };
	const offer = async () => {
		setError(null);
		let parsed: unknown;
		try { parsed = JSON.parse(transports || "[]"); } catch (failure) { return setError(new Error(t("error.json", {message: (failure as Error).message}))); }
		setBusy(true);
		try {
			setMade(await guard(() => api("post", "/links/offers", {body: {tag: tag.trim(), inbound, direction, name: name.trim(), inbound_public_key: key.trim(), transport_public_key: transportKey.trim() || null, dialler: lines(dialler), listener: direction === "reverse" ? lines(listener) : [], transports: parsed, lifetime: minutes === "" ? null : minutes * 60}})) as typeof made);
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	if (made) return <Glass className="p-panel p-form">
		<h2 className="vw-h2">{t("links.offerMade")}</h2>
		<p className="vw-muted">{t("links.offerMadeBody", {time: time(new Date(made.expires_at * 1000))})}</p>
		<Copyable label={t("links.offerCode")} value={made.code} multiline/>
		<AnswerStep id={made.id} onCompare={onCompare} onClose={onClose} inline/>
	</Glass>;
	return <Glass className="p-panel p-form">
		<form className="p-stack" onSubmit={event => { event.preventDefault(); void offer(); }} noValidate>
			<div><h2 className="vw-h2">{t("links.offer")}</h2><p className="vw-muted">{t("links.offerLead")}</p></div>
			{running.data && !inbounds.length ? <Banner tone="warning" title={t("links.noInbound")}>{t("links.noInboundBody")}</Banner> : <SelectField label={t("links.inbound")} hint={t("links.inboundHint")} value={inbound} onChange={pick} options={inbounds.map(tagOf => ({value: tagOf, label: tagOf}))}/>}
			{!fixed && <RadioGroup label={t("links.direction")} value={direction} onChange={setDirection} options={[{value: "forward", label: t("links.forward"), detail: t("links.forwardDetail")}, {value: "reverse", label: t("links.reverse"), detail: t("links.reverseDetail")}]}/>}
			<div className="p-pair">
				<TextField label={t("links.tag")} hint={t("links.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} technical required/>
				<TextField label={t("links.name")} hint={t("links.nameHint")} value={name} onChange={setName} maxLength={64} required/>
			</div>
			<TextField label={t("profiles.inboundKey")} hint={t("profiles.inboundKeyHint")} value={key} onChange={setKey} readOnly={Boolean(reportedOf(inbound)?.public_key)} technical required/>
			<TextField label={t("links.transportKey")} hint={t("links.transportKeyHint")} value={transportKey} onChange={setTransportKey} readOnly={Boolean(reportedOf(inbound)?.transport_public_key)} technical optional/>
			<LinesField label={t("links.dialler")} hint={t("links.diallerHint")} value={dialler} onChange={setDialler} rows={2}/>
			{direction === "reverse" && <LinesField label={t("links.listener")} hint={t("links.listenerHint")} value={listener} onChange={setListener} rows={2}/>}
			<Field label={t("links.transports")} hint={t("links.transportsHint")}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={6} value={transports} onChange={event => setTransports(event.target.value)}/>}</Field>
			<NumberField label={t("links.lifetime")} unit={t("subs.minutesUnit")} min={1} max={60} value={minutes} onChange={setMinutes}/>
			<ErrorNote error={error}/>
			<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !inbound}>{t("links.makeOffer")}</Button><Button variant="quiet" onClick={onClose}>{t("action.cancel")}</Button></div>
		</form>
	</Glass>;
}

// Step 3 on the node that offered: the other node's answer, which turns the offer into a pairing that waits for the fingerprints.
function AnswerStep({id, onCompare, onClose, inline}: {id: string, onCompare: (pairing: Compare) => void, onClose: () => void, inline?: boolean}) {
	const {t} = useP(), guard = useGuard(), [code, setCode] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const take = () => { setBusy(true); setError(null); void guard(() => api("post", "/links/offers/answer", {body: {code: code.trim()}})).then(answer => { const a = answer as {id: string, fingerprint: string}; onCompare({id: a.id || id, fingerprint: a.fingerprint, name: ""}); }, setError).finally(() => setBusy(false)); };
	const body = <form className="p-stack" onSubmit={event => { event.preventDefault(); take(); }}>
		<div><h3 className="vw-h3">{t("links.answerTitle")}</h3><p className="vw-muted">{t("links.answerLead")}</p></div>
		<Field label={t("links.answerCode")}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={4} value={code} onChange={event => setCode(event.target.value)}/>}</Field>
		<ErrorNote error={error}/>
		<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !code.trim()}>{t("links.takeAnswer")}</Button><Button variant="quiet" onClick={onClose}>{inline ? t("links.later") : t("action.cancel")}</Button></div>
	</form>;
	return inline ? body : <Glass className="p-panel p-form">{body}</Glass>;
}

// Step 2 on the node that was offered a link: first what it would dial, then the answer code once the operator agreed.
function PasteFlow({onCompare, onClose, half}: {onCompare: (pairing: Compare) => void, onClose: () => void, half?: Side}) {
	const {t, date} = useP(), guard = useGuard(), [code, setCode] = useState(""), [seen, setSeen] = useState<Pasted | null>(null), [tag, setTag] = useState(""), [accept, setAccept] = useState(false);
	const [answer, setAnswer] = useState<{id: string, answer: string, fingerprint: string} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const read = () => { setBusy(true); setError(null); void api("post", "/links/paste", {body: {code: code.trim()}}).then(found => setSeen(found as Pasted), setError).finally(() => setBusy(false)); };
	const reply = () => { setBusy(true); setError(null); void guard(() => api("post", "/links/paste/answer", {body: {code: code.trim(), tag: tag.trim(), accept}})).then(found => setAnswer(found as typeof answer), setError).finally(() => setBusy(false)); };
	if (answer) return <Glass className="p-panel p-form">
		<h2 className="vw-h2">{t("links.answerMade")}</h2>
		<Banner tone="warning" title={t("links.answerOnce")}/>
		<Copyable label={t("links.answerCode")} value={answer.answer} multiline/>
		<p className="vw-muted">{t("links.answerNext")}</p>
		<div><Button variant="primary" onClick={() => onCompare({id: answer.id, fingerprint: answer.fingerprint, name: seen?.name ?? ""})}>{t("links.compare")}</Button></div>
	</Glass>;
	return <Glass className="p-panel p-form">
		{!seen ? <form className="p-stack" onSubmit={event => { event.preventDefault(); read(); }}>
			<div><h2 className="vw-h2">{t("links.paste")}</h2><p className="vw-muted">{t("links.pasteLead")}</p></div>
			<Field label={t("links.offerCode")}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={4} value={code} onChange={event => setCode(event.target.value)} autoFocus/>}</Field>
			<ErrorNote error={error}/>
			<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !code.trim()}>{t("links.readOffer")}</Button><Button variant="quiet" onClick={onClose}>{t("action.cancel")}</Button></div>
		</form> : <form className="p-stack" onSubmit={event => { event.preventDefault(); reply(); }}>
			<div><h2 className="vw-h2">{t("links.offerFrom", {name: seen.name})}</h2><p className="vw-muted">{t(seen.half === "exit" ? "links.youExit" : "links.youEntry")} {t("links.expires", {date: date(new Date(seen.expires_at * 1000), {dateStyle: "medium", timeStyle: "short"})})}</p></div>
			{seen.expired && <Banner tone="danger" title={t("links.expired")}>{t("links.expiredBody")}</Banner>}
			{seen.overlaps_pool && <Banner tone="danger" title={t("links.overlap")}>{t("links.overlapBody")}</Banner>}
			{half && seen.half !== half && <Banner tone="danger" title={t("preset.wrongWay")}>{t(half === "entry" ? "preset.wrongWayEntry" : "preset.wrongWayExit")}</Banner>}
			<div className="p-stack">
				<span className="vw-label">{t("links.dials")}</span>
				<ul className="p-transports">{seen.dials.map(d => <li key={d.address}><span className="vw-code">{d.address}</span>{d.private && <Mark tone="warning">{t("links.private")}</Mark>}</li>)}</ul>
				<p className="vw-muted vw-small">{t("links.dialsBody", {types: seen.transports.map(tr => tr.type).join(", ")})}</p>
			</div>
			{seen.ws_warning && <Banner tone="info" title={t("links.wsWarning")}>{t("links.wsWarningBody")}</Banner>}
			<TextField label={t("links.tag")} hint={t("links.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} technical required/>
			<Checkbox label={t("links.accept")} checked={accept} onChange={setAccept}/>
			<ErrorNote error={error}/>
			<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !accept || !tag.trim() || seen.expired || seen.overlaps_pool || (half !== undefined && seen.half !== half)}>{t("links.answer")}</Button><Button variant="quiet" onClick={onClose}>{t("action.cancel")}</Button></div>
		</form>}
	</Glass>;
}

// The last step on both nodes. Each operator reads their own eight groups aloud and types the other side's: a code changed on its way gives two fingerprints that do not match. The groups are hexadecimal and read left to right in both languages.
function Fingerprints({pairing, onClose}: {pairing: Compare, onClose: (tag?: string) => void}) {
	const {t, number} = useP(), guard = useGuard(), toast = useToast(), say = useSay(), mine = pairing.fingerprint.split(" "), [typed, setTyped] = useState<string[]>(Array(8).fill("")), boxes = useRef<(HTMLInputElement | null)[]>([]);
	const [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const full = typed.every(group => /^[0-9a-f]{4}$/.test(group)), own = full && typed.join(" ") === pairing.fingerprint;
	const put = (at: number, raw: string) => {
		const clean = raw.toLowerCase().replace(/[^0-9a-f]/g, "");
		// A whole fingerprint pasted into any box fills all eight.
		if (clean.length > 4) { const groups = clean.slice(0, 32).match(/.{1,4}/g) ?? []; setTyped(Array.from({length: 8}, (_, i) => groups[i] ?? "")); boxes.current[Math.min(7, groups.length)]?.focus(); return; }
		setTyped(typed.map((group, i) => i === at ? clean : group));
		if (clean.length === 4 && at < 7) boxes.current[at + 1]?.focus();
	};
	const confirm = async () => {
		setBusy(true);
		setError(null);
		try {
			const running = await loadRunning(), done = await guard(() => api("post", "/links/pairings/{id}/confirm", {params: {id: pairing.id}, body: {typed: typed.join(" "), revision: running.revision}})) as {tag: string};
			toast({tone: "success", title: t("links.paired", {tag: done.tag})});
			onClose(done.tag);
		} catch (failure) {
			setError(failure);
			if (failure instanceof ApiError && failure.code === "fingerprint_mismatch") setTyped(Array(8).fill(""));
		} finally {
			setBusy(false);
		}
	};
	const gone = error instanceof ApiError && (error.status === 404 || error.status === 410);
	return <div className="p-stack">
		<div className="p-row"><div><h2 className="vw-h2">{t("print.title")}</h2><p className="vw-muted p-lead">{t("print.lead")}</p></div><Button variant="quiet" onClick={() => onClose()}>{t("print.later")}</Button></div>
		<div className="p-columns">
			<Glass className="p-panel">
				<div><h3 className="vw-h3">{t("print.read")}</h3><p className="vw-muted vw-small">{t("print.readBody")}</p></div>
				<ol className="p-print" dir="ltr" aria-label={t("print.read")}>{mine.map((group, i) => <li key={i}><span className="p-print-n" aria-hidden="true">{number(i + 1)}</span><span className="p-print-g">{group}</span></li>)}</ol>
			</Glass>
			<Glass className="p-panel">
				<div><h3 className="vw-h3">{t("print.type")}</h3><p className="vw-muted vw-small">{t("print.typeBody")}</p></div>
				<form className="p-stack" onSubmit={event => { event.preventDefault(); if (full && !own) void confirm(); }}>
					<ol className="p-print" dir="ltr">{typed.map((group, i) => <li key={i}><label className="p-print-n" htmlFor={"print-" + i}><span className="vw-sr">{t("print.group", {number: i + 1})}</span><span aria-hidden="true">{number(i + 1)}</span></label><input id={"print-" + i} ref={box => { boxes.current[i] = box; }} className="vw-input p-print-g p-print-in" value={group} onChange={event => put(i, event.target.value)} onKeyDown={event => { if (event.key === "Backspace" && !group && i > 0) boxes.current[i - 1]?.focus(); }} maxLength={39} autoComplete="off" autoCapitalize="off" spellCheck={false} inputMode="text" aria-invalid={group.length === 4 && !/^[0-9a-f]{4}$/.test(group) ? true : undefined}/></li>)}</ol>
					{own && <Banner tone="warning" title={t("print.own")}>{t("print.ownBody")}</Banner>}
					{error !== null && <Banner tone="danger" title={error instanceof ApiError && error.code === "fingerprint_mismatch" ? t("print.mismatch") : gone ? t("print.gone") : say(error)}>{error instanceof ApiError && error.code === "fingerprint_mismatch" ? t("print.mismatchBody") : gone ? t("print.goneBody") : undefined}</Banner>}
					<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !full || own || gone}>{t("print.confirm")}</Button>{typed.some(Boolean) && <Button variant="quiet" onClick={() => { setTyped(Array(8).fill("")); boxes.current[0]?.focus(); }}>{t("print.clear")}</Button>}</div>
				</form>
			</Glass>
		</div>
		<p className="vw-muted vw-small">{t("print.channel")}</p>
	</div>;
}

// Who connects where, drawn for the side this panel is on. The arrow on the link runs from the node that dials to the node that waits.
function Route({side, direction}: {side: Side | null, direction: string}) {
	const {t} = useP(), stop = (name: string, role: string, here: boolean) => <div className="p-route-stop" data-here={here || undefined}><strong>{name}</strong><span>{role}</span></div>;
	return <figure className="p-route" data-dial={direction === "forward" ? "out" : "back"}>
		{stop(t("preset.route.users"), t("preset.route.usersRole"), false)}
		<span className="p-route-line" aria-hidden="true"/>
		{stop(side === "entry" ? t("preset.route.here") : t("preset.route.entry"), t("preset.route.entryRole"), side === "entry")}
		<figcaption className="p-route-link"><span className="p-route-say">{t(direction === "forward" ? "preset.route.forward" : "preset.route.reverse")}</span><span className="p-route-arrow" aria-hidden="true"/></figcaption>
		{stop(side === "exit" ? t("preset.route.here") : t("preset.route.exit"), t("preset.route.exitRole"), side === "exit")}
		<span className="p-route-line" aria-hidden="true"/>
		{stop(t("preset.route.internet"), t("preset.route.internetRole"), false)}
	</figure>;
}

// A guided pairing for one side of a link: what it does, which way it dials, the pairing steps above, then what the link is for on this node.
function Preset({start, onClose}: {start: {side: Side | null, direction: string}, onClose: () => void}) {
	const {t, number} = useP(), running = useRunning(), [side, setSide] = useState<Side | null>(start.side), [direction, setDirection] = useState(start.direction), [step, setStep] = useState(0), [pairing, setPairing] = useState<Compare | null>(null), [tag, setTag] = useState(""), [done, setDone] = useState<string[]>([]);
	// The node with the Veilway inbound makes the offer: the exit of a forward link, the entry of a reverse one.
	const offers = (side === "exit") === (direction === "forward"), other = side === "entry" ? "preset.exit" : "preset.entry";
	const names = [t("preset.step.intro"), t("preset.step.direction"), t("preset.step.pair"), t("preset.step.compare"), t(side === "exit" ? "preset.step.exitUse" : "preset.step.entryUse")];
	const toCompare = (next: Compare) => { setPairing(next); setStep(3); };
	const finish = (changes: string[]) => { setDone(changes); setStep(5); running.reload(); };
	return <div className="p-stack">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t(side === null ? "preset.reverse" : side === "entry" ? "preset.entry" : "preset.exit")}</h2></div><Button variant="quiet" onClick={onClose}>{t(step === 5 ? "preset.back" : "preset.leave")}</Button></div>
		<ol className="p-steps" aria-label={t("preset.steps")}>{names.map((name, i) => <li key={i} data-state={i < step ? "done" : i === step ? "now" : undefined} aria-current={i === step ? "step" : undefined}><span className="p-steps-n">{i < step ? <Icon name="check"/> : number(i + 1)}</span><span>{name}</span></li>)}</ol>
		{step === 0 && <Glass className="p-panel p-form">
			<div><h3 className="vw-h3">{t(start.side === null ? "preset.introReverse" : side === "entry" ? "preset.introEntry" : "preset.introExit")}</h3><p className="vw-muted">{t(start.side === null ? "preset.introReverseBody" : side === "entry" ? "preset.introEntryBody" : "preset.introExitBody")}</p></div>
			<Route side={side} direction={direction}/>
			{start.side === null && <RadioGroup label={t("preset.which")} value={side ?? ""} onChange={value => setSide(value as Side)} options={[{value: "entry", label: t("preset.whichEntry"), detail: t("preset.whichEntryDetail")}, {value: "exit", label: t("preset.whichExit"), detail: t("preset.whichExitDetail")}]}/>}
			{start.side !== null && <p className="vw-muted vw-small">{t("preset.needOther")}</p>}
			<div className="p-cluster"><Button variant="primary" disabled={side === null} onClick={() => setStep(1)}>{t("preset.next")}</Button></div>
		</Glass>}
		{step === 1 && side !== null && <Glass className="p-panel p-form">
			<div><h3 className="vw-h3">{t("preset.directionTitle")}</h3><p className="vw-muted">{t("preset.directionLead")}</p></div>
			<RadioGroup label={t("preset.step.direction")} value={direction} onChange={setDirection} options={[{value: "forward", label: t("preset.forward"), detail: t(side === "entry" ? "preset.forwardEntry" : "preset.forwardExit")}, {value: "reverse", label: t("preset.reverseWay"), detail: t(side === "entry" ? "preset.reverseEntry" : "preset.reverseExit")}]}/>
			<Route side={side} direction={direction}/>
			<p className="vw-muted vw-small">{t(offers ? "preset.youOffer" : "preset.youPaste", {other: t(other), direction: t(direction === "forward" ? "preset.forward" : "preset.reverseWay")})}</p>
			<div className="p-cluster"><Button variant="primary" onClick={() => setStep(2)}>{t("preset.next")}</Button><Button variant="quiet" onClick={() => setStep(0)}>{t("preset.previous")}</Button></div>
		</Glass>}
		{step === 2 && (offers ? <OfferFlow fixed={direction} onCompare={toCompare} onClose={() => setStep(1)}/> : <PasteFlow half={side ?? undefined} onCompare={toCompare} onClose={() => setStep(1)}/>)}
		{step === 3 && pairing && <Fingerprints pairing={pairing} onClose={found => { if (!found) return onClose(); setTag(found); running.reload(); setStep(4); }}/>}
		{step === 4 && (running.error && !running.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={running.reload}>{t("action.retry")}</Button>}/> : !running.data || running.loading ? <StateBlock kind="loading" title={t("preset.reading")}/> : side === "exit" ? <ExitUse link={tag} running={running.data} onReload={running.reload} onApplied={finish} onSkip={onClose}/> : <EntryUse link={tag} running={running.data} onReload={running.reload} onApplied={finish} onSkip={onClose}/>)}
		{step === 5 && <Glass className="p-panel p-form">
			<div><h3 className="vw-h3">{t("preset.doneTitle")}</h3><p className="vw-muted">{t("preset.doneLead", {link: tag})}</p></div>
			<ul className="p-changes">{done.map(line => <li key={line}><Icon name="check"/><span>{line}</span></li>)}</ul>
			<p>{t(side === "exit" ? "preset.checkExit" : "preset.checkEntry")}</p>
			{side === "entry" && <p className="vw-muted vw-small">{t("preset.noPublish")}</p>}
			<div className="p-cluster"><Button variant="primary" onClick={onClose}>{t("preset.back")}</Button></div>
		</Glass>}
	</div>;
}

const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/;

// The last step on the entry: an exit that leaves through the new link, whether it becomes the default, and whether every user may pick it. The config changes in one apply, then the users.
function EntryUse({link, running, onReload, onApplied, onSkip}: {link: string, running: Running, onReload: () => void, onApplied: (changes: string[]) => void, onSkip: () => void}) {
	const {t} = useP(), users = useLoad(() => api("get", "/users") as Promise<{users: User[]}>, []), exits = (running.document.exits ?? []) as {tag: string}[], routing = (running.document.routing ?? {}) as {default?: string};
	const [tag, setTag] = useState(exits.some(exit => exit.tag === link) ? "" : link), [name, setName] = useState(""), [country, setCountry] = useState(""), [main, setMain] = useState(true), [everyone, setEveryone] = useState(true), [review, setReview] = useState<string[] | null>(null), [busy, setBusy] = useState(false);
	const clean = tag.trim(), taken = exits.some(exit => exit.tag === clean), listed = (users.data?.users ?? []).filter(user => Array.isArray(user.exits) && !(user.exits as string[]).includes(clean)), adds = everyone && listed.length > 0;
	const ready = TAG.test(clean) && !taken && name.trim().length > 0 && (country === "" || /^[A-Z]{2}$/.test(country)) && users.data !== null;
	const whole = {...running.document, exits: [...exits, {tag: clean, name: name.trim(), ...(country ? {country} : {}), backend: {type: "chain", links: [link]}}], ...(main ? {routing: {...routing, default: clean}} : {})};
	const changes = [t("preset.change.exit", {tag: clean, name: name.trim(), link}), ...(main ? [t(routing.default ? "preset.change.default" : "preset.change.defaultNew", {tag: clean, was: routing.default ?? ""})] : []), ...(adds ? [t("preset.change.users", {tag: clean, count: listed.length})] : [])];
	const applied = async (fresh: boolean) => {
		setReview(null);
		if (!fresh) return onReload();
		setBusy(true);
		// The exit exists on the node now, so a user's list may name it.
		const results = adds ? await Promise.allSettled(listed.map(user => api("patch", "/users/{id}", {params: {id: user.id}, body: {exits: [...user.exits as string[], clean]} as UserPatch}))) : [], failed = results.filter(result => result.status === "rejected").length;
		setBusy(false);
		onApplied(failed ? [...changes.slice(0, -1), t("preset.change.usersFailed", {count: failed, total: listed.length})] : changes);
	};
	return <Glass className="p-panel p-form">
		<form className="p-stack" onSubmit={event => { event.preventDefault(); if (ready) setReview(changes); }} noValidate>
			<div><h3 className="vw-h3">{t("preset.useTitle")}</h3><p className="vw-muted">{t("preset.useLead", {link})}</p></div>
			<div className="p-pair">
				<TextField label={t("preset.exitName")} hint={t("preset.exitNameHint")} value={name} onChange={setName} maxLength={64} required/>
				<TextField label={t("config.country")} hint={t("config.countryHint")} value={country} onChange={value => setCountry(value.toUpperCase())} maxLength={2} error={country && !/^[A-Z]{2}$/.test(country) ? t("preset.countryBad") : undefined} technical optional/>
			</div>
			<TextField label={t("preset.exitTag")} hint={t("preset.exitTagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} error={taken ? t("preset.exitTaken") : clean && !TAG.test(clean) ? t("preset.exitTagBad") : undefined} technical required/>
			<Switch label={t("preset.makeDefault")} hint={routing.default ? t("preset.makeDefaultHint", {was: routing.default}) : t("preset.makeDefaultNone")} checked={main} onChange={setMain}/>
			<Switch label={t("preset.addUsers")} hint={users.data ? listed.length ? t("preset.addUsersHint", {count: listed.length}) : t("preset.addUsersNone") : t("preset.addUsersLoading")} checked={adds} disabled={!listed.length} onChange={setEveryone}/>
			{users.error !== null && <Banner tone="danger" title={t("preset.usersFailed")} action={<Button size="sm" icon="refresh" onClick={users.reload}>{t("action.retry")}</Button>}/>}
			<div className="p-cluster"><Button type="submit" variant="primary" disabled={!ready || busy}>{t("config.review")}</Button><Button variant="quiet" onClick={onSkip}>{t("preset.skip")}</Button></div>
		</form>
		{review && <SectionReview section="document" running={running} value={whole} summary={<ul className="p-changes">{review.map(line => <li key={line}><span>{line}</span></li>)}</ul>} onClose={() => setReview(null)} onDone={fresh => void applied(fresh)}/>}
	</Glass>;
}

// The last step on the exit: which of this node's exits the link's traffic may leave through. Private networks stay closed unless the operator opens them on purpose.
function ExitUse({link, running, onReload, onApplied, onSkip}: {link: string, running: Running, onReload: () => void, onApplied: (changes: string[]) => void, onSkip: () => void}) {
	const {t} = useP(), configured = (running.document.links ?? []) as LinkConfig[], found = configured.find(held => held.tag === link), exits = ((running.document.exits ?? []) as {tag: string, name?: string, backend?: {type?: string}}[]).filter(exit => exit.backend?.type !== "chain");
	const [allowed, setAllowed] = useState(found?.exits ?? []), [open, setOpen] = useState(found?.allow_private ?? false), [review, setReview] = useState(false);
	if (!found) return <StateBlock kind="error" title={t("preset.linkMissing")} action={<Button icon="refresh" onClick={onReload}>{t("action.retry")}</Button>}>{t("preset.linkMissingBody", {link})}</StateBlock>;
	const made: LinkConfig = {...found, exits: allowed, allow_private: open};
	if (!allowed.length) delete made.exits;
	if (!open) delete made.allow_private;
	const changes = [allowed.length ? t("preset.change.exits", {link, exits: allowed.join(", ")}) : t("preset.change.exitsRules", {link}), t(open ? "preset.change.private" : "preset.change.noPrivate")];
	return <Glass className="p-panel p-form">
		<form className="p-stack" onSubmit={event => { event.preventDefault(); setReview(true); }} noValidate>
			<div><h3 className="vw-h3">{t("preset.allowTitle")}</h3><p className="vw-muted">{t("preset.allowLead", {link})}</p></div>
			<div className="vw-field"><span className="vw-label">{t("links.exits")}</span><p className="vw-note">{t("preset.exitsHint")}</p><ul className="p-row-list p-exit-list">{exits.map(exit => <li key={exit.tag}><label className="p-exit"><input type="checkbox" className="p-check" checked={allowed.includes(exit.tag)} onChange={event => setAllowed(event.target.checked ? [...allowed, exit.tag] : allowed.filter(held => held !== exit.tag))}/><span className="p-row-text"><strong className="vw-code">{exit.tag}</strong>{exit.name && <span>{exit.name}</span>}</span><span/></label></li>)}</ul></div>
			<Switch label={t("links.privateRules")} hint={t("links.privateHint")} checked={open} onChange={setOpen}/>
			{open && <Banner tone="warning" title={t("preset.privateWarn")}>{t("preset.privateWarnBody")}</Banner>}
			<div className="p-cluster"><Button type="submit" variant="primary">{t("config.review")}</Button><Button variant="quiet" onClick={onSkip}>{t("preset.skip")}</Button></div>
		</form>
		{review && <SectionReview section="links" running={running} value={configured.map(held => held.tag === link ? made : held)} summary={<ul className="p-changes">{changes.map(line => <li key={line}><span>{line}</span></li>)}</ul>} onClose={() => setReview(false)} onDone={fresh => { setReview(false); if (fresh) onApplied(changes); else onReload(); }}/>}
	</Glass>;
}
