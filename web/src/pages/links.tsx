import {Banner, Button, Checkbox, DataTable, Field, Glass, IconButton, List, ListRow, NumberField, RadioGroup, SelectField, StateBlock, TextField, useToast} from "@veilway/ui";
import {useRef, useState} from "react";
import {api, ApiError, type NodeLink, type Pairings, type Pasted, type Template} from "../api.ts";
import {ago, Copyable, ErrorNote, lines, LinesField, Mark, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {loadRunning} from "./config.tsx";

type Compare = {id: string, fingerprint: string, name: string};
const STATE_TONE: Record<string, "success" | "info" | "warning" | "danger" | undefined> = {up: "success", connecting: "info", unreachable: "warning", refused: "danger"};

export function LinksTab() {
	const {t, bytes, time} = useP(), say = useSay(), toast = useToast(), links = useLoad(() => api("get", "/links") as Promise<{links: NodeLink[] | null}>, []), pairings = useLoad(() => api("get", "/links/pairings") as Promise<Pairings>, []);
	const [flow, setFlow] = useState<"offer" | "paste" | null>(null), [compare, setCompare] = useState<Compare | null>(null), [answering, setAnswering] = useState<string | null>(null);
	const refresh = () => { links.reload(); pairings.reload(); };
	const toCompare = (next: Compare) => { setFlow(null); setAnswering(null); setCompare(next); pairings.reload(); };
	const drop = (id: string) => void api("delete", "/links/pairings/{id}", {params: {id}}).then(() => { toast({tone: "success", title: t("links.dropped")}); pairings.reload(); }, failure => toast({tone: "danger", title: say(failure)}));
	const waiting = pairings.data ? pairings.data.offers.length + pairings.data.answered.length : 0;
	if (compare) return <Fingerprints pairing={compare} onClose={() => { setCompare(null); refresh(); }}/>;
	return <div className="p-stack">
		<div className="p-row"><p className="vw-muted p-lead">{t("links.lead")}</p><div className="p-cluster"><Button variant={flow === "offer" ? "primary" : "secondary"} icon="plus" onClick={() => setFlow(flow === "offer" ? null : "offer")}>{t("links.offer")}</Button><Button variant={flow === "paste" ? "primary" : "secondary"} onClick={() => setFlow(flow === "paste" ? null : "paste")}>{t("links.paste")}</Button></div></div>
		{flow === "offer" && <OfferFlow onCompare={toCompare} onClose={() => { setFlow(null); pairings.reload(); }}/>}
		{flow === "paste" && <PasteFlow onCompare={toCompare} onClose={() => setFlow(null)}/>}
		{answering && <AnswerStep id={answering} onCompare={toCompare} onClose={() => setAnswering(null)}/>}
		{pairings.data && waiting > 0 && <Glass className="p-panel">
			<h2 className="vw-h3">{t("links.waiting")}</h2>
			<List label={t("links.waiting")}>
				{pairings.data.answered.map(p => <ListRow key={p.id} title={p.name} detail={t("links.answeredDetail", {time: time(new Date(p.expires_at * 1000)), tries: 5 - p.tries})} trailing={<><Button size="sm" variant="primary" onClick={() => toCompare({id: p.id, fingerprint: p.fingerprint, name: p.name})}>{t("links.compare")}</Button><IconButton icon="close" label={t("links.drop", {name: p.name})} onClick={() => drop(p.id)}/></>}/>)}
				{pairings.data.offers.map(p => <ListRow key={p.id} title={p.name} detail={t("links.offerDetail", {time: time(new Date(p.expires_at * 1000))})} trailing={<><Button size="sm" onClick={() => setAnswering(p.id)}>{t("links.pasteAnswer")}</Button><IconButton icon="close" label={t("links.drop", {name: p.name})} onClick={() => drop(p.id)}/></>}/>)}
			</List>
		</Glass>}
		{links.error && !links.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={links.reload}>{t("action.retry")}</Button>}>{say(links.error)}</StateBlock>
		: !links.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <Glass className="p-pad"><DataTable caption={t("node.tab.links")} rows={links.data.links ?? []} rowKey={l => l.id} empty={<StateBlock kind="empty" title={t("links.empty")} action={<Button variant="primary" icon="plus" onClick={() => setFlow("offer")}>{t("links.offer")}</Button>}>{t("links.emptyBody")}</StateBlock>} columns={[
			{id: "tag", header: t("config.col.tag"), cell: l => <span className="p-user"><span className="vw-code">{l.tag}</span><span className="vw-muted vw-small">{t(l.half === "exit" ? "links.half.exit" : "links.half.entry")}</span></span>},
			{id: "state", header: t("links.col.state"), cell: l => { const since = ago(l.state_secs); return <span className="p-user"><Mark tone={STATE_TONE[l.state]}>{["up", "connecting", "unreachable", "refused", "ended"].includes(l.state) ? t(`links.state.${l.state as "up"}`) : l.state}</Mark><span className="vw-muted vw-small">{t("links.since", {time: t(since.key, {count: since.count})})}</span></span>; }},
			{id: "traffic", header: t("links.col.traffic"), align: "end", cell: l => <span className="vw-num">{bytes(l.traffic.up_bytes + l.traffic.down_bytes).text}</span>}
		]}/></Glass>}
	</div>;
}

// Step 1 on the node that offers: the terms the other node will see, made into a code that holds no secret.
function OfferFlow({onCompare, onClose}: {onCompare: (pairing: Compare) => void, onClose: () => void}) {
	const {t, time} = useP(), guard = useGuard(), running = useLoad(loadRunning, []), derived = useLoad(() => api("get", "/profiles/derived") as Promise<{templates: Template[]}>, []), nodeInbounds = useLoad(() => api("get", "/links/inbounds") as Promise<{inbounds: {tag: string, public_key: string, transport_public_key: string | null}[]}>, []);
	const inbounds = ((running.data?.document.inbounds ?? []) as {tag: string, type: string}[]).filter(inbound => inbound.type === "veilway").map(inbound => inbound.tag);
	const [inbound, setInbound] = useState(""), [tag, setTag] = useState(""), [name, setName] = useState(""), [direction, setDirection] = useState("forward"), [key, setKey] = useState(""), [transportKey, setTransportKey] = useState(""), [dialler, setDialler] = useState(""), [listener, setListener] = useState(""), [transports, setTransports] = useState(""), [minutes, setMinutes] = useState<number | "">(10);
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
			<RadioGroup label={t("links.direction")} value={direction} onChange={setDirection} options={[{value: "forward", label: t("links.forward"), detail: t("links.forwardDetail")}, {value: "reverse", label: t("links.reverse"), detail: t("links.reverseDetail")}]}/>
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
function PasteFlow({onCompare, onClose}: {onCompare: (pairing: Compare) => void, onClose: () => void}) {
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
			<div className="p-stack">
				<span className="vw-label">{t("links.dials")}</span>
				<ul className="p-transports">{seen.dials.map(d => <li key={d.address}><span className="vw-code">{d.address}</span>{d.private && <Mark tone="warning">{t("links.private")}</Mark>}</li>)}</ul>
				<p className="vw-muted vw-small">{t("links.dialsBody", {types: seen.transports.map(tr => tr.type).join(", ")})}</p>
			</div>
			{seen.ws_warning && <Banner tone="info" title={t("links.wsWarning")}>{t("links.wsWarningBody")}</Banner>}
			<TextField label={t("links.tag")} hint={t("links.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} technical required/>
			<Checkbox label={t("links.accept")} checked={accept} onChange={setAccept}/>
			<ErrorNote error={error}/>
			<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !accept || !tag.trim() || seen.expired || seen.overlaps_pool}>{t("links.answer")}</Button><Button variant="quiet" onClick={onClose}>{t("action.cancel")}</Button></div>
		</form>}
	</Glass>;
}

// The last step on both nodes. Each operator reads their own eight groups aloud and types the other side's: a code changed on its way gives two fingerprints that do not match. The groups are hexadecimal and read left to right in both languages.
function Fingerprints({pairing, onClose}: {pairing: Compare, onClose: () => void}) {
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
			onClose();
		} catch (failure) {
			setError(failure);
			if (failure instanceof ApiError && failure.code === "fingerprint_mismatch") setTyped(Array(8).fill(""));
		} finally {
			setBusy(false);
		}
	};
	const gone = error instanceof ApiError && (error.status === 404 || error.status === 410);
	return <div className="p-stack">
		<div className="p-row"><div><h2 className="vw-h2">{t("print.title")}</h2><p className="vw-muted p-lead">{t("print.lead")}</p></div><Button variant="quiet" onClick={onClose}>{t("print.later")}</Button></div>
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
