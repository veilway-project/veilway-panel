import {Banner, Button, Dialog, Glass, Icon, NumberField, RadioGroup, SelectField, Segmented, StateBlock, Switch, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type NodePatch, type NodeRow} from "../api.ts";
import {ago, ErrorNote, Mark, PageHead, useGuard, useP, useSay} from "../kit.tsx";
import {offline, useServers} from "../servers.tsx";
import {useRunning} from "./apply.tsx";
import {type Compare, Fingerprints, OfferFlow, PasteFlow} from "./links.tsx";

const STATE_TONE: Record<string, "success" | "warning" | "danger" | undefined> = {up: "success", connecting: "warning", unreachable: "danger", refused: "danger"};
const RATE = 1_000_000;

// Every server this panel controls, one card each. Server 1 is the one the panel runs next to; the others are reached through managed links.
export function ServersPage() {
	const {t, number} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), {nodes, reload} = useServers(), [adding, setAdding] = useState(false), [editing, setEditing] = useState<NodeRow | null>(null), [removing, setRemoving] = useState<NodeRow | null>(null), [busy, setBusy] = useState<number | null>(null);
	const span = (seconds: number) => { const found = ago(seconds); return t(found.key, {count: found.count}); }, now = Date.now() / 1000;
	const sync = (node: NodeRow) => { setBusy(node.id); void api("post", "/nodes/{id}/sync", {params: {id: node.id}}).then(answer => { toast(answer.synced ? {tone: "success", title: t("servers.synced", {name: node.name})} : {tone: "danger", title: t("servers.syncFailed", {name: node.name}), body: answer.error ?? undefined}); reload(); }, failure => toast({tone: "danger", title: say(failure)})).finally(() => setBusy(null)); };
	const count = (node: NodeRow, counted: boolean) => void guard(() => api("patch", "/nodes/{id}", {params: {id: node.id}, body: {counted} as NodePatch})).then(reload, failure => toast({tone: "danger", title: say(failure)}));
	if (adding) return <><PageHead title={t("nav.servers")}/><AddServer onClose={() => { setAdding(false); reload(); }}/></>;
	return <>
		<PageHead title={t("nav.servers")} lead={t("servers.lead")}>
			<Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t("servers.add")}</Button>
		</PageHead>
		{nodes.length === 0 && <StateBlock kind="loading" title={t("common.loading")}/>}
		<div className="p-columns p-node-cards">
			{nodes.map(node => <Glass key={node.id} className={node.id === 1 ? "p-node-card p-sheet-new" : "p-node-card"}>
				<div className="p-sheet-head"><div><strong className="vw-h3">{node.id === 1 ? t("servers.this") : node.name}</strong><span className="vw-small vw-muted">{node.id === 1 ? node.name : node.link ? t("servers.viaLink", {link: node.link}) : ""}</span></div>
					{node.id === 1 ? <Mark tone="success">{t("servers.state.up")}</Mark> : <Mark tone={STATE_TONE[node.link_state ?? ""] ?? "muted"}>{["up", "connecting", "unreachable", "refused", "ended"].includes(node.link_state ?? "") ? t(`links.state.${node.link_state as "up"}`) : t("servers.state.unknown")}</Mark>}
				</div>
				{offline(node) && node.down_since && <p className="vw-small vw-muted">{t("servers.downFor", {time: span(Math.max(0, now - node.down_since))})}</p>}
				<dl>
					<div><dt>{t("servers.pool")}</dt><dd className="vw-code" dir="ltr">{node.pool_v4}</dd></div>
					<div><dt>{t("servers.devices")}</dt><dd className="vw-num">{number(node.devices)}</dd></div>
					<div><dt>{t("servers.sync")}</dt><dd>{node.behind ? <Mark tone="warning">{t("servers.behind", {count: Math.max(1, node.wanted_rev - node.applied_rev)})}</Mark> : t("servers.inSync")}</dd></div>
					<div><dt>{t("servers.lastSync")}</dt><dd className="vw-num">{node.last_seen ? t("servers.ago", {time: span(Math.max(0, now - node.last_seen))}) : t("servers.never")}</dd></div>
					{node.version && <div><dt>{t("nodes.version")}</dt><dd className="vw-code">{node.version}</dd></div>}
				</dl>
				{node.last_error && <Banner tone="warning" title={t("servers.lastError")}>{node.last_error}</Banner>}
				<Switch label={t("servers.counted")} hint={t("servers.countedHint")} checked={node.counted} onChange={on => count(node, on)}/>
				<span className="p-cluster"><Button size="sm" variant="quiet" icon="refresh" disabled={busy === node.id} onClick={() => sync(node)}>{t("servers.syncNow")}</Button><Button size="sm" variant="quiet" onClick={() => setEditing(node)}>{t("user.edit")}</Button>{node.id !== 1 && <Button size="sm" variant="quiet" onClick={() => setRemoving(node)}>{t("common.remove")}</Button>}</span>
			</Glass>)}
		</div>
		{nodes.length === 1 && <Glass className="p-panel"><StateBlock kind="empty" title={t("servers.only")} action={<Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t("servers.add")}</Button>}>{t("servers.onlyBody")}</StateBlock></Glass>}
		{editing && <EditServer key={editing.id} node={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }}/>}
		{removing && <RemoveServer key={removing.id} node={removing} onClose={() => setRemoving(null)} onRemoved={() => { setRemoving(null); reload(); }}/>}
	</>;
}

// The pool changes only while no device holds an address in it, and never for server 1, whose pool is a panel setting.
function EditServer({node, onClose, onSaved}: {node: NodeRow, onClose: () => void, onSaved: () => void}) {
	const {t} = useP(), guard = useGuard(), toast = useToast(), [name, setName] = useState(node.name), [place, setPlace] = useState<number | "">(node.place), [pool, setPool] = useState(node.pool_v4), [rate, setRate] = useState<number | "">(node.max_rate ? node.max_rate / RATE : ""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const locked = node.id === 1 || node.devices > 0, save = async () => {
		setBusy(true);
		setError(null);
		try {
			await guard(() => api("patch", "/nodes/{id}", {params: {id: node.id}, body: {name: name.trim(), place: place === "" ? undefined : place, pool_v4: locked ? undefined : pool.trim(), max_rate: rate === "" ? null : Math.round(rate * RATE)} as NodePatch}));
			toast({tone: "success", title: t("servers.saved", {name: name.trim()})});
			onSaved();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("servers.editTitle", {name: node.name})}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); void save(); }} noValidate>
			<TextField label={t("servers.name")} hint={t("servers.nameHint")} value={name} onChange={setName} maxLength={32} required/>
			<NumberField label={t("servers.place")} hint={t("servers.placeHint")} unit={t("servers.unitPlace")} min={0} value={place} onChange={setPlace} optional/>
			<TextField label={t("servers.poolLabel")} hint={t(node.id === 1 ? "servers.poolHere" : locked ? "servers.poolLocked" : "servers.poolHint")} value={pool} onChange={setPool} disabled={locked} technical/>
			<NumberField label={t("servers.rate")} hint={t("servers.rateHint")} unit={t("servers.unitRate")} min={1} value={rate} onChange={setRate} optional/>
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy || !name.trim()}>{t("common.save")}</Button></div>
		</form>
	</Dialog>;
}

// Removing asks the server to empty itself and let go of the link. A server that is lost cannot be asked, so taken skips that and only forgets it.
function RemoveServer({node, onClose, onRemoved}: {node: NodeRow, onClose: () => void, onRemoved: () => void}) {
	const {t} = useP(), guard = useGuard(), toast = useToast(), [way, setWay] = useState(offline(node) ? "taken" : "normal"), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const remove = async () => {
		setBusy(true);
		setError(null);
		try {
			await guard(() => api("delete", "/nodes/{id}", {params: {id: node.id}, query: {taken: way === "taken" ? "true" : undefined}}));
			toast({tone: "success", title: t("servers.removed", {name: node.name})});
			onRemoved();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("servers.removeTitle", {name: node.name})} description={t("servers.removeLead")}>
		<div className="p-stack">
			<RadioGroup label={t("servers.removeWay")} value={way} onChange={setWay} options={[{value: "normal", label: t("servers.removeNormal"), detail: t("servers.removeNormalDetail")}, {value: "taken", label: t("servers.removeTaken"), detail: t("servers.removeTakenDetail")}]}/>
			{way === "normal" && offline(node) && <Banner tone="warning" title={t("servers.removeOffline")}>{t("servers.removeOfflineBody")}</Banner>}
			<p className="vw-muted vw-small">{t("servers.removeUsers", {count: node.devices})}</p>
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button variant="danger" disabled={busy} onClick={() => void remove()}>{t("servers.removeConfirm")}</Button></div>
		</div>
	</Dialog>;
}

// Three steps: a managed link between this panel's node and the other server, what to call the server and where its devices get addresses, then the first sync.
function AddServer({onClose}: {onClose: () => void}) {
	const {t, number} = useP(), guard = useGuard(), {nodes} = useServers(), running = useRunning(), [step, setStep] = useState(0), [way, setWay] = useState("offer"), [pairing, setPairing] = useState<Compare | null>(null), [tag, setTag] = useState(""), [spare, setSpare] = useState("");
	const [name, setName] = useState(""), [place, setPlace] = useState<number | "">(""), [pool, setPool] = useState(""), [added, setAdded] = useState<NodeRow | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const names = [t("servers.step.link"), t("servers.step.details"), t("servers.step.done")];
	// Links that node 1 manages and no server uses yet, for a pairing made on the command line.
	const free = ((running.data?.document.links ?? []) as {tag: string, manage?: string}[]).filter(link => link.manage === "peer" && !nodes.some(node => node.link === link.tag)).map(link => link.tag);
	const create = async () => {
		setBusy(true);
		setError(null);
		try {
			setAdded(await guard(() => api("post", "/nodes", {body: {name: name.trim(), link: tag, pool_v4: pool.trim(), place: place === "" ? null : place}})));
			setStep(2);
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <div className="p-stack">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t("servers.add")}</h2></div><Button variant="quiet" onClick={onClose}>{t(step === 2 ? "servers.back" : "servers.leave")}</Button></div>
		<ol className="p-steps" aria-label={t("preset.steps")}>{names.map((label, i) => <li key={i} data-state={i < step ? "done" : i === step ? "now" : undefined} aria-current={i === step ? "step" : undefined}><span className="p-steps-n">{i < step ? <Icon name="check"/> : number(i + 1)}</span><span>{label}</span></li>)}</ol>
		{step === 0 && !pairing && <>
			<Glass className="p-panel p-form">
				<div><h3 className="vw-h3">{t("servers.addTitle")}</h3><p className="vw-muted">{t("servers.addLead")}</p></div>
				<Banner tone="warning" title={t("servers.control")}>{t("servers.controlBody")}</Banner>
				<Segmented label={t("servers.way")} value={way} onChange={setWay} options={[{value: "offer", label: t("servers.wayOffer")}, {value: "paste", label: t("servers.wayPaste")}]}/>
				<p className="vw-muted vw-small">{t(way === "offer" ? "servers.wayOfferNote" : "servers.wayPasteNote")}</p>
			</Glass>
			{way === "offer" ? <OfferFlow managed onCompare={setPairing} onClose={onClose}/> : <PasteFlow onCompare={setPairing} onClose={onClose}/>}
			{free.length > 0 && <Glass className="p-panel p-form">
				<div><h3 className="vw-h3">{t("servers.spare")}</h3><p className="vw-muted">{t("servers.spareBody")}</p></div>
				<SelectField label={t("servers.spareLink")} value={spare} onChange={setSpare} options={[{value: "", label: t("servers.spareNone")}, ...free.map(link => ({value: link, label: link}))]}/>
				<div><Button variant="primary" disabled={!spare} onClick={() => { setTag(spare); setStep(1); }}>{t("preset.next")}</Button></div>
			</Glass>}
		</>}
		{step === 0 && pairing && <Fingerprints pairing={pairing} onClose={found => { if (!found) return onClose(); setTag(found); setStep(1); }}/>}
		{step === 1 && <Glass className="p-panel p-form">
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void create(); }} noValidate>
				<div><h3 className="vw-h3">{t("servers.detailsTitle")}</h3><p className="vw-muted">{t("servers.detailsLead", {link: tag})}</p></div>
				<div className="p-pair">
					<TextField label={t("servers.name")} hint={t("servers.nameHint")} value={name} onChange={setName} maxLength={32} required/>
					<NumberField label={t("servers.place")} hint={t("servers.placeHint")} unit={t("servers.unitPlace")} min={0} value={place} onChange={setPlace} optional/>
				</div>
				<TextField label={t("servers.poolLabel")} hint={t("servers.poolNew", {used: nodes.map(node => node.pool_v4).join(", ")})} placeholder="10.67.0.0/24" value={pool} onChange={setPool} technical required/>
				<ErrorNote error={error}/>
				<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy || !name.trim() || !pool.trim()}>{t("servers.create")}</Button><Button variant="quiet" onClick={() => setStep(0)}>{t("preset.previous")}</Button></div>
			</form>
		</Glass>}
		{step === 2 && added && <Glass className="p-panel p-form">
			<div><h3 className="vw-h3">{t("servers.doneTitle", {name: added.name})}</h3><p className="vw-muted">{t("servers.doneLead")}</p></div>
			<p>{t("servers.doneNext")}</p>
			<div className="p-cluster"><Button variant="primary" onClick={onClose}>{t("servers.doneButton")}</Button></div>
		</Glass>}
	</div>;
}
