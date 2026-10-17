import {Banner, Button, ConfirmDialog, Dialog, Glass, NumberField, RadioGroup, SelectField, StateBlock, Switch, TextField} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type Running} from "../api.ts";
import {lines, LinesField, Mark, useLoad, useP} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {SectionReview} from "./apply.tsx";

type Item = Record<string, unknown>;
type Tunnel = {tag: string, enabled?: boolean, protocol: "tcp" | "udp", listen: string, exit: string, target: string, sources?: string[], max_connections?: number};
type Counters = {name: string, opened: number, open: number, refused_sources: number, refused_limit: number, refused_client: number, refused_rate: number, refused_down: number, refused_full: number, up_bytes: number, down_bytes: number};
const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/, SOURCE = /^[0-9A-Fa-f:.]+(\/(0|[1-9][0-9]{0,2}))?$/, MAX_TUNNELS = 64, MAX_SOURCES = 64, MAX_CONNECTIONS = 4096, DEFAULT_CONNECTIONS = 256, TOTAL_CONNECTIONS = 16384;
const REFUSED = ["sources", "limit", "client", "rate", "down", "full"] as const;
const list = (value: unknown) => Array.isArray(value) ? value as Item[] : [];
const str = (value: unknown) => typeof value === "string" ? value : "";
const SPLIT = /^(?:\[([0-9A-Fa-f:.]+)\]|([0-9.]+)):([0-9]{1,5})$/;
// An address and port as the node reads it: an IPv6 address needs its brackets and the port is 1 to 65535.
const addr = (text: string) => {
	const found = text.trim().match(SPLIT), host = found?.[1] ?? found?.[2] ?? "", port = Number(found?.[3]);
	const v4 = !host.includes(":") && host.split(".").length === 4 && host.split(".").every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
	return found && port >= 1 && port <= 65535 && (v4 || (found[1] !== undefined && found[1].includes(":"))) ? {host: host.toLowerCase(), port, v6: !v4} : null;
};
const unspecified = (host: string) => host === "0.0.0.0" || /^[0:]+$/.test(host);
const loopback = (host: string) => host.startsWith("127.") || host === "::1";
const overlap = (a: NonNullable<ReturnType<typeof addr>>, b: NonNullable<ReturnType<typeof addr>>) => a.port === b.port && a.v6 === b.v6 && (a.host === b.host || unspecified(a.host) || unspecified(b.host));
const ip4 = (host: string) => host.split(".").reduce((sum, part) => sum * 256 + Number(part), 0);

// Where the tunnels are managed: each one with what it counted since the node started, then the form and the review that applies the list.
export function TunnelCards({running, onChanged, onAdd}: {running: Running, onChanged: () => void, onAdd: () => void}) {
	const {t, bytes, number} = useP(), live = useLoad(() => api("get", "/stats/now"), []), tunnels = list(running.document.tunnels) as Tunnel[];
	const [editing, setEditing] = useState<number | null>(null), [removing, setRemoving] = useState<Tunnel | null>(null), [proposed, setProposed] = useState<{value: Tunnel[], summary: string} | null>(null);
	useEffect(() => { const timer = setInterval(live.reload, 10000); return () => clearInterval(timer); }, [live.reload]);
	const counters = ((live.data as {tunnels?: Counters[] | null} | null)?.tunnels ?? []) as Counters[];
	return <>
		<Glass className="p-panel">
			<div className="p-sheet-head"><div><h2 className="vw-h2">{t("tunnels.title")}</h2><p>{t("tunnels.lead")}</p></div><Button size="sm" icon="plus" onClick={() => setEditing(-1)}>{t("tunnels.add")}</Button></div>
			{!tunnels.length && <StateBlock kind="empty" title={t("tunnels.empty")} action={<Button variant="primary" icon="plus" onClick={onAdd}>{t("tunnels.forward")}</Button>}>{t("tunnels.emptyBody")}</StateBlock>}
			<div className="p-columns p-node-cards">
				{tunnels.map((tunnel, index) => {
					const seen = counters.find(row => row.name === tunnel.tag), refused = seen ? REFUSED.map(why => [why, seen[`refused_${why}`]] as const) : [], lost = refused.reduce((sum, [, count]) => sum + count, 0);
					return <Glass key={tunnel.tag} className="p-node-card">
						<div className="p-sheet-head"><div><strong className="vw-code vw-h3">{tunnel.tag}</strong><span className="vw-small vw-muted vw-code" dir="ltr">{tunnel.protocol + " " + tunnel.listen + " > " + tunnel.target}</span></div><Mark tone={tunnel.enabled === false ? "muted" : seen ? "success" : "warning"}>{t(tunnel.enabled === false ? "links.off" : seen ? "tunnels.listening" : "tunnels.notRunning")}</Mark></div>
						<dl>
							<div><dt>{t("tunnels.exit")}</dt><dd className="vw-code">{tunnel.exit}</dd></div>
							<div><dt>{t("tunnels.open")}</dt><dd className="vw-num">{seen ? t("tunnels.openOf", {open: number(seen.open), max: number(tunnel.max_connections ?? DEFAULT_CONNECTIONS)}) : t("users.usageUnknown")}</dd></div>
							<div><dt>{t("tunnels.opened")}</dt><dd className="vw-num">{seen ? number(seen.opened) : t("users.usageUnknown")}</dd></div>
							<div><dt>{t("tunnels.refused")}</dt><dd className="vw-num">{seen ? number(lost) : t("users.usageUnknown")}</dd></div>
							<div><dt>{t("tunnels.up")}</dt><dd className="vw-num">{seen ? bytes(seen.up_bytes).text : t("users.usageUnknown")}</dd></div>
							<div><dt>{t("tunnels.down")}</dt><dd className="vw-num">{seen ? bytes(seen.down_bytes).text : t("users.usageUnknown")}</dd></div>
						</dl>
						{lost > 0 && <p className="vw-small vw-muted">{t("tunnels.refusedBy", {reasons: refused.filter(([, count]) => count > 0).map(([why, count]) => t(`tunnels.refused.${why}`) + " " + number(count)).join(", ")})}</p>}
						<span className="p-cluster"><Button size="sm" variant="quiet" onClick={() => setEditing(index)}>{t("links.manage")}</Button><Button size="sm" variant="quiet" onClick={() => setRemoving(tunnel)}>{t("common.remove")}</Button></span>
					</Glass>;
				})}
			</div>
		</Glass>
		{editing !== null && <Dialog open onOpenChange={open => { if (!open) setEditing(null); }} title={t(editing < 0 ? "tunnels.addTitle" : "tunnels.editTitle", {name: tunnels[editing]?.tag ?? ""})} description={t("tunnels.formLead")}>
			<TunnelForm running={running} start={editing < 0 ? null : tunnels[editing]!} onCancel={() => setEditing(null)} onSave={made => { const was = editing; setEditing(null); setProposed({value: was < 0 ? [...tunnels, made] : tunnels.map((old, i) => i === was ? made : old), summary: t(was < 0 ? "tunnels.summaryAdd" : "tunnels.summaryEdit", {name: made.tag})}); }}/>
		</Dialog>}
		<ConfirmDialog open={removing !== null} onOpenChange={open => { if (!open) setRemoving(null); }} danger title={t("tunnels.removeTitle", {name: removing?.tag ?? ""})} body={t("tunnels.removeBody", {name: removing?.tag ?? ""})} confirmLabel={t("links.removeConfirm")} onConfirm={() => { const gone = removing!; setRemoving(null); setProposed({value: tunnels.filter(held => held.tag !== gone.tag), summary: t("tunnels.summaryRemove", {name: gone.tag})}); }}/>
		{proposed && <SectionReview section="tunnels" running={running} value={proposed.value} summary={<p>{proposed.summary}</p>} onClose={() => setProposed(null)} onDone={() => { setProposed(null); onChanged(); }}/>}
	</>;
}

// The preset page: one fixed protocol, a chain exit picked from the node's own, and the sources up front since they are what keeps strangers off the forwarded port.
export function TunnelPreset({protocol, running, onClose}: {protocol: "tcp" | "udp", running: Running, onClose: () => void}) {
	const {t} = useP(), [proposed, setProposed] = useState<Tunnel | null>(null);
	return <div className="p-stack">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t(protocol === "tcp" ? "preset.tunnel" : "preset.tunnelUdp")}</h2></div><Button variant="quiet" onClick={onClose}>{t("preset.leave")}</Button></div>
		<Glass className="p-panel p-form">
			<div><h3 className="vw-h3">{t("preset.tunnelIntro")}</h3><p className="vw-muted">{t(protocol === "tcp" ? "preset.tunnelBody" : "preset.tunnelUdpBody")}</p></div>
			<Banner tone="info" title={t("preset.tunnelPrivate")}>{t("preset.tunnelPrivateBody", {setting: t("links.privateRules")})}</Banner>
			<TunnelForm running={running} start={null} preset={protocol} onCancel={onClose} onSave={setProposed}/>
		</Glass>
		{proposed && <SectionReview section="tunnels" running={running} value={[...list(running.document.tunnels), proposed]} summary={<p>{t("tunnels.summaryAdd", {name: proposed.tag})}</p>} onClose={() => setProposed(null)} onDone={() => { setProposed(null); onClose(); }}/>}
	</div>;
}

// Every key of a tunnel with the node's own checks, so a mistake shows at its field before the review. The node stays the authority: the pools of its inbounds and what its gate refuses are checked by it alone, beyond the obvious ones.
function TunnelForm({running, start, preset, onCancel, onSave}: {running: Running, start: Tunnel | null, preset?: "tcp" | "udp", onCancel: () => void, onSave: (tunnel: Tunnel) => void}) {
	const {t, number} = useP(), document = running.document, others = (list(document.tunnels) as Tunnel[]).filter(held => held.tag !== start?.tag);
	const chains = list(document.exits).filter(exit => (exit.backend as Item | undefined)?.type === "chain").map(exit => str(exit.tag)).filter(Boolean);
	const [tag, setTag] = useState(start?.tag ?? ""), [enabled, setEnabled] = useState(start?.enabled ?? true), [protocol, setProtocol] = useState<"tcp" | "udp">(start?.protocol ?? preset ?? "tcp"), [listen, setListen] = useState(start?.listen ?? ""), [exit, setExit] = useState(start?.exit ?? chains[0] ?? ""), [target, setTarget] = useState(start?.target ?? "");
	const [sources, setSources] = useState((start?.sources ?? []).join("\n")), [limit, setLimit] = useState<number | "">(start?.max_connections ?? ""), [tried, setTried] = useState(false);
	const clean = tag.trim(), here = addr(listen), there = addr(target), nets = lines(sources), udp = protocol === "udp";
	const transports = list(document.inbounds).flatMap(inbound => list(inbound.transports)).map(transport => ({datagram: ["udp", "udp-obfs"].includes(str(transport.type)), at: addr(str(transport.listen))})), xrays = list((document.xray as Item | undefined)?.inbounds).map(inbound => addr(str(inbound.listen)));
	const links = list(document.links).flatMap(link => [...((link.addresses as Item | undefined)?.dialler as string[] | undefined ?? []), ...((link.addresses as Item | undefined)?.listener as string[] | undefined ?? [])]).map(address => address.toLowerCase());
	const pools = list(document.inbounds).flatMap(inbound => (inbound.address as string[] | undefined) ?? []).filter(pool => /^[0-9.]+\/\d+$/.test(pool));
	const errors: Partial<Record<"tag" | "listen" | "exit" | "target" | "sources" | "limit", PanelKey>> = {}, warnings: PanelKey[] = [];
	if (!TAG.test(clean)) errors.tag = "tunnels.err.tag";
	else if (others.some(held => held.tag === clean)) errors.tag = "tunnels.err.tagTaken";
	if (!here) errors.listen = "tunnels.err.addr";
	else if (transports.some(row => row.at && row.datagram === udp && overlap(here, row.at)) || others.some(held => held.protocol === protocol && addr(held.listen) && overlap(here, addr(held.listen)!)) || (!udp && xrays.some(row => row && overlap(here, row)))) errors.listen = "tunnels.err.listenTaken";
	if (!chains.includes(exit)) errors.exit = "tunnels.err.exit";
	if (!there) errors.target = "tunnels.err.addr";
	else if (transports.some(row => row.at && overlap(there, row.at)) || xrays.some(row => row && overlap(there, row)) || [...others.map(held => addr(held.listen)), here].some(row => row && overlap(there, row))) errors.target = "tunnels.err.targetSelf";
	else if (links.includes(there.host)) errors.target = "tunnels.err.targetLink";
	else if (unspecified(there.host) || loopback(there.host) || /^(169\.254\.|2(2[4-9]|3\d)\.|fe[89ab][0-9a-f]?:|ff[0-9a-f]{2}:)/.test(there.host) || (!there.v6 && pools.some(pool => { const [base, bits] = pool.split("/"); const mask = bits === "0" ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0; return (ip4(there.host) & mask) >>> 0 === (ip4(base!) & mask) >>> 0; }))) errors.target = "tunnels.err.targetGate";
	if (nets.length > MAX_SOURCES || nets.some(net => !SOURCE.test(net))) errors.sources = nets.length > MAX_SOURCES ? "tunnels.err.sourcesMany" : "tunnels.err.source";
	else if (!nets.length && udp && here && !loopback(here.host)) errors.sources = "tunnels.err.sourcesUdp";
	else if (!nets.length && !udp && here && !loopback(here.host)) warnings.push("tunnels.warn.sources");
	const room = TOTAL_CONNECTIONS - others.reduce((sum, held) => sum + (held.max_connections ?? DEFAULT_CONNECTIONS), 0);
	if (limit !== "" && (limit < 1 || limit > MAX_CONNECTIONS || !Number.isInteger(limit))) errors.limit = "tunnels.err.limit";
	else if ((limit === "" ? DEFAULT_CONNECTIONS : limit) > room) errors.limit = "tunnels.err.total";
	if (!start && others.length >= MAX_TUNNELS) errors.tag = "tunnels.err.many";
	const ok = Object.keys(errors).length === 0, say = (key: PanelKey | undefined, values?: Record<string, string | number>) => tried && key ? t(key, values) : undefined;
	const submit = () => {
		setTried(true);
		if (!ok) return;
		const made: Tunnel = {tag: clean, protocol, listen: listen.trim(), exit, target: target.trim()};
		if (!enabled) made.enabled = false;
		if (nets.length) made.sources = nets;
		if (limit !== "") made.max_connections = limit;
		onSave(made);
	};
	const sourcesField = <LinesField label={t("tunnels.sources")} hint={t(preset ? "tunnels.sourcesHintPreset" : "tunnels.sourcesHint")} value={sources} onChange={setSources} rows={preset ? 4 : 3} optional={!udp} error={say(errors.sources)}/>;
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); submit(); }} noValidate>
		{!chains.length && <Banner tone="warning" title={t("tunnels.noChain")}>{t("tunnels.noChainBody")}</Banner>}
		{preset && sourcesField}
		<div className="p-pair">
			<TextField label={t("tunnels.tag")} hint={t("tunnels.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} error={say(errors.tag, {max: MAX_TUNNELS})} technical required/>
			<SelectField label={t("tunnels.exit")} hint={t("tunnels.exitHint")} value={exit} onChange={setExit} options={chains.map(name => ({value: name, label: name}))}/>
		</div>
		{!preset && <RadioGroup label={t("tunnels.protocol")} value={protocol} onChange={value => setProtocol(value as "tcp" | "udp")} options={[{value: "tcp", label: "TCP", detail: t("tunnels.tcpDetail")}, {value: "udp", label: "UDP", detail: t("tunnels.udpDetail")}]}/>}
		<div className="p-pair">
			<TextField label={t("tunnels.listen")} hint={t("tunnels.listenHint")} value={listen} onChange={setListen} error={say(errors.listen)} technical required/>
			<TextField label={t("tunnels.target")} hint={t("tunnels.targetHint")} value={target} onChange={setTarget} error={say(errors.target)} technical required/>
		</div>
		{!preset && sourcesField}
		<NumberField label={t("tunnels.limit")} hint={t(udp ? "tunnels.limitHintUdp" : "tunnels.limitHint", {room: number(Math.max(room, 0))})} unit={t(udp ? "unit.sessions" : "unit.connections")} min={1} max={MAX_CONNECTIONS} value={limit} onChange={setLimit} error={say(errors.limit, {room: number(Math.max(room, 0))})} optional/>
		{!preset && <Switch label={t("tunnels.enabled")} hint={t("tunnels.enabledHint")} checked={enabled} onChange={setEnabled}/>}
		{warnings.map(key => <Banner key={key} tone="warning" title={t(key)}>{t(`${key}Body` as PanelKey)}</Banner>)}
		<div className="p-cluster"><Button type="submit" variant="primary">{t("config.review")}</Button><Button variant="quiet" onClick={onCancel}>{t("action.cancel")}</Button></div>
	</form>;
}
