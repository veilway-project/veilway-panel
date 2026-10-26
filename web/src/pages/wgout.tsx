import {Banner, Button, NumberField, SecretField, TextField} from "@veilway/ui";
import {useState} from "react";
import {ago, LinesField, Mark, useP} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {hostAddress, hostPort, isV4, KEY, parseWgQuick, type Note} from "../wgimport.ts";

type Item = Record<string, unknown>;
// What GET /v1/exits says of an exit that goes through a WireGuard outbound. Every field is null for another exit.
export type WgState = {outbound_up?: boolean | null, outbound_down_secs?: number | null, outbound_down_reason?: string | null, handshake_secs?: number | null, endpoint?: string | null, flows?: number | null};
const marker = (text: string) => text.startsWith("<redacted");
const str = (value: unknown) => typeof value === "string" ? value : "";

// What the node would refuse in the fields as typed, keyed by the field. The node stays the authority. A marker stands for the saved key only while the server and the server's key are the saved ones, which `original` tells.
export function wgProblems(draft: Item, original: Item | null): Record<string, PanelKey> {
	const found: Record<string, PanelKey> = {}, addresses = Array.isArray(draft.addresses) ? draft.addresses.map(str) : [], moved = original !== null && (original.server !== draft.server || original.public_key !== draft.public_key);
	if (!hostPort(str(draft.server))) found.server = "wg.err.server";
	if (!KEY.test(str(draft.public_key))) found.publicKey = "wg.err.needKey";
	for (const [field, name] of [["private_key", "privateKey"], ["preshared_key", "presharedKey"]] as const) {
		const value = str(draft[field]);
		if (marker(value) && moved) found[name] = "wg.err.writeKey";
		else if (!marker(value) && (field === "private_key" || value) && !KEY.test(value)) found[name] = "wg.err.needKey";
	}
	if (!addresses.length || !addresses.every(hostAddress) || addresses.length > 2 || addresses.filter(item => isV4(item.split("/")[0]!)).length > 1 || addresses.filter(item => !isV4(item.split("/")[0]!)).length > 1) found.addresses = "wg.err.addresses";
	const range = (key: string, low: number, high: number, to: PanelKey) => { const value = draft[key]; if (value !== undefined && !(Number.isInteger(value) && (value as number) >= low && (value as number) <= high)) found[key] = to; };
	range("mtu", 1280, 1500, "wg.err.mtu");
	range("keepalive_secs", 0, 3600, "wg.err.keepalive");
	range("max_flows", 16, 16384, "wg.err.flows");
	return found;
}

// The fields of one of the outbounds of type wireguard, written into the draft of the outbound form: typed, or read from a pasted wg-quick file. Secrets arrive as the node's marker and go back as it, which keeps the saved one.
export function WireguardOutboundFields({draft, setDraft, set, original, problems, tried}: {draft: Item, setDraft: (item: Item) => void, set: (key: string, next: unknown) => void, original: Item | null, problems: Record<string, PanelKey>, tried: boolean}) {
	const {t} = useP(), [pasted, setPasted] = useState(""), [result, setResult] = useState<{error?: Note, notes: Note[], warnings: Note[]} | null>(null), [addresses, setAddresses] = useState(() => (Array.isArray(draft.addresses) ? draft.addresses.map(str) : []).join(", "));
	const why = (field: string) => tried && problems[field] ? t(problems[field]!) : undefined, say = (note: Note) => t(note.key, note.values), number = (key: string, value: number | "") => set(key, value === "" ? undefined : value);
	const read = () => {
		const found = parseWgQuick(pasted);
		if (!("fields" in found)) return setResult({error: found, notes: [], warnings: []});
		const kept: Item = {type: "wireguard", tag: draft.tag, ...found.fields};
		for (const key of ["bind", "interface", "max_flows"]) if (draft[key] !== undefined) kept[key] = draft[key];
		setDraft(kept);
		setAddresses((found.fields.addresses as string[]).join(", "));
		setPasted("");
		setResult({notes: found.notes, warnings: found.warnings});
	};
	return <>
		<LinesField label={t("wg.import")} hint={t("wg.importHint")} rows={5} optional={false} value={pasted} onChange={value => { setPasted(value); setResult(null); }}/>
		<div className="p-cluster"><Button size="sm" disabled={!pasted.trim()} onClick={read}>{t("wg.read")}</Button></div>
		{result?.error && <Banner tone="danger" title={t("wg.refusedTitle")}>{say(result.error)}</Banner>}
		{result && !result.error && <>
			<Banner tone="success" title={t("wg.readTitle")}>{t("wg.readBody")}</Banner>
			{result.warnings.map(note => <Banner key={note.key} tone="warning" title={t("wg.warnTitle")}>{say(note)}</Banner>)}
			{result.notes.map(note => <p key={note.key} className="vw-muted vw-small">{say(note)}</p>)}
		</>}
		<TextField label={t("wg.server")} hint={t("wg.serverHint")} placeholder="vpn.example.com:51820" value={str(draft.server)} onChange={value => set("server", value.trim().toLowerCase())} error={why("server")} technical/>
		<div className="p-pair">
			<TextField label={t("wg.publicKey")} hint={t("wg.publicKeyHint")} value={str(draft.public_key)} onChange={value => set("public_key", value.trim())} error={why("publicKey")} technical/>
			<SecretField label={t("wg.privateKey")} hint={t("wg.secretHint")} value={str(draft.private_key)} onChange={value => set("private_key", value.trim())} error={why("privateKey")}/>
		</div>
		<div className="p-pair">
			<SecretField label={t("wg.presharedKey")} hint={t("wg.secretHint")} value={str(draft.preshared_key)} onChange={value => set("preshared_key", value.trim())} error={why("presharedKey")} optional/>
			<TextField label={t("wg.addresses")} hint={t("wg.addressesHint")} placeholder="10.2.0.2, fd00::2" value={addresses} onChange={value => { setAddresses(value); set("addresses", value.split(",").map(item => item.trim()).filter(Boolean)); }} error={why("addresses")} technical/>
		</div>
		<details className="p-details" open={Object.keys(problems).some(key => ["mtu", "keepalive_secs", "max_flows"].includes(key)) && tried || undefined}>
			<summary>{t("wg.tuning")}</summary>
			<div className="p-pair">
				<NumberField label={t("wg.mtu")} hint={t("wg.mtuHint")} unit={t("wg.unitBytes")} min={1280} max={1500} value={typeof draft.mtu === "number" ? draft.mtu : ""} onChange={value => number("mtu", value)} error={why("mtu")} optional/>
				<NumberField label={t("wg.keepalive")} hint={t("wg.keepaliveHint")} unit={t("unit.seconds")} min={0} max={3600} value={typeof draft.keepalive_secs === "number" ? draft.keepalive_secs : ""} onChange={value => number("keepalive_secs", value)} error={why("keepalive_secs")} optional/>
				<NumberField label={t("wg.maxFlows")} hint={t("wg.maxFlowsHint")} unit={t("wg.unitFlows")} min={16} max={16384} value={typeof draft.max_flows === "number" ? draft.max_flows : ""} onChange={value => number("max_flows", value)} error={why("max_flows")} optional/>
			</div>
			<div className="p-pair">
				<TextField label={t("config.bindLabel")} hint={t("config.bindHint")} value={str(draft.bind)} onChange={value => set("bind", value.trim())} technical optional/>
				<TextField label={t("config.outInterface")} hint={t("config.outInterfaceHint")} placeholder="eth1" value={str(draft.interface)} onChange={value => set("interface", value.trim())} maxLength={15} technical optional/>
			</div>
		</details>
		<Banner tone="warning" title={t("wg.trustTitle")}>{t("wg.trustBody")}</Banner>
		<p className="vw-muted vw-small">{t("wg.plain")}</p>
	</>;
}

// How the node's WireGuard tunnel of an exit is doing: carrying or down (since when, and why), the last handshake, the server it talks to and the flows open through it.
export function WgHealth({state, compact}: {state: WgState | undefined, compact?: boolean}) {
	const {t} = useP(), time = (seconds: number) => { const found = ago(seconds); return t(found.key, {count: found.count}); };
	if (state?.outbound_up === undefined || state.outbound_up === null) return <Mark tone="muted">{t("xo.state.unknown")}</Mark>;
	const handshake = state.handshake_secs === null || state.handshake_secs === undefined ? t("wg.noHandshake") : t("wg.handshake", {time: time(state.handshake_secs)});
	const mark = <Mark tone={state.outbound_up ? "success" : "danger"} title={compact ? [state.outbound_down_reason, state.endpoint].filter(Boolean).join(", ") : undefined}>{state.outbound_up ? t("xo.state.up") : t("wg.down", {time: time(state.outbound_down_secs ?? 0)})}</Mark>;
	if (compact) return mark;
	return <span className="p-user">
		{mark}
		{!state.outbound_up && state.outbound_down_reason && <span className="vw-muted vw-small">{state.outbound_down_reason}</span>}
		<span className="vw-muted vw-small">{handshake}, {state.endpoint && <><bdi dir="ltr">{state.endpoint}</bdi>, </>}{t("wg.flows", {count: state.flows ?? 0})}</span>
	</span>;
}
