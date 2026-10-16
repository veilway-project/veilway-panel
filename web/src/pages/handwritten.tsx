import {Banner, Button, Checkbox, Field, IconButton, NumberField, Segmented, SelectField, TextField} from "@veilway/ui";
import {useMemo, useState} from "react";
import {Mark, useP} from "../kit.tsx";

// The profiles of the settings, as the subscription format writes them ("A profile" and "Transports of a profile" of the format page). The text stays the one value: the form edits the parsed list and writes it back, so the JSON view always shows what is saved, and members the form does not know are kept.
type Obj = Record<string, unknown>;
type Check = (key: string) => string | undefined;
const TYPES = ["udp", "udp-obfs", "tls", "ws", "fronted"];
const STREAM = ["tls", "ws", "fronted"];
const KEY = /^[A-Za-z0-9+/]{43}=$/;
const HOST = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const obj = (value: unknown): Obj => value && typeof value === "object" && !Array.isArray(value) ? value as Obj : {};
const arr = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const str = (value: unknown) => typeof value === "string" ? value : "";
const textOf = (value: unknown) => typeof value === "string" ? value : str(obj(value).default);
const isKey = (text: string) => KEY.test(text) && atob(text).split("").some(c => c !== "\0");
const isIp = (text: string) => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(text) || (text.includes(":") && !text.includes("%") && (() => { try { return new URL(`http://[${text}]/`).hostname !== ""; } catch { return false; } })());
// "192.0.2.10:51820" or "[2001:db8::10]:51820" as address and port, and back.
const split = (dial: string): [string, string] => { const at = dial.lastIndexOf(":"), v6 = dial.startsWith("["); return at < 0 || (!v6 && dial.indexOf(":") !== at) ? [dial, ""] : [dial.slice(v6 ? 1 : 0, v6 ? dial.lastIndexOf("]") : at), dial.slice(at + 1)]; };
const join = (address: string, port: string) => !address && !port ? "" : address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
// What the client's parser refuses when the document is read: the address forms it never dials, and a port of 0 or with a leading zero.
const dialable = (dial: string) => { const [address, port] = split(dial); if (!isIp(address) || !/^[1-9]\d{0,4}$/.test(port) || Number(port) > 65535) return false; const low = address.toLowerCase(), first = Number(address.split(".")[0]); return address.includes(":") ? !["::", "::1"].includes(low) && !/^(ff|fe[89ab]|fe[c-f]|::ffff:|64:ff9b:|2002:|2001:0?:)/.test(low) : first !== 0 && first !== 127 && first < 224 && !address.startsWith("169.254.") && address !== "255.255.255.255"; };

// Each problem keyed by its place: "0.id", "0.transports.1.candidates.0.pins". The server only checks the shape of the list, so these are what an app would refuse the profile for.
function problems(list: unknown[], t: ReturnType<typeof useP>["t"]) {
	const found = new Map<string, string>(), ids = list.map(p => str(obj(p).id));
	list.forEach((item, i) => {
		const p = obj(item), at = i + ".", put = (key: string, text: string) => { if (!found.has(at + key)) found.set(at + key, text); }, transports = arr(p.transports).map(obj), gateways = arr(p.gateways).map(str);
		if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(str(p.id))) put("id", t("hand.problem.id")); else if (ids.indexOf(str(p.id)) !== i) put("id", t("hand.problem.idTwice"));
		if (!textOf(p.name).trim() || [...textOf(p.name)].length > 64) put("name", t("hand.problem.name"));
		if (!isKey(str(p.inbound_public_key))) put("inbound_public_key", t("hand.problem.key"));
		if (gateways.length < 1 || gateways.length > 2 || !gateways.every(isIp) || (gateways.length === 2 && !(!gateways[0]!.includes(":") && gateways[1]!.includes(":")))) put("gateways", t("hand.problem.gateways"));
		if (typeof p.mtu !== "number" || !Number.isInteger(p.mtu) || p.mtu < 1280 || p.mtu > 1500) put("mtu", t("hand.problem.mtu"));
		if (transports.some(tr => STREAM.includes(str(tr.type))) ? !isKey(str(p.transport_public_key)) : p.transport_public_key !== undefined && !isKey(str(p.transport_public_key))) put("transport_public_key", t("hand.problem.transportKey"));
		if (transports.length < 1 || transports.length > 8) put("transports", t("hand.problem.transports"));
		transports.forEach((tr, j) => {
			const type = str(tr.type), here = `transports.${j}.`;
			if (!STREAM.includes(type)) {
				const endpoints = arr(tr.endpoints).map(str);
				if (endpoints.length < 1 || endpoints.length > 16) put(here + "endpoints", t("hand.problem.endpoints"));
				endpoints.forEach((dial, k) => { if (!dialable(dial)) put(here + "endpoints." + k, t("hand.problem.dial")); });
				return;
			}
			const path = str(tr.path), candidates = arr(tr.candidates).map(obj);
			if (path.length < 12 || path.length > 256 || !/^\/[A-Za-z0-9._~/-]*$/.test(path) || path.split("/").includes("..")) put(here + "path", t("hand.problem.path"));
			if (candidates.length < 1 || candidates.length > 16) put(here + "candidates", t("hand.problem.candidates"));
			candidates.forEach((c, k) => {
				const spot = here + "candidates." + k + ".", sni = str(c.sni), pins = arr(c.pins).map(str), self = c.self_signed === true;
				if (!dialable(str(c.address))) put(spot + "address", t("hand.problem.dial"));
				if (sni && !HOST.test(sni)) put(spot + "sni", t("hand.problem.host"));
				if (!HOST.test(str(c.host))) put(spot + "host", t("hand.problem.host"));
				if (self ? c.verify_name !== undefined : !sni !== (c.verify_name !== undefined) || (c.verify_name !== undefined && !HOST.test(str(c.verify_name)))) put(spot + "verify_name", t(self ? "hand.problem.verifySelf" : "hand.problem.verify"));
				if (type === "tls" && (pins.length < 1 || pins.length > 4)) put(spot + "pins", t("hand.problem.pinsNeeded"));
				if (type === "fronted" && c.pins !== undefined) put(spot + "pins", t("hand.problem.pinsFronted"));
				pins.forEach((pin, m) => { if (!KEY.test(pin)) put(spot + "pins." + m, t("hand.problem.pin")); });
			});
		});
	});
	return found;
}

export function ProfilesEditor({value, onChange}: {value: string, onChange: (text: string) => void}) {
	const {t, number} = useP(), list = useMemo(() => { try { const read: unknown = JSON.parse(value); return Array.isArray(read) ? read : null; } catch { return null; } }, [value]);
	const [mode, setMode] = useState(list ? "form" : "json"), found = useMemo(() => list ? problems(list, t) : new Map<string, string>(), [list, t]);
	const write = (next: unknown[]) => onChange(JSON.stringify(next, null, 2));
	const counts = list ? list.map((_, i) => [...found.keys()].filter(key => key.startsWith(i + ".")).length) : [], refused = counts.filter(Boolean).length;
	return <div className="p-stack">
		<div className="p-row"><Segmented label={t("hand.view")} value={mode} onChange={next => { if (next === "json" || list) setMode(next); }} options={[{value: "form", label: t("hand.form")}, {value: "json", label: "JSON"}]}/>{list && <span className="vw-muted vw-small">{t("hand.count", {count: list.length})}</span>}</div>
		{mode === "form" && !list && <Banner tone="danger" title={t("hand.badJson")}>{t("hand.badJsonBody")}</Banner>}
		{refused > 0 && <Banner tone="warning" title={t("hand.refused", {count: refused})}>{t("hand.refusedBody")}</Banner>}
		{mode === "json" ? <Field label={t("subs.profilesField")} hint={t("subs.profilesHint")}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={14} value={value} onChange={event => onChange(event.target.value)}/>}</Field>
		: list && <>
			{list.length === 0 && <p className="vw-muted vw-small">{t("hand.empty")}</p>}
			{list.map((item, i) => <ProfileCard key={i} index={i} profile={item} open={list.length === 1} count={counts[i] ?? 0} check={key => found.get(i + "." + key)} onChange={next => write(list.map((old, j) => j === i ? next : old))} onRemove={() => write(list.filter((_, j) => j !== i))}/>)}
			{list.length < 64 && <div><Button size="sm" icon="plus" onClick={() => write([...list, {id: "", name: "", type: "veilway", inbound_public_key: "", gateways: [], mtu: 1420, transports: [{type: "udp", endpoints: [""]}]}])}>{t("hand.add")}</Button></div>}
			<p className="vw-muted vw-small">{t("hand.limits", {max: number(64)})}</p>
		</>}
	</div>;
}

function ProfileCard({index, profile, open, count, check, onChange, onRemove}: {index: number, profile: unknown, open: boolean, count: number, check: Check, onChange: (next: unknown) => void, onRemove: () => void}) {
	const {t} = useP(), p = obj(profile), transports = arr(p.transports), gateways = arr(p.gateways).map(str), exits = arr(p.exits).map(obj), name = textOf(p.name);
	const set = (key: string, next: unknown) => onChange(next === undefined ? Object.fromEntries(Object.entries(p).filter(([k]) => k !== key)) : {...p, [key]: next});
	if (p.type !== "veilway") return <div className="p-hand"><div className="p-hand-summary p-row"><strong>{t("hand.profile", {number: index + 1})}</strong><IconButton icon="close" label={t("hand.remove", {number: index + 1})} onClick={onRemove}/></div><p className="vw-muted vw-small">{t("hand.notForm")}</p></div>;
	return <details className="p-hand" open={open || undefined}>
		<summary className="p-hand-summary"><span className="p-hand-title"><strong>{name || t("hand.profile", {number: index + 1})}</strong><span className="vw-code vw-muted vw-small">{str(p.id) || t("hand.noId")}</span></span><span className="p-tags">{transports.map((tr, j) => <span key={j} className="p-tag vw-code">{str(obj(tr).type) || "?"}</span>)}</span>{count > 0 ? <Mark tone="warning">{t("hand.problems", {count})}</Mark> : <Mark tone="success">{t("hand.ok")}</Mark>}</summary>
		<div className="p-stack p-hand-body">
			<div className="p-pair">
				<TextField label={t("hand.id")} hint={t("hand.idHint")} value={str(p.id)} onChange={v => set("id", v.toLowerCase())} error={check("id")} maxLength={64} technical/>
				<TextField label={t("hand.name")} hint={typeof p.name === "object" ? t("hand.nameTranslated") : t("hand.nameHint")} value={name} onChange={v => set("name", typeof p.name === "object" && p.name ? {...obj(p.name), default: v} : v)} error={check("name")}/>
			</div>
			<TextField label={t("hand.inboundKey")} hint={t("hand.inboundKeyHint")} value={str(p.inbound_public_key)} onChange={v => set("inbound_public_key", v.trim())} error={check("inbound_public_key")} technical/>
			<div className="p-pair">
				<TextField label={t("hand.gateway")} hint={t("hand.gatewayHint")} placeholder="10.7.0.1" value={gateways[0] ?? ""} onChange={v => set("gateways", [v.trim(), gateways[1] ?? ""].filter(Boolean))} error={check("gateways")} technical/>
				<TextField label={t("hand.gateway6")} placeholder="fd00:7::1" value={gateways[1] ?? ""} onChange={v => set("gateways", [gateways[0] ?? "", v.trim()].filter(Boolean))} technical optional/>
				<NumberField label="MTU" hint={t("hand.mtuHint")} unit={t("hand.bytes")} min={1280} max={1500} value={typeof p.mtu === "number" ? p.mtu : ""} onChange={v => set("mtu", v === "" ? undefined : v)} error={check("mtu")}/>
				<SelectField label={t("hand.cap")} hint={t("hand.capHint")} value={str(p.rating_cap) || "none"} onChange={v => set("rating_cap", v === "none" ? undefined : v)} options={[{value: "none", label: t("hand.capNone")}, {value: "detectable", label: t("hand.capDetectable")}, {value: "unsafe", label: t("hand.capUnsafe")}]}/>
			</div>
			{(transports.some(tr => STREAM.includes(str(obj(tr).type))) || p.transport_public_key !== undefined) && <TextField label={t("hand.transportKey")} hint={t("hand.transportKeyHint")} value={str(p.transport_public_key)} onChange={v => set("transport_public_key", v.trim() || undefined)} error={check("transport_public_key")} technical/>}
			<div className="p-stack">
				<h3 className="vw-h3">{t("hand.transports")}</h3>
				{check("transports") && <p className="p-hand-error">{check("transports")}</p>}
				{transports.map((tr, j) => <TransportBlock key={j} index={j} transport={tr} check={key => check(`transports.${j}.${key}`)} onChange={next => set("transports", transports.map((old, k) => k === j ? next : old))} onRemove={() => set("transports", transports.filter((_, k) => k !== j))} onMove={transports.length > 1 && j > 0 ? () => set("transports", transports.map((old, k) => k === j - 1 ? transports[j] : k === j ? transports[j - 1] : old)) : undefined}/>)}
				{transports.length < 8 && <div><Button size="sm" icon="plus" onClick={() => set("transports", [...transports, {type: "udp", endpoints: [""]}])}>{t("hand.addTransport")}</Button></div>}
			</div>
			<div className="p-stack">
				<h3 className="vw-h3">{t("hand.exits")}</h3>
				{exits.length === 0 ? <p className="vw-muted vw-small">{t("hand.noExits")}</p> : <ul className="p-row-list p-hand-exits">{exits.map((exit, k) => <li key={k}><span className="vw-code">{str(exit.tag)}</span><span>{textOf(exit.name)}{exit.linked === true && <span className="vw-muted vw-small"> {t("hand.linked")}</span>}</span><span className="vw-code vw-muted">{str(exit.country)}</span></li>)}</ul>}
				<p className="vw-muted vw-small">{t("hand.exitsHint")}</p>
			</div>
			<div className="p-form-foot"><p>{t("hand.kept")}</p><Button size="sm" variant="quiet" onClick={onRemove}>{t("hand.remove", {number: index + 1})}</Button></div>
		</div>
	</details>;
}

// One transport. Switching between the datagram types and the stream types keeps what still fits and drops the members the new type refuses.
function TransportBlock({index, transport, check, onChange, onRemove, onMove}: {index: number, transport: unknown, check: Check, onChange: (next: Obj) => void, onRemove: () => void, onMove?: () => void}) {
	const {t} = useP(), tr = obj(transport), type = str(tr.type), endpoints = arr(tr.endpoints).map(str), candidates = arr(tr.candidates).map(obj), known = TYPES.includes(type);
	const retype = (next: string) => {
		if (!STREAM.includes(next)) return onChange({type: next, endpoints: endpoints.length ? endpoints : [""]});
		const kept = (candidates.length ? candidates : [{address: "", sni: "", host: ""}]).map(c => Object.fromEntries(Object.entries(c).filter(([k]) => !(k === "self_signed" && next !== "tls") && !(k === "pins" && next === "fronted"))));
		onChange({type: next, path: str(tr.path), candidates: kept});
	};
	const setCandidate = (k: number, key: string, value: unknown) => onChange({...tr, candidates: candidates.map((c, m) => m !== k ? c : value === undefined ? Object.fromEntries(Object.entries(c).filter(([name]) => name !== key)) : {...c, [key]: value})});
	return <fieldset className="p-mirror">
		<legend className="p-row"><strong>{t("hand.transport", {number: index + 1})}</strong><span className="p-cluster">{onMove && <Button size="sm" variant="quiet" onClick={onMove}>{t("hand.moveUp")}</Button>}<IconButton icon="close" label={t("hand.removeTransport", {number: index + 1})} onClick={onRemove}/></span></legend>
		{!known ? <p className="vw-muted vw-small">{t("hand.unknownType", {type})}</p> : <>
			<SelectField label={t("hand.type")} hint={t(`hand.type.${type as "udp"}`)} value={type} onChange={retype} options={TYPES.map(value => ({value, label: value}))}/>
			{!STREAM.includes(type) ? <div className="p-stack">
				{check("endpoints") && <p className="p-hand-error">{check("endpoints")}</p>}
				{endpoints.map((dial, k) => <DialRow key={k} label={t("hand.endpoint", {number: k + 1})} value={dial} error={check("endpoints." + k)} onChange={next => onChange({...tr, endpoints: endpoints.map((old, m) => m === k ? next : old)})} onRemove={endpoints.length > 1 ? () => onChange({...tr, endpoints: endpoints.filter((_, m) => m !== k)}) : undefined}/>)}
				{endpoints.length < 16 && <div><Button size="sm" icon="plus" onClick={() => onChange({...tr, endpoints: [...endpoints, ""]})}>{t("hand.addEndpoint")}</Button></div>}
			</div> : <div className="p-stack">
				<TextField label={t("hand.path")} hint={t("hand.pathHint")} placeholder="/api/v2/stream-sync" value={str(tr.path)} onChange={v => onChange({...tr, path: v.trim()})} error={check("path")} technical/>
				{check("candidates") && <p className="p-hand-error">{check("candidates")}</p>}
				{candidates.map((c, k) => { const at = (key: string) => check(`candidates.${k}.${key}`), pins = arr(c.pins).map(str), self = c.self_signed === true, sni = str(c.sni); return <div key={k} className="p-hand-candidate p-stack">
					<div className="p-row"><span className="vw-label">{t("hand.candidate", {number: k + 1})}</span>{candidates.length > 1 && <IconButton icon="close" label={t("hand.removeCandidate", {number: k + 1})} onClick={() => onChange({...tr, candidates: candidates.filter((_, m) => m !== k)})}/>}</div>
					<DialRow label={t("hand.address")} value={str(c.address)} error={at("address")} onChange={next => setCandidate(k, "address", next)}/>
					<div className="p-pair">
						<TextField label={t("hand.host")} hint={t("hand.hostHint")} placeholder="cdn.example.org" value={str(c.host)} onChange={v => setCandidate(k, "host", v.trim().toLowerCase())} error={at("host")} technical/>
						<TextField label={t("hand.sni")} hint={t(self ? "hand.sniSelfHint" : "hand.sniHint")} value={sni} onChange={v => setCandidate(k, "sni", v.trim().toLowerCase())} error={at("sni")} technical optional/>
						{(!self && !sni) || c.verify_name !== undefined ? <TextField label={t("hand.verify")} hint={t("hand.verifyHint")} value={str(c.verify_name)} onChange={v => setCandidate(k, "verify_name", v.trim().toLowerCase() || undefined)} error={at("verify_name")} technical/> : null}
					</div>
					{type === "tls" && <Checkbox label={t("hand.selfSigned")} checked={self} onChange={on => setCandidate(k, "self_signed", on || undefined)}/>}
					{type !== "fronted" ? <div className="p-stack">
						<span className="vw-label">{t(type === "tls" ? "hand.pinsNeeded" : "hand.pinsOptional")}</span>
						{at("pins") && <p className="p-hand-error">{at("pins")}</p>}
						{pins.map((pin, m) => <div key={m} className="p-hand-line"><TextField label={t("hand.pin", {number: m + 1})} value={pin} onChange={v => setCandidate(k, "pins", pins.map((old, n) => n === m ? v.trim() : old))} error={at("pins." + m)} technical/><IconButton icon="close" label={t("hand.removePin", {number: m + 1})} onClick={() => setCandidate(k, "pins", pins.length > 1 ? pins.filter((_, n) => n !== m) : undefined)}/></div>)}
						{pins.length < 4 && <div><Button size="sm" variant="quiet" icon="plus" onClick={() => setCandidate(k, "pins", [...pins, ""])}>{t("hand.addPin")}</Button></div>}
					</div> : at("pins") && <p className="p-hand-error">{at("pins")}</p>}
				</div>; })}
				{candidates.length < 16 && <div><Button size="sm" icon="plus" onClick={() => onChange({...tr, candidates: [...candidates, {address: "", sni: "", host: ""}]})}>{t("hand.addCandidate")}</Button></div>}
			</div>}
		</>}
	</fieldset>;
}

// An address a client dials, as two inputs: the IP address and the port.
function DialRow({label, value, error, onChange, onRemove}: {label: string, value: string, error?: string, onChange: (next: string) => void, onRemove?: () => void}) {
	const {t} = useP(), [address, port] = split(value);
	return <div className="p-hand-line">
		<div className="p-hand-dial">
			<TextField label={label} placeholder="192.0.2.10" value={address} onChange={v => onChange(join(v.trim(), port))} error={error} technical/>
			<TextField label={t("hand.port")} placeholder="443" inputMode="numeric" value={port} onChange={v => onChange(join(address, v.replace(/\D/g, "").slice(0, 5)))} technical/>
		</div>
		{onRemove && <IconButton icon="close" label={t("hand.removeEndpoint", {label})} onClick={onRemove}/>}
	</div>;
}
