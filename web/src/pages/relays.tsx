import {Button, Checkbox, IconButton, NumberField, Switch, TextField} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type Relay, type Template} from "../api.ts";
import {ErrorNote, Mark, useLoad, useP} from "../kit.tsx";

const KINDS = ["udp", "udp-obfs", "tls", "ws", "fronted"] as const;
// A profile lists at most 16 candidates per transport and the node keeps one of its own.
const MOST = 15;
type Entry = string | {address?: string};
type Transport = {type?: string, endpoints?: Entry[], candidates?: Entry[]};

// The relays save with the rest of the settings. The preview asks the server what every profile would carry with the relays as they are on screen, so it shows the effect before anything is saved.
export function RelaysEditor({value, onChange}: {value: Relay[], onChange: (relays: Relay[]) => void}) {
	const {t} = useP(), derived = useLoad(() => api("get", "/profiles/derived") as Promise<{templates: Template[]}>, []), [preview, setPreview] = useState<Template[] | null>(null), [error, setError] = useState<unknown>(null);
	const tags = derived.data?.templates.map(template => template.inbound) ?? [], ready = value.filter(relay => relay.name.trim() && relay.address.trim()), key = JSON.stringify(ready);
	useEffect(() => {
		let current = true;
		const timer = setTimeout(() => void (api("post", "/profiles/preview", {body: {relays: ready}}) as Promise<{templates: Template[]}>).then(answer => { if (current) { setPreview(answer.templates); setError(null); } }, failure => { if (current) setError(failure); }), 400);
		return () => { current = false; clearTimeout(timer); };
	}, [key]);
	const edit = (index: number, change: Partial<Relay>) => onChange(value.map((relay, i) => i === index ? {...relay, ...change} : relay));
	// An empty list carries everything, new inbounds included, so every box checked is stored as empty and the last box cannot be cleared.
	const pick = (all: string[], chosen: string[], item: string, on: boolean) => { const now = chosen.length ? chosen : all, next = on ? [...now, item] : now.filter(old => old !== item); return all.every(one => next.includes(one)) ? [] : all.filter(one => next.includes(one)); };
	const owner = (address: string) => value.find(relay => relay.enabled && address.startsWith(relay.address.includes(":") ? "[" + relay.address + "]:" : relay.address + ":"))?.name;
	return <div className="p-form">
		{value.length === 0 ? <p className="vw-muted vw-small">{t("relays.none")}</p> : value.map((relay, i) => {
			const kinds = relay.transports.length ? relay.transports : [...KINDS], inbounds = relay.inbounds.length ? relay.inbounds : tags, name = relay.name.trim() || t("relays.unnamed", {number: i + 1});
			return <fieldset key={i} className="p-mirror">
				<legend className="p-row"><span className="p-cluster"><strong>{name}</strong>{!relay.enabled && <Mark tone="muted">{t("relays.off")}</Mark>}{relay.enabled && relay.prefer && <Mark>{t("relays.first")}</Mark>}</span><IconButton icon="close" label={t("relays.remove", {name})} onClick={() => onChange(value.filter((_, j) => j !== i))}/></legend>
				<div className="p-pair">
					<TextField label={t("relays.name")} value={relay.name} onChange={next => edit(i, {name: next})} maxLength={32}/>
					<TextField label={t("relays.address")} hint={t("relays.addressHint")} placeholder="198.51.100.7" value={relay.address} onChange={next => edit(i, {address: next.trim()})} technical/>
				</div>
				<div className="p-relay-carry" role="group" aria-label={t("relays.transports")}>
					<span className="vw-label">{t("relays.transports")}</span>
					<div className="p-cluster">{KINDS.map(kind => <Checkbox key={kind} label={kind} checked={kinds.includes(kind)} disabled={kinds.length === 1 && kinds.includes(kind)} onChange={on => edit(i, {transports: pick([...KINDS], relay.transports, kind, on)})}/>)}</div>
					<div className="p-relay-ports">{KINDS.filter(kind => kinds.includes(kind)).map(kind => <NumberField key={kind} label={t("relays.port", {kind})} unit={kind.startsWith("udp") ? "UDP" : "TCP"} placeholder={t("relays.samePort")} min={1} max={65535} value={relay.ports[kind] ?? ""} onChange={port => { const ports = {...relay.ports}; if (port === "") delete ports[kind]; else ports[kind] = port; edit(i, {ports}); }}/>)}</div>
				</div>
				{tags.length > 1 && <div className="p-relay-carry" role="group" aria-label={t("relays.inbounds")}>
					<span className="vw-label">{t("relays.inbounds")}</span>
					<div className="p-cluster">{tags.map(tag => <Checkbox key={tag} label={tag} checked={inbounds.includes(tag)} disabled={inbounds.length === 1 && inbounds.includes(tag)} onChange={on => edit(i, {inbounds: pick(tags, relay.inbounds, tag, on)})}/>)}</div>
				</div>}
				{kinds.some(kind => kind === "udp" || kind === "udp-obfs") && kinds.some(kind => kind === "tls" || kind === "ws" || kind === "fronted") && <p className="vw-small p-relay-warn">{t("relays.note.mixed")}</p>}
				<details className="p-details">
					<summary>{t("relays.works")}</summary>
					<ul className="p-relay-notes vw-small vw-muted">
						{kinds.some(kind => kind === "udp" || kind === "udp-obfs") && <li>{t("relays.note.udp")}</li>}
						{kinds.includes("tls") && <li>{t("relays.note.tls")}</li>}
						{kinds.includes("ws") && <li>{t("relays.note.ws")}</li>}
						{kinds.includes("fronted") && <li>{t("relays.note.fronted")}</li>}
					</ul>
				</details>
				<Switch label={t("relays.enabled")} checked={relay.enabled} onChange={on => edit(i, {enabled: on})}/>
				<Switch label={t("relays.prefer")} hint={t("relays.preferHint")} checked={relay.prefer} onChange={on => edit(i, {prefer: on})}/>
			</fieldset>;
		})}
		{value.length < MOST && <div><Button size="sm" icon="plus" onClick={() => onChange([...value, {name: "", address: "", inbounds: [], transports: [], ports: {}, prefer: false, enabled: true}])}>{t("relays.add")}</Button></div>}
		<div className="p-relay-preview">
			<div><h3 className="vw-label">{t("relays.preview")}</h3><p className="vw-small vw-muted">{t("relays.previewLead")} <a className="p-link" href="#/profiles">{t("relays.publish")}</a></p></div>
			{error ? <ErrorNote error={error}/> : !preview ? <p className="vw-small vw-muted">{t("common.loading")}</p> : preview.length === 0 ? <p className="vw-small vw-muted">{t("relays.noProfiles")}</p> : preview.map(template => <div key={template.inbound} className="p-relay-profile">
				<strong className="vw-code">{template.inbound}</strong>
				{((template.profile.transports ?? []) as Transport[]).map((transport, j) => <div key={j} className="p-relay-line">
					<span className="vw-code">{transport.type}</span>
					<ol dir="ltr">{(transport.endpoints ?? transport.candidates ?? []).map((entry, k) => { const address = typeof entry === "string" ? entry : entry.address ?? "", by = owner(address); return <li key={k} data-relay={by ? "" : undefined}><span className="vw-code">{address}</span><span className="vw-small" dir="auto">{by ?? t("relays.own")}</span></li>; })}</ol>
				</div>)}
			</div>)}
		</div>
	</div>;
}
