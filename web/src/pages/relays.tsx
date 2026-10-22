import {Button, Checkbox, IconButton, NumberField, RadioGroup, Switch, TextField} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type Relay, type Template} from "../api.ts";
import {ErrorNote, Mark, useLoad, useP} from "../kit.tsx";

const KINDS = ["udp", "udp-obfs", "tls", "ws", "fronted", "fronted-shaped"] as const;
// A profile lists at most 16 candidates per transport and the node keeps one of its own.
const MOST = 15;
// A panel can hold thousands of accounts, so a search offers this many at most.
const FOUND = 20;
type Entry = string | {address?: string};
type Transport = {type?: string, endpoints?: Entry[], candidates?: Entry[]};
type Account = {id: number, name: string};

function toggle<T>(list: T[], item: T, on: boolean) { return on ? [...list.filter(one => one !== item), item] : list.filter(one => one !== item); }

// The name of an account that a relay names by its id. An account that no longer exists shows its id.
function AccountName({id}: {id: number}) {
	const {t} = useP(), account = useLoad(() => api("get", "/users/{id}", {params: {id}}), [id]);
	return <span>{account.data ? account.data.name : account.error ? t("relays.goneAccount", {id}) : t("common.loading")}</span>;
}

// Accounts are found by name as the user types, never listed whole. A pick is reported, and the search starts again.
function AccountSearch({label, exclude, onPick}: {label: string, exclude: number[], onPick: (account: Account) => void}) {
	const {t} = useP(), [query, setQuery] = useState(""), [found, setFound] = useState<Account[]>([]);
	useEffect(() => {
		const text = query.trim();
		let current = true;
		const timer = setTimeout(() => void (text ? api("get", "/users", {query: {q: text}}).then(answer => { if (current) setFound(answer.users.slice(0, FOUND)); }, () => { if (current) setFound([]); }) : setFound([])), 250);
		return () => { current = false; clearTimeout(timer); };
	}, [query]);
	const shown = found.filter(account => !exclude.includes(account.id));
	return <div className="p-stack">
		<TextField label={label} value={query} onChange={setQuery} placeholder={t("relays.searchAccounts")}/>
		{query.trim() && <div className="p-cluster">{shown.map(account => <Button key={account.id} size="sm" variant="quiet" onClick={() => { onPick({id: account.id, name: account.name}); setQuery(""); }}>{account.name}</Button>)}{shown.length === 0 && <p className="vw-small vw-muted">{t("relays.noMatch")}</p>}</div>}
	</div>;
}

// The relays save with the rest of the settings. The preview asks the server what every profile would carry with the relays as they are on screen, so it shows the effect before anything is saved.
export function RelaysEditor({value, onChange}: {value: Relay[], onChange: (relays: Relay[]) => void}) {
	const {t} = useP(), derived = useLoad(() => api("get", "/profiles/derived") as Promise<{templates: Template[]}>, []), groupRows = useLoad(() => api("get", "/endpoints"), []), [preview, setPreview] = useState<Template[] | null>(null), [error, setError] = useState<unknown>(null), [previewFor, setPreviewFor] = useState<Account | null>(null), [scoped, setScoped] = useState<number[]>([]);
	const tags = derived.data?.templates.map(template => template.inbound) ?? [], held: Record<string, string[]> = Object.fromEntries((derived.data?.templates ?? []).filter(template => template.kind !== "faketls").map(template => [template.inbound, ((template.profile.transports ?? []) as {type?: string}[]).map(transport => transport.type ?? "")])), groups = groupRows.data?.groups ?? [], ready = value.filter(relay => relay.name.trim() && relay.address.trim()), key = JSON.stringify([ready, previewFor?.id ?? null]);
	useEffect(() => {
		let current = true;
		const timer = setTimeout(() => void (api("post", "/profiles/preview", {body: {relays: ready, user: previewFor?.id ?? null}}) as Promise<{templates: Template[]}>).then(answer => { if (current) { setPreview(answer.templates); setError(null); } }, failure => { if (current) setError(failure); }), 400);
		return () => { current = false; clearTimeout(timer); };
	}, [key]);
	const edit = (index: number, change: Partial<Relay>) => onChange(value.map((relay, i) => i === index ? {...relay, ...change} : relay));
	// An empty list carries everything, new inbounds included, so every box checked is stored as empty and the last box cannot be cleared.
	const pick = (all: string[], chosen: string[], item: string, on: boolean) => { const now = chosen.length ? chosen : all, next = on ? [...now, item] : now.filter(old => old !== item); return all.every(one => next.includes(one)) ? [] : all.filter(one => next.includes(one)); };
	const owner = (address: string) => value.find(relay => relay.enabled && address.startsWith(relay.address.includes(":") ? "[" + relay.address + "]:" : relay.address + ":"))?.name;
	// A relay with no group or account chosen reaches everyone, so a choice of chosen groups and accounts stays on screen until something is picked.
	const chosen = (relay: Relay, i: number) => scoped.includes(i) || relay.groups.length > 0 || relay.users.length > 0;
	return <div className="p-form">
		{value.length === 0 ? <p className="vw-muted vw-small">{t("relays.none")}</p> : value.map((relay, i) => {
			const kinds = relay.transports.length ? relay.transports : [...KINDS], inbounds = relay.inbounds.length ? relay.inbounds : tags, name = relay.name.trim() || t("relays.unnamed", {number: i + 1}), audience = [...relay.groups, ...(relay.users.length ? [t("relays.accountCount", {count: relay.users.length})] : [])], groupNames = [...new Set([...groups.map(group => group.name), ...relay.groups])].sort();
			return <fieldset key={i} className="p-mirror">
				<legend className="p-row"><span className="p-cluster"><strong>{name}</strong>{!relay.enabled && <Mark tone="muted">{t("relays.off")}</Mark>}{relay.enabled && relay.prefer && <Mark>{t("relays.first")}</Mark>}<Mark tone="muted">{audience.length ? t("relays.onlyFor", {names: audience.join(", ")}) : t("relays.everyone")}</Mark></span><IconButton icon="close" label={t("relays.remove", {name})} onClick={() => { onChange(value.filter((_, j) => j !== i)); setScoped(scoped.filter(one => one !== i).map(one => one > i ? one - 1 : one)); }}/></legend>
				<div className="p-pair">
					<TextField label={t("relays.name")} value={relay.name} onChange={next => edit(i, {name: next})} maxLength={32}/>
					<TextField label={t("relays.address")} hint={t("relays.addressHint")} placeholder="198.51.100.7" value={relay.address} onChange={next => edit(i, {address: next.trim()})} technical/>
				</div>
				<div className="p-relay-carry" role="group" aria-label={t("relays.transports")}>
					<span className="vw-label">{t("relays.transports")}</span>
					<div className="p-cluster">{KINDS.map(kind => <Checkbox key={kind} label={kind} checked={kinds.includes(kind)} disabled={kinds.length === 1 && kinds.includes(kind)} onChange={on => edit(i, {transports: pick([...KINDS], relay.transports, kind, on)})}/>)}</div>
					<p className="vw-small vw-muted">{t("relays.noFaketls")}</p>
					<div className="p-relay-ports">{KINDS.filter(kind => kinds.includes(kind)).flatMap(kind => {
						const sharing = inbounds.filter(tag => held[tag]?.includes(kind)), unit = kind.startsWith("udp") ? "UDP" : "TCP";
						if (sharing.length < 2) return [<NumberField key={kind} label={t("relays.port", {kind})} unit={unit} placeholder={t("relays.samePort")} min={1} max={65535} value={relay.ports[kind] ?? ""} onChange={port => { const ports = {...relay.ports}; if (port === "") delete ports[kind]; else ports[kind] = port; edit(i, {ports}); }}/>];
						return sharing.map(tag => <NumberField key={tag + "/" + kind} label={t("relays.portFor", {inbound: tag, kind})} unit={unit} placeholder={relay.ports[kind] ? String(relay.ports[kind]) : t("relays.samePort")} min={1} max={65535} value={relay.inbound_ports[tag + "/" + kind] ?? ""} onChange={port => { const found = {...relay.inbound_ports}; if (port === "") delete found[tag + "/" + kind]; else found[tag + "/" + kind] = port; edit(i, {inbound_ports: found}); }}/>);
					})}</div>
				</div>
				{tags.length > 1 && <div className="p-relay-carry" role="group" aria-label={t("relays.inbounds")}>
					<span className="vw-label">{t("relays.inbounds")}</span>
					<div className="p-cluster">{tags.map(tag => <Checkbox key={tag} label={tag} checked={inbounds.includes(tag)} disabled={inbounds.length === 1 && inbounds.includes(tag)} onChange={on => edit(i, {inbounds: pick(tags, relay.inbounds, tag, on)})}/>)}</div>
				</div>}
				<div className="p-relay-carry">
					<p className="vw-small vw-muted">{t("relays.whoHint")}</p>
					<RadioGroup label={t("relays.who")} value={chosen(relay, i) ? "some" : "all"} onChange={next => { setScoped(next === "all" ? scoped.filter(one => one !== i) : [...scoped.filter(one => one !== i), i]); edit(i, next === "all" ? {groups: [], users: []} : {}); }} options={[{value: "all", label: t("relays.whoAll")}, {value: "some", label: t("relays.whoSome")}]}/>
					{chosen(relay, i) && <>
						<span className="vw-label">{t("relays.groups")}</span>
						<div className="p-cluster">{groupNames.map(group => <Checkbox key={group} label={groups.some(one => one.name === group && one.users === 0) ? t("relays.groupEmpty", {group}) : group} checked={relay.groups.includes(group)} onChange={on => edit(i, {groups: toggle(relay.groups, group, on)})}/>)}</div>
						<span className="vw-label">{t("relays.accounts")}</span>
						<AccountSearch label={t("relays.findAccount")} exclude={relay.users} onPick={account => edit(i, {users: [...relay.users, account.id]})}/>
						{relay.users.length > 0 && <div className="p-stack">{relay.users.map(id => <div key={id} className="p-row"><AccountName id={id}/><IconButton icon="close" label={t("relays.removeAccount", {id})} onClick={() => edit(i, {users: relay.users.filter(one => one !== id)})}/></div>)}</div>}
						{audience.length === 0 && <p className="vw-small vw-muted">{t("relays.whoEmpty")}</p>}
					</>}
				</div>
				{kinds.some(kind => kind === "udp" || kind === "udp-obfs") && kinds.some(kind => kind === "tls" || kind === "ws" || kind === "fronted" || kind === "fronted-shaped") && <p className="vw-small p-relay-warn">{t("relays.note.mixed")}</p>}
				<details className="p-details">
					<summary>{t("relays.works")}</summary>
					<ul className="p-relay-notes vw-small vw-muted">
						{kinds.some(kind => kind === "udp" || kind === "udp-obfs") && <li>{t("relays.note.udp")}</li>}
						{kinds.includes("tls") && <li>{t("relays.note.tls")}</li>}
						{kinds.includes("ws") && <li>{t("relays.note.ws")}</li>}
						{kinds.includes("fronted") && <li>{t("relays.note.fronted")}</li>}
						{kinds.includes("fronted-shaped") && <li>{t("relays.note.frontedShaped")}</li>}
					</ul>
				</details>
				<Switch label={t("relays.enabled")} checked={relay.enabled} onChange={on => edit(i, {enabled: on})}/>
				<Switch label={t("relays.prefer")} hint={t("relays.preferHint")} checked={relay.prefer} onChange={on => edit(i, {prefer: on})}/>
			</fieldset>;
		})}
		{value.length < MOST && <div><Button size="sm" icon="plus" onClick={() => onChange([...value, {name: "", address: "", inbounds: [], transports: [], ports: {}, inbound_ports: {}, prefer: false, enabled: true, groups: [], users: []}])}>{t("relays.add")}</Button></div>}
		<div className="p-relay-preview">
			<div><h3 className="vw-label">{t("relays.preview")}</h3><p className="vw-small vw-muted">{t("relays.previewLead")} <a className="p-link" href="#/profiles">{t("relays.publish")}</a></p></div>
			<AccountSearch label={t("relays.previewFor")} exclude={[]} onPick={setPreviewFor}/>
			<p className="vw-small vw-muted">{previewFor ? t("relays.previewingFor", {name: previewFor.name}) : t("relays.previewNone")} {previewFor && <Button size="sm" variant="quiet" onClick={() => setPreviewFor(null)}>{t("relays.previewClear")}</Button>}</p>
			{error ? <ErrorNote error={error}/> : !preview ? <p className="vw-small vw-muted">{t("common.loading")}</p> : preview.length === 0 ? <p className="vw-small vw-muted">{t("relays.noProfiles")}</p> : preview.map(template => <div key={template.inbound} className="p-relay-profile">
				<strong className="vw-code">{template.inbound}</strong>
				{(template.trimmed ?? []).map((cut, k) => <p key={k} className="vw-small p-relay-warn">{t("relays.trimmed", {relay: cut.relay, transport: cut.transport})}</p>)}
				{((template.profile.transports ?? []) as Transport[]).map((transport, j) => <div key={j} className="p-relay-line">
					<span className="vw-code">{transport.type}</span>
					<ol dir="ltr">{(transport.endpoints ?? transport.candidates ?? []).map((entry, k) => { const address = typeof entry === "string" ? entry : entry.address ?? "", by = owner(address); return <li key={k} data-relay={by ? "" : undefined}><span className="vw-code">{address}</span><span className="vw-small" dir="auto">{by ?? t("relays.own")}</span></li>; })}</ol>
				</div>)}
			</div>)}
		</div>
	</div>;
}
