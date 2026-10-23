import {Banner, Button, Checkbox, ConfirmDialog, Glass, NumberField, RadioGroup, Switch, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type NodeState, type Running, type User} from "../api.ts";
import {Copyable, ErrorNote, Mark, NodeNote, useGuard, useLoad, useP} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {useSettings} from "../settings.ts";

type Item = Record<string, unknown>;
export const PROXY_TYPES = ["socks5", "http", "mixed"];
export type Access = "all" | "chosen";
// Pools of a proxy inbound with the range and default the node uses.
const LIMITS = [["connections", 1024], ["per_source", 64], ["handshakes", 256]] as const;
const MOST = 65536;
const SPLIT = /^(?:\[([0-9A-Fa-f:.]+)\]|(\d{1,3}(?:\.\d{1,3}){3})):(\d{1,5})$/;
const str = (value: unknown) => typeof value === "string" ? value : "";
const strings = (value: unknown) => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
// A listen address as the node reads it. Only loopback is silent. A private address (RFC 1918, shared address space 100.64.0.0/10, unique local IPv6) is allowed and warned about, since NAT or the local network may expose it. Anything else needs `public`.
export function proxyListen(text: string) {
	const found = text.trim().match(SPLIT), host = found?.[1] ?? found?.[2] ?? "", port = Number(found?.[3]), parts = host.split(".").map(Number);
	const v4 = found?.[2] !== undefined && parts.length === 4 && parts.every(part => part <= 255);
	if (!found || port < 1 || port > 65535 || !(v4 || (found[1] !== undefined && found[1].includes(":")))) return null;
	const lower = host.toLowerCase();
	const loopback = v4 ? parts[0] === 127 : lower === "::1" || lower === "0:0:0:0:0:0:0:1";
	const priv = v4 ? loopback || parts[0] === 10 || (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) || (parts[0] === 192 && parts[1] === 168) || (parts[0] === 100 && parts[1]! >= 64 && parts[1]! <= 127) : loopback || /^f[cd][0-9a-f]{0,2}:/.test(lower);
	return {host, port, v6: !v4, loopback, private: priv && !loopback, wildcard: v4 ? parts.every(part => part === 0) : /^[0:]+$/.test(lower)};
}

export type ProxyProblems = Partial<Record<"listen" | "public" | "access" | "connections" | "per_source" | "handshakes", PanelKey>>;

// What the node would refuse, said before it is asked. The node stays the authority on clashes with its other listeners.
export function proxyProblems(draft: Item, access: Access): ProxyProblems {
	const found = proxyListen(str(draft.listen)), limits = (draft.limits ?? {}) as Item, out: ProxyProblems = {};
	if (!found) out.listen = "proxy.err.listen";
	else if (!found.loopback && !found.private && draft.public !== true) out.public = "proxy.err.public";
	if (access === "chosen" && !strings(draft.users).length && !strings(draft.groups).length) out.access = "proxy.err.access";
	for (const [key] of LIMITS) if (typeof limits[key] === "number" && !(Number.isInteger(limits[key]) && (limits[key] as number) >= 1 && (limits[key] as number) <= MOST)) out[key] = "limit.range";
	return out;
}

// The form of a socks5, http or mixed inbound. It edits the item as the node holds it, so what it does not show stays.
export function ProxyFields({draft, setDraft, access, setAccess, problems, tried}: {draft: Item, setDraft: (draft: Item) => void, access: Access, setAccess: (access: Access) => void, problems: ProxyProblems, tried: boolean}) {
	const {t, number} = useP(), people = useLoad(() => api("get", "/users"), []), kind = str(draft.type), found = proxyListen(str(draft.listen)), limits = (draft.limits ?? {}) as Item;
	const chosenUsers = strings(draft.users), chosenGroups = strings(draft.groups), accounts = people.data?.users ?? [], groups = [...new Set([...accounts.flatMap(user => user.groups), ...chosenGroups])].sort();
	const change = (key: string, next: unknown) => { const copy = {...draft}; if (next === undefined || next === "" || (Array.isArray(next) && !next.length)) delete copy[key]; else copy[key] = next; setDraft(copy); };
	const say = (key: keyof ProxyProblems) => problems[key] && (tried || (key === "listen" && str(draft.listen))) ? t(problems[key]!, {min: number(1), max: number(MOST)}) : undefined;
	const admitted = access === "all" ? accounts.filter(user => user.proxy_login) : accounts.filter(user => user.proxy_login && (chosenUsers.includes(user.name) || user.groups.some(group => chosenGroups.includes(group))));
	const pick = (key: "users" | "groups", name: string, on: boolean) => { const held = key === "users" ? chosenUsers : chosenGroups; change(key, on ? [...held, name] : held.filter(other => other !== name)); };
	return <>
		<TextField label={t("proxy.listen")} hint={t("proxy.listenHint")} placeholder="127.0.0.1:1080" value={str(draft.listen)} onChange={value => { const copy: Item = {...draft, listen: value.trim()}, next = proxyListen(value); if (!value.trim()) delete copy.listen; if (next?.loopback) { delete copy.public; delete copy.udp_any_port; } setDraft(copy); }} error={say("listen")} technical required/>
		{found?.private && <Banner tone="warning" title={t("proxy.private.title")}>{t("proxy.private.body")}</Banner>}
		{found && !found.loopback && !found.private && <div className="p-stack">
			<Banner tone="warning" title={t("proxy.public.title")}>{t("proxy.public.body")}</Banner>
			<Checkbox label={t("proxy.public.confirm")} checked={draft.public === true} onChange={on => change("public", on ? true : undefined)}/>
			{say("public") && <p className="vw-note p-exit-problem" role="alert">{say("public")}</p>}
		</div>}
		{kind !== "http" && <Switch label={t("proxy.udp")} hint={t("proxy.udpHint")} checked={draft.udp !== false} onChange={on => { const copy: Item = {...draft}; if (on) delete copy.udp; else { copy.udp = false; delete copy.udp_any_port; } setDraft(copy); }}/>}
		{kind !== "http" && draft.udp !== false && found && !found.loopback && <Switch label={t("proxy.anyPort")} hint={t("proxy.anyPortHint")} checked={draft.udp_any_port === true} onChange={on => change("udp_any_port", on ? true : undefined)}/>}
		<RadioGroup label={t("proxy.access")} value={access} onChange={value => setAccess(value === "chosen" ? "chosen" : "all")} options={[{value: "all", label: t("proxy.access.all"), detail: t("proxy.access.allDetail")}, {value: "chosen", label: t("proxy.access.chosen"), detail: t("proxy.access.chosenDetail")}]}/>
		{access === "chosen" && <div className="p-stack">
			{([["users", t("proxy.accounts"), accounts.map(user => ({name: user.name, plain: user.proxy_login})), chosenUsers, t("proxy.noAccounts")], ["groups", t("proxy.groups"), groups.map(name => ({name, plain: true})), chosenGroups, t("proxy.noGroups")]] as const).map(([key, label, options, held, empty]) => <div key={key} className="vw-field">
				<span className="vw-label">{label}</span>
				{options.length ? <ul className="p-row-list p-exit-list">{options.map(option => <li key={option.name}><label className="p-exit"><input type="checkbox" className="p-check" checked={held.includes(option.name)} onChange={event => pick(key, option.name, event.target.checked)}/><span className="p-row-text"><strong className="vw-code">{option.name}</strong>{!option.plain && <span className="vw-small vw-muted">{t("proxy.noLogin")}</span>}</span><span/></label></li>)}</ul> : <p className="vw-small vw-muted">{empty}</p>}
			</div>)}
			{say("access") && <p className="vw-note p-exit-problem" role="alert">{say("access")}</p>}
		</div>}
		{people.data && !admitted.length && <Banner tone="info" title={t("proxy.nobody")}>{t("proxy.nobodyBody")}</Banner>}
		<details className="p-details" open={LIMITS.some(([key]) => problems[key]) || undefined}>
			<summary>{t("proxy.limits")}</summary>
			<p className="vw-muted vw-small">{t("proxy.limitsLead")}</p>
			<div className="p-pair">{LIMITS.map(([key, fallback]) => <NumberField key={key} label={t(`proxy.limit.${key}` as PanelKey)} hint={key === "per_source" ? t("proxy.limit.per_sourceHint") : undefined} unit={t("unit.connections")} min={1} max={MOST} placeholder={String(fallback)} value={typeof limits[key] === "number" ? limits[key] as number : ""} onChange={value => { const next = {...limits}; if (value === "") delete next[key]; else next[key] = value; change("limits", Object.keys(next).length ? next : undefined); }} error={say(key)} optional/>)}</div>
		</details>
	</>;
}

// The proxy login of one account: a name and password for the proxy inbounds, with the addresses to copy into an app. The password is opened only on request.
export function ProxyLogin({user, onChanged}: {user: User, onChanged: () => void}) {
	const {t} = useP(), toast = useToast(), guard = useGuard(), settings = useSettings(), config = useLoad(() => api("get", "/config") as Promise<Running>, []);
	const [shown, setShown] = useState<{username: string, password: string} | null>(null), [dialog, setDialog] = useState<"again" | "remove" | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [node, setNode] = useState<NodeState | null>(null);
	const id = user.id, host = settings?.node_host?.trim() ?? "";
	const inbounds = ((config.data?.document.inbounds ?? []) as Item[]).filter(inbound => PROXY_TYPES.includes(str(inbound.type)) && (!strings(inbound.users).length && !strings(inbound.groups).length || strings(inbound.users).includes(user.name) || user.groups.some(group => strings(inbound.groups).includes(group))));
	const reveal = async () => { setShown(await guard(() => api("post", "/users/{id}/proxy/show", {params: {id}}))); };
	const run = async (work: () => Promise<{node: NodeState}>, done: PanelKey, after?: () => Promise<void>) => {
		setBusy(true);
		setError(null);
		try {
			setNode((await guard(work)).node);
			setDialog(null);
			setShown(null);
			toast({tone: "success", title: t(done)});
			onChanged();
			await after?.();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const make = () => void run(() => api("post", "/users/{id}/proxy", {params: {id}}), "proxy.made", reveal);
	return <Glass className="p-panel">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2">{t("proxy.title")}</h2><p>{t("proxy.lead")}</p></div>
			{user.proxy_login ? <div className="p-cluster">
				{!shown && <Button size="sm" icon="eye" onClick={() => { setError(null); void reveal().catch(setError); }}>{t("proxy.show")}</Button>}
				{shown && <Button size="sm" variant="quiet" onClick={() => setShown(null)}>{t("proxy.hide")}</Button>}
				<Button size="sm" onClick={() => { setError(null); setDialog("again"); }}>{t("proxy.again")}</Button>
				<Button size="sm" variant="quiet" onClick={() => { setError(null); setDialog("remove"); }}>{t("common.remove")}</Button>
			</div> : <Button size="sm" icon="plus" disabled={busy} onClick={make}>{t("proxy.make")}</Button>}
		</div>
		<NodeNote node={node}/>
		{!user.proxy_login && <p className="vw-muted">{t("proxy.none")}</p>}
		{shown && <div className="p-stack">
			<div className="p-pair"><Copyable label={t("proxy.username")} value={shown.username}/><Copyable label={t("proxy.password")} value={shown.password}/></div>
			{!inbounds.length && config.data && <p className="vw-muted vw-small">{t("proxy.noInbounds")}</p>}
			{inbounds.flatMap(inbound => {
				const at = proxyListen(str(inbound.listen)), tag = str(inbound.tag);
				if (!at) return [];
				const where = at.wildcard ? host || t("proxy.hostHolder") : at.host, name = `${shown.username}:${shown.password}@${where.includes(":") ? `[${where.replace(/^\[|\]$/g, "")}]` : where}:${at.port}`;
				return [...(str(inbound.type) !== "http" ? [["socks5", "SOCKS5"]] : []), ...(str(inbound.type) !== "socks5" ? [["http", "HTTP"]] : [])].map(([scheme, label]) => <Copyable key={tag + scheme} label={t("proxy.line", {tag, kind: label!})} value={`${scheme}://${name}`}/>);
			})}
			{inbounds.some(inbound => proxyListen(str(inbound.listen))?.loopback) && <p className="vw-small vw-muted">{t("proxy.loopback")}</p>}
			{inbounds.some(inbound => proxyListen(str(inbound.listen))?.wildcard) && !host && <p className="vw-small vw-muted">{t("proxy.noHost")}</p>}
			{inbounds.length > 0 && <Mark tone="warning">{t("proxy.clear")}</Mark>}
		</div>}
		{!dialog && <ErrorNote error={error}/>}
		<ConfirmDialog open={dialog === "again"} onOpenChange={open => { if (!open) setDialog(null); }} title={t("proxy.againTitle", {name: user.name})} body={t("proxy.againBody")} confirmLabel={t("proxy.again")} onConfirm={make}/>
		<ConfirmDialog open={dialog === "remove"} onOpenChange={open => { if (!open) setDialog(null); }} danger title={t("proxy.removeTitle", {name: user.name})} body={t("proxy.removeBody")} confirmLabel={t("common.remove")} onConfirm={() => void run(() => api("delete", "/users/{id}/proxy", {params: {id}}), "proxy.removed")}/>
	</Glass>;
}
