import {Banner, Button, Field, Glass, NumberField, StateBlock, TextField, useToast} from "@veilway/ui";
import {useContext, useState} from "react";
import {api, type Template} from "../api.ts";
import {ErrorNote, Mark, PageHead, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {SettingsContext} from "../settings.ts";

const MISSING = ["inbound_public_key", "transport_public_key", "node_host"];
const REFUSALS = ["not_acknowledged", "behind_proxy", "key_shared", "no_public_key", "bad_site", "node_host", "profile_id", "no_name", "plain_host", "plain_shared", "plain_key", "plain_cookie"];

// A profile with every transport left out is not published, so what it lacks blocks nothing.
const emptyTemplate = (template: Template) => !(Array.isArray(template.profile.transports) && template.profile.transports.length) && (template.kind === "faketls" || (template.refused ?? []).length > 0);

// Profiles are made from the node's inbounds. What the node cannot know (its public keys and its public address) comes from the overrides and the node host, and publishing waits until nothing is missing.
export function ProfilesPage() {
	const {t} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), derived = useLoad(() => api("get", "/profiles/derived") as Promise<{revision: string, templates: Template[]}>, []), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const templates = derived.data?.templates ?? [], blocked = templates.filter(template => template.missing.length && !emptyTemplate(template)).length;
	const publish = () => { setBusy(true); setError(null); void guard(() => api("post", "/profiles/publish")).then(() => toast({tone: "success", title: t("profiles.published")}), setError).finally(() => setBusy(false)); };
	return <>
		<PageHead title={t("nav.profiles")} lead={t("profiles.lead")}><Button variant="primary" disabled={busy || blocked > 0 || !templates.length} onClick={publish}>{t("profiles.publish")}</Button></PageHead>
		{derived.error && !derived.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={derived.reload}>{t("action.retry")}</Button>}>{say(derived.error)}</StateBlock>
		: !derived.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <>
			{blocked > 0 && <Banner tone="warning" title={t("profiles.blocked", {count: blocked})}/>}
			<ErrorNote error={error}/>
			{templates.length === 0 ? <StateBlock kind="empty" title={t("profiles.empty")} action={<Button onClick={() => { location.hash = "#/inbounds"; }}>{t("nav.inbounds")}</Button>}>{t("profiles.emptyBody")}</StateBlock> : <div className="p-columns">{templates.map(template => template.kind === "faketls" ? <Borrowed key={template.inbound + "/faketls"} template={template}/> : <Override key={template.inbound} template={template} onSaved={derived.reload}/>)}</div>}
		</>}
	</>;
}

// The profile of the borrowed-site transports of an inbound. It has no overrides of its own: it takes the inbound's, except the members that belong to the other profile.
function Borrowed({template}: {template: Template}) {
	const {t} = useP(), empty = emptyTemplate(template);
	return <Glass className="p-panel">
		<div className="p-row"><h2 className="vw-h3 vw-code">{String(template.profile.name ?? template.inbound)}</h2><Mark tone="warning">{t("profiles.alpha")}</Mark>{empty || template.missing.length ? <Mark tone="warning">{t("profiles.incomplete")}</Mark> : <Mark tone="success">{t("profiles.ready")}</Mark>}</div>
		<p className="vw-muted vw-small">{t("profiles.borrowedLead")}</p>
		{empty && <p className="vw-muted vw-small">{t("profiles.borrowedNone")}</p>}
		{template.missing.length > 0 && !empty && <Banner tone="warning" title={t("profiles.missing")}>{template.missing.map(name => MISSING.includes(name) ? t(`profiles.missing.${name}` as PanelKey) : name).join(" ")}</Banner>}
		<Refusals refused={template.refused ?? []}/>
		<details className="p-details">
			<summary>{t("profiles.show")}</summary>
			<pre className="vw-code p-pre" dir="ltr">{JSON.stringify(template.profile, null, 2)}</pre>
		</details>
	</Glass>;
}

// The transports a profile left out, each with the reason in plain words.
function Refusals({refused}: {refused: NonNullable<Template["refused"]>}) {
	const {t} = useP();
	return refused.length > 0 ? <Banner tone="warning" title={t("profiles.refused")}>{refused.map(item => <span key={item.transport} className="p-block"><span className="vw-code p-block" dir="ltr">{item.transport}</span>{REFUSALS.includes(item.code) ? t(`profiles.refused.${item.code}` as PanelKey) : item.reason}</span>)}</Banner> : null;
}

function Override({template, onSaved}: {template: Template, onSaved: () => void}) {
	const {t} = useP(), toast = useToast(), shared = useContext(SettingsContext), current = (shared.settings?.profile_overrides?.[template.inbound] ?? {}) as Record<string, unknown>;
	const [text, setText] = useState(JSON.stringify(current, null, 2)), [key, setKey] = useState(String(current.inbound_public_key ?? "")), [hosts, setHosts] = useState((Array.isArray(current.node_addresses) ? current.node_addresses as string[] : []).join(", ")), [port, setPort] = useState<number | "">(typeof current.web_port === "number" ? current.web_port : ""), [plainHost, setPlainHost] = useState(String(current.plain_host ?? "")), [plainPort, setPlainPort] = useState<number | "">(typeof current.plain_port === "number" ? current.plain_port : ""), plain = ((template.profile.transports ?? []) as {type?: string}[]).some(transport => transport.type === "ws-plain") || (template.refused ?? []).some(item => item.code.startsWith("plain_")), fronted = ((template.profile.transports ?? []) as {type?: string}[]).some(transport => transport.type === "ws" || transport.type === "fronted-shaped"), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const save = async (set: Record<string, unknown>) => {
		setBusy(true);
		setError(null);
		try {
			const answer = await api("put", "/profiles/overrides/{inbound}", {params: {inbound: template.inbound}, body: {set}}) as {overrides: Record<string, unknown>};
			if (shared.settings) shared.set({...shared.settings, profile_overrides: answer.overrides});
			setText(JSON.stringify(set, null, 2));
			toast({tone: "success", title: t("common.saved")});
			onSaved();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const fromText = () => { let set: unknown; try { set = JSON.parse(text || "{}"); } catch (failure) { return setError(new Error(t("error.json", {message: (failure as Error).message}))); } if (!set || typeof set !== "object" || Array.isArray(set) || "device" in set || "id" in set) return setError(new Error(t("profiles.overrideShape"))); void save(set as Record<string, unknown>); };
	return <Glass className="p-panel">
		<div className="p-row"><h2 className="vw-h3 vw-code">{template.inbound}</h2>{emptyTemplate(template) || template.missing.length ? <Mark tone="warning">{t("profiles.incomplete")}</Mark> : <Mark tone="success">{t("profiles.ready")}</Mark>}</div>
		{template.missing.length > 0 && <Banner tone="warning" title={t("profiles.missing")}>{template.missing.map(name => MISSING.includes(name) ? t(`profiles.missing.${name}` as PanelKey) : name).join(" ")}</Banner>}
		<Refusals refused={template.refused ?? []}/>
		{template.missing.includes("inbound_public_key") && <form className="p-inline-form" onSubmit={event => { event.preventDefault(); void save({...current, inbound_public_key: key.trim()}); }}>
			<TextField label={t("profiles.inboundKey")} hint={t("profiles.inboundKeyHint")} value={key} onChange={setKey} technical/>
			<Button type="submit" disabled={busy || !key.trim()}>{t("common.save")}</Button>
		</form>}
		<form className="p-inline-form" onSubmit={event => { event.preventDefault(); const list = hosts.split(/[\s,]+/).filter(Boolean), {node_addresses: _old, ...rest} = current; void save(list.length ? {...rest, node_addresses: list} : rest); }}>
			<TextField label={t("profiles.addresses")} hint={t("profiles.addressesHint")} placeholder="203.0.113.10, vpn.example.org" value={hosts} onChange={setHosts} technical/>
			<Button type="submit" disabled={busy}>{t("common.save")}</Button>
		</form>
		{fronted && <form className="p-inline-form" onSubmit={event => { event.preventDefault(); const {web_port: _old, ...rest} = current; void save(port === "" || port === 443 ? rest : {...rest, web_port: port}); }}>
			<NumberField label={t("profiles.webPort")} hint={t("profiles.webPortHint")} unit="TCP" placeholder="443" min={1} max={65535} value={port} onChange={setPort}/>
			<Button type="submit" disabled={busy}>{t("common.save")}</Button>
		</form>}
		{plain && <form className="p-inline-form" onSubmit={event => { event.preventDefault(); const {plain_host: _host, plain_port: _port, ...rest} = current; void save({...rest, ...(plainHost.trim() ? {plain_host: plainHost.trim().toLowerCase()} : {}), ...(plainPort === "" || plainPort === 80 ? {} : {plain_port: plainPort})}); }}>
			<TextField label={t("profiles.plainHost")} hint={t("profiles.plainHostHint")} placeholder="plain.example.org" value={plainHost} onChange={setPlainHost} technical/>
			<NumberField label={t("profiles.plainPort")} hint={t("profiles.plainPortHint")} unit="TCP" placeholder="80" min={1} max={65535} value={plainPort} onChange={setPlainPort}/>
			<Button type="submit" disabled={busy}>{t("common.save")}</Button>
		</form>}
		<details className="p-details">
			<summary>{t("profiles.show")}</summary>
			<pre className="vw-code p-pre" dir="ltr">{JSON.stringify(template.profile, null, 2)}</pre>
		</details>
		<details className="p-details" open={template.overridden.length > 0}>
			<summary>{t("profiles.overrides", {count: template.overridden.length})}</summary>
			<div className="p-stack">
				<Field label={t("profiles.overrideField")} hint={t("profiles.overrideHint")}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={6} value={text} onChange={event => setText(event.target.value)}/>}</Field>
				<div className="p-cluster"><Button disabled={busy} onClick={fromText}>{t("profiles.saveOverride")}</Button>{template.overridden.length > 0 && <Button variant="quiet" disabled={busy} onClick={() => void save({})}>{t("profiles.clear")}</Button>}</div>
			</div>
		</details>
		<ErrorNote error={error}/>
	</Glass>;
}
