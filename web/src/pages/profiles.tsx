import {Banner, Button, Field, Glass, StateBlock, TextField, useToast} from "@veilway/ui";
import {useContext, useState} from "react";
import {api, type Template} from "../api.ts";
import {ErrorNote, Mark, PageHead, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";
import {SettingsContext} from "../settings.ts";

const MISSING = ["inbound_public_key", "transport_public_key", "node_host"];

// Profiles are made from the node's inbounds. What the node cannot know (its public keys and its public address) comes from the overrides and the node host, and publishing waits until nothing is missing.
export function ProfilesPage() {
	const {t} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), derived = useLoad(() => api("get", "/profiles/derived") as Promise<{revision: string, templates: Template[]}>, []), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const templates = derived.data?.templates ?? [], blocked = templates.filter(template => template.missing.length).length;
	const publish = () => { setBusy(true); setError(null); void guard(() => api("post", "/profiles/publish")).then(() => toast({tone: "success", title: t("profiles.published")}), setError).finally(() => setBusy(false)); };
	return <>
		<PageHead title={t("nav.profiles")} lead={t("profiles.lead")}><Button variant="primary" disabled={busy || blocked > 0 || !templates.length} onClick={publish}>{t("profiles.publish")}</Button></PageHead>
		{derived.error && !derived.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={derived.reload}>{t("action.retry")}</Button>}>{say(derived.error)}</StateBlock>
		: !derived.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <>
			{blocked > 0 && <Banner tone="warning" title={t("profiles.blocked", {count: blocked})}/>}
			<ErrorNote error={error}/>
			{templates.length === 0 ? <StateBlock kind="empty" title={t("profiles.empty")} action={<Button onClick={() => { location.hash = "#/inbounds"; }}>{t("nav.inbounds")}</Button>}>{t("profiles.emptyBody")}</StateBlock> : <div className="p-columns">{templates.map(template => <Override key={template.inbound} template={template} onSaved={derived.reload}/>)}</div>}
		</>}
	</>;
}

function Override({template, onSaved}: {template: Template, onSaved: () => void}) {
	const {t} = useP(), toast = useToast(), shared = useContext(SettingsContext), current = (shared.settings?.profile_overrides?.[template.inbound] ?? {}) as Record<string, unknown>;
	const [text, setText] = useState(JSON.stringify(current, null, 2)), [key, setKey] = useState(String(current.inbound_public_key ?? "")), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
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
		<div className="p-row"><h2 className="vw-h3 vw-code">{template.inbound}</h2>{template.missing.length ? <Mark tone="warning">{t("profiles.incomplete")}</Mark> : <Mark tone="success">{t("profiles.ready")}</Mark>}</div>
		{template.missing.length > 0 && <Banner tone="warning" title={t("profiles.missing")}>{template.missing.map(name => MISSING.includes(name) ? t(`profiles.missing.${name}` as PanelKey) : name).join(" ")}</Banner>}
		{template.missing.includes("inbound_public_key") && <form className="p-inline-form" onSubmit={event => { event.preventDefault(); void save({...current, inbound_public_key: key.trim()}); }}>
			<TextField label={t("profiles.inboundKey")} hint={t("profiles.inboundKeyHint")} value={key} onChange={setKey} technical/>
			<Button type="submit" disabled={busy || !key.trim()}>{t("common.save")}</Button>
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
