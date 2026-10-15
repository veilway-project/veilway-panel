import {Banner, Button, ConfirmDialog, Field, Glass, IconButton, List, ListRow, NumberField, StateBlock, Switch, Tabs, TextField, useToast} from "@veilway/ui";
import {useContext, useState} from "react";
import {api, type Settings} from "../api.ts";
import {ErrorNote, lines, LinesField, PageHead, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {SettingsContext} from "../settings.ts";

type Mirror = {url: string, pins: string};

export function SubscriptionsPage() {
	const {t} = useP(), say = useSay(), settings = useLoad(() => api("get", "/settings"), []), [tab, setTab] = useState("endpoint");
	return <>
		<PageHead title={t("subs.title")} lead={t("subs.lead")}/>
		{settings.error && !settings.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={settings.reload}>{t("action.retry")}</Button>}>{say(settings.error)}</StateBlock>
		: !settings.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <Tabs label={t("subs.title")} value={tab} onChange={setTab} items={[
			{id: "endpoint", label: t("subs.tab.endpoint"), content: <SettingsForm initial={settings.data} onSaved={settings.set}/>},
			{id: "keys", label: t("subs.tab.keys"), content: <Keys/>},
			{id: "mirrors", label: t("subs.tab.mirrors"), content: <SettingsForm initial={settings.data} onSaved={settings.set} part="mirrors"/>},
			{id: "profiles", label: t("subs.tab.profiles"), content: <SettingsForm initial={settings.data} onSaved={settings.set} part="profiles"/>}
		]}/>}
	</>;
}

// The settings are one document saved with PUT, so each tab edits its own part of a copy and sends the whole thing.
function SettingsForm({initial, onSaved, part = "endpoint"}: {initial: Settings, onSaved: (settings: Settings) => void, part?: "endpoint" | "mirrors" | "profiles"}) {
	const {t} = useP(), toast = useToast(), guard = useGuard(), shared = useContext(SettingsContext);
	const [draft, setDraft] = useState(initial), [pins, setPins] = useState((initial.endpoint_pins ?? []).join("\n")), [profiles, setProfiles] = useState(JSON.stringify(initial.profiles ?? [], null, 2));
	const [mirrors, setMirrors] = useState<Mirror[]>(() => (initial.refresh_mirrors ?? []).map(m => typeof m === "string" ? {url: m, pins: ""} : {url: String((m as {url?: string}).url ?? ""), pins: ((m as {pins?: string[]}).pins ?? []).join("\n")})), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const patch = (change: Partial<Settings>) => setDraft({...draft, ...change});
	const save = async () => {
		setError(null);
		let parsed: unknown;
		try { parsed = JSON.parse(profiles); } catch (failure) { return setError(new Error(t("error.json", {message: (failure as Error).message}))); }
		if (!Array.isArray(parsed) || parsed.length > 64 || parsed.some(p => !p || typeof p !== "object" || Array.isArray(p) || "device" in p)) return setError(new Error(t("error.profiles")));
		setBusy(true);
		try {
			const saved = await guard(() => api("put", "/settings", {body: {...draft, endpoint_pins: lines(pins), profiles: parsed as Settings["profiles"], refresh_mirrors: mirrors.filter(m => m.url.trim()).map(m => lines(m.pins).length ? {url: m.url.trim(), pins: lines(m.pins)} : m.url.trim())}}));
			onSaved(saved);
			shared.set(saved);
			toast({tone: "success", title: t("common.saved")});
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void save(); }} noValidate>
		{part === "endpoint" && <Glass className="p-panel p-form">
			<TextField label={t("subs.provider")} hint={t("subs.providerHint")} value={draft.provider_name ?? ""} onChange={value => patch({provider_name: value})} maxLength={64}/>
			<TextField label={t("subs.endpoint")} hint={t("subs.endpointHint")} type="url" placeholder="https://" value={draft.endpoint_url ?? ""} onChange={value => patch({endpoint_url: value.trim()})} technical/>
			<LinesField label={t("subs.pins")} hint={t("subs.pinsHint")} value={pins} onChange={setPins} rows={2}/>
			<div className="p-pair">
				<NumberField label={t("subs.interval")} unit={t("subs.minutesUnit")} min={15} max={10080} value={Math.round((draft.update_interval ?? 3600) / 60)} onChange={value => patch({update_interval: value === "" ? 3600 : value * 60})}/>
				<NumberField label={t("subs.days")} unit={t("subs.daysUnit")} min={1} max={90} value={draft.document_days ?? 14} onChange={value => patch({document_days: value === "" ? 14 : value})}/>
			</div>
			<div className="p-pair">
				<NumberField label={t("subs.limit")} hint={t("form.limitHint")} unit={t("form.devices")} min={0} max={65535} value={draft.default_device_limit ?? 3} onChange={value => patch({default_device_limit: value === "" ? 0 : value})}/>
				<TextField label={t("subs.pool")} hint={t("subs.poolHint")} value={draft.pool_v4 ?? ""} onChange={value => patch({pool_v4: value.trim()})} technical/>
			</div>
			<Switch label={t("subs.once")} hint={t("subs.onceHint")} checked={draft.show_links_once ?? false} onChange={on => patch({show_links_once: on})}/>
		</Glass>}
		{part === "mirrors" && <>
			<Glass className="p-panel">
				<p className="vw-muted">{t("subs.mirrorsLead")}</p>
				{mirrors.length === 0 ? <StateBlock kind="empty" title={t("subs.noMirrors")}>{t("subs.noMirrorsBody")}</StateBlock> : mirrors.map((m, i) => <fieldset key={i} className="p-mirror">
					<legend className="p-row"><strong>{t("subs.mirror", {number: i + 1})}</strong><IconButton icon="close" label={t("common.remove")} onClick={() => setMirrors(mirrors.filter((_, j) => j !== i))}/></legend>
					<TextField label={t("subs.mirrorUrl")} type="url" placeholder="https://" value={m.url} onChange={url => setMirrors(mirrors.map((x, j) => j === i ? {...x, url} : x))} technical/>
					<LinesField label={t("subs.mirrorPins")} hint={t("subs.mirrorPinsHint")} value={m.pins} onChange={value => setMirrors(mirrors.map((x, j) => j === i ? {...x, pins: value} : x))} rows={2}/>
				</fieldset>)}
				{mirrors.length < 4 && <div><Button icon="plus" onClick={() => setMirrors([...mirrors, {url: "", pins: ""}])}>{t("subs.addMirror")}</Button></div>}
			</Glass>
			<Banner tone="info" title={t("subs.notFound")}>{t("subs.notFoundBody")}</Banner>
		</>}
		{part === "profiles" && <Glass className="p-panel">
			<p className="vw-muted">{t("subs.profilesLead")}</p>
			<Field label={t("subs.profilesField")} hint={t("subs.profilesHint")}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={14} value={profiles} onChange={event => setProfiles(event.target.value)}/>}</Field>
		</Glass>}
		<ErrorNote error={error}/>
		<div><Button type="submit" variant="primary" disabled={busy}>{t("common.save")}</Button></div>
	</form>;
}

function Keys() {
	const {t, date} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), keys = useLoad(() => api("get", "/signing-keys"), []), [ask, setAsk] = useState<"rotate" | "finish" | null>(null), [error, setError] = useState<unknown>(null);
	const list = keys.data?.keys ?? [], current = list.filter(k => k.state === "current");
	const run = (path: "/signing-keys/rotate" | "/signing-keys/finish") => { setError(null); void guard(() => api("post", path)).then(answer => { keys.set(answer); toast({tone: "success", title: t("common.saved")}); }, setError); };
	if (keys.error && !keys.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={keys.reload}>{t("action.retry")}</Button>}>{say(keys.error)}</StateBlock>;
	return <Glass className="p-panel">
		<p className="vw-muted">{t("subs.keysLead")}</p>
		{!keys.data ? <StateBlock kind="loading" title={t("common.loading")}/> : list.length === 0 ? <StateBlock kind="empty" title={t("subs.noKeys")}>{t("subs.noKeysBody")}</StateBlock> : <List label={t("subs.tab.keys")}>{list.map(k => <ListRow key={k.kid} title={<span className="vw-code">{k.fingerprint}</span>} detail={k.state === "current" ? t("subs.key.current") + ". " + t("subs.key.made", {date: date(new Date(k.created * 1000))}) : t("subs.key.retired", {date: date(new Date((k.retired_at ?? k.created) * 1000))})}/>)}</List>}
		<ErrorNote error={error}/>
		<div className="p-cluster">
			{current.length < 2 && <Button onClick={() => setAsk("rotate")}>{t("subs.rotate")}</Button>}
			{current.length > 1 && <Button variant="primary" onClick={() => setAsk("finish")}>{t("subs.finish")}</Button>}
		</div>
		<ConfirmDialog open={ask !== null} onOpenChange={o => { if (!o) setAsk(null); }} danger={ask === "finish"} title={t(ask === "finish" ? "subs.finishTitle" : "subs.rotateTitle")} body={t(ask === "finish" ? "subs.finishBody" : "subs.rotateBody")} confirmLabel={t(ask === "finish" ? "subs.finish" : "subs.rotate")} onConfirm={() => run(ask === "finish" ? "/signing-keys/finish" : "/signing-keys/rotate")}/>
	</Glass>;
}
