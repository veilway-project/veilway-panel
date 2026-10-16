import {Button, ConfirmDialog, Field, Glass, IconButton, List, ListRow, NumberField, StateBlock, Switch, TextField, useToast} from "@veilway/ui";
import {useContext, useEffect, useState} from "react";
import {api, type NotFound, type Settings} from "../api.ts";
import {ErrorNote, lines, LinesField, Mark, PageHead, useGuard, useLoad, useP, useReorder, useSay} from "../kit.tsx";
import {SettingsContext} from "../settings.ts";
import {ProfilesEditor} from "./handwritten.tsx";

type Mirror = {url: string, pins: string};
const SECTIONS = ["endpoint", "refresh", "new-users", "mirrors", "strangers", "profiles", "keys"] as const;

// Every setting on one page. The settings are one document saved with PUT, so the whole form saves at once from the bar that shows while anything is changed; signing keys act on their own.
export function SettingsPage() {
	const {t} = useP(), say = useSay(), settings = useLoad(() => api("get", "/settings"), []), [at, setAt] = useState<string>("endpoint");
	useEffect(() => {
		if (!settings.data) return;
		const watch = new IntersectionObserver(entries => { const top = entries.filter(entry => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0]; if (top) setAt(top.target.id.replace("set-", "")); }, {rootMargin: "0px 0px -70% 0px"});
		SECTIONS.forEach(id => { const found = document.getElementById("set-" + id); if (found) watch.observe(found); });
		return () => watch.disconnect();
	}, [settings.data]);
	const jump = (id: string) => { setAt(id); const found = document.getElementById("set-" + id); found?.scrollIntoView({behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start"}); found?.querySelector<HTMLElement>("h2")?.focus({preventScroll: true}); };
	return <>
		<PageHead title={t("nav.settings")} lead={t("subs.lead")}/>
		{settings.error && !settings.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={settings.reload}>{t("action.retry")}</Button>}>{say(settings.error)}</StateBlock>
		: !settings.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <div className="p-settings">
			<Glass className="p-subnav" role="navigation" aria-label={t("settings.jump")}>{SECTIONS.map(id => <button key={id} type="button" aria-current={at === id ? "location" : undefined} onClick={() => jump(id)}>{t(`settings.nav.${id}`)}</button>)}</Glass>
			<div className="p-stack">
				<SettingsForm initial={settings.data} onSaved={settings.set}/>
				<Keys/>
			</div>
		</div>}
	</>;
}

function SettingsForm({initial, onSaved}: {initial: Settings, onSaved: (settings: Settings) => void}) {
	const {t} = useP(), toast = useToast(), guard = useGuard(), shared = useContext(SettingsContext);
	const start = (from: Settings) => ({draft: from, pins: (from.endpoint_pins ?? []).join("\n"), profiles: JSON.stringify(from.profiles ?? [], null, 2), custom: from.not_found != null, answer: {status: from.not_found?.status ?? 404 as number | "", headers: (from.not_found?.headers ?? [["content-type", "text/html"]]).map(([name, value]) => name + ": " + value).join("\n"), body: from.not_found?.body ?? ""}, mirrors: (from.refresh_mirrors ?? []).map(m => typeof m === "string" ? {url: m, pins: ""} : {url: String((m as {url?: string}).url ?? ""), pins: ((m as {pins?: string[]}).pins ?? []).join("\n")}) as Mirror[]});
	const [base, setBase] = useState(() => start(initial)), [form, setForm] = useState(base), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const {draft, pins, profiles, custom, answer, mirrors} = form, changed = JSON.stringify(form) !== JSON.stringify(base);
	const patch = (change: Partial<Settings>) => setForm({...form, draft: {...draft, ...change}});
	const set = (change: Partial<typeof form>) => setForm({...form, ...change});
	// The mirrors reach clients in this order, so the order is part of the form and saves with it.
	const reorder = useReorder(mirrors.length, index => t("subs.mirror", {number: index + 1}), (from, to) => { const next = mirrors.filter((_, i) => i !== from); next.splice(to, 0, mirrors[from]!); set({mirrors: next}); });
	const save = async () => {
		setError(null);
		let parsed: unknown;
		try { parsed = JSON.parse(profiles); } catch (failure) { return setError(new Error(t("error.json", {message: (failure as Error).message}))); }
		if (!Array.isArray(parsed) || parsed.length > 64 || parsed.some(p => !p || typeof p !== "object" || Array.isArray(p) || "device" in p)) return setError(new Error(t("error.profiles")));
		const headers = lines(answer.headers).map(line => [line.slice(0, line.indexOf(":")).trim(), line.slice(line.indexOf(":") + 1).trim()]);
		if (custom && headers.some(([name]) => !name)) return setError(new Error(t("subs.nfHeadersWrong")));
		const notFound: NotFound | null = custom ? {status: answer.status === "" ? 404 : answer.status, headers: headers as [string, string][], body: answer.body} : null;
		setBusy(true);
		try {
			const saved = await guard(() => api("put", "/settings", {body: {...draft, not_found: notFound, endpoint_pins: lines(pins), profiles: parsed as Settings["profiles"], refresh_mirrors: mirrors.filter(m => m.url.trim()).map(m => lines(m.pins).length ? {url: m.url.trim(), pins: lines(m.pins)} : m.url.trim())}}));
			onSaved(saved);
			shared.set(saved);
			const next = start(saved);
			setBase(next);
			setForm(next);
			toast({tone: "success", title: t("common.saved")});
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const head = (key: "endpoint" | "refresh" | "newUsers" | "mirrors" | "strangers" | "profiles") => <div><h2 className="vw-h3" tabIndex={-1}>{t(`settings.${key}`)}</h2><p>{t(`settings.${key}Lead`)}</p></div>;
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void save(); }} noValidate>
		<Glass className="p-panel p-sections">
			<section className="p-section" id="set-endpoint">
				{head("endpoint")}
				<div className="p-form">
					<TextField label={t("subs.provider")} hint={t("subs.providerHint")} value={draft.provider_name ?? ""} onChange={value => patch({provider_name: value})} maxLength={64}/>
					<TextField label={t("subs.endpoint")} hint={t("subs.endpointHint")} type="url" placeholder="https://" value={draft.endpoint_url ?? ""} onChange={value => patch({endpoint_url: value.trim()})} technical/>
					<TextField label={t("subs.nodeHost")} hint={t("subs.nodeHostHint")} placeholder="vpn.example.org" value={draft.node_host ?? ""} onChange={value => patch({node_host: value.trim()})} technical/>
					<LinesField label={t("subs.pins")} hint={t("subs.pinsHint")} value={pins} onChange={value => set({pins: value})} rows={2}/>
				</div>
			</section>
			<section className="p-section" id="set-refresh">
				{head("refresh")}
				<div className="p-pair">
					<NumberField label={t("subs.interval")} unit={t("subs.minutesUnit")} min={15} max={10080} value={Math.round((draft.update_interval ?? 3600) / 60)} onChange={value => patch({update_interval: value === "" ? 3600 : value * 60})}/>
					<NumberField label={t("subs.days")} unit={t("subs.daysUnit")} min={1} max={90} value={draft.document_days ?? 14} onChange={value => patch({document_days: value === "" ? 14 : value})}/>
				</div>
			</section>
			<section className="p-section" id="set-new-users">
				{head("newUsers")}
				<div className="p-form">
					<Switch label={t("subs.once")} hint={t("subs.onceHint")} checked={draft.show_links_once ?? false} onChange={on => patch({show_links_once: on})}/>
					<div className="p-pair">
						<NumberField label={t("subs.limit")} hint={t("form.limitHint")} unit={t("form.devices")} min={0} max={65535} value={draft.default_device_limit ?? 3} onChange={value => patch({default_device_limit: value === "" ? 0 : value})}/>
						<TextField label={t("subs.pool")} hint={t("subs.poolHint")} value={draft.pool_v4 ?? ""} onChange={value => patch({pool_v4: value.trim()})} technical/>
					</div>
				</div>
			</section>
			<section className="p-section" id="set-mirrors">
				{head("mirrors")}
				<div className="p-form">
					{mirrors.length === 0 ? <p className="vw-muted vw-small">{t("subs.noMirrorsBody")}</p> : mirrors.map((m, i) => <fieldset key={i} className="p-mirror" data-order-row>
						<legend className="p-row"><span className="p-order">{reorder.handle(i)}<strong>{t("subs.mirror", {number: i + 1})}</strong></span><span className="p-cluster">{reorder.steps(i)}<IconButton icon="close" label={t("subs.removeMirror", {number: i + 1})} onClick={() => set({mirrors: mirrors.filter((_, j) => j !== i)})}/></span></legend>
						<TextField label={t("subs.mirrorUrl")} type="url" placeholder="https://" value={m.url} onChange={url => set({mirrors: mirrors.map((x, j) => j === i ? {...x, url} : x)})} technical/>
						<LinesField label={t("subs.mirrorPins")} hint={t("subs.mirrorPinsHint")} value={m.pins} onChange={value => set({mirrors: mirrors.map((x, j) => j === i ? {...x, pins: value} : x)})} rows={2}/>
					</fieldset>)}
					{reorder.live}
					{mirrors.length < 4 && <div><Button size="sm" icon="plus" onClick={() => set({mirrors: [...mirrors, {url: "", pins: ""}]})}>{t("subs.addMirror")}</Button></div>}
				</div>
			</section>
			<section className="p-section" id="set-strangers">
				{head("strangers")}
				<div className="p-form">
					<Switch label={t("subs.nfCustom")} hint={t("subs.nfCustomHint")} checked={custom} onChange={on => set({custom: on})}/>
					{custom && <>
						<NumberField label={t("subs.nfStatus")} unit="HTTP" min={100} max={599} value={answer.status} onChange={status => set({answer: {...answer, status}})}/>
						<LinesField label={t("subs.nfHeaders")} hint={t("subs.nfHeadersHint")} value={answer.headers} onChange={headers => set({answer: {...answer, headers}})} rows={3}/>
						<Field label={t("subs.nfBody")} hint={t("subs.nfBodyHint")} optional>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={6} value={answer.body} onChange={event => set({answer: {...answer, body: event.target.value}})}/>}</Field>
					</>}
				</div>
			</section>
			<section className="p-section" id="set-profiles">
				{head("profiles")}
				<ProfilesEditor value={profiles} onChange={text => set({profiles: text})}/>
			</section>
		</Glass>
		{(changed || error !== null) && <Glass className="p-savebar" layer="chrome" role="region" aria-label={t("settings.unsaved")}>
			{error ? <ErrorNote error={error}/> : <span>{t("settings.unsavedBody")}</span>}
			<div className="p-cluster"><Button variant="quiet" onClick={() => { setForm(base); setError(null); }}>{t("config.undo")}</Button><Button type="submit" variant="primary" disabled={busy || !changed}>{t("common.save")}</Button></div>
		</Glass>}
	</form>;
}

function Keys() {
	const {t, date} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), keys = useLoad(() => api("get", "/signing-keys"), []), [ask, setAsk] = useState<"rotate" | "finish" | null>(null), [error, setError] = useState<unknown>(null);
	const list = keys.data?.keys ?? [], current = list.filter(k => k.state === "current");
	const run = (path: "/signing-keys/rotate" | "/signing-keys/finish") => { setError(null); void guard(() => api("post", path)).then(answer => { keys.set(answer); toast({tone: "success", title: t("common.saved")}); }, setError); };
	return <Glass className="p-panel" id="set-keys">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2" tabIndex={-1}>{t("subs.tab.keys")}</h2><p>{t("subs.keysLead")}</p></div>
			<div className="p-cluster">
				{current.length < 2 && <Button size="sm" onClick={() => setAsk("rotate")}>{t("subs.rotate")}</Button>}
				{current.length > 1 && <Button size="sm" variant="primary" onClick={() => setAsk("finish")}>{t("subs.finish")}</Button>}
			</div>
		</div>
		{keys.error && !keys.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={keys.reload}>{t("action.retry")}</Button>}>{say(keys.error)}</StateBlock>
		: !keys.data ? <StateBlock kind="loading" title={t("common.loading")}/> : list.length === 0 ? <StateBlock kind="empty" title={t("subs.noKeys")}>{t("subs.noKeysBody")}</StateBlock> : <List label={t("subs.tab.keys")}>{list.map(k => <ListRow key={k.kid} title={<span className="vw-code">{k.fingerprint}</span>} detail={k.state === "current" ? t("subs.key.made", {date: date(new Date(k.created * 1000))}) : t("subs.key.retired", {date: date(new Date((k.retired_at ?? k.created) * 1000))})} trailing={<Mark tone={k.state === "current" ? "success" : "muted"}>{k.state === "current" ? t("subs.key.current") : t("subs.key.retiredShort")}</Mark>}/>)}</List>}
		<ErrorNote error={error}/>
		<ConfirmDialog open={ask !== null} onOpenChange={o => { if (!o) setAsk(null); }} danger={ask === "finish"} title={t(ask === "finish" ? "subs.finishTitle" : "subs.rotateTitle")} body={t(ask === "finish" ? "subs.finishBody" : "subs.rotateBody")} confirmLabel={t(ask === "finish" ? "subs.finish" : "subs.rotate")} onConfirm={() => run(ask === "finish" ? "/signing-keys/finish" : "/signing-keys/rotate")}/>
	</Glass>;
}
