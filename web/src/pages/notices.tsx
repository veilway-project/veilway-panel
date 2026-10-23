import {Banner, Button, Dialog, Glass, IconButton, Segmented, StateBlock, TextField, useToast} from "@veilway/ui";
import {useContext, useState} from "react";
import {api, type Settings} from "../api.ts";
import {useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {SettingsContext} from "../settings.ts";
import {SectionReview, useRunning} from "./apply.tsx";

type Notice = {severity?: "information" | "warning", text: string, translations?: Record<string, string>};
type Own = NonNullable<Settings["subscription_notices"]>[number];
// The language tags the apps read: two or three lowercase letters, then an optional script and region.
const TAG = /^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2})?$/;
const TRANSLATIONS = 8;
const MAX = 4, BYTES = 280;
// What the node refuses on sight: control, direction and invisible characters. The joiners Persian spelling needs pass here and the node judges them.
const HIDDEN = /[\p{Cc}\u00ad\u061c\u200b\u200e\u200f\u2028-\u202e\u2060-\u206f\ufeff]/u;
const size = (text: string) => new TextEncoder().encode(text).length;

// What every connected app shows at the top, through the control channel of the veilway inbounds.
export function NoticesPanel() {
	const {t} = useP(), say = useSay(), running = useRunning(), [draft, setDraft] = useState<Notice[] | null>(null), [editing, setEditing] = useState<number | null>(null), [review, setReview] = useState(false);
	const live = (Array.isArray(running.data?.document.notices) ? running.data.document.notices : []) as Notice[], list = draft ?? live, changed = draft !== null && JSON.stringify(draft) !== JSON.stringify(live);
	return <Glass className="p-panel">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2">{t("notices.title")}</h2><p>{t("notices.lead")}</p></div>
			{running.data && <Button size="sm" icon="plus" disabled={list.length >= MAX} onClick={() => setEditing(list.length)}>{t("notices.add")}</Button>}
		</div>
		{running.error && !running.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={running.reload}>{t("action.retry")}</Button>}>{say(running.error)}</StateBlock>
		: !running.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: list.length === 0 ? <p className="vw-muted">{t("notices.empty")}</p>
		: <ul className="p-notices" aria-label={t("notices.title")}>{list.map((notice, i) => <li key={i}>
			<div dir="auto"><Banner tone={notice.severity === "warning" ? "warning" : "info"} title={notice.text}/></div>
			<span className="p-cluster"><Button size="sm" variant="quiet" onClick={() => setEditing(i)}>{t("user.edit")}</Button><IconButton icon="close" label={t("notices.remove")} onClick={() => setDraft(list.filter((_, j) => j !== i))}/></span>
		</li>)}</ul>}
		{running.data && list.length >= MAX && <p className="vw-small vw-muted">{t("notices.full", {count: MAX})}</p>}
		{changed && <div className="p-form-foot"><Button variant="quiet" onClick={() => setDraft(null)}>{t("config.undo")}</Button><Button variant="primary" onClick={() => setReview(true)}>{t("config.review")}</Button></div>}
		{editing !== null && <NoticeDialog notice={list[editing] ?? null} others={list.filter((_, i) => i !== editing)} onClose={() => setEditing(null)} onSave={notice => { setDraft(list.length > editing ? list.map((old, i) => i === editing ? notice : old) : [...list, notice]); setEditing(null); }}/>}
		{review && running.data && draft && <SectionReview section="notices" running={running.data} value={draft} summary={<p>{t("notices.summary", {count: draft.length})}</p>} onClose={() => setReview(false)} onDone={() => { setReview(false); setDraft(null); running.reload(); }}/>}
	</Glass>;
}

function NoticeDialog({notice, others, translate, onClose, onSave}: {notice: Notice | null, others: Notice[], translate?: boolean, onClose: () => void, onSave: (notice: Notice) => void}) {
	const {t, number} = useP(), [severity, setSeverity] = useState(notice?.severity ?? "information"), [text, setText] = useState(notice?.text ?? ""), [tried, setTried] = useState(false);
	const [rows, setRows] = useState(() => Object.entries(notice?.translations ?? {}).map(([tag, value]) => ({tag, value})));
	const rowProblem = (row: {tag: string, value: string}, i: number) => !TAG.test(row.tag) ? t("notices.tagWrong") : rows.some((other, j) => j < i && other.tag === row.tag) ? t("notices.tagTwice") : !row.value.trim() ? t("notices.needText") : size(row.value.trim()) > BYTES ? t("notices.tooLong", {count: BYTES}) : HIDDEN.test(row.value) ? t("notices.hidden") : undefined;
	const used = size(text.trim()), problem = !text.trim() ? t("notices.needText") : used > BYTES ? t("notices.tooLong", {count: BYTES}) : HIDDEN.test(text) ? t("notices.hidden") : others.some(other => other.text === text.trim() && (other.severity ?? "information") === severity) ? t("notices.twice") : undefined;
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t(notice ? "notices.editTitle" : "notices.addTitle")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); setTried(true); if (!problem && !rows.some(rowProblem)) onSave({severity, text: text.trim(), ...(translate ? {translations: Object.fromEntries(rows.map(row => [row.tag, row.value.trim()]))} : {})}); }} noValidate>
			<div className="vw-field"><span className="vw-label">{t("notices.severity")}</span><Segmented label={t("notices.severity")} value={severity} onChange={value => setSeverity(value as typeof severity)} options={[{value: "information", label: t("notices.information")}, {value: "warning", label: t("notices.warning")}]}/></div>
			<TextField label={t("notices.text")} hint={t("notices.textHint")} value={text} onChange={value => setText(value.replace(/[\r\n]+/g, " "))} error={tried || used > BYTES ? problem : undefined} required autoFocus/>
			<p className="vw-small p-count-line" data-over={used > BYTES ? "" : undefined} aria-live="polite">{t("notices.bytes", {used: number(used), limit: number(BYTES)})}</p>
			<div className="vw-field"><span className="vw-label">{t("notices.preview")}</span><div dir={text.trim() ? "auto" : undefined}><Banner tone={severity === "warning" ? "warning" : "info"} title={text.trim() || t("notices.previewEmpty")}/></div></div>
			{translate && <div className="p-stack">
				<div className="vw-field"><span className="vw-label">{t("notices.translations")}</span><p className="vw-small vw-muted">{t("notices.translationsHint")}</p></div>
				{rows.map((row, i) => <div className="p-stack" key={i}>
					<div className="p-lang">
						<TextField label={t("notices.tag")} placeholder="de" value={row.tag} onChange={value => setRows(rows.map((old, j) => j === i ? {...old, tag: value.trim()} : old))} error={tried ? rowProblem(row, i) : undefined} technical/>
						<TextField label={t("notices.text")} value={row.value} onChange={value => setRows(rows.map((old, j) => j === i ? {...old, value: value.replace(/[\r\n]+/g, " ")} : old))} lang={TAG.test(row.tag) ? row.tag : undefined}/>
						<IconButton icon="close" label={t("notices.removeTranslation")} onClick={() => setRows(rows.filter((_, j) => j !== i))}/>
					</div>
					<p className="vw-small p-count-line" data-over={size(row.value.trim()) > BYTES ? "" : undefined}>{t("notices.bytes", {used: number(size(row.value.trim())), limit: number(BYTES)})}</p>
				</div>)}
				<div><Button size="sm" icon="plus" disabled={rows.length >= TRANSLATIONS} onClick={() => setRows([...rows, {tag: "", value: ""}])}>{t("notices.addTranslation")}</Button></div>
			</div>}
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t(notice ? "notices.keep" : "notices.add")}</Button></div>
		</form>
	</Dialog>;
}

// What apps keep from their last refresh and show with no connection. It is a panel setting, so it saves with its own button and reaches the next document of every account at once.
export function SubscriptionNoticesPanel() {
	const {t} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), shared = useContext(SettingsContext), saved = useLoad(() => api("get", "/settings"), []), [draft, setDraft] = useState<Notice[] | null>(null), [editing, setEditing] = useState<number | null>(null), [busy, setBusy] = useState(false), [failure, setFailure] = useState<unknown>(null);
	const live: Notice[] = (saved.data?.subscription_notices ?? []).map(own => ({severity: own.severity === "warning" ? "warning" : "information", text: own.text, translations: own.translations ?? {}})), list = draft ?? live, changed = draft !== null && JSON.stringify(draft) !== JSON.stringify(live);
	const save = async () => {
		if (!saved.data || !draft) return;
		setBusy(true);
		setFailure(null);
		try {
			const {faketls_keys: _kept, inbound_keys: _keys, transport_keys: _transport, ...sent} = await guard(() => api("get", "/settings"));
			const stored = await guard(() => api("put", "/settings", {body: {...sent, subscription_notices: draft.map((notice): Own => ({severity: notice.severity === "warning" ? "warning" : "info", text: notice.text, translations: notice.translations ?? {}}))} as Settings}));
			shared.set(stored);
			saved.set(stored);
			setDraft(null);
			toast({tone: "success", title: t("common.saved")});
		} catch (error) {
			setFailure(error);
		} finally {
			setBusy(false);
		}
	};
	return <Glass className="p-panel">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2">{t("subNotices.title")}</h2><p>{t("subNotices.lead")}</p></div>
			{saved.data && <Button size="sm" icon="plus" disabled={list.length >= MAX} onClick={() => setEditing(list.length)}>{t("notices.add")}</Button>}
		</div>
		{saved.error && !saved.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={saved.reload}>{t("action.retry")}</Button>}>{say(saved.error)}</StateBlock>
		: !saved.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: list.length === 0 ? <p className="vw-muted">{t("subNotices.empty")}</p>
		: <ul className="p-notices" aria-label={t("subNotices.title")}>{list.map((notice, i) => <li key={i}>
			<div dir="auto"><Banner tone={notice.severity === "warning" ? "warning" : "info"} title={notice.text}>{Object.keys(notice.translations ?? {}).length > 0 && <span className="vw-small">{t("subNotices.languages", {tags: Object.keys(notice.translations ?? {}).join(", ")})}</span>}</Banner></div>
			<span className="p-cluster"><Button size="sm" variant="quiet" onClick={() => setEditing(i)}>{t("user.edit")}</Button><IconButton icon="close" label={t("notices.remove")} onClick={() => setDraft(list.filter((_, j) => j !== i))}/></span>
		</li>)}</ul>}
		{saved.data && <p className="vw-small vw-muted">{list.length >= MAX ? t("subNotices.full", {count: MAX}) : t("subNotices.hint")}</p>}
		{failure !== null && <p className="vw-small" role="alert">{say(failure)}</p>}
		{changed && <div className="p-form-foot"><Button variant="quiet" disabled={busy} onClick={() => setDraft(null)}>{t("config.undo")}</Button><Button variant="primary" disabled={busy} onClick={() => void save()}>{t("subNotices.save")}</Button></div>}
		{editing !== null && <NoticeDialog translate notice={list[editing] ?? null} others={list.filter((_, i) => i !== editing)} onClose={() => setEditing(null)} onSave={notice => { setDraft(list.length > editing ? list.map((old, i) => i === editing ? notice : old) : [...list, notice]); setEditing(null); }}/>}
	</Glass>;
}
