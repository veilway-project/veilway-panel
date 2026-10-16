import {Banner, Button, Dialog, Glass, IconButton, Segmented, StateBlock, TextField} from "@veilway/ui";
import {useState} from "react";
import {useP, useSay} from "../kit.tsx";
import {SectionReview, useRunning} from "./apply.tsx";

type Notice = {severity?: "information" | "warning", text: string};
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

function NoticeDialog({notice, others, onClose, onSave}: {notice: Notice | null, others: Notice[], onClose: () => void, onSave: (notice: Notice) => void}) {
	const {t, number} = useP(), [severity, setSeverity] = useState(notice?.severity ?? "information"), [text, setText] = useState(notice?.text ?? ""), [tried, setTried] = useState(false);
	const used = size(text.trim()), problem = !text.trim() ? t("notices.needText") : used > BYTES ? t("notices.tooLong", {count: BYTES}) : HIDDEN.test(text) ? t("notices.hidden") : others.some(other => other.text === text.trim() && (other.severity ?? "information") === severity) ? t("notices.twice") : undefined;
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t(notice ? "notices.editTitle" : "notices.addTitle")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); setTried(true); if (!problem) onSave({severity, text: text.trim()}); }} noValidate>
			<div className="vw-field"><span className="vw-label">{t("notices.severity")}</span><Segmented label={t("notices.severity")} value={severity} onChange={value => setSeverity(value as typeof severity)} options={[{value: "information", label: t("notices.information")}, {value: "warning", label: t("notices.warning")}]}/></div>
			<TextField label={t("notices.text")} hint={t("notices.textHint")} value={text} onChange={value => setText(value.replace(/[\r\n]+/g, " "))} error={tried || used > BYTES ? problem : undefined} required autoFocus/>
			<p className="vw-small p-count-line" data-over={used > BYTES ? "" : undefined} aria-live="polite">{t("notices.bytes", {used: number(used), limit: number(BYTES)})}</p>
			<div className="vw-field"><span className="vw-label">{t("notices.preview")}</span><div dir={text.trim() ? "auto" : undefined}><Banner tone={severity === "warning" ? "warning" : "info"} title={text.trim() || t("notices.previewEmpty")}/></div></div>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary">{t(notice ? "notices.keep" : "notices.add")}</Button></div>
		</form>
	</Dialog>;
}
