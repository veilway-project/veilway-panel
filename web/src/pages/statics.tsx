import {Banner, Button, IconButton, NumberField, StateBlock, TextField, useToast} from "@veilway/ui";
import {api, type Settings} from "../api.ts";
import {Copyable, ErrorNote, Mark, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {useState} from "react";

// Static mirrors: plain file hosting that holds a sealed copy of each device's document. The addresses and the interval are part of the settings form and save with it. What the panel has made of them comes from its own route, as of the last save.
export function StaticMirrors({draft, patch, saved}: {draft: Settings, patch: (change: Partial<Settings>) => void, saved: Settings}) {
	const {t} = useP(), bases = draft.static_mirrors ?? [];
	return <section className="p-section" id="set-static">
		<div><h2 className="vw-h3" tabIndex={-1}>{t("settings.static")}</h2><p>{t("settings.staticLead")}</p></div>
		<div className="p-form">
			{bases.length === 0 ? <p className="vw-muted vw-small">{t("static.none")}</p> : <>
				{bases.map((url, i) => <div key={i} className="p-static-url">
					<TextField label={t("static.url", {number: i + 1})} type="url" placeholder="https://" value={url} onChange={value => patch({static_mirrors: bases.map((other, j) => j === i ? value.trim() : other)})} technical/>
					<IconButton icon="close" label={t("static.remove", {number: i + 1})} onClick={() => patch({static_mirrors: bases.filter((_, j) => j !== i)})}/>
				</div>)}
				<p className="vw-muted vw-small">{t("static.urlHint")}</p>
			</>}
			{bases.length < 4 && <div><Button size="sm" icon="plus" onClick={() => patch({static_mirrors: [...bases, ""]})}>{t("static.add")}</Button></div>}
			{bases.length > 0 && <NumberField label={t("static.interval")} hint={t("static.intervalHint")} unit={t("static.hours")} min={1} max={12} value={draft.static_interval ?? 6} onChange={value => patch({static_interval: value === "" ? 6 : value})}/>}
			<Folders saved={saved}/>
		</div>
	</section>;
}

function Folders({saved}: {saved: Settings}) {
	const {t, date, time, bytes} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState("");
	const status = useLoad(() => api("get", "/static"), [JSON.stringify([saved.static_mirrors, saved.static_interval])]);
	if ((saved.static_mirrors ?? []).length === 0) return null;
	if (status.error && !status.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={status.reload}>{t("action.retry")}</Button>}>{say(status.error)}</StateBlock>;
	if (!status.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const {folders, last_round, next_round, error: failure} = status.data, when = (at: number) => date(new Date(at * 1000), {month: "short", day: "numeric"}) + " " + time(new Date(at * 1000));
	const download = async (label: string) => {
		setBusy(label);
		setError(null);
		try {
			const made = await guard(() => api("post", "/static/{label}/zip", {params: {label}}));
			const link = document.createElement("a");
			link.href = URL.createObjectURL(new Blob([Uint8Array.from(atob(made.file), char => char.charCodeAt(0))], {type: "application/zip"}));
			link.download = made.filename;
			link.click();
			URL.revokeObjectURL(link.href);
			toast({tone: "success", title: t("static.downloaded")});
		} catch (failed) {
			setError(failed);
		} finally {
			setBusy("");
		}
	};
	return <div className="p-static">
		<dl className="p-static-facts">
			<div><dt>{t("static.last")}</dt><dd className="vw-num">{last_round ? when(last_round) : t("static.noRound")}</dd></div>
			<div><dt>{t("static.next")}</dt><dd className="vw-num">{next_round ? when(next_round) : t("common.never")}</dd></div>
		</dl>
		{failure && <Banner tone="danger" title={t("static.failed")}>{failure}</Banner>}
		{folders.map(folder => <div key={folder.label} className="p-mirror">
			<div className="p-row"><strong className="vw-code">{folder.base_url}</strong>{folder.shared_host ? <Mark tone="success">{t("static.shared")}</Mark> : <Mark tone="warning">{t("static.ownHost")}</Mark>}</div>
			<p className="vw-small">{folder.files == null || folder.size == null ? t("static.waiting") : <>{t("static.files", {count: folder.files})}, {t("static.each", {size: bytes(folder.size).text})}. <span className="vw-muted">{t("static.filesHint")}</span></>}{folder.written_at ? " " + t("static.written", {when: when(folder.written_at)}) : ""}</p>
			<Copyable label={t("static.folder")} value={folder.path}/>
			<p className="vw-muted vw-small">{t("static.syncLead")}</p>
			{folder.sync.map(hint => <Copyable key={hint.tool} label={hint.tool} value={hint.command}/>)}
			<div><Button size="sm" icon="download" disabled={busy !== "" || folder.files == null} onClick={() => void download(folder.label)}>{t("static.download")}</Button></div>
		</div>)}
		<ErrorNote error={error}/>
	</div>;
}
