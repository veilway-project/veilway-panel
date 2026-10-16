import {Banner, Button, Dialog, StateBlock, useToast} from "@veilway/ui";
import {useEffect, useState, type ReactNode} from "react";
import {api, ApiError, type Diff, type Report, type Running} from "../api.ts";
import {ErrorNote, Issues, useGuard, useLoad, useP} from "../kit.tsx";
import {loadRunning} from "./config.tsx";

export type NodeSection = "notices" | "dns" | "log" | "links" | "replay";

// The running config, read once per page, so every change below is made on the revision the page shows.
export const useRunning = () => useLoad(loadRunning, []);

// The same two steps as the config pages: a dry run on the node, then the apply on the revision read. summary says what the change is in the reader's words, since the node's diff does not name these sections. With section "document", value is the whole document, for one change that spans sections.
export function SectionReview({section, running, value, summary, onClose, onDone}: {section: NodeSection | "document", running: Running, value: unknown, summary: ReactNode, onClose: () => void, onDone: (applied: boolean) => void}) {
	const {t} = useP(), guard = useGuard(), toast = useToast(), [answer, setAnswer] = useState<{valid: boolean, report: Report, diff: Diff | null} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [stale, setStale] = useState(false), [refused, setRefused] = useState<Report | null>(null);
	useEffect(() => { api("post", "/config/diff", {body: {document: section === "document" ? value as Record<string, unknown> : {...running.document, [section]: value}}}).then(found => setAnswer(found as typeof answer), setError); }, []);
	const apply = async () => {
		setBusy(true);
		setError(null);
		try {
			const done = await guard(() => section === "document" ? api("put", "/config", {body: {revision: running.revision, document: value}}) : api("put", "/config/{section}", {params: {section}, body: {revision: running.revision, value}})) as {generation?: number};
			toast({tone: "success", title: t("config.applied", {generation: done.generation ?? running.generation + 1})});
			onDone(true);
		} catch (failure) {
			if (failure instanceof ApiError && failure.status === 409) setStale(true);
			else if (failure instanceof ApiError && failure.code === "invalid_config") { try { setRefused((JSON.parse(failure.message) as {report: Report}).report); } catch { setError(failure); } }
			else setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const report = refused ?? answer?.report, lost = answer?.diff?.user_changes?.filter(change => change.lost_access).map(change => change.name) ?? [];
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("review.title")} description={t("review.body")}>
		<div className="p-stack">
			{!answer && !error && <StateBlock kind="loading" title={t("review.asking")}/>}
			{stale && <Banner tone="warning" title={t("review.stale")} action={<Button size="sm" icon="refresh" onClick={() => onDone(false)}>{t("review.reload")}</Button>}>{t("review.staleBody")}</Banner>}
			{report && (report.errors ?? []).length > 0 && <><Banner tone="danger" title={t("review.invalid")}>{t("review.invalidBody")}</Banner><Issues issues={report.errors.map(p => ({path: p.path, text: p.message}))}/></>}
			{answer?.valid && !refused && <>{summary}{lost.length > 0 && <Banner tone="danger" title={t("review.lost", {count: lost.length})}>{lost.join(", ")}</Banner>}</>}
			{report && (report.warnings ?? []).length > 0 && <><p className="vw-label">{t("review.warnings")}</p><Issues issues={report.warnings.map(p => ({path: p.path, text: p.message}))}/></>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy || !answer?.valid || stale || refused !== null} onClick={() => void apply()}>{t("review.apply")}</Button></div>
		</div>
	</Dialog>;
}
