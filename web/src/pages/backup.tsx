import {Banner, Button, ConfirmDialog, Field, Glass, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api} from "../api.ts";
import {ErrorNote, useGuard, useP} from "../kit.tsx";

const FILE_MAX = 64 * 1024 * 1024, PASSPHRASE_MIN = 12;

export function BackupTab() {
	const {t} = useP(), guard = useGuard(), toast = useToast(), [passphrase, setPassphrase] = useState(""), [again, setAgain] = useState(""), [tried, setTried] = useState(false), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const [file, setFile] = useState<File | null>(null), [restorePass, setRestorePass] = useState(""), [asking, setAsking] = useState(false), [restoreError, setRestoreError] = useState<unknown>(null), [restoring, setRestoring] = useState(false), [restored, setRestored] = useState(false), [warnings, setWarnings] = useState<string[]>([]), [triedRestore, setTriedRestore] = useState(false);
	const problems = {passphrase: passphrase.length >= PASSPHRASE_MIN ? undefined : t("backup.error.length"), again: again === passphrase ? undefined : t("backup.error.match")};
	const fileProblem = !file ? t("backup.error.noFile") : file.size > FILE_MAX ? t("backup.error.size") : undefined;
	const download = async () => {
		setTried(true);
		if (problems.passphrase || problems.again) return;
		setBusy(true);
		setError(null);
		try {
			const made = await guard(() => api("post", "/backup/download", {body: {passphrase}}));
			const link = document.createElement("a");
			link.href = URL.createObjectURL(new Blob([Uint8Array.from(atob(made.file), char => char.charCodeAt(0))], {type: "application/octet-stream"}));
			link.download = made.filename;
			link.click();
			URL.revokeObjectURL(link.href);
			setPassphrase("");
			setAgain("");
			setTried(false);
			toast({tone: "success", title: t("backup.download.done")});
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const restore = async () => {
		if (!file) return;
		setRestoring(true);
		setRestoreError(null);
		try {
			const bytes = new Uint8Array(await file.arrayBuffer());
			let binary = "";
			for (let at = 0; at < bytes.length; at += 0x8000) binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
			const before = (await api("get", "/status")).start_id;
			const done = await guard(() => api("post", "/backup/restore", {body: {file: btoa(binary), passphrase: restorePass}}));
			setRestored(true);
			// The panel stops and starts again on the restored files. The page reloads once the server answers with another start id; the old sessions are gone, so it lands on the sign-in page.
			for (let tries = 0; tries < 120; tries++) {
				await new Promise(resolve => setTimeout(resolve, 1000));
				const now = await api("get", "/status").then(status => status.start_id, () => null);
				if (now !== null && now !== before) break;
			}
			// What the restore found about the gateway keys is read before the page goes on, since the reload lands on the sign-in page.
			if (done.warnings.length > 0) { setWarnings(done.warnings); return; }
			location.reload();
		} catch (failure) {
			setRestoreError(failure);
			setRestoring(false);
		}
	};
	return <div className="p-columns">
		<Glass className="p-panel">
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void download(); }} noValidate>
				<div><h2 className="vw-h2">{t("backup.download.title")}</h2><p className="vw-muted">{t("backup.download.lead")}</p></div>
				<Banner tone="warning" title={t("backup.download.warn")}/>
				<TextField label={t("backup.passphrase")} hint={t("backup.passphraseHint")} type="password" autoComplete="new-password" value={passphrase} onChange={setPassphrase} error={tried ? problems.passphrase : undefined}/>
				<TextField label={t("backup.passphraseAgain")} type="password" autoComplete="new-password" value={again} onChange={setAgain} error={tried ? problems.again : undefined}/>
				<ErrorNote error={error}/>
				<div><Button type="submit" variant="primary" icon="download" disabled={busy}>{t("backup.download.button")}</Button></div>
			</form>
		</Glass>
		<Glass className="p-panel">
			<form className="p-stack" onSubmit={event => { event.preventDefault(); setTriedRestore(true); if (!fileProblem && restorePass) setAsking(true); }} noValidate>
				<div><h2 className="vw-h2">{t("backup.restore.title")}</h2><p className="vw-muted">{t("backup.restore.lead")}</p></div>
				<Field label={t("backup.file")} error={triedRestore ? fileProblem : undefined}>{ids => <input {...ids} className="vw-input" type="file" accept=".vwbackup" onChange={event => setFile(event.target.files?.[0] ?? null)}/>}</Field>
				<TextField label={t("backup.passphrase")} type="password" autoComplete="off" value={restorePass} onChange={setRestorePass} error={triedRestore && !restorePass ? t("backup.error.passphrase") : undefined}/>
				<ErrorNote error={restoreError}/>
				{restored && <Banner tone="info" title={t("backup.restore.done")}/>}
				{warnings.length > 0 && <Banner tone="warning" title={t("backup.restore.warnTitle")} action={<Button size="sm" onClick={() => location.reload()}>{t("backup.restore.continue")}</Button>}>{warnings.join(" ")}</Banner>}
				<div><Button type="submit" variant="danger" disabled={restoring}>{t("backup.restore.button")}</Button></div>
			</form>
		</Glass>
		<ConfirmDialog open={asking} onOpenChange={setAsking} danger title={t("backup.restore.confirmTitle")} body={t("backup.restore.confirmBody")} confirmLabel={t("backup.restore.confirm")} onConfirm={() => void restore()}/>
	</div>;
}
