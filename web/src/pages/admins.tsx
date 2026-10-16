import {Banner, Button, ConfirmDialog, Dialog, Glass, List, ListRow, StateBlock, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type AdminRow, type Totp} from "../api.ts";
import {Copyable, ErrorNote, Mark, Qr, useGuard, useLoad, useP, useSay} from "../kit.tsx";

const NAME = /^[a-z0-9._-]{3,32}$/;

// Everyone who can sign in. Adding and resetting end on the new authenticator key, shown once; removing never offers yourself, and the server refuses the last admin too.
export function AdminsTab() {
	const {t, date} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), admins = useLoad(() => api("get", "/admins"), []);
	const [form, setForm] = useState<{kind: "add"} | {kind: "reset", admin: AdminRow} | null>(null), [removing, setRemoving] = useState<AdminRow | null>(null), [shown, setShown] = useState<{name: string, totp: Totp, reset: boolean} | null>(null);
	const [name, setName] = useState(""), [password, setPassword] = useState(""), [again, setAgain] = useState(""), [tried, setTried] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null);
	const target = form?.kind === "reset" ? form.admin.username : name.trim();
	const problems = {name: form?.kind === "add" && !NAME.test(name.trim()) ? t("error.username") : undefined, password: password.length >= 12 && password.length <= 256 ? undefined : t("error.password"), again: again === password ? undefined : t("error.passwordMatch")};
	const open = (next: typeof form) => { setName(""); setPassword(""); setAgain(""); setTried(false); setError(null); setForm(next); };
	const submit = async () => {
		setTried(true);
		if (!form || problems.name || problems.password || problems.again) return;
		setBusy(true);
		setError(null);
		try {
			const totp = form.kind === "add" ? await guard(() => api("post", "/admins", {body: {username: target, password}})) : await guard(() => api("post", "/admins/{id}/reset", {params: {id: form.admin.id}, body: {new_password: password}}));
			if (totp.totp_secret) setShown({name: target, totp, reset: form.kind === "reset"}); else toast({tone: "success", title: t("twostep.noCode", {name: target})});
			setForm(null);
			admins.reload();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const list = admins.data?.admins ?? [];
	return <Glass className="p-panel">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2">{t("admins.title")}</h2><p>{t("admins.lead")}</p></div>
			<Button icon="plus" onClick={() => open({kind: "add"})}>{t("admins.add")}</Button>
		</div>
		{admins.error && !admins.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={admins.reload}>{t("action.retry")}</Button>}>{say(admins.error)}</StateBlock>
		: !admins.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <List label={t("admins.title")}>{list.map(a => <ListRow key={a.id} title={<span className="p-flags"><strong className="vw-code">{a.username}</strong>{a.you && <span className="vw-muted vw-small">{t("admins.you")}</span>}</span>} detail={<span className="p-meta"><span>{t("admins.added", {date: date(new Date(a.created * 1000))})}</span><span>{a.last_login ? t("admins.lastLogin", {date: date(new Date(a.last_login * 1000), {dateStyle: "medium", timeStyle: "short"})}) : t("admins.neverLogin")}</span>{a.totp_used ? <Mark tone="success">{t("admins.codeSet")}</Mark> : <Mark tone="warning" title={t("admins.codeUnusedHint")}>{t("admins.codeUnused")}</Mark>}</span>} trailing={a.you ? undefined : <span className="p-cluster">
			<Button size="sm" variant="quiet" aria-label={t("admins.resetName", {name: a.username})} onClick={() => open({kind: "reset", admin: a})}>{t("admins.reset")}</Button>
			{list.length > 1 && <Button size="sm" variant="quiet" aria-label={t("admins.removeName", {name: a.username})} onClick={() => setRemoving(a)}>{t("common.remove")}</Button>}
		</span>}/>)}</List>}
		<Dialog open={form !== null} onOpenChange={o => { if (!o) setForm(null); }} title={form?.kind === "reset" ? t("admins.resetTitle", {name: target}) : t("admins.add")} description={form?.kind === "reset" ? t("admins.resetBody", {name: target}) : t("admins.addBody")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }} noValidate>
				{form?.kind === "add" && <TextField label={t("setup.username")} hint={t("admins.nameHint")} autoComplete="off" value={name} onChange={value => setName(value.toLowerCase())} error={tried ? problems.name : undefined} maxLength={32} technical autoFocus/>}
				<TextField label={t(form?.kind === "reset" ? "security.newPassword" : "setup.password")} hint={t("admins.passwordHint")} type="password" autoComplete="new-password" value={password} onChange={setPassword} error={tried ? problems.password : undefined}/>
				<TextField label={t(form?.kind === "reset" ? "security.confirm" : "setup.confirm")} type="password" autoComplete="new-password" value={again} onChange={setAgain} error={tried ? problems.again : undefined}/>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setForm(null)}>{t("action.cancel")}</Button><Button type="submit" variant={form?.kind === "reset" ? "danger" : "primary"} disabled={busy}>{form?.kind === "reset" ? t("admins.resetSubmit") : t("admins.addSubmit")}</Button></div>
			</form>
		</Dialog>
		<Dialog open={shown !== null} onOpenChange={o => { if (!o) setShown(null); }} title={t(shown?.reset ? "admins.shownResetTitle" : "admins.shownTitle", {name: shown?.name ?? ""})} description={t("admins.shownBody", {name: shown?.name ?? ""})}>
			{shown && <div className="p-stack">
				<Banner tone="warning" title={t("admins.copyNow")}>{t("admins.copyNowBody", {name: shown.name})}</Banner>
				<Qr text={shown.totp.otpauth} label={t("admins.qr", {name: shown.name})}/>
				<Copyable label={t("totp.key")} value={shown.totp.totp_secret}/>
				<div className="vw-dialog-foot"><Button variant="primary" onClick={() => setShown(null)}>{t("admins.shownDone")}</Button></div>
			</div>}
		</Dialog>
		<ConfirmDialog open={removing !== null} onOpenChange={o => { if (!o) setRemoving(null); }} danger title={t("admins.removeTitle", {name: removing?.username ?? ""})} body={t("admins.removeBody", {name: removing?.username ?? ""})} confirmLabel={t("admins.removeName", {name: removing?.username ?? ""})} onConfirm={() => { const a = removing!; void guard(() => api("delete", "/admins/{id}", {params: {id: a.id}})).then(() => { toast({tone: "success", title: t("admins.removed", {name: a.username})}); admins.reload(); }, failure => toast({tone: "danger", title: say(failure)})); }}/>
	</Glass>;
}
