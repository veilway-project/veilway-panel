import {Button, DataTable, Glass, List, ListRow, Segmented, StateBlock, Tabs, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type AuditRow, type Totp} from "../api.ts";
import {BackupTab} from "./backup.tsx";
import {ErrorNote, PageHead, TotpShown, useGuard, useLoad, useP, useSay} from "../kit.tsx";

export type Prefs = {locale: "en" | "fa", scheme: "system" | "dark" | "light"};

const TABS = ["sessions", "security", "audit", "backup", "display"];

export function AccountPage({tab, username, prefs, onPrefs, onLogout}: {tab: string, username: string, prefs: Prefs, onPrefs: (prefs: Prefs) => void, onLogout: () => void}) {
	const {t} = useP();
	return <>
		<PageHead title={t("account.title")} lead={t("account.lead", {name: username})}><Button icon="power" onClick={onLogout}>{t("account.logout")}</Button></PageHead>
		<Tabs label={t("account.title")} value={TABS.includes(tab) ? tab : "sessions"} onChange={id => { location.hash = "#/account/" + id; }} items={[
			{id: "sessions", label: t("account.tab.sessions"), content: <Sessions/>},
			{id: "security", label: t("account.tab.security"), content: <Security/>},
			{id: "audit", label: t("account.tab.audit"), content: <Audit/>},
			{id: "backup", label: t("account.tab.backup"), content: <BackupTab/>},
			{id: "display", label: t("account.tab.display"), content: <Glass className="p-panel p-form">
				<div className="p-field-row"><span className="vw-label">{t("display.scheme")}</span><Segmented label={t("display.scheme")} value={prefs.scheme} onChange={scheme => onPrefs({...prefs, scheme: scheme as Prefs["scheme"]})} options={[{value: "system", label: t("display.system")}, {value: "dark", label: t("display.dark")}, {value: "light", label: t("display.light")}]}/></div>
				<div className="p-field-row"><span className="vw-label">{t("display.language")}</span><Segmented label={t("display.language")} value={prefs.locale} onChange={locale => onPrefs({...prefs, locale: locale as Prefs["locale"]})} options={[{value: "en", label: "English"}, {value: "fa", label: "فارسی"}]}/></div>
			</Glass>}
		]}/>
	</>;
}

function Sessions() {
	const {t, date} = useP(), say = useSay(), toast = useToast(), sessions = useLoad(() => api("get", "/sessions"), []);
	if (sessions.error && !sessions.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={sessions.reload}>{t("action.retry")}</Button>}>{say(sessions.error)}</StateBlock>;
	if (!sessions.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	return <Glass className="p-panel"><List label={t("account.tab.sessions")}>{sessions.data.sessions.map(s => <ListRow key={s.id} title={s.current ? t("sessions.current") : s.agent || s.source} detail={<span className="p-meta"><span>{t("sessions.detail", {source: s.source, date: date(new Date(s.last_seen * 1000), {dateStyle: "medium", timeStyle: "short"})})}</span><span>{t("sessions.started", {date: date(new Date(s.created * 1000))})}</span></span>} trailing={s.current ? undefined : <Button size="sm" variant="quiet" onClick={() => void api("delete", "/sessions/{sid}", {params: {sid: s.id}}).then(() => { toast({tone: "success", title: t("sessions.ended")}); sessions.reload(); }, failure => toast({tone: "danger", title: say(failure)}))}>{t("sessions.end")}</Button>}/>)}</List></Glass>;
}

function Security() {
	const {t} = useP(), guard = useGuard(), toast = useToast(), [password, setPassword] = useState(""), [again, setAgain] = useState(""), [tried, setTried] = useState(false);
	const [error, setError] = useState<unknown>(null), [totpError, setTotpError] = useState<unknown>(null), [busy, setBusy] = useState(false), [totp, setTotp] = useState<Totp | null>(null);
	const problems = {password: password.length >= 12 && password.length <= 256 ? undefined : t("error.password"), again: again === password ? undefined : t("error.passwordMatch")};
	const change = async () => {
		setTried(true);
		if (problems.password || problems.again) return;
		setBusy(true);
		setError(null);
		try {
			await guard(() => api("post", "/account/password", {body: {new_password: password}}));
			setPassword("");
			setAgain("");
			setTried(false);
			toast({tone: "success", title: t("security.passwordDone")});
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <div className="p-columns">
		<Glass className="p-panel">
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void change(); }} noValidate>
				<div><h2 className="vw-h2">{t("security.password")}</h2><p className="vw-muted">{t("security.passwordLead")}</p></div>
				<TextField label={t("security.newPassword")} hint={t("setup.passwordHint")} type="password" autoComplete="new-password" value={password} onChange={setPassword} error={tried ? problems.password : undefined}/>
				<TextField label={t("security.confirm")} type="password" autoComplete="new-password" value={again} onChange={setAgain} error={tried ? problems.again : undefined}/>
				<ErrorNote error={error}/>
				<div><Button type="submit" variant="primary" disabled={busy}>{t("security.password")}</Button></div>
			</form>
		</Glass>
		<Glass className="p-panel">
			{totp ? <TotpShown totp={totp} done={t("totp.doneAccount")} onDone={() => setTotp(null)}/> : <>
				<div><h2 className="vw-h2">{t("security.totp")}</h2><p className="vw-muted">{t("security.totpLead")}</p></div>
				<ErrorNote error={totpError}/>
				<div><Button onClick={() => { setTotpError(null); void guard(() => api("post", "/account/totp")).then(setTotp, setTotpError); }}>{t("security.totpButton")}</Button></div>
			</>}
		</Glass>
	</div>;
}

function Audit() {
	const {t, date, time} = useP(), say = useSay(), [older, setOlder] = useState<AuditRow[]>([]), [more, setMore] = useState(true), [error, setError] = useState<unknown>(null);
	const first = useLoad(() => api("get", "/audit", {query: {limit: 50}}), []);
	if (first.error && !first.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={first.reload}>{t("action.retry")}</Button>}>{say(first.error)}</StateBlock>;
	if (!first.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const rows = [...first.data.entries, ...older], last = rows[rows.length - 1];
	return <Glass className="p-panel">
		<DataTable caption={t("account.tab.audit")} rows={rows} rowKey={r => String(r.id)} empty={<StateBlock kind="empty" title={t("audit.empty")}>{t("audit.emptyBody")}</StateBlock>} columns={[
			{id: "when", header: t("audit.col.when"), cell: r => <span className="vw-num">{date(new Date(r.at * 1000), {month: "short", day: "numeric"}) + " " + time(new Date(r.at * 1000))}</span>},
			{id: "who", header: t("audit.col.who"), cell: r => <span className="vw-code">{r.actor}</span>},
			{id: "action", header: t("audit.col.action"), cell: r => <span className="p-user"><span className="vw-code">{r.action}</span>{r.detail && <span className="vw-muted vw-small">{r.detail}</span>}</span>},
			{id: "target", header: t("audit.col.target"), cell: r => <span className="vw-code">{r.target}</span>},
			{id: "source", header: t("audit.col.source"), cell: r => <span className="vw-code vw-muted">{r.source}</span>}
		]}/>
		<ErrorNote error={error}/>
		{more && rows.length >= 50 && last && <div><Button onClick={() => void api("get", "/audit", {query: {limit: 50, before: last.id}}).then(answer => { setOlder([...older, ...answer.entries]); setMore(answer.entries.length === 50); }, setError)}>{t("audit.older")}</Button></div>}
	</Glass>;
}
