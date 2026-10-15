import {Button, ConfirmDialog, DataTable, Dialog, Glass, RadioGroup, StateBlock, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type Token} from "../api.ts";
import {Copyable, DayField, ErrorNote, fromDay, lines, LinesField, PageHead, useGuard, useLoad, useP, useSay} from "../kit.tsx";

const SCOPES = ["read", "users", "full"] as const;

export function TokensPage() {
	const {t, date} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), tokens = useLoad(() => api("get", "/tokens"), []);
	const [making, setMaking] = useState(false), [revoking, setRevoking] = useState<Token | null>(null), [made, setMade] = useState<{name: string, token: string} | null>(null);
	const [name, setName] = useState(""), [scope, setScope] = useState<string>("read"), [day, setDay] = useState(""), [sources, setSources] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const scopeLabel = (s: string) => SCOPES.includes(s as typeof SCOPES[number]) ? t(`tokens.scope.${s as typeof SCOPES[number]}`) : s;
	const make = async () => {
		setBusy(true);
		setError(null);
		try {
			const answer = await guard(() => api("post", "/tokens", {body: {name: name.trim(), scope, expires_at: fromDay(day), allowed_sources: lines(sources)}}));
			setMaking(false);
			setMade({name: answer.name, token: answer.token});
			tokens.reload();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const add = () => { setName(""); setScope("read"); setDay(""); setSources(""); setError(null); setMaking(true); };
	return <>
		<PageHead title={t("tokens.title")} lead={t("tokens.lead")}><Button variant="primary" icon="plus" onClick={add}>{t("tokens.add")}</Button></PageHead>
		{tokens.error && !tokens.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={tokens.reload}>{t("action.retry")}</Button>}>{say(tokens.error)}</StateBlock>
		: !tokens.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <Glass className="p-pad"><DataTable caption={t("tokens.title")} rows={tokens.data.tokens} rowKey={k => String(k.id)} empty={<StateBlock kind="empty" title={t("tokens.empty")} action={<Button variant="primary" icon="plus" onClick={add}>{t("tokens.add")}</Button>}>{t("tokens.emptyBody")}</StateBlock>} columns={[
			{id: "name", header: t("tokens.col.name"), cell: k => <span className="p-user"><span>{k.name}</span><span className="vw-code vw-muted vw-small">{k.prefix}</span></span>},
			{id: "scope", header: t("tokens.col.scope"), cell: k => scopeLabel(k.scope)},
			{id: "sources", header: t("tokens.col.sources"), cell: k => k.allowed_sources.length ? <span className="vw-code">{k.allowed_sources.join(", ")}</span> : t("tokens.anywhere")},
			{id: "expiry", header: t("tokens.col.expiry"), cell: k => k.revoked_at ? t("tokens.revoked", {date: date(new Date(k.revoked_at * 1000))}) : k.expires_at ? date(new Date(k.expires_at * 1000)) : t("common.never")},
			{id: "used", header: t("tokens.col.used"), cell: k => k.last_used ? date(new Date(k.last_used * 1000)) : t("common.never")},
			{id: "revoke", header: "", align: "end", cell: k => k.revoked_at ? null : <Button size="sm" variant="quiet" aria-label={t("tokens.revoke", {name: k.name})} onClick={() => setRevoking(k)}>{t("tokens.revokeShort")}</Button>}
		]}/></Glass>}
		<Dialog open={making} onOpenChange={setMaking} title={t("tokens.add")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void make(); }}>
				<TextField label={t("tokens.name")} hint={t("tokens.nameHint")} value={name} onChange={setName} maxLength={64} required autoFocus/>
				<RadioGroup label={t("tokens.scope")} value={scope} onChange={setScope} options={SCOPES.map(s => ({value: s, label: t(`tokens.scope.${s}`), detail: t(`tokens.scope.${s}Detail`)}))}/>
				<DayField label={t("tokens.expiry")} hint={t("tokens.expiryHint")} value={day} onChange={setDay} optional/>
				<LinesField label={t("tokens.sources")} hint={t("tokens.sourcesHint")} value={sources} onChange={setSources}/>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setMaking(false)}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy}>{t("tokens.create")}</Button></div>
			</form>
		</Dialog>
		<Dialog open={made !== null} onOpenChange={open => { if (!open) setMade(null); }} title={t("tokens.shownTitle")} description={t("tokens.shownBody")}>
			{made && <Copyable label={t("tokens.shown", {name: made.name})} value={made.token}/>}
			<div className="vw-dialog-foot"><Button variant="primary" onClick={() => setMade(null)}>{t("tokens.done")}</Button></div>
		</Dialog>
		<ConfirmDialog open={revoking !== null} onOpenChange={open => { if (!open) setRevoking(null); }} danger title={t("tokens.revokeTitle", {name: revoking?.name ?? ""})} body={t("tokens.revokeBody")} confirmLabel={t("tokens.revoke", {name: revoking?.name ?? ""})} onConfirm={() => { const k = revoking!; void api("delete", "/tokens/{id}", {params: {id: k.id}}).then(() => { toast({tone: "success", title: t("tokens.revoked.toast", {name: k.name})}); tokens.reload(); }, failure => toast({tone: "danger", title: say(failure)})); }}/>
	</>;
}
