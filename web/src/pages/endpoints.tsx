import {Banner, Button, Dialog, Icon, IconButton, SelectField, StateBlock, TextField} from "@veilway/ui";
import {useState} from "react";
import {api, type MoveOut, type Settings} from "../api.ts";
import {ErrorNote, LinesField, Mark, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {useSettings} from "../settings.ts";

export type EndpointDraft = {name: string, url: string, pins: string};
// A select cannot hold an empty value, so "follow" is this one in the lists and an empty string everywhere else.
const FOLLOW = "*";
export const isPlain = (url: string) => /^http:/i.test(url.trim());

// The cost of a plain http endpoint, said the same wherever one is listed or chosen. The exchange stays sealed, so what is lost is hiding, not secrecy.
export function PlainNote() {
	const {t} = useP();
	return <span className="p-flag p-wrap" data-tone="warning"><Icon name="warning"/>{t("endpoints.plain")}</span>;
}

// A choice of endpoint by name. An empty value follows the group's endpoint or the default.
export function EndpointPick({label, hint, value, onChange, followLabel}: {label: string, hint?: string, value: string, onChange: (value: string) => void, followLabel: string}) {
	const endpoints = useSettings()?.endpoints ?? [];
	return <div className="p-stack">
		<SelectField label={label} hint={hint} value={value || FOLLOW} onChange={next => onChange(next === FOLLOW ? "" : next)} options={[{value: FOLLOW, label: followLabel}, ...endpoints.map(e => ({value: e.name, label: e.name}))]}/>
		{isPlain(endpoints.find(e => e.name === value)?.url ?? "") && <PlainNote/>}
	</div>;
}

// The endpoints are part of the settings form and save with it. What the panel counts for each comes from its own route, as of the last save.
export function EndpointsSection({rows, onRows, draft, patch, saved, onMoved}: {rows: EndpointDraft[], onRows: (rows: EndpointDraft[]) => void, draft: Settings, patch: (change: Partial<Settings>) => void, saved: Settings, onMoved: () => void}) {
	const {t, number} = useP(), [moving, setMoving] = useState(false);
	const stats = useLoad(() => api("get", "/endpoints"), [JSON.stringify([saved.endpoints, saved.default_endpoint, saved.group_endpoints])]);
	const names = rows.map(r => r.name.trim()).filter(Boolean), known = new Map((stats.data?.endpoints ?? []).map(e => [e.name, e])), groups = stats.data?.groups ?? [], follow = draft.group_endpoints ?? {};
	const change = (index: number, part: Partial<EndpointDraft>) => onRows(rows.map((r, i) => i === index ? {...r, ...part} : r));
	return <section className="p-section" id="set-endpoints">
		<div><h2 className="vw-h3" tabIndex={-1}>{t("settings.endpoints")}</h2><p>{t("settings.endpointsLead")}</p></div>
		<div className="p-form">
			{rows.length === 0 && <p className="vw-muted vw-small">{t("endpoints.none")}</p>}
			{rows.map((row, i) => {
				const own = known.get(row.name), used = own?.users ?? 0, isDefault = row.name.trim() !== "" && row.name.trim() === draft.default_endpoint;
				return <fieldset key={i} className="p-mirror">
					<legend className="p-row"><span className="p-cluster"><strong className="vw-code">{row.name.trim() || t("endpoints.new")}</strong>{isDefault && <Mark tone="success">{t("endpoints.default")}</Mark>}</span><IconButton icon="close" label={used > 0 ? t("endpoints.inUse") : t("endpoints.remove", {name: row.name.trim() || String(i + 1)})} disabled={used > 0} onClick={() => onRows(rows.filter((_, j) => j !== i))}/></legend>
					<div className="p-pair">
						<TextField label={t("endpoints.name")} hint={t("endpoints.nameHint")} value={row.name} onChange={value => change(i, {name: value.trim()})} maxLength={64} technical/>
						<TextField label={t("endpoints.url")} hint={t("endpoints.urlHint")} type="url" placeholder="https://" value={row.url} onChange={value => change(i, {url: value.trim()})} technical/>
					</div>
					{isPlain(row.url) ? <PlainNote/> : <LinesField label={t("subs.pins")} hint={t("endpoints.pinsHint")} value={row.pins} onChange={value => change(i, {pins: value})} rows={2}/>}
					{own && <p className="vw-small vw-muted">{t("endpoints.users", {count: own.users})}{own.assigned > 0 ? " " + t("endpoints.assigned", {count: own.assigned}) : ""}</p>}
					{own && own.still_here > 0 && <Mark tone="warning">{t("endpoints.stillHere", {count: own.still_here})}</Mark>}
					{own && own.still_here === 0 && used === 0 && !own.default && <p className="vw-small vw-muted">{t("endpoints.retire")}</p>}
					{used > 0 && <p className="vw-small vw-muted">{t("endpoints.inUseNote")}</p>}
				</fieldset>;
			})}
			{!!stats.error && !stats.data && <ErrorNote error={stats.error}/>}
			<div className="p-cluster">
				{rows.length < 16 && <Button size="sm" icon="plus" onClick={() => onRows([...rows, {name: "", url: "", pins: ""}])}>{t("endpoints.add")}</Button>}
				{known.size > 0 && <Button size="sm" onClick={() => setMoving(true)}>{t("endpoints.move")}</Button>}
			</div>
			{names.length > 0 && <SelectField label={t("endpoints.defaultLabel")} hint={t("endpoints.defaultHint")} value={names.includes(draft.default_endpoint ?? "") ? draft.default_endpoint ?? "" : FOLLOW} onChange={value => patch({default_endpoint: value === FOLLOW ? "" : value})} options={[...(names.includes(draft.default_endpoint ?? "") ? [] : [{value: FOLLOW, label: t("endpoints.noDefault")}]), ...names.map(n => ({value: n, label: n}))]}/>}
			{groups.length > 0 && <div className="p-stack">
				<div><strong>{t("endpoints.groups")}</strong><p className="vw-small vw-muted">{t("endpoints.groupsHint")}</p></div>
				{groups.map(g => <div key={g.name} className="p-stack">
					<SelectField label={g.name} hint={t("endpoints.members", {count: g.users})} value={follow[g.name] ?? FOLLOW} onChange={value => patch({group_endpoints: Object.fromEntries(Object.entries({...follow, [g.name]: value}).filter(([, v]) => v !== FOLLOW))})} options={[{value: FOLLOW, label: t("endpoints.followDefault")}, ...names.map(n => ({value: n, label: n}))]}/>
					{isPlain(rows.find(r => r.name.trim() === follow[g.name])?.url ?? "") && <PlainNote/>}
				</div>)}
			</div>}
			{stats.data === null && stats.loading && !stats.error && <p className="vw-muted vw-small">{t("common.loading")}</p>}
		</div>
		{moving && <MoveDialog onClose={() => setMoving(false)} onDone={() => { stats.reload(); onMoved(); }}/>}
	</section>;
}

// Moves a group or a selection of accounts to an endpoint. The count comes first and nothing changes until the second step.
export function MoveDialog({users, onClose, onDone}: {users?: number[], onClose: () => void, onDone: () => void}) {
	const {t, number} = useP(), say = useSay(), guard = useGuard(), list = useLoad(() => api("get", "/endpoints"), []);
	const [to, setTo] = useState<string | null>(null), [group, setGroup] = useState<string | null>(null), [summary, setSummary] = useState<MoveOut | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const endpoints = list.data?.endpoints ?? [], groups = list.data?.groups ?? [], target = to ?? endpoints.find(e => !e.default)?.name ?? endpoints[0]?.name ?? "", scope = users ? undefined : group ?? groups[0]?.name;
	const run = async (dry: boolean) => {
		setBusy(true);
		setError(null);
		try {
			const answer = await guard(() => api("post", "/endpoints/move", {body: {users: users ?? null, group: users ? null : scope ?? null, endpoint: target || null, dry_run: dry}}));
			setSummary(answer);
			if (!dry) { onDone(); onClose(); }
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("move.title")} description={users ? t("move.leadUsers", {count: users.length}) : t("move.leadGroup")}>
		{list.error && !list.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={list.reload}>{t("action.retry")}</Button>}>{say(list.error)}</StateBlock> : !list.data ? <StateBlock kind="loading" title={t("common.loading")}/> : <form className="p-stack" onSubmit={event => { event.preventDefault(); void run(true); }}>
			{!users && (groups.length === 0 ? <Banner tone="info" title={t("move.noGroups")}/> : <SelectField label={t("move.group")} value={scope ?? ""} onChange={value => { setGroup(value); setSummary(null); }} options={groups.map(g => ({value: g.name, label: g.name + " (" + number(g.users) + ")"}))}/>)}
			<SelectField label={t("move.to")} value={target || FOLLOW} onChange={value => { setTo(value === FOLLOW ? "" : value); setSummary(null); }} options={[...endpoints.map(e => ({value: e.name, label: e.name})), {value: FOLLOW, label: t(users ? "move.followUser" : "move.followGroup")}]}/>
			{endpoints.find(e => e.name === target)?.plain && <PlainNote/>}
			{summary && <div className="p-stack" role="status">
				<dl className="p-kv">
					<dt>{t("move.moving")}</dt><dd className="vw-num">{number(summary.moving)}</dd>
					<dt>{t("move.staying")}</dt><dd className="vw-num">{number(summary.staying)}</dd>
					<dt>{t("move.check")}</dt><dd className="vw-num">{number(summary.changes_check)}</dd>
					<dt>{t("move.plain")}</dt><dd className="vw-num">{number(summary.to_plain)}</dd>
				</dl>
				{summary.names.length > 0 && <span className="p-tags">{summary.names.map(n => <span key={n} className="p-tag vw-code">{n}</span>)}</span>}
				{summary.moving > summary.names.length && <p className="vw-small vw-muted">{t("move.more", {count: summary.moving - summary.names.length})}</p>}
				<p className="vw-small vw-muted">{t("move.note")}</p>
			</div>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button>{summary ? <Button variant="primary" disabled={busy || (!users && !scope)} onClick={() => void run(false)}>{t("move.confirm", {count: summary.moving})}</Button> : <Button type="submit" variant="primary" disabled={busy || endpoints.length === 0 || (!users && !scope)}>{t("move.preview")}</Button>}</div>
		</form>}
	</Dialog>;
}
