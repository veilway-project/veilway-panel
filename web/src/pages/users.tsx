import {Banner, Button, Checkbox, ConfirmDialog, DataTable, Dialog, Glass, NumberField, RadioGroup, Segmented, SelectField, StateBlock, Switch, TextField, UsageBar, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type LinkView, type NodeState, type NodeUser, type User} from "../api.ts";
import {DayField, ErrorNote, fromDay, LinkDialog, NodeNote, PageHead, toDay, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {useSettings} from "../settings.ts";

const GB = 1024 ** 3;
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
type Period = "none" | "daily" | "weekly" | "monthly";

// The expiry in a row: days left, or that it has passed.
export function useExpiry() {
	const {t} = useP();
	return (seconds: number | null | undefined) => {
		if (!seconds) return t("users.noExpiry");
		const days = Math.ceil((seconds * 1000 - Date.now()) / 86400000);
		return days < 0 ? t("users.expired") : t("count.daysLeft", {count: days});
	};
}

export function UsersPage() {
	const {t, number} = useP(), toast = useToast(), say = useSay(), guard = useGuard(), expiry = useExpiry(), settings = useSettings();
	const [search, setSearch] = useState(""), [query, setQuery] = useState(""), [shown, setShown] = useState("all"), [picked, setPicked] = useState<Set<number>>(new Set());
	const [form, setForm] = useState<User | "new" | null>(null), [created, setCreated] = useState<{name: string, link: LinkView} | null>(null);
	const [confirm, setConfirm] = useState<"delete" | "reset_usage" | null>(null), [more, setMore] = useState(false), [result, setResult] = useState<{done: number, failed: {id: number, error: string}[], node: NodeState} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	useEffect(() => { const timer = setTimeout(() => setQuery(search.trim()), 250); return () => clearTimeout(timer); }, [search]);
	const users = useLoad(() => api("get", "/users", {query: {q: query, enabled: shown === "all" ? undefined : String(shown === "enabled")}}), [query, shown]);
	const rows = users.data?.users ?? [], names = new Map(rows.map(u => [u.id, u.name]));
	const bulk = async (action: string, value?: unknown) => {
		setBusy(true);
		setError(null);
		setResult(null);
		try {
			const answer = await guard(() => api("post", "/users/bulk", {body: {ids: [...picked], action, value}}));
			setResult(answer);
			if (!answer.failed.length) setPicked(new Set());
			setMore(false);
			users.reload();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const toggle = (id: number, on: boolean) => setPicked(old => { const next = new Set(old); if (on) next.add(id); else next.delete(id); return next; });
	return <>
		<PageHead title={t("users.title")} lead={users.data ? t("count.users", {count: rows.length}) : undefined}><Button variant="primary" icon="plus" onClick={() => setForm("new")}>{t("users.add")}</Button></PageHead>
		<div className="p-filters">
			<TextField label={t("users.search")} type="search" placeholder={t("users.searchHint")} value={search} onChange={setSearch}/>
			{rows.length > 0 && <Checkbox label={t("users.selectAll")} checked={rows.every(u => picked.has(u.id))} onChange={on => setPicked(on ? new Set(rows.map(u => u.id)) : new Set())}/>}
			<Segmented label={t("users.filter")} value={shown} onChange={setShown} options={[{value: "all", label: t("users.all")}, {value: "enabled", label: t("users.enabledOnly")}, {value: "disabled", label: t("users.disabledOnly")}]}/>
		</div>
		{picked.size > 0 && <Glass className="p-bulk" aria-live="polite">
			<strong>{t("bulk.selected", {count: picked.size})}</strong>
			<div className="p-cluster">
				<Button size="sm" disabled={busy} onClick={() => void bulk("enable")}>{t("bulk.enable")}</Button>
				<Button size="sm" disabled={busy} onClick={() => void bulk("disable")}>{t("bulk.disable")}</Button>
				<Button size="sm" disabled={busy} onClick={() => setConfirm("reset_usage")}>{t("bulk.resetUsage")}</Button>
				<Button size="sm" disabled={busy} onClick={() => setMore(true)}>{t("bulk.more")}</Button>
				<Button size="sm" variant="danger" disabled={busy} onClick={() => setConfirm("delete")}>{t("bulk.delete")}</Button>
				<Button size="sm" variant="quiet" onClick={() => setPicked(new Set())}>{t("bulk.clear")}</Button>
			</div>
		</Glass>}
		<ErrorNote error={error}/>
		{result && <Banner tone={result.failed.length ? "warning" : "success"} title={t("bulk.done", {count: result.done}) + (result.failed.length ? ". " + t("bulk.failed", {count: result.failed.length}) : "")}>{result.failed.length ? result.failed.map(f => (names.get(f.id) ?? f.id) + ": " + f.error).join("; ") : undefined}</Banner>}
		<NodeNote node={result?.node}/>
		{users.error && !users.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={users.reload}>{t("action.retry")}</Button>}>{say(users.error)}</StateBlock>
		: !users.data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: <Glass className="p-pad"><DataTable caption={t("users.title")} rows={rows} rowKey={u => String(u.id)} empty={query || shown !== "all" ? <StateBlock kind="empty" title={t("users.noMatch")} action={<Button onClick={() => { setSearch(""); setShown("all"); }}>{t("users.clear")}</Button>}>{t("users.noMatchBody")}</StateBlock> : <StateBlock kind="empty" title={t("users.empty")} action={<Button variant="primary" icon="plus" onClick={() => setForm("new")}>{t("users.add")}</Button>}>{t("users.emptyBody")}</StateBlock>} columns={[
			{id: "pick", header: "", cell: u => <input type="checkbox" className="p-check" aria-label={t("users.select", {name: u.name})} checked={picked.has(u.id)} onChange={event => toggle(u.id, event.target.checked)}/>},
			{id: "name", header: t("users.col.user"), cell: u => {
				const node = u.node as NodeUser | null, state = !u.enabled ? t("users.disabled") : node?.denied === "quota" ? t("users.overQuota") : node?.denied === "expired" ? t("users.expired") : u.pending_devices ? t("users.pending", {count: u.pending_devices}) : "";
				return <span className="p-user"><a className="vw-code p-link" href={"#/users/" + u.id}>{u.name}</a>{state && <span className="vw-muted vw-small">{state}</span>}</span>;
			}},
			{id: "groups", header: t("users.col.groups"), cell: u => u.groups.length ? <span className="vw-code">{u.groups.join(", ")}</span> : <span className="vw-muted">{t("common.none")}</span>},
			{id: "usage", header: t("users.col.usage"), cell: u => {
				const node = u.node as NodeUser | null;
				return node?.used_bytes === undefined ? <span className="vw-muted">{t("users.usageUnknown")}</span> : <UsageBar compact label={u.name} used={node.used_bytes} total={u.quota_bytes ?? null}/>;
			}},
			{id: "expiry", header: t("users.col.expiry"), cell: u => expiry(u.expires_at)},
			{id: "devices", header: t("users.col.devices"), align: "end", cell: u => <span className="vw-num">{u.device_limit ? number(u.devices) + " / " + number(u.device_limit) : number(u.devices)}</span>}
		]}/></Glass>}
		{form && <UserForm user={form === "new" ? null : form} defaultLimit={settings?.default_device_limit ?? 3} onClose={() => setForm(null)} onSaved={(user, link, linkError) => { setForm(null); users.reload(); toast({tone: "success", title: t("form.created", {name: user.name})}); if (link) setCreated({name: user.name, link}); if (linkError) toast({tone: "warning", title: t("link.failed", {error: linkError})}); }}/>}
		<LinkDialog name={created?.name ?? ""} link={created?.link ?? null} once={settings?.show_links_once ?? false} onClose={() => setCreated(null)}/>
		<ConfirmDialog open={confirm !== null} onOpenChange={open => { if (!open) setConfirm(null); }} danger={confirm === "delete"} title={t(confirm === "delete" ? "bulk.deleteTitle" : "bulk.resetTitle", {count: picked.size})} body={t(confirm === "delete" ? "bulk.deleteBody" : "bulk.resetBody")} confirmLabel={t(confirm === "delete" ? "bulk.delete" : "bulk.resetUsage")} onConfirm={() => { if (confirm) void bulk(confirm); }}/>
		{more && <BulkChange count={picked.size} busy={busy} error={error} onClose={() => setMore(false)} onApply={(action, value) => void bulk(action, value)}/>}
	</>;
}

// The bulk changes that need a value, behind one dialog so the bar stays short.
function BulkChange({count, busy, error, onClose, onApply}: {count: number, busy: boolean, error: unknown, onClose: () => void, onApply: (action: string, value: unknown) => void}) {
	const {t} = useP(), [action, setAction] = useState("add_group"), [group, setGroup] = useState(""), [quota, setQuota] = useState<number | "">(""), [period, setPeriod] = useState<Period>("monthly"), [day, setDay] = useState(""), [limit, setLimit] = useState<number | "">(3), [problem, setProblem] = useState("");
	const apply = () => {
		if ((action === "add_group" || action === "remove_group") && !NAME.test(group)) return setProblem(t("error.group"));
		setProblem("");
		onApply(action, action === "set_quota" ? {quota_bytes: quota === "" ? null : Math.round(quota * GB), quota_period: quota === "" || period === "none" ? null : period} : action === "set_expiry" ? fromDay(day) : action === "set_device_limit" ? (limit === "" ? 0 : limit) : group);
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("bulk.changeTitle", {count})}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); apply(); }}>
			<RadioGroup label={t("bulk.action")} value={action} onChange={setAction} options={[{value: "add_group", label: t("bulk.addGroup")}, {value: "remove_group", label: t("bulk.removeGroup")}, {value: "set_quota", label: t("bulk.setQuota")}, {value: "set_expiry", label: t("bulk.setExpiry")}, {value: "set_device_limit", label: t("bulk.setLimit")}]}/>
			{(action === "add_group" || action === "remove_group") && <TextField label={t("form.groups")} value={group} onChange={value => setGroup(value.toLowerCase().trim())} error={problem || undefined} technical/>}
			{action === "set_quota" && <><NumberField label={t("form.quota")} hint={t("form.quotaHint")} unit={t("unit.gb")} min={0} step="any" value={quota} onChange={setQuota}/><SelectField label={t("form.period")} value={period} onChange={value => setPeriod(value as Period)} disabled={quota === ""} options={(["none", "daily", "weekly", "monthly"] as const).map(p => ({value: p, label: t(`form.period.${p}`)}))}/></>}
			{action === "set_expiry" && <DayField label={t("form.expiry")} hint={t("form.expiryHint")} value={day} onChange={setDay}/>}
			{action === "set_device_limit" && <NumberField label={t("form.limit")} hint={t("form.limitHint")} unit={t("form.devices")} min={0} max={65535} value={limit} onChange={setLimit}/>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy}>{t("bulk.apply")}</Button></div>
		</form>
	</Dialog>;
}

export function UserForm({user, defaultLimit, onClose, onSaved}: {user: User | null, defaultLimit: number, onClose: () => void, onSaved: (user: User, link: LinkView | null, linkError: string | null) => void}) {
	const {t} = useP(), guard = useGuard();
	const [name, setName] = useState(user?.name ?? ""), [groups, setGroups] = useState(user?.groups.join(", ") ?? ""), [quota, setQuota] = useState<number | "">(user?.quota_bytes ? Math.round(user.quota_bytes / GB * 100) / 100 : "");
	const [period, setPeriod] = useState<Period>((user?.quota_period as Period | null) ?? "none"), [day, setDay] = useState(toDay(user?.expires_at)), [limit, setLimit] = useState<number | "">(user?.device_limit ?? defaultLimit), [note, setNote] = useState(user?.note ?? ""), [enabled, setEnabled] = useState(user?.enabled ?? true);
	const [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [tried, setTried] = useState(false);
	const list = groups.split(",").map(g => g.trim().toLowerCase()).filter(Boolean);
	const problems = {name: NAME.test(name) ? undefined : t("error.userName"), groups: list.every(g => NAME.test(g)) ? undefined : t("error.group")};
	const save = async () => {
		setTried(true);
		if (problems.name || problems.groups) return;
		setBusy(true);
		setError(null);
		const body = {name, groups: list, quota_bytes: quota === "" ? null : Math.round(quota * GB), quota_period: quota === "" || period === "none" ? null : period, expires_at: fromDay(day), device_limit: limit === "" ? 0 : limit, note, enabled};
		try {
			if (user) onSaved((await guard(() => api("patch", "/users/{id}", {params: {id: user.id}, body}))).user, null, null);
			else {
				const answer = await guard(() => api("post", "/users", {body}));
				onSaved(answer.user, answer.link ?? null, answer.link_error ?? null);
			}
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={user ? t("form.editTitle", {name: user.name}) : t("form.addTitle")}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); void save(); }} noValidate>
			<TextField label={t("form.name")} hint={t("form.nameHint")} value={name} onChange={value => setName(value.toLowerCase())} error={tried ? problems.name : undefined} technical required autoFocus/>
			<TextField label={t("form.groups")} hint={t("form.groupsHint")} value={groups} onChange={setGroups} error={tried ? problems.groups : undefined} optional technical/>
			<div className="p-pair">
				<NumberField label={t("form.quota")} hint={t("form.quotaHint")} unit={t("unit.gb")} min={0} step="any" value={quota} onChange={setQuota} optional/>
				<SelectField label={t("form.period")} hint={quota === "" ? t("form.periodHint") : undefined} value={quota === "" ? "none" : period} onChange={value => setPeriod(value as Period)} disabled={quota === ""} options={(["none", "daily", "weekly", "monthly"] as const).map(p => ({value: p, label: t(`form.period.${p}`)}))}/>
			</div>
			<div className="p-pair">
				<DayField label={t("form.expiry")} hint={t("form.expiryHint")} value={day} onChange={setDay} optional/>
				<NumberField label={t("form.limit")} hint={t("form.limitHint")} unit={t("form.devices")} min={0} max={65535} value={limit} onChange={setLimit}/>
			</div>
			<TextField label={t("form.note")} hint={t("form.noteHint")} value={note} onChange={setNote} optional/>
			<Switch label={t("form.enabled")} hint={t("form.enabledHint")} checked={enabled} onChange={setEnabled}/>
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy}>{user ? t("common.save") : t("form.create")}</Button></div>
		</form>
	</Dialog>;
}
