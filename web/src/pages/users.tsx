import {Banner, Button, Checkbox, ConfirmDialog, Dialog, Glass, NumberField, RadioGroup, Segmented, SelectField, StateBlock, Switch, TextField, UsageBar, useToast} from "@veilway/ui";
import {useEffect, useId, useState} from "react";
import {api, type LinkView, type NodeState, type NodeUser, type User, type UserPatch} from "../api.ts";
import {ago, DayField, ErrorNote, fromDay, Mark, NodeNote, PageHead, toDay, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {useSettings} from "../settings.ts";
import {EndpointPick, MoveDialog} from "./endpoints.tsx";

const GB = 1024 ** 3;
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const PAGE = 50;
type Period = "none" | "daily" | "weekly" | "monthly";
export type Exits = "all" | string[];
type ExitRow = {tag: string, name: string, country: string, up: boolean | null};

// The expiry in a row: days left, or that it has passed.
export function useExpiry() {
	const {t} = useP();
	return (seconds: number | null | undefined) => {
		if (!seconds) return t("users.noExpiry");
		const days = Math.ceil((seconds * 1000 - Date.now()) / 86400000);
		return days < 0 ? t("users.expired") : t("count.daysLeft", {count: days});
	};
}

// A link made when a user is added, handed to their page so it opens showing it.
export const handoff: {current: {id: number, link: LinkView} | null} = {current: null};

export function UsersPage({adding}: {adding: boolean}) {
	const {t, number, bytes, date} = useP(), toast = useToast(), say = useSay(), guard = useGuard(), expiry = useExpiry(), settings = useSettings();
	const [search, setSearch] = useState(""), [query, setQuery] = useState(""), [shown, setShown] = useState("all"), [group, setGroup] = useState("*"), [sort, setSort] = useState("name"), [page, setPage] = useState(0), [picked, setPicked] = useState<Set<number>>(new Set());
	const [form, setForm] = useState<User | "new" | null>(adding ? "new" : null);
	const [confirm, setConfirm] = useState<"delete" | "reset_usage" | "reset_links" | null>(null), [removeDevices, setRemoveDevices] = useState(false), [more, setMore] = useState(false), [moving, setMoving] = useState(false), [result, setResult] = useState<{done: number, failed: {id: number, error: string}[], node: NodeState, devices_removed?: number | null} | null>(null), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	useEffect(() => { const timer = setTimeout(() => setQuery(search.trim()), 250); return () => clearTimeout(timer); }, [search]);
	useEffect(() => setPage(0), [query, shown, group, sort]);
	// Every user matching the search comes in one answer, so the counts, the group filter and the order are worked out here.
	const users = useLoad(() => api("get", "/users", {query: {q: query}}), [query]);
	const all = users.data?.users ?? [], names = new Map(all.map(u => [u.id, u.name])), groups = [...new Set(all.flatMap(u => u.groups))].sort();
	const used = (u: User) => (u.node as NodeUser | null)?.used_bytes ?? -1;
	const rows = all.filter(u => (shown === "all" || u.enabled === (shown === "enabled")) && (group === "*" || u.groups.includes(group))).sort((a, b) => sort === "usage" ? used(b) - used(a) : sort === "expiry" ? (a.expires_at ?? Infinity) - (b.expires_at ?? Infinity) : a.name.localeCompare(b.name));
	const pages = Math.max(1, Math.ceil(rows.length / PAGE)), visible = rows.slice(page * PAGE, page * PAGE + PAGE);
	const bulk = async (action: string, value?: unknown, remove = false) => {
		setBusy(true);
		setError(null);
		setResult(null);
		try {
			const answer = await guard(() => api("post", "/users/bulk", {body: {ids: [...picked], action, value, remove_devices: remove}}));
			setResult(answer);
			if (!answer.failed.length) setPicked(new Set());
			setMore(false);
			setConfirm(null);
			users.reload();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const toggle = (id: number, on: boolean) => setPicked(old => { const next = new Set(old); if (on) next.add(id); else next.delete(id); return next; });
	const cols = [t("users.col.user"), t("users.col.groups"), t("users.col.exits"), t("users.col.usage"), t("users.col.expiry"), t("users.col.devices"), t("users.col.state")];
	const state = (u: User) => {
		const node = u.node as NodeUser | null, ages = (node?.devices ?? []).map(d => d.handshake_age_secs).filter((age): age is number => typeof age === "number"), age = ages.length ? Math.min(...ages) : null;
		if (!u.enabled) return <Mark tone="muted">{t("users.disabled")}</Mark>;
		if (node?.denied === "quota") return <Mark tone="danger">{t("users.overQuota")}</Mark>;
		if (node?.denied === "expired") return <Mark tone="muted">{t("users.expired")}</Mark>;
		// WireGuard makes a new session every two minutes while traffic flows, so an older one means the device went quiet.
		if (age !== null && age < 180) return <Mark tone="success">{t("users.online")}</Mark>;
		if (u.pending_devices) return <Mark tone="info">{t("users.pending", {count: u.pending_devices})}</Mark>;
		return <Mark tone="muted">{age === null ? t("users.notSeen") : (span => t("users.seen", {time: t(span.key, {count: span.count})}))(ago(age))}</Mark>;
	};
	return <>
		<PageHead title={t("users.title")} lead={users.data ? t("users.lead", {count: all.length}) : undefined}><Button variant="primary" icon="plus" onClick={() => setForm("new")}>{t("users.add")}</Button></PageHead>
		<Glass className="p-panel">
			<div className="p-toolbar">
				<TextField label={t("users.search")} type="search" placeholder={t("users.searchHint")} value={search} onChange={setSearch}/>
				<SelectField label={t("users.group")} value={group} onChange={setGroup} options={[{value: "*", label: t("users.everyGroup")}, ...groups.map(g => ({value: g, label: g}))]}/>
				<SelectField label={t("users.sort")} value={sort} onChange={setSort} options={(["name", "usage", "expiry"] as const).map(s => ({value: s, label: t(`users.sort.${s}`)}))}/>
			</div>
			<Segmented label={t("users.filter")} value={shown} onChange={setShown} options={[{value: "all", label: t("users.all") + " " + number(all.length)}, {value: "enabled", label: t("users.enabledOnly") + " " + number(all.filter(u => u.enabled).length)}, {value: "disabled", label: t("users.disabledOnly") + " " + number(all.filter(u => !u.enabled).length)}]}/>
			{picked.size > 0 && <div className="vw-well p-bulk" role="region" aria-label={t("bulk.region")} aria-live="polite">
				<strong>{t("bulk.selected", {count: picked.size})}</strong>
				<Button size="sm" disabled={busy} onClick={() => void bulk("enable")}>{t("bulk.enable")}</Button>
				<Button size="sm" disabled={busy} onClick={() => void bulk("disable")}>{t("bulk.disable")}</Button>
				<Button size="sm" disabled={busy} onClick={() => setConfirm("reset_usage")}>{t("bulk.resetUsage")}</Button>
				<Button size="sm" disabled={busy} onClick={() => { setRemoveDevices(false); setConfirm("reset_links"); }}>{t("bulk.resetLinks")}</Button>
				<Button size="sm" disabled={busy} onClick={() => setMoving(true)}>{t("bulk.moveEndpoint")}</Button>
				<Button size="sm" disabled={busy} onClick={() => setMore(true)}>{t("bulk.more")}</Button>
				<Button size="sm" variant="danger" disabled={busy} onClick={() => setConfirm("delete")}>{t("bulk.delete")}</Button>
				<Button size="sm" variant="quiet" onClick={() => setPicked(new Set())}>{t("bulk.clear")}</Button>
			</div>}
			<ErrorNote error={error}/>
			{result && <Banner tone={result.failed.length ? "warning" : "success"} title={(result.devices_removed == null ? t("bulk.done", {count: result.done}) : t("bulk.linksDone", {count: result.done, devices: result.devices_removed})) + (result.failed.length ? ". " + t("bulk.failed", {count: result.failed.length}) : "")}>{result.failed.length ? result.failed.map(f => (names.get(f.id) ?? f.id) + ": " + f.error).join("; ") : undefined}</Banner>}
			<NodeNote node={result?.node}/>
			{users.error && !users.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={users.reload}>{t("action.retry")}</Button>}>{say(users.error)}</StateBlock>
			: !users.data ? <StateBlock kind="loading" title={t("common.loading")}/>
			: rows.length === 0 ? (query || shown !== "all" || group !== "*" ? <StateBlock kind="empty" title={t("users.noMatch")} action={<Button onClick={() => { setSearch(""); setShown("all"); setGroup("*"); }}>{t("users.clear")}</Button>}>{t("users.noMatchBody")}</StateBlock> : <StateBlock kind="empty" title={t("users.empty")} action={<Button variant="primary" icon="plus" onClick={() => setForm("new")}>{t("users.add")}</Button>}>{t("users.emptyBody")}</StateBlock>)
			: <div className="vw-table-wrap"><table className="vw-table">
				<caption className="vw-sr">{t("users.title")}</caption>
				<thead><tr><th scope="col"><input type="checkbox" className="p-check" aria-label={t("users.selectAll")} checked={visible.every(u => picked.has(u.id))} onChange={event => setPicked(old => { const next = new Set(old); for (const u of visible) if (event.target.checked) next.add(u.id); else next.delete(u.id); return next; })}/></th>{cols.map((c, i) => <th key={c} scope="col" data-align={i === 5 ? "end" : undefined}>{c}</th>)}</tr></thead>
				<tbody>{visible.map(u => {
					const node = u.node as NodeUser | null, gone = !!u.expires_at && u.expires_at * 1000 < Date.now();
					return <tr key={u.id} className={gone || !u.enabled ? "p-row-muted" : undefined}>
						<td><input type="checkbox" className="p-check" aria-label={t("users.select", {name: u.name})} checked={picked.has(u.id)} onChange={event => toggle(u.id, event.target.checked)}/></td>
						<td data-label={cols[0]}><span className="p-user"><a className="vw-code p-link" href={"#/users/" + u.id}>{u.name}</a>{u.note && <span>{u.note}</span>}</span></td>
						<td data-label={cols[1]}>{u.groups.length ? <span className="p-tags">{u.groups.map(g => <span key={g} className="p-tag vw-code">{g}</span>)}</span> : <span className="vw-muted">{t("common.none")}</span>}</td>
						<td data-label={cols[2]}>{Array.isArray(u.exits) ? <span className={u.exits.length ? "vw-num" : "vw-muted"}>{u.exits.length ? t("exits.count", {count: u.exits.length}) : t("exits.none")}</span> : <span className="vw-muted">{t("exits.all")}</span>}</td>
						<td data-label={cols[3]} className="p-usage-cell">{node?.used_bytes === undefined ? <span className="vw-muted">{t("users.usageUnknown")}</span> : u.quota_bytes ? <UsageBar compact label={u.name} used={node.used_bytes} total={u.quota_bytes}/> : <span className="p-user"><span className="vw-num">{bytes(node.used_bytes).text}</span><span>{t("users.noLimit")}</span></span>}</td>
						<td data-label={cols[4]}>{u.expires_at ? <span className="p-user"><span className="vw-num">{date(new Date(u.expires_at * 1000))}</span><span>{expiry(u.expires_at)}</span></span> : <span className="vw-muted">{t("users.noExpiry")}</span>}</td>
						<td data-label={cols[5]} data-align="end"><span className="vw-num">{u.device_limit ? t("users.devicesOf", {used: number(u.devices), limit: number(u.device_limit)}) : number(u.devices)}</span></td>
						<td data-label={cols[6]}>{state(u)}</td>
					</tr>;
				})}</tbody>
			</table></div>}
			{rows.length > PAGE && <div className="p-foot">
				<span>{t("users.showing", {from: number(page * PAGE + 1), to: number(page * PAGE + visible.length), total: number(rows.length)})}</span>
				<div className="p-cluster"><Button size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>{t("users.previous")}</Button><span className="vw-num">{t("users.page", {page: number(page + 1), pages: number(pages)})}</span><Button size="sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>{t("users.next")}</Button></div>
			</div>}
		</Glass>
		{form && <UserForm user={form === "new" ? null : form} defaultLimit={settings?.default_device_limit ?? 3} onClose={() => { setForm(null); if (adding) location.replace("#/users"); }} onSaved={(user, link, linkError) => { setForm(null); toast({tone: "success", title: t("form.created", {name: user.name})}); if (linkError) toast({tone: "warning", title: t("link.failed", {error: linkError})}); if (link) { handoff.current = {id: user.id, link}; location.hash = "#/users/" + user.id; } else users.reload(); }}/>}
		<ConfirmDialog open={confirm === "delete" || confirm === "reset_usage"} onOpenChange={open => { if (!open) setConfirm(null); }} danger={confirm === "delete"} title={t(confirm === "delete" ? "bulk.deleteTitle" : "bulk.resetTitle", {count: picked.size})} body={t(confirm === "delete" ? "bulk.deleteBody" : "bulk.resetBody")} confirmLabel={t(confirm === "delete" ? "bulk.delete" : "bulk.resetUsage")} onConfirm={() => { if (confirm) void bulk(confirm); }}/>
		<Dialog open={confirm === "reset_links"} onOpenChange={open => { if (!open) setConfirm(null); }} title={t("bulk.resetLinksTitle", {count: picked.size})} description={t("bulk.resetLinksBody")}>
			<Checkbox label={t("bulk.removeDevices")} checked={removeDevices} onChange={setRemoveDevices}/>
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={() => setConfirm(null)}>{t("action.cancel")}</Button><Button variant="danger" disabled={busy} onClick={() => void bulk("reset_links", undefined, removeDevices)}>{t("bulk.resetLinksConfirm")}</Button></div>
		</Dialog>
		{moving && <MoveDialog users={[...picked]} onClose={() => setMoving(false)} onDone={() => { setMoving(false); users.reload(); toast({tone: "success", title: t("move.done")}); }}/>}
		{more && <BulkChange count={picked.size} busy={busy} error={error} onClose={() => setMore(false)} onApply={(action, value) => void bulk(action, value)}/>}
	</>;
}

// The bulk changes that need a value, behind one dialog so the bar stays short.
function BulkChange({count, busy, error, onClose, onApply}: {count: number, busy: boolean, error: unknown, onClose: () => void, onApply: (action: string, value: unknown) => void}) {
	const {t} = useP(), [action, setAction] = useState("add_group"), [group, setGroup] = useState("*"), [quota, setQuota] = useState<number | "">(""), [period, setPeriod] = useState<Period>("monthly"), [day, setDay] = useState(""), [limit, setLimit] = useState<number | "">(3), [problem, setProblem] = useState("");
	const [exits, setExits] = useState<Exits>("all"), nodeExits = useExits(action === "set_exits"), kept = keptExits(exits, nodeExits.data);
	const apply = () => {
		if ((action === "add_group" || action === "remove_group") && !NAME.test(group)) return setProblem(t("error.group"));
		if (action === "set_exits" && kept.length === 0) return setProblem(t("exits.pick"));
		setProblem("");
		onApply(action, action === "set_quota" ? {quota_bytes: quota === "" ? null : Math.round(quota * GB), quota_period: quota === "" || period === "none" ? null : period} : action === "set_expiry" ? fromDay(day) : action === "set_device_limit" ? (limit === "" ? 0 : limit) : action === "set_exits" ? kept : group);
	};
	return <Dialog open onOpenChange={open => { if (!open) onClose(); }} title={t("bulk.changeTitle", {count})}>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); apply(); }}>
			<RadioGroup label={t("bulk.action")} value={action} onChange={setAction} options={[{value: "add_group", label: t("bulk.addGroup")}, {value: "remove_group", label: t("bulk.removeGroup")}, {value: "set_quota", label: t("bulk.setQuota")}, {value: "set_expiry", label: t("bulk.setExpiry")}, {value: "set_device_limit", label: t("bulk.setLimit")}, {value: "set_exits", label: t("bulk.setExits")}]}/>
			{(action === "add_group" || action === "remove_group") && <TextField label={t("form.groups")} value={group} onChange={value => setGroup(value.toLowerCase().trim())} error={problem || undefined} technical/>}
			{action === "set_quota" && <><NumberField label={t("form.quota")} hint={t("form.quotaHint")} unit={t("unit.gb")} min={0} step="any" value={quota} onChange={setQuota}/><SelectField label={t("form.period")} value={period} onChange={value => setPeriod(value as Period)} disabled={quota === ""} options={(["none", "daily", "weekly", "monthly"] as const).map(p => ({value: p, label: t(`form.period.${p}`)}))}/></>}
			{action === "set_expiry" && <DayField label={t("form.expiry")} hint={t("form.expiryHint")} value={day} onChange={setDay}/>}
			{action === "set_device_limit" && <NumberField label={t("form.limit")} hint={t("form.limitHint")} unit={t("form.devices")} min={0} max={65535} value={limit} onChange={setLimit}/>}
			{action === "set_exits" && <><p className="vw-note">{t("bulk.exitsNote")}</p><ExitPicker value={exits} onChange={setExits} exits={nodeExits} problem={problem || undefined}/></>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy}>{t("bulk.apply")}</Button></div>
		</form>
	</Dialog>;
}

// The node's exits, with whether each is up when the node reports it, for choosing which exits a user may use.
export function useExits(wanted = true) {
	return useLoad<ExitRow[]>(async () => {
		if (!wanted) return [];
		const [section, live] = await Promise.all([api("get", "/config/{section}", {params: {section: "exits"}}) as Promise<{value?: unknown}>, api("get", "/stats/now").catch(() => null)]);
		const states = new Map(((live?.reachable && Array.isArray(live.exits) ? live.exits : []) as {tag: string, interface_up: boolean | null, link_up: boolean | null}[]).map(e => [e.tag, e.interface_up !== false && e.link_up !== false]));
		return ((Array.isArray(section.value) ? section.value : []) as {tag: string, name?: string, country?: string}[]).map(e => ({tag: e.tag, name: e.name ?? "", country: e.country ?? "", up: states.get(e.tag) ?? null}));
	}, [wanted]);
}

// What a save sends: tags the node no longer has are dropped, which is how a deleted exit leaves a user.
export const keptExits = (value: Exits, rows: ExitRow[] | null) => value === "all" || !rows ? value : value.filter(tag => rows.some(e => e.tag === tag));

// The default exit a save sends: none once the exits leave it out or the node no longer has it.
export const keptFallback = (value: Exits, fallback: string | null | undefined, rows: ExitRow[] | null) => fallback && (value === "all" ? !rows || rows.some(e => e.tag === fallback) : keptExits(value, rows).includes(fallback)) ? fallback : null;

export function ExitPicker({value, onChange, exits, problem, fallback, onFallback}: {value: Exits, onChange: (value: Exits) => void, exits: ReturnType<typeof useExits>, problem?: string, fallback?: string | null, onFallback?: (exit: string | null) => void}) {
	const {t} = useP(), id = useId(), chosen = value === "all" ? [] : value, rows = exits.data ?? [], missing = exits.data ? chosen.filter(tag => !rows.some(e => e.tag === tag)) : [];
	const allowed = rows.filter(e => value === "all" || chosen.includes(e.tag)), picker = onFallback && <SelectField label={t("exits.default")} hint={t("exits.defaultHint")} value={keptFallback(value, fallback, exits.data) ?? ""} onChange={next => onFallback(next || null)} disabled={!exits.data} options={[{value: "", label: t("exits.nodeDefault")}, ...allowed.map(e => ({value: e.tag, label: e.name ? e.name + " (" + e.tag + ")" : e.tag}))]}/>;
	const pick = (tag: string, on: boolean) => onChange(on ? [...chosen, tag] : chosen.filter(held => held !== tag));
	return <div className="p-stack">
		<Segmented label={t("exits.choice")} value={value === "all" ? "all" : "only"} onChange={next => onChange(next === "all" ? "all" : chosen)} options={[{value: "all", label: t("exits.all")}, {value: "only", label: t("exits.only")}]}/>
		{value === "all" && picker}
		{value !== "all" && (exits.error && !exits.data ? <Banner tone="danger" title={t("exits.loadFailed")} action={<Button size="sm" icon="refresh" onClick={exits.reload}>{t("action.retry")}</Button>}/>
		: !exits.data ? <p className="vw-muted vw-small">{t("common.loading")}</p>
		: <>
			{rows.length === 0 && <p className="vw-muted vw-small">{t("exits.empty")}</p>}
			{missing.length > 0 && <Banner tone="warning" title={t("exits.missingNote", {count: missing.length})}/>}
			<ul className="p-row-list p-exit-list" aria-label={t("exits.only")}>
				{rows.map(e => <li key={e.tag}><label className="p-exit" htmlFor={id + e.tag}>
					<input type="checkbox" className="p-check" id={id + e.tag} checked={chosen.includes(e.tag)} onChange={event => pick(e.tag, event.target.checked)}/>
					<span className="p-row-text">{e.name ? <><strong>{e.name}</strong><span className="vw-code">{e.tag}</span></> : <strong className="vw-code">{e.tag}</strong>}</span>
					<span className="p-flags">{e.country && <span className="p-tag vw-code" title={t("exits.country")}>{e.country}</span>}{e.up !== null && <Mark tone={e.up ? "success" : "danger"}>{t(e.up ? "exits.up" : "exits.down")}</Mark>}</span>
				</label></li>)}
				{missing.map(tag => <li key={tag}><label className="p-exit" htmlFor={id + tag}>
					<input type="checkbox" className="p-check" id={id + tag} checked onChange={() => pick(tag, false)}/>
					<span className="p-row-text"><strong className="vw-code">{tag}</strong></span>
					<span className="p-flags"><Mark tone="danger">{t("exits.missing")}</Mark></span>
				</label></li>)}
			</ul>
			{problem && <p className="vw-note p-exit-problem" role="alert">{problem}</p>}
			{picker}
		</>)}
	</div>;
}

export function UserForm({user, defaultLimit, onClose, onSaved}: {user: User | null, defaultLimit: number, onClose: () => void, onSaved: (user: User, link: LinkView | null, linkError: string | null) => void}) {
	const {t} = useP(), guard = useGuard(), choices = (useSettings()?.endpoints ?? []).length;
	const [name, setName] = useState(user?.name ?? ""), [groups, setGroups] = useState(user?.groups.join(", ") ?? ""), [quota, setQuota] = useState<number | "">(user?.quota_bytes ? Math.round(user.quota_bytes / GB * 100) / 100 : "");
	const [period, setPeriod] = useState<Period>((user?.quota_period as Period | null) ?? "none"), [day, setDay] = useState(toDay(user?.expires_at)), [limit, setLimit] = useState<number | "">(user?.device_limit ?? defaultLimit), [note, setNote] = useState(user?.note ?? ""), [enabled, setEnabled] = useState(user?.enabled ?? true);
	const [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [tried, setTried] = useState(false), [exits, setExits] = useState<Exits>("all"), [fallback, setFallback] = useState<string | null>(null), [endpoint, setEndpoint] = useState(""), nodeExits = useExits(!user);
	const list = groups.split(",").map(g => g.trim().toLowerCase()).filter(Boolean);
	const problems = {name: NAME.test(name) ? undefined : t("error.userName"), groups: list.every(g => NAME.test(g)) ? undefined : t("error.group"), exits: keptExits(exits, nodeExits.data).length === 0 ? t("exits.pick") : undefined};
	const save = async () => {
		setTried(true);
		if (problems.name || problems.groups || (!user && problems.exits)) return;
		setBusy(true);
		setError(null);
		const body = {name, groups: list, quota_bytes: quota === "" ? null : Math.round(quota * GB), quota_period: quota === "" || period === "none" ? null : period, expires_at: fromDay(day), device_limit: limit === "" ? 0 : limit, note, enabled};
		try {
			// The schema lists the nullable fields as required, but the server leaves out what is not sent, so the default exit stays.
			if (user) onSaved((await guard(() => api("patch", "/users/{id}", {params: {id: user.id}, body: body as UserPatch}))).user, null, null);
			else {
				const answer = await guard(() => api("post", "/users", {body: {...body, exits: keptExits(exits, nodeExits.data), exit: keptFallback(exits, fallback, nodeExits.data), endpoint: endpoint || null}}));
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
			{!user && <div className="vw-field"><span className="vw-label">{t("exits.title")}</span><p className="vw-note">{t("exits.lead")}</p><ExitPicker value={exits} onChange={setExits} exits={nodeExits} problem={tried ? problems.exits : undefined} fallback={fallback} onFallback={setFallback}/></div>}
			{!user && choices > 0 && <EndpointPick label={t("endpoint.label")} hint={t("endpoint.hint")} value={endpoint} onChange={setEndpoint} followLabel={t("endpoint.follow")}/>}
			<TextField label={t("form.note")} hint={t("form.noteHint")} value={note} onChange={setNote} optional/>
			<Switch label={t("form.enabled")} hint={t("form.enabledHint")} checked={enabled} onChange={setEnabled}/>
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy}>{user ? t("common.save") : t("form.create")}</Button></div>
		</form>
	</Dialog>;
}
