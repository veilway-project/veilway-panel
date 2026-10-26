import {Banner, Button, Checkbox, ConfirmDialog, Glass, RadioGroup, SelectField, StateBlock, Switch, TextField, UsageBar, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type Inspected, type Review, type Upstream, type UpstreamChoice} from "../api.ts";
import {ago, ErrorNote, Mark, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {ServerPicker, useServers} from "../servers.tsx";
import {loadRunning} from "./config.tsx";

const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const AUTO = "auto";
const ENGINE = ["connecting", "reconnecting", "connected", "failed"];
const STOPPED = ["quota", "expired", "disabled", "node-stopping"];
const STATE_TONE = {up: "success", fetching: "warning", connecting: "warning", down: "danger"} as const;
const tags = (value: unknown) => (Array.isArray(value) ? value as {tag?: unknown, type?: unknown}[] : []);
// Node 1 keeps its own routes; every other server names itself as {id}. The calls pass the id either way, and a path without {id} ignores it.
const route = (server: number) => server === 1 ? "/upstreams" as const : "/nodes/{id}/upstreams" as const;

// Other providers whose subscription is an exit of the server picked above: one status card each, and the steps that add one. Nothing is fetched before the operator has seen the host and the key fingerprint and said so, and nothing is written to the config before the provider's document was read and a recent re-authentication confirmed it.
export function UpstreamsTab() {
	const {selected} = useServers();
	return <Upstreams key={selected} server={selected}/>;
}

function Upstreams({server}: {server: number}) {
	const {t} = useP(), say = useSay(), [adding, setAdding] = useState(false), found = useLoad(() => api("get", route(server), {params: {id: server}}), []);
	useEffect(() => { const timer = setInterval(found.reload, 15000); return () => clearInterval(timer); }, [found.reload]);
	// A preview belongs to the server that made it, so the picker stays in view but cannot move while a provider is being added.
	if (adding) return <div className="p-stack"><ServerPicker disabled/><AddFlow server={server} onClose={() => { setAdding(false); found.reload(); }}/></div>;
	if (found.error && !found.data) return <div className="p-stack"><ServerPicker/><StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={found.reload}>{t("action.retry")}</Button>}>{say(found.error)}</StateBlock></div>;
	if (!found.data) return <div className="p-stack"><ServerPicker/><StateBlock kind="loading" title={t("common.loading")}/></div>;
	return <div className="p-stack">
		<ServerPicker/>
		<div className="p-row"><p className="vw-muted p-lead">{t("up.lead")}</p><Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t("up.add")}</Button></div>
		{!found.data.upstreams.length && <Glass className="p-panel"><StateBlock kind="empty" title={t("up.empty")} action={<Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t("up.add")}</Button>}>{t("up.emptyBody")}</StateBlock></Glass>}
		<div className="p-columns p-node-cards">{found.data.upstreams.map(upstream => <UpstreamCard key={upstream.tag} server={server} upstream={upstream} onChanged={found.reload}/>)}</div>
	</div>;
}

function UpstreamCard({server, upstream, onChanged}: {server: number, upstream: Upstream, onChanged: () => void}) {
	const {t, bytes, number, date} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), [busy, setBusy] = useState(false), [removing, setRemoving] = useState(false);
	const waiting = upstream.pending_move != null || upstream.pending_hosts.length > 0, since = (at: number) => { const found = ago(Math.max(0, Date.now() / 1000 - at)); return t(found.key, {count: found.count}); };
	const unknown = t("users.usageUnknown"), day = (at?: number | null) => at ? date(new Date(at * 1000)) : unknown;
	const act = <T,>(work: () => Promise<T>, done: (result: T) => void) => { setBusy(true); void guard(work).then(done, failure => toast({tone: "danger", title: say(failure)})).finally(() => setBusy(false)); };
	const {choice, exits, profiles, transports, quota} = upstream, [reason, stoppedFor] = (upstream.engine_state ?? "").split(":"), engine = !upstream.engine_state ? unknown : ENGINE.includes(upstream.engine_state) ? t(`up.engine.${upstream.engine_state as "failed"}`) : reason === "stopped" ? t("up.engine.stopped", {reason: STOPPED.includes(stoppedFor ?? "") ? t(`up.engine.reason.${stoppedFor as "quota"}`) : stoppedFor ?? ""}) : upstream.engine_state;
	const ask = (body: UpstreamChoice) => act(() => api("patch", `${route(server)}/{tag}` as const, {params: {id: server, tag: upstream.tag}, body: body as never}), done => { toast({tone: "success", title: t(done.live ? "up.choice.live" : "up.choice.restart")}); onChanged(); });
	// A value the node holds that the lists no longer carry stays selectable, so the select never shows nothing.
	const options = (held: string | null | undefined, listed: {value: string, label: string, detail?: string}[]) => [{value: AUTO, label: t("up.choice.auto")}, ...listed, ...(held && !listed.some(item => item.value === held) ? [{value: held, label: held}] : [])];
	const unusable = profiles.filter(item => !item.usable);
	return <Glass className="p-node-card">
		<div className="p-sheet-head"><div><strong className="vw-h3"><bdi className="vw-code" dir="ltr">{upstream.tag}</bdi></strong><span className="vw-small vw-muted">{upstream.provider ?? t("up.unnamed")}</span></div><Mark tone={STATE_TONE[upstream.state as keyof typeof STATE_TONE]}>{t(`up.state.${upstream.state as "up"}`)}</Mark></div>
		{upstream.reason && <p className="vw-small" dir="auto">{upstream.reason}</p>}
		{upstream.refresh_error && <Banner tone="warning" title={t("up.refreshError")}><span dir="auto">{upstream.refresh_error}</span></Banner>}
		{waiting && <Banner tone="warning" title={t("up.pending.title")} action={<Button size="sm" disabled={busy} onClick={() => act(() => api("post", `${route(server)}/{tag}/confirm` as const, {params: {id: server, tag: upstream.tag}, body: {move: upstream.pending_move != null, hosts: upstream.pending_hosts.length > 0}}), () => { toast({tone: "success", title: t("up.confirmed")}); onChanged(); })}>{t("up.pending.confirm")}</Button>}>
			<p>{t("up.pending.body")}</p>
			{upstream.pending_move != null && <p>{t("up.pending.move")} <bdi className="vw-code" dir="ltr">{upstream.pending_move}</bdi></p>}
			{upstream.pending_hosts.length > 0 && <p>{t("up.pending.hosts")} <bdi className="vw-code" dir="ltr">{upstream.pending_hosts.join(", ")}</bdi></p>}
		</Banner>}
		<dl>
			<div><dt>{t("up.since")}</dt><dd className="vw-num">{since(Date.now() / 1000 - upstream.state_secs)}</dd></div>
			<div><dt>{t("up.profile")}</dt><dd className="vw-code">{upstream.profile ? upstream.profile + (upstream.transport ? " / " + upstream.transport : "") : unknown}</dd></div>
			<div><dt>{t("up.exitUsed")}</dt><dd className="vw-code">{upstream.exit ?? unknown}</dd></div>
			<div><dt>{t("up.tunnel")}</dt><dd>{engine}{upstream.connected_secs != null && <> <span className="vw-muted vw-num">{t("up.connectedFor", {time: since(Date.now() / 1000 - upstream.connected_secs)})}</span></>}</dd></div>
			<div><dt>{t("up.accountEnds")}</dt><dd className="vw-num">{quota?.account_expires_at ? day(quota.account_expires_at) : unknown}</dd></div>
			<div><dt>{t("up.validUntil")}</dt><dd className="vw-num">{day(upstream.expires_at)}</dd></div>
			<div><dt>{t("up.refreshed")}</dt><dd className="vw-num">{upstream.refreshed_at ? since(upstream.refreshed_at) : unknown}</dd></div>
			<div><dt>{t("up.mtu")}</dt><dd className="vw-num">{upstream.mtu == null ? unknown : number(upstream.mtu)}</dd></div>
			<div><dt>{t("up.traffic")}</dt><dd className="vw-num">{bytes(upstream.counters.traffic.up_bytes + upstream.counters.traffic.down_bytes).text}</dd></div>
			<div><dt>{t("up.refusedFlows")}</dt><dd className="vw-num">{number(upstream.counters.refused)}</dd></div>
			<div><dt>{t("up.dropped")}</dt><dd className="vw-num">{number(upstream.counters.dropped)}</dd></div>
		</dl>
		<div className="p-stack"><span className="vw-label">{t("up.quota")}</span>{quota?.quota_bytes ? <UsageBar compact label={t("up.quota")} used={quota.used_bytes} total={quota.quota_bytes}/> : <span className="vw-small vw-muted">{quota ? t("up.noQuota") : unknown}</span>}{quota?.period && quota.period !== "none" && <span className="vw-small vw-muted">{t(`up.period.${quota.period as "daily"}`)}</span>}</div>
		<div className="p-stack">
			<span className="vw-label">{t("up.choice.title")}</span>
			<SelectField label={t("up.choice.exit")} hint={exits.length ? undefined : t("up.choice.exitWait")} value={choice.exit ?? AUTO} disabled={busy || (!exits.length && !choice.exit)} onChange={value => ask({exit: value === AUTO ? null : value})} options={options(choice.exit, exits.map(item => ({value: item.tag, label: item.name, detail: item.country ?? undefined})))}/>
			<SelectField label={t("up.choice.profile")} hint={t("up.choice.profileHint")} value={choice.profile ?? AUTO} disabled={busy} onChange={value => ask({profile: value === AUTO ? null : value})} options={options(choice.profile, profiles.map(item => ({value: item.id, label: item.name, detail: item.usable ? undefined : t("up.choice.notUsable")})))}/>
			{choice.profile && <Checkbox label={t("up.choice.failover")} checked={choice.failover} disabled={busy} onChange={on => ask({failover: on})}/>}
			<SelectField label={t("up.choice.transport")} hint={t("up.choice.transportHint")} value={choice.transport ?? AUTO} disabled={busy} onChange={value => ask({transport: value === AUTO ? null : value})} options={options(choice.transport, transports.map(item => ({value: item, label: item})))}/>
			<p className="vw-small vw-muted">{t("up.choice.note")}</p>
		</div>
		{unusable.length > 0 && <div className="p-stack"><span className="vw-label">{t("up.unusable")}</span><ul className="p-row-list">{unusable.map(item => <li key={item.id} className="vw-small" dir="auto"><strong>{item.name}</strong> {item.reason}</li>)}</ul></div>}
		{upstream.provider_notices.length > 0 ? <div className="p-stack"><span className="vw-label">{t("up.notices")}</span>{upstream.provider_notices.map((notice, i) => notice.severity === "warning" ? <Banner key={i} tone="warning" title={t("up.notice.warning")}><span dir="auto">{notice.text}</span></Banner> : <p key={i} className="vw-small" dir="auto">{notice.text}</p>)}</div> : upstream.notices.length > 0 && <div className="p-stack"><span className="vw-label">{t("up.notices")}</span><ul className="p-row-list">{upstream.notices.map((notice, i) => <li key={i} className="vw-small" dir="auto">{notice}</li>)}</ul></div>}
		<span className="p-cluster"><Button size="sm" variant="quiet" icon="refresh" disabled={busy} onClick={() => act(() => api("post", `${route(server)}/{tag}/retry` as const, {params: {id: server, tag: upstream.tag}}), () => { toast({tone: "success", title: t("up.retried")}); onChanged(); })}>{t("up.retry")}</Button><Button size="sm" variant="quiet" disabled={busy} onClick={() => setRemoving(true)}>{t("common.remove")}</Button></span>
		<ConfirmDialog open={removing} onOpenChange={setRemoving} danger title={t("up.removeTitle", {name: upstream.tag})} body={t("up.removeBody", {name: upstream.tag})} confirmLabel={t("up.removeConfirm")} onConfirm={() => { setRemoving(false); act(() => api("delete", `${route(server)}/{tag}` as const, {params: {id: server, tag: upstream.tag}}), gone => { toast({tone: gone.confirmed === false ? "warning" : "success", title: t(gone.confirmed === false ? "up.removed.unconfirmed" : gone.confirmed ? "up.removed.confirmed" : "up.removed")}); onChanged(); }); }}/>
	</Glass>;
}

// Paste and read the link offline, fetch on the operator's word, read what the provider sent, then confirm. The device key and secret never reach this page.
function AddFlow({server, onClose}: {server: number, onClose: () => void}) {
	const {t, date, bytes, number} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), [link, setLink] = useState(""), [via, setVia] = useState(""), [read, setRead] = useState<Inspected | null>(null), [review, setReview] = useState<Review | null>(null);
	const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [profile, setProfile] = useState(""), [exit, setExit] = useState(""), [transport, setTransport] = useState(""), [allow, setAllow] = useState<string[]>([]), [tag, setTag] = useState("provider"), [name, setName] = useState("");
	const running = useLoad(() => loadRunning(server), []), outbounds = tags(running.data?.document.outbounds).filter(item => item.type === "direct" || item.type === "socks5").map(item => String(item.tag)), taken = [...tags(running.data?.document.upstreams), ...tags(running.data?.document.exits)].map(item => item.tag);
	const work = (job: () => Promise<void>) => { setBusy(true); setError(null); void job().catch(setError).finally(() => setBusy(false)); };
	const leave = () => { if (review) void api("delete", `${route(server)}/previews/{preview}` as const, {params: {id: server, preview: review.id}}).catch(() => { }); onClose(); };
	const usable = review?.profiles.filter(item => !item.refused) ?? [], chosen = review?.profiles.find(item => item.id === profile);
	const pool = chosen ? [chosen] : usable, poolExits = [...new Map(pool.flatMap(item => item.exits).map(item => [item.tag, item])).values()], poolTransports = [...new Set(pool.flatMap(item => item.transports))];
	const tagWrong = !TAG.test(tag) ? t("up.err.tag") : taken.includes(tag) ? t("up.err.tagTaken") : undefined;
	const warning = <Banner tone="warning" title={t("up.warn.title")}>{t("up.warn.body")}</Banner>;
	const show = (next: Review) => { setReview(next); setProfile(""); setExit(""); setTransport(""); };
	if (!review) return <Glass className="p-panel p-form">
		<div><h2 className="vw-h2">{t("up.add")}</h2><p className="vw-muted">{t("up.addLead")}</p></div>
		{warning}
		<TextField label={t("up.link")} hint={t("up.linkHint")} value={link} onChange={value => { setLink(value); setRead(null); }} technical/>
		<SelectField label={t("up.via")} hint={t("up.viaHint")} value={via || "direct"} onChange={value => setVia(value === "direct" ? "" : value)} options={[{value: "direct", label: t("config.viaDirect")}, ...outbounds.map(item => ({value: item, label: item}))]}/>
		{read && <div className="p-stack">
			<dl className="p-facts"><div><dt>{t("up.host")}</dt><dd className="vw-code" dir="ltr">{read.host}</dd></div><div><dt>{t("up.fingerprint")}</dt><dd className="vw-code" dir="ltr">{read.fingerprint}</dd></div></dl>
			<Banner tone="info" title={t("up.fetchAsk")}>{t("up.fetchBody")}</Banner>
		</div>}
		<ErrorNote error={error}/>
		{busy && read && <StateBlock kind="loading" title={t("up.fetching")}/>}
		<div className="p-form-foot"><Button onClick={onClose}>{t("action.cancel")}</Button>{read ? <Button variant="primary" disabled={busy} onClick={() => work(async () => show(await api("post", `${route(server)}/previews` as const, {params: {id: server}, body: {link: link.trim(), via: via || undefined}})))}>{t("up.fetch")}</Button> : <Button variant="primary" disabled={busy || !link.trim()} onClick={() => work(async () => setRead(await api("post", "/upstreams/inspect", {body: {link: link.trim()}})))}>{t("up.read")}</Button>}</div>
	</Glass>;
	const privateSeen = review.profiles.some(item => item.private_addresses.length > 0), classes = review.classes.filter(item => item !== "cover");
	const add = () => work(async () => {
		const done = await guard(() => api("post", `${route(server)}/previews/{preview}/confirm` as const, {params: {id: server, preview: review.id}, body: {tag, name: name.trim() || undefined, profile: profile || undefined, exit: exit || undefined, transport: transport || undefined, allow}}));
		toast({tone: "success", title: t("up.added", {tag: done.tag})});
		onClose();
	});
	return <Glass className="p-panel p-form">
		<div><h2 className="vw-h2">{t("up.reviewTitle")}</h2><p className="vw-muted">{t("up.reviewLead")}</p></div>
		{warning}
		<dl className="p-facts">
			<div><dt>{t("up.claimed")}</dt><dd>{review.provider}</dd></div>
			<div><dt>{t("up.host")}</dt><dd className="vw-code" dir="ltr">{review.host}</dd></div>
			<div><dt>{t("up.fingerprint")}</dt><dd className="vw-code" dir="ltr">{review.fingerprint}</dd></div>
			<div><dt>{t("up.validUntil")}</dt><dd className="vw-num">{date(new Date(review.expires_at * 1000))}</dd></div>
			<div><dt>{t("up.account")}</dt><dd className="vw-num">{review.account_expires_at ? date(new Date(review.account_expires_at * 1000)) : t("up.never")}</dd></div>
			<div><dt>{t("up.quota")}</dt><dd className="vw-num">{review.quota ? (review.quota.quota_bytes ? t("up.quotaUsed", {used: bytes(review.quota.used_bytes).text, quota: bytes(review.quota.quota_bytes).text}) : t("up.noQuota")) : t("users.usageUnknown")}</dd></div>
			<div><dt>{t("up.devices")}</dt><dd className="vw-num">{review.device_limit ? t("up.devicesOf", {count: number(review.devices), limit: number(review.device_limit)}) : number(review.devices)}</dd></div>
		</dl>
		<RadioGroup label={t("up.profiles")} value={chosen?.id ?? AUTO} onChange={value => { setProfile(value === AUTO ? "" : value); setExit(""); setTransport(""); }} options={[{value: AUTO, label: t("up.choice.auto"), detail: t("up.choice.profileHint")}, ...review.profiles.map(item => ({value: item.id, label: item.name, disabled: !!item.refused, detail: item.refused ? t("up.profile.refused", {why: item.refused}) : [t(`up.rating.${item.rating as "protected"}`), item.transports.join(", "), t("up.profile.mtu", {mtu: number(item.mtu)}), item.exits.length ? t("up.profile.exits", {exits: item.exits.map(found => found.name).join(", ")}) : "", item.private_addresses.length ? t("up.profile.private", {addresses: item.private_addresses.join(", ")}) : ""].filter(Boolean).join(". ")}))]}/>
		{privateSeen && <div className="p-stack">
			<Switch label={t("up.private")} hint={t("up.privateHint")} checked={review.allow_private} disabled={busy} onChange={on => work(async () => show(await api("post", `${route(server)}/previews/{preview}/private` as const, {params: {id: server, preview: review.id}, body: {allow_private: on}})))}/>
			{review.allow_private && <Banner tone="danger" title={t("up.private.warnTitle")}>{t("up.private.warn")}</Banner>}
		</div>}
		{poolExits.length > 0 && <SelectField label={t("up.exitChoice")} value={exit || "default"} onChange={value => setExit(value === "default" ? "" : value)} options={[{value: "default", label: t("up.exitDefault")}, ...poolExits.map(item => ({value: item.tag, label: item.name}))]}/>}
		{poolTransports.length > 0 && <SelectField label={t("up.choice.transport")} hint={t("up.choice.transportHint")} value={transport || AUTO} onChange={value => setTransport(value === AUTO ? "" : value)} options={[{value: AUTO, label: t("up.choice.auto")}, ...poolTransports.map(item => ({value: item, label: item}))]}/>}
		{classes.length > 0 && <div className="vw-field"><span className="vw-label">{t("up.classes")}</span><p className="vw-note">{t("up.classesHint")}</p><div className="p-pick-list">{classes.map(item => <div key={item} className="p-pick-row"><Checkbox label={t(`up.class.${item as "plain"}`)} checked={allow.includes(item)} onChange={on => setAllow(on ? [...allow, item] : allow.filter(held => held !== item))}/></div>)}</div></div>}
		<div className="p-pair">
			<TextField label={t("up.tag")} hint={t("up.tagHint")} value={tag} onChange={setTag} error={tagWrong} technical/>
			<TextField label={t("up.exitName")} value={name} onChange={setName} maxLength={64} optional/>
		</div>
		<ErrorNote error={error}/>
		{busy && <StateBlock kind="loading" title={t("up.fetching")}/>}
		<div className="p-form-foot"><p>{t("up.confirmNote")}</p><Button onClick={leave} disabled={busy}>{t("up.decline")}</Button><Button variant="primary" disabled={busy || !!tagWrong || !usable.length} onClick={add}>{t("up.confirm")}</Button></div>
	</Glass>;
}
