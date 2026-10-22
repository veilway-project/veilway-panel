import {Banner, Button, Checkbox, ConfirmDialog, Glass, RadioGroup, SelectField, StateBlock, Switch, TextField, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type Inspected, type Review, type Upstream} from "../api.ts";
import {ago, ErrorNote, Mark, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {loadRunning} from "./config.tsx";

const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const STATE_TONE = {up: "success", fetching: "warning", connecting: "warning", down: "danger"} as const;
const tags = (value: unknown) => (Array.isArray(value) ? value as {tag?: unknown, type?: unknown}[] : []);

// Other providers whose subscription is an exit of this node: one status card each, and the steps that add one. Nothing is fetched before the operator has seen the host and the key fingerprint and said so, and nothing is written to the config before the provider's document was read and a recent re-authentication confirmed it.
export function UpstreamsTab() {
	const {t} = useP(), say = useSay(), [adding, setAdding] = useState(false), found = useLoad(() => api("get", "/upstreams"), []);
	useEffect(() => { const timer = setInterval(found.reload, 15000); return () => clearInterval(timer); }, [found.reload]);
	if (adding) return <AddFlow onClose={() => { setAdding(false); found.reload(); }}/>;
	return <div className="p-stack">
		<div className="p-row"><p className="vw-muted p-lead">{t("up.lead")}</p><Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t("up.add")}</Button></div>
		{!!found.error && !found.data && <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={found.reload}>{t("action.retry")}</Button>}>{say(found.error)}</StateBlock>}
		{found.data && !found.data.upstreams.length && <Glass className="p-panel"><StateBlock kind="empty" title={t("up.empty")} action={<Button variant="primary" icon="plus" onClick={() => setAdding(true)}>{t("up.add")}</Button>}>{t("up.emptyBody")}</StateBlock></Glass>}
		<div className="p-columns p-node-cards">{(found.data?.upstreams ?? []).map(upstream => <UpstreamCard key={upstream.tag} upstream={upstream} onChanged={found.reload}/>)}</div>
	</div>;
}

function UpstreamCard({upstream, onChanged}: {upstream: Upstream, onChanged: () => void}) {
	const {t, bytes, number, date} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), [busy, setBusy] = useState(false), [removing, setRemoving] = useState(false);
	const waiting = upstream.pending_move != null || upstream.pending_hosts.length > 0, since = (at: number) => { const found = ago(Math.max(0, Date.now() / 1000 - at)); return t(found.key, {count: found.count}); };
	const unknown = t("users.usageUnknown"), day = (at?: number | null) => at ? date(new Date(at * 1000)) : unknown;
	const act = <T,>(work: () => Promise<T>, done: (result: T) => void) => { setBusy(true); void guard(work).then(done, failure => toast({tone: "danger", title: say(failure)})).finally(() => setBusy(false)); };
	return <Glass className="p-node-card">
		<div className="p-sheet-head"><div><strong className="vw-h3"><bdi className="vw-code" dir="ltr">{upstream.tag}</bdi></strong><span className="vw-small vw-muted">{upstream.provider ?? t("up.unnamed")}</span></div><Mark tone={STATE_TONE[upstream.state as keyof typeof STATE_TONE]}>{t(`up.state.${upstream.state as "up"}`)}</Mark></div>
		{upstream.reason && <p className="vw-small" dir="auto">{upstream.reason}</p>}
		{upstream.refresh_error && <Banner tone="warning" title={t("up.refreshError")}><span dir="auto">{upstream.refresh_error}</span></Banner>}
		{waiting && <Banner tone="warning" title={t("up.pending.title")} action={<Button size="sm" disabled={busy} onClick={() => act(() => api("post", "/upstreams/{tag}/confirm", {params: {tag: upstream.tag}, body: {move: upstream.pending_move != null, hosts: upstream.pending_hosts.length > 0}}), () => { toast({tone: "success", title: t("up.confirmed")}); onChanged(); })}>{t("up.pending.confirm")}</Button>}>
			<p>{t("up.pending.body")}</p>
			{upstream.pending_move != null && <p>{t("up.pending.move")} <bdi className="vw-code" dir="ltr">{upstream.pending_move}</bdi></p>}
			{upstream.pending_hosts.length > 0 && <p>{t("up.pending.hosts")} <bdi className="vw-code" dir="ltr">{upstream.pending_hosts.join(", ")}</bdi></p>}
		</Banner>}
		<dl>
			<div><dt>{t("up.since")}</dt><dd className="vw-num">{since(Date.now() / 1000 - upstream.state_secs)}</dd></div>
			<div><dt>{t("up.profile")}</dt><dd className="vw-code">{upstream.profile ? upstream.profile + (upstream.transport ? " / " + upstream.transport : "") : unknown}</dd></div>
			<div><dt>{t("up.exitUsed")}</dt><dd className="vw-code">{upstream.exit ?? unknown}</dd></div>
			<div><dt>{t("up.quota")}</dt><dd className="vw-num">{upstream.quota ? (upstream.quota.quota_bytes ? t("up.quotaUsed", {used: bytes(upstream.quota.used_bytes).text, quota: bytes(upstream.quota.quota_bytes).text}) : t("up.noQuota")) : unknown}</dd></div>
			<div><dt>{t("up.validUntil")}</dt><dd className="vw-num">{day(upstream.expires_at)}</dd></div>
			<div><dt>{t("up.refreshed")}</dt><dd className="vw-num">{upstream.refreshed_at ? since(upstream.refreshed_at) : unknown}</dd></div>
			<div><dt>{t("up.mtu")}</dt><dd className="vw-num">{upstream.mtu == null ? unknown : number(upstream.mtu)}</dd></div>
			<div><dt>{t("up.traffic")}</dt><dd className="vw-num">{bytes(upstream.counters.traffic.up_bytes + upstream.counters.traffic.down_bytes).text}</dd></div>
			<div><dt>{t("up.refusedFlows")}</dt><dd className="vw-num">{number(upstream.counters.refused)}</dd></div>
			<div><dt>{t("up.dropped")}</dt><dd className="vw-num">{number(upstream.counters.dropped)}</dd></div>
		</dl>
		{upstream.notices.length > 0 && <div className="p-stack"><span className="vw-label">{t("up.notices")}</span><ul className="p-row-list">{upstream.notices.map((notice, i) => <li key={i} className="vw-small" dir="auto">{notice}</li>)}</ul></div>}
		<span className="p-cluster"><Button size="sm" variant="quiet" icon="refresh" disabled={busy} onClick={() => act(() => api("post", "/upstreams/{tag}/retry", {params: {tag: upstream.tag}}), () => { toast({tone: "success", title: t("up.retried")}); onChanged(); })}>{t("up.retry")}</Button><Button size="sm" variant="quiet" disabled={busy} onClick={() => setRemoving(true)}>{t("common.remove")}</Button></span>
		<ConfirmDialog open={removing} onOpenChange={setRemoving} danger title={t("up.removeTitle", {name: upstream.tag})} body={t("up.removeBody", {name: upstream.tag})} confirmLabel={t("up.removeConfirm")} onConfirm={() => { setRemoving(false); act(() => api("delete", "/upstreams/{tag}", {params: {tag: upstream.tag}}), gone => { toast({tone: gone.confirmed === false ? "warning" : "success", title: t(gone.confirmed === false ? "up.removed.unconfirmed" : gone.confirmed ? "up.removed.confirmed" : "up.removed")}); onChanged(); }); }}/>
	</Glass>;
}

// Paste and read the link offline, fetch on the operator's word, read what the provider sent, then confirm. The device key and secret never reach this page.
function AddFlow({onClose}: {onClose: () => void}) {
	const {t, date, bytes, number} = useP(), say = useSay(), toast = useToast(), guard = useGuard(), [link, setLink] = useState(""), [via, setVia] = useState(""), [read, setRead] = useState<Inspected | null>(null), [review, setReview] = useState<Review | null>(null);
	const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [profile, setProfile] = useState(""), [exit, setExit] = useState(""), [allow, setAllow] = useState<string[]>([]), [tag, setTag] = useState("provider"), [name, setName] = useState("");
	const running = useLoad(loadRunning, []), outbounds = tags(running.data?.document.outbounds).filter(item => item.type === "direct" || item.type === "socks5").map(item => String(item.tag)), taken = [...tags(running.data?.document.upstreams), ...tags(running.data?.document.exits)].map(item => item.tag);
	const work = (job: () => Promise<void>) => { setBusy(true); setError(null); void job().catch(setError).finally(() => setBusy(false)); };
	const leave = () => { if (review) void api("delete", "/upstreams/previews/{preview}", {params: {preview: review.id}}).catch(() => { }); onClose(); };
	const usable = review?.profiles.filter(item => !item.refused) ?? [], chosen = review ? review.profiles.find(item => item.id === (profile || usable[0]?.id)) : undefined;
	const tagWrong = !TAG.test(tag) ? t("up.err.tag") : taken.includes(tag) ? t("up.err.tagTaken") : undefined;
	const warning = <Banner tone="warning" title={t("up.warn.title")}>{t("up.warn.body")}</Banner>;
	const show = (next: Review) => { setReview(next); setProfile(""); setExit(""); };
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
		<div className="p-form-foot"><Button onClick={onClose}>{t("action.cancel")}</Button>{read ? <Button variant="primary" disabled={busy} onClick={() => work(async () => show(await api("post", "/upstreams/previews", {body: {link: link.trim(), via: via || undefined}})))}>{t("up.fetch")}</Button> : <Button variant="primary" disabled={busy || !link.trim()} onClick={() => work(async () => setRead(await api("post", "/upstreams/inspect", {body: {link: link.trim()}})))}>{t("up.read")}</Button>}</div>
	</Glass>;
	const privateSeen = review.profiles.some(item => item.private_addresses.length > 0), classes = review.classes.filter(item => item !== "cover");
	const add = () => work(async () => {
		const done = await guard(() => api("post", "/upstreams/previews/{preview}/confirm", {params: {preview: review.id}, body: {tag, name: name.trim() || undefined, profile: profile || undefined, exit: exit || undefined, allow}}));
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
		<RadioGroup label={t("up.profiles")} value={chosen?.id ?? ""} onChange={value => { setProfile(value); setExit(""); }} options={review.profiles.map(item => ({value: item.id, label: item.name, disabled: !!item.refused, detail: item.refused ? t("up.profile.refused", {why: item.refused}) : [t(`up.rating.${item.rating as "protected"}`), item.transports.join(", "), t("up.profile.mtu", {mtu: number(item.mtu)}), item.exits.length ? t("up.profile.exits", {exits: item.exits.map(found => found.name).join(", ")}) : "", item.private_addresses.length ? t("up.profile.private", {addresses: item.private_addresses.join(", ")}) : ""].filter(Boolean).join(". ")}))}/>
		{privateSeen && <div className="p-stack">
			<Switch label={t("up.private")} hint={t("up.privateHint")} checked={review.allow_private} disabled={busy} onChange={on => work(async () => show(await api("post", "/upstreams/previews/{preview}/private", {params: {preview: review.id}, body: {allow_private: on}})))}/>
			{review.allow_private && <Banner tone="danger" title={t("up.private.warnTitle")}>{t("up.private.warn")}</Banner>}
		</div>}
		{chosen && chosen.exits.length > 0 && <SelectField label={t("up.exitChoice")} value={exit || "default"} onChange={value => setExit(value === "default" ? "" : value)} options={[{value: "default", label: t("up.exitDefault")}, ...chosen.exits.map(item => ({value: item.tag, label: item.name}))]}/>}
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
