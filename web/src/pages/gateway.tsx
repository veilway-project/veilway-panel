import {Banner, Button, ConfirmDialog, Dialog, List, ListRow, NumberField, SecretField, StateBlock, useToast} from "@veilway/ui";
import {Fragment, useState} from "react";
import {api, type ResetOut, type Settings, type Switched} from "../api.ts";
import {Copyable, ErrorNote, Mark, useGuard, useLoad, useP, useSay} from "../kit.tsx";

type Ask = "switch" | "theft" | "recreate" | "load" | "reset" | null;

// The gateway keys behind the subscription endpoint. The days a retired key is kept save with the settings form; every other action acts on its own and asks for a fresh sign-in.
export function GatewaySection({draft, patch}: {draft: Settings, patch: (change: Partial<Settings>) => void}) {
	const {t, date, number} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), keys = useLoad(() => api("get", "/gateway-keys"), []);
	const [ask, setAsk] = useState<Ask>(null), [paste, setPaste] = useState(""), [keyId, setKeyId] = useState<number | "">(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [made, setMade] = useState<Switched | null>(null), [count, setCount] = useState<number | null>(null), [links, setLinks] = useState<ResetOut | null>(null);
	const data = keys.data, day = (seconds: number) => date(new Date(seconds * 1000)), close = () => { setAsk(null); setPaste(""); setKeyId(""); setError(null); setCount(null); };
	const act = async (work: () => Promise<void>) => {
		setBusy(true);
		setError(null);
		try {
			await guard(work);
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const swap = (path: "/gateway-keys/rotate" | "/gateway-keys/theft") => act(async () => {
		const answer = await api("post", path, {body: {private: paste.trim() || null, confirm: false}});
		setMade(answer);
		keys.set(answer.gateway);
		close();
	});
	const load = () => act(async () => {
		const answer = await api("post", "/gateway-keys/rotate", {body: {private: paste.trim(), id: keyId === "" ? null : keyId, confirm: true}});
		setMade(answer);
		keys.set(answer.gateway);
		close();
	});
	const recreate = () => act(async () => {
		const answer = await api("post", "/gateway-keys/recreate", {body: {confirm: true}});
		setMade(answer);
		keys.set(answer.gateway);
		close();
	});
	const preview = () => { setAsk("reset"); void act(async () => setCount((await api("post", "/gateway-keys/reset-affected", {body: {dry_run: true}})).count)); };
	const reset = () => act(async () => {
		const answer = await api("post", "/gateway-keys/reset-affected", {body: {dry_run: false}});
		setLinks(answer);
		close();
		keys.reload();
		toast({tone: "success", title: t("gateway.resetDone", {count: answer.count})});
	});
	return <section className="p-section" id="set-gateway">
		<div><h2 className="vw-h3" tabIndex={-1}>{t("settings.gateway")}</h2><p>{t("settings.gatewayLead")}</p></div>
		<div className="p-form">
			{keys.error && !data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={keys.reload}>{t("action.retry")}</Button>}>{say(keys.error)}</StateBlock>
			: !data ? <StateBlock kind="loading" title={t("common.loading")}/>
			: <>
				{!data.loaded && <Banner tone="danger" title={t("gateway.lost")} action={<span className="p-cluster"><Button size="sm" onClick={() => setAsk("load")}>{t("gateway.load")}</Button><Button size="sm" variant="danger" onClick={() => setAsk("recreate")}>{t("gateway.recreate")}</Button></span>}>{t("gateway.lostBody")}</Banner>}
				{data.loaded && data.switch_due && <Banner tone="info" title={t("gateway.due")}>{t("gateway.dueBody")}</Banner>}
				{data.next?.on_host && <Banner tone="warning" title={t("gateway.onHost")}>{t("gateway.onHostBody")}</Banner>}
				{(data.active || data.next || data.retired.length > 0) && <List label={t("settings.gateway")}>
					{data.active && <ListRow title={<span className="vw-code">{data.active.fingerprint}</span>} detail={t("gateway.made", {date: day(data.active.created)})} trailing={<Mark tone="success">{t("gateway.active")}</Mark>}/>}
					{data.next && <ListRow title={<span className="vw-code">{data.next.fingerprint}</span>} detail={t("gateway.made", {date: day(data.next.created)})} trailing={<Mark tone="info">{t("gateway.next")}</Mark>}/>}
					{data.retired.map(k => <ListRow key={k.id} title={<span className="vw-code">{k.fingerprint}</span>} detail={t("gateway.retiredOn", {date: day(k.retired_at), destroy: day(k.destroy_at)}) + " " + t("gateway.accounts", {recent: number(k.accounts_recent), total: number(k.accounts)})} trailing={<Mark tone="muted">{t("gateway.retired")}</Mark>}/>)}
				</List>}
				{!data.active && !data.next && data.retired.length === 0 && <p className="vw-muted vw-small">{t("gateway.noKeys")}</p>}
				{data.accounts_without_device > 0 && <p className="vw-small vw-muted">{t("gateway.noDevice", {count: data.accounts_without_device})}</p>}
				<NumberField label={t("gateway.keep")} hint={t("gateway.keepHint")} unit={t("subs.daysUnit")} min={30} max={365} value={draft.gateway_retired_days ?? 120} onChange={value => patch({gateway_retired_days: value === "" ? 120 : value})}/>
				{data.loaded && <div className="p-cluster">
					<Button onClick={() => setAsk("switch")}>{t("gateway.switch")}</Button>
					<Button variant="danger" onClick={() => setAsk("theft")}>{t("gateway.theft")}</Button>
				</div>}
				{data.affected > 0 && <Banner tone="warning" title={t("gateway.affected", {count: data.affected})} action={<Button size="sm" onClick={preview}>{t("gateway.reset")}</Button>}>{t("gateway.affectedBody")}</Banner>}
				<details className="p-details">
					<summary>{t("gateway.counters")}</summary>
					<dl className="p-kv">
						{(["served", "size", "key", "open", "request", "window", "replay", "source", "full"] as const).map(k => <Fragment key={k}><dt>{t(`gateway.count.${k}`)}</dt><dd className="vw-num">{number(data.counts[k])}</dd></Fragment>)}
						<dt>{t("gateway.remembered")}</dt><dd className="vw-num">{number(data.remembered)}</dd>
						<dt>{t("gateway.clockSteps")}</dt><dd className="vw-num">{number(data.clock_steps)}</dd>
					</dl>
					<p className="vw-small vw-muted">{t("gateway.countersHint")}</p>
				</details>
			</>}
			<ErrorNote error={ask === null ? error : null}/>
		</div>
		<Dialog open={ask === "switch" || ask === "theft"} onOpenChange={open => { if (!open) close(); }} title={t(ask === "theft" ? "gateway.theftTitle" : "gateway.switchTitle")} description={t(ask === "theft" ? "gateway.theftBody" : "gateway.switchBody")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void swap(ask === "theft" ? "/gateway-keys/theft" : "/gateway-keys/rotate"); }}>
				{ask === "theft" && <Banner tone="warning" title={t("gateway.theftWarn")}>{t("gateway.theftWarnBody")}</Banner>}
				<SecretField label={t("gateway.paste")} hint={t("gateway.pasteHint")} value={paste} onChange={setPaste} autoComplete="off" optional/>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={close}>{t("action.cancel")}</Button><Button type="submit" variant={ask === "theft" ? "danger" : "primary"} disabled={busy}>{t(ask === "theft" ? "gateway.theftConfirm" : "gateway.switchConfirm")}</Button></div>
			</form>
		</Dialog>
		<Dialog open={ask === "load"} onOpenChange={open => { if (!open) close(); }} title={t("gateway.loadTitle")} description={t("gateway.loadBody")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void load(); }}>
				<SecretField label={t("gateway.paste")} value={paste} onChange={setPaste} autoComplete="off"/>
				<NumberField label={t("gateway.loadId")} hint={t("gateway.loadIdHint")} unit="" min={0} max={255} value={keyId} onChange={setKeyId}/>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={close}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy || !paste.trim() || keyId === ""}>{t("gateway.loadConfirm")}</Button></div>
			</form>
		</Dialog>
		<ConfirmDialog open={ask === "recreate"} onOpenChange={open => { if (!open) close(); }} danger title={t("gateway.recreateTitle")} body={t("gateway.recreateBody")} confirmLabel={t("gateway.recreate")} onConfirm={() => void recreate()}/>
		<Dialog open={ask === "reset"} onOpenChange={open => { if (!open) close(); }} title={t("gateway.resetTitle")} description={t("gateway.resetBody")}>
			<div className="p-stack">
				{count === null ? (error ? null : <p className="vw-muted">{t("common.loading")}</p>) : <p role="status">{t("gateway.resetCount", {count})}</p>}
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={close}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy || !count} onClick={() => void reset()}>{t("gateway.resetConfirm", {count: count ?? 0})}</Button></div>
			</div>
		</Dialog>
		<Dialog open={made !== null} onOpenChange={open => { if (!open) setMade(null); }} title={t("gateway.newTitle")} description={t("gateway.newBody")}>
			{made && <div className="p-stack">
				<Banner tone="warning" title={t("gateway.newWarn")}>{t("gateway.newWarnBody")}</Banner>
				{!made.next_file_written && <Banner tone="danger" title={t("gateway.noFile")}>{t("gateway.noFileBody")}</Banner>}
				<Copyable label={t("gateway.newKey")} value={made.next_private}/>
				{made.affected > 0 && <p>{t("gateway.affected", {count: made.affected})}</p>}
				<div className="vw-dialog-foot"><Button variant="primary" onClick={() => setMade(null)}>{t("gateway.newDone")}</Button></div>
			</div>}
		</Dialog>
		<Dialog open={links !== null} onOpenChange={open => { if (!open) setLinks(null); }} title={t("gateway.linksTitle")} description={t("gateway.linksBody")}>
			{links && <div className="p-stack">
				{links.node && !links.node.synced && <Banner tone="warning" title={t("node.notSynced")}>{t("node.notSyncedBody", {error: links.node.error ?? ""})}</Banner>}
				{links.links.map(l => l.link ? <Copyable key={l.id} label={l.name} value={l.link}/> : <Banner key={l.id} tone="danger" title={l.name}>{l.error ?? t("error.unknown")}</Banner>)}
				<div className="vw-dialog-foot"><Button variant="primary" onClick={() => setLinks(null)}>{t("gateway.newDone")}</Button></div>
			</div>}
		</Dialog>
	</section>;
}
