import {Button, Glass, Icon, Segmented, StatRow, StatTile, StateBlock, TrafficLine, UsageBar, type TrafficPoint} from "@veilway/ui";
import {useEffect, useMemo, useState} from "react";
import {api, type Live, type NodeUser} from "../api.ts";
import {ago, Mark, PageHead, useLoad, useP, useSay} from "../kit.tsx";
import {NoticesPanel, SubscriptionNoticesPanel} from "./notices.tsx";
import {PERIODS} from "./traffic.tsx";
import {WgHealth, type WgState} from "./wgout.tsx";

type Period = "day" | "week" | "month";
type Rated = {name: string, up_bytes_per_sec: number, down_bytes_per_sec: number, udp?: boolean | null};
type ExitState = {tag: string, name: string, backend?: {type?: string}, udp: boolean | null, udp_down_secs: number | null, interface_up: boolean | null, interface_down_secs: number | null, link_up: boolean | null} & WgState;
const NEAR = 0.85;

// The one page an operator opens first: speed now, the day's shape, who is about to run out, where traffic leaves, and what changed.
export function DashboardPage({live, onLive}: {live: Live | null, onLive: () => void}) {
	const {t, rate, number, bytes, time, date} = useP(), say = useSay(), [period, setPeriod] = useState<Period>("day");
	const users = useLoad(() => api("get", "/users"), []), month = useLoad(() => api("get", "/stats/usage", {query: {kind: "inbound", period: "month"}}), []), audit = useLoad(() => api("get", "/audit", {query: {limit: 5}}), []);
	const {resolution, size, span} = PERIODS[period];
	// The node keeps history per inbound, so the node's own line is the sum of its inbounds' lines.
	const chart = useLoad(async () => {
		const usage = await api("get", "/stats/usage", {query: {kind: "inbound", period}}), since = Math.floor(Date.now() / 1000) - span;
		const histories = await Promise.all(usage.entries.map(entry => api("get", "/stats/history", {query: {kind: "inbound", name: entry.name, resolution, since}})));
		return {usage: usage.entries, histories};
	}, [period]);
	useEffect(() => { const timer = setInterval(onLive, 10000); return () => clearInterval(timer); }, [onLive]);
	const points = useMemo<TrafficPoint[]>(() => {
		if (!chart.data) return [];
		const found = new Map<number, {down: number, up: number}>(), last = Math.floor(Date.now() / 1000 / size) * size - size;
		for (const p of chart.data.histories.flatMap(history => history.points)) found.set(p.at, {down: (found.get(p.at)?.down ?? 0) + p.down_bytes, up: (found.get(p.at)?.up ?? 0) + p.up_bytes});
		return Array.from({length: span / size}, (_, i) => last - (span / size - 1 - i) * size).map(at => ({time: new Date(at * 1000), down: (found.get(at)?.down ?? 0) / size, up: (found.get(at)?.up ?? 0) / size}));
	}, [chart.data]);
	const rates = (live?.rates ?? {}) as Record<string, Rated[] | null>, inbounds = rates.inbounds ?? [], outbounds = rates.outbounds ?? [], exits = (Array.isArray(live?.exits) ? live.exits : []) as ExitState[];
	const down = inbounds.reduce((sum, r) => sum + r.down_bytes_per_sec, 0), up = inbounds.reduce((sum, r) => sum + r.up_bytes_per_sec, 0);
	const used = month.data?.entries.reduce((sum, e) => sum + e.down_bytes + e.up_bytes, 0), peak = period === "day" && points.length ? points.reduce((best, p) => p.down > best.down ? p : best) : null;
	const list = users.data?.users ?? [], devices = list.reduce((sum, u) => sum + u.devices, 0), pending = list.reduce((sum, u) => sum + u.pending_devices, 0);
	const near = list.map(u => ({user: u, usage: u.node as NodeUser | null})).filter(({user, usage}) => user.quota_bytes && usage?.used_bytes !== undefined && usage.used_bytes / user.quota_bytes >= NEAR).sort((a, b) => b.usage!.used_bytes! / b.user.quota_bytes! - a.usage!.used_bytes! / a.user.quota_bytes!);
	const totals = chart.data?.usage.reduce((sum, e) => ({down: sum.down + e.down_bytes, up: sum.up + e.up_bytes}), {down: 0, up: 0});
	const since = (seconds: number | null) => { if (seconds === null) return ""; const found = ago(seconds); return t(found.key, {count: found.count}); };
	const today = new Date().toDateString();
	return <>
		<PageHead title={t("nav.dashboard")} lead={t("dashboard.lead")}>
			<Segmented label={t("traffic.period")} value={period} onChange={value => setPeriod(value as Period)} options={(["day", "week", "month"] as const).map(p => ({value: p, label: t(`traffic.period.${p}`)}))}/>
			<Button variant="primary" icon="plus" onClick={() => { location.hash = "#/users/new"; }}>{t("users.add")}</Button>
		</PageHead>
		<Glass className="p-panel p-figures" aria-labelledby="now-title">
			<div className="p-sheet-head"><div><h2 className="vw-h2" id="now-title">{t("dashboard.now")}</h2><p>{live ? (live.reachable ? t("dashboard.nowLead", {time: time(new Date(live.at * 1000))}) : t("traffic.unreachableBody")) : t("common.loading")}</p></div></div>
			<StatRow>
				<StatTile lead label={t("traffic.downNow")} value={live ? rate(down).value : "0"} unit={rate(down).unit} detail={peak ? t("dashboard.peak", {rate: rate(peak.down).text, time: time(peak.time)}) : undefined}/>
				<StatTile label={t("traffic.upNow")} value={live ? rate(up).value : "0"} unit={rate(up).unit}/>
				<StatTile label={t("dashboard.month")} value={used === undefined ? "0" : bytes(used).value} unit={used === undefined ? undefined : bytes(used).unit}/>
				<StatTile label={t("users.col.devices")} value={number(devices)} detail={pending ? t("dashboard.waiting", {count: pending}) : undefined}/>
			</StatRow>
			{chart.error && !chart.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={chart.reload}>{t("action.retry")}</Button>}>{say(chart.error)}</StateBlock>
			: !chart.data ? <StateBlock kind="loading" title={t("common.loading")}/>
			: <>
				<TrafficLine key={period} label={t(`dashboard.chart.${period}`)} points={points}/>
				{totals && <p className="p-chart-total">{t(`dashboard.total.${period}`, {down: bytes(totals.down).text, up: bytes(totals.up).text})}</p>}
			</>}
		</Glass>
		<div className="p-grid-2">
			<Glass className="p-panel">
				<div className="p-sheet-head">
					<div><h2 className="vw-h2">{t("dashboard.near")}</h2><p>{users.data ? t("dashboard.nearLead", {count: near.length}) : t("common.loading")}</p></div>
					<Button className="p-more" size="sm" variant="quiet" onClick={() => { location.hash = "#/users"; }}>{t("dashboard.allUsers")}<Icon name="chevronForward"/></Button>
				</div>
				{users.error && !users.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={users.reload}>{t("action.retry")}</Button>}>{say(users.error)}</StateBlock>
				: users.data && near.length === 0 ? <p className="vw-muted">{t("dashboard.nearNone")}</p>
				: <ul className="p-row-list">{near.slice(0, 5).map(({user, usage}) => <li key={user.id}>
					<span className="p-avatar" data-tone="quiet" aria-hidden="true">{user.name.slice(0, 2).toUpperCase()}</span>
					<div className="p-row-text"><a className="p-name p-link" href={"#/users/" + user.id}>{user.name}</a><UsageBar compact label={user.name} used={usage!.used_bytes!} total={user.quota_bytes!}/></div>
					{usage?.denied === "quota" ? <Mark tone="danger">{t("users.overQuota")}</Mark> : <span className="vw-small vw-muted">{user.quota_period ? t(`form.period.${user.quota_period as "daily"}`) : ""}</span>}
				</li>)}</ul>}
			</Glass>
			<Glass className="p-panel">
				<div className="p-sheet-head">
					<div><h2 className="vw-h2">{t("traffic.exits")}</h2><p>{t("dashboard.exitsLead")}</p></div>
					<Button className="p-more" size="sm" variant="quiet" onClick={() => { location.hash = "#/routing/exits"; }}>{t("nav.routing")}<Icon name="chevronForward"/></Button>
				</div>
				{!live ? <StateBlock kind="loading" title={t("common.loading")}/> : exits.length === 0 && outbounds.length === 0 ? <p className="vw-muted">{t("traffic.noExits")}</p> : <ul className="p-row-list">
					{exits.map(e => { const bad = e.interface_up === false || e.link_up === false || e.outbound_up === false, warn = e.udp === false; return <li key={"e" + e.tag}>
						<span className="p-tile-icon" data-tone={bad ? "danger" : warn ? "warning" : "success"}><Icon name={e.backend?.type === "chain" ? "device" : "upload"}/></span>
						<div className="p-row-text"><strong className="p-name">{e.tag}</strong><span>{e.name !== e.tag ? e.name : t("traffic.exitKind", {backend: e.backend?.type ?? ""})}</span></div>
						<span className="p-flags">
							{e.interface_up !== null && <Mark tone={e.interface_up ? "success" : "danger"}>{e.interface_up ? t("traffic.interfaceUp") : t("traffic.interfaceDown", {time: since(e.interface_down_secs)})}</Mark>}
							{e.link_up !== null && <Mark tone={e.link_up ? "success" : "danger"}>{t(e.link_up ? "traffic.linkUp" : "traffic.linkDown")}</Mark>}
							{e.udp !== null && <Mark tone={e.udp ? "success" : "warning"}>{e.udp ? t("traffic.udp") : t("traffic.noUdp", {time: since(e.udp_down_secs)})}</Mark>}
							{e.outbound_up !== null && e.outbound_up !== undefined && <WgHealth state={e} compact/>}
							{e.interface_up === null && e.link_up === null && e.udp === null && (e.outbound_up === null || e.outbound_up === undefined) && <Mark tone="muted">{t("traffic.noState")}</Mark>}
						</span>
					</li>; })}
					{outbounds.map(o => <li key={"o" + o.name}>
						<span className="p-tile-icon" data-tone={o.udp === false ? "warning" : "success"}><Icon name="upload"/></span>
						<div className="p-row-text"><strong className="p-name">{o.name}</strong><span>{t("traffic.outbound", {rate: rate(o.down_bytes_per_sec + o.up_bytes_per_sec).text})}</span></div>
						{o.udp === null || o.udp === undefined ? <Mark tone="muted">{t("traffic.udpUnknown")}</Mark> : <Mark tone={o.udp ? "success" : "warning"}>{o.udp ? t("traffic.udp") : t("traffic.noUdpShort")}</Mark>}
					</li>)}
				</ul>}
			</Glass>
		</div>
		<NoticesPanel/>
		<SubscriptionNoticesPanel/>
		<Glass className="p-panel">
			<div className="p-sheet-head">
				<div><h2 className="vw-h2">{t("dashboard.changes")}</h2><p>{t("dashboard.changesLead")}</p></div>
				<Button className="p-more" size="sm" variant="quiet" onClick={() => { location.hash = "#/account/audit"; }}>{t("account.tab.audit")}<Icon name="chevronForward"/></Button>
			</div>
			{audit.error && !audit.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={audit.reload}>{t("action.retry")}</Button>}>{say(audit.error)}</StateBlock>
			: !audit.data ? <StateBlock kind="loading" title={t("common.loading")}/>
			: audit.data.entries.length === 0 ? <p className="vw-muted">{t("audit.emptyBody")}</p>
			: <ul className="p-row-list">{audit.data.entries.map(r => { const at = new Date(r.at * 1000); return <li key={r.id}>
				<span className="p-when">{at.toDateString() === today ? time(at) : date(at, {month: "short", day: "numeric"})}</span>
				<div className="p-row-text"><strong><span className="vw-code">{r.action}</span> <span className="vw-code vw-muted">{r.target}</span></strong><span>{[r.actor, r.detail].filter(Boolean).join(", ")}</span></div>
				<span/>
			</li>; })}</ul>}
		</Glass>
	</>;
}
