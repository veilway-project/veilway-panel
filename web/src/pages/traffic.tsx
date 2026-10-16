import {Banner, Button, DataTable, Glass, Segmented, StateBlock, TrafficLine, type TrafficPoint} from "@veilway/ui";
import {useEffect, useMemo, useState} from "react";
import {api, type Live} from "../api.ts";
import {PageHead, useLoad, useP, useSay} from "../kit.tsx";

type Kind = "user" | "inbound" | "exit" | "outbound";
type Period = "day" | "week" | "month" | "year";
const KINDS: Kind[] = ["user", "inbound", "exit", "outbound"];
// Each period is read at the finest resolution the panel keeps that far back: minutes for a day, hours for a week or a month, days for a year.
export const PERIODS: Record<Period, {resolution: string, size: number, span: number}> = {day: {resolution: "minute", size: 60, span: 86400}, week: {resolution: "hour", size: 3600, span: 7 * 86400}, month: {resolution: "hour", size: 3600, span: 30 * 86400}, year: {resolution: "day", size: 86400, span: 365 * 86400}};

export function TrafficPage() {
	const {t} = useP(), say = useSay(), live = useLoad(() => api("get", "/stats/now"), []);
	const [kind, setKind] = useState<Kind>("inbound"), [period, setPeriod] = useState<Period>("day"), [picked, setPicked] = useState<string | null>(null);
	const usage = useLoad(() => api("get", "/stats/usage", {query: {kind, period}}), [kind, period]);
	const name = picked ?? usage.data?.entries[0]?.name ?? null, {resolution, size, span} = PERIODS[period];
	const history = useLoad(() => name ? api("get", "/stats/history", {query: {kind, name, resolution, since: Math.floor(Date.now() / 1000) - span}}) : Promise.resolve(null), [kind, name, period]);
	useEffect(() => { const timer = setInterval(live.reload, 10000); return () => clearInterval(timer); }, [live.reload]);
	const now = live.data as Live | null;
	// The node keeps no bucket for a quiet stretch, so every missing bucket is a zero and the line does not skip across it.
	const points = useMemo<TrafficPoint[]>(() => {
		if (!history.data) return [];
		const found = new Map(history.data.points.map(p => [p.at, p])), last = Math.floor(Date.now() / 1000 / size) * size;
		return Array.from({length: span / size}, (_, i) => last - (span / size - 1 - i) * size).map(at => ({time: new Date(at * 1000), down: (found.get(at)?.down_bytes ?? 0) / size, up: (found.get(at)?.up_bytes ?? 0) / size}));
	}, [history.data]);
	const choose = (next: Kind) => { setPicked(null); setKind(next); };
	return <>
		<PageHead title={t("traffic.title")} lead={t("traffic.lead")}><Segmented label={t("traffic.period")} value={period} onChange={value => setPeriod(value as Period)} options={(["day", "week", "month", "year"] as const).map(p => ({value: p, label: t(`traffic.period.${p}`)}))}/></PageHead>
		{now && !now.reachable && <Banner tone="warning" title={t("traffic.unreachable")}>{t("traffic.unreachableBody")}</Banner>}
		<Glass className="p-panel">
			<div className="p-sheet-head"><div><h2 className="vw-h2">{t("traffic.usage")}</h2><p>{t("traffic.usageLead")}</p></div><Segmented label={t("traffic.kind")} value={kind} onChange={value => choose(value as Kind)} options={KINDS.map(k => ({value: k, label: t(`traffic.kind.${k}`)}))}/></div>
			{usage.error && !usage.data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={usage.reload}>{t("action.retry")}</Button>}>{say(usage.error)}</StateBlock>
			: !usage.data ? <StateBlock kind="loading" title={t("common.loading")}/>
			: usage.data.entries.length === 0 ? <StateBlock kind="empty" title={t("traffic.none")}>{t("traffic.noneBody")}</StateBlock>
			: <>
				{name && <TrafficLine key={kind + name + period} label={t("traffic.chart", {name})} points={points}/>}
				<p className="vw-muted vw-small">{t("traffic.chartNote", {name: name ?? ""})}</p>
				<Usage entries={usage.data.entries} name={name} onPick={setPicked}/>
			</>}
		</Glass>
		<Glass className="p-panel">
			<div className="p-sheet-head"><div><h2 className="vw-h2">{t("traffic.onlineUsers")}</h2>{now && <p>{t("traffic.sessions", {count: now.sessions})}</p>}</div></div>
			{live.error && !now ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={live.reload}>{t("action.retry")}</Button>}>{say(live.error)}</StateBlock>
			: !now ? <StateBlock kind="loading" title={t("common.loading")}/>
			: now.online_users.length === 0 ? <p className="vw-muted">{t("traffic.nobody")}</p> : <ul className="p-names">{now.online_users.map(user => <li key={user} className="vw-code">{user}</li>)}</ul>}
		</Glass>
	</>;
}

function Usage({entries, name, onPick}: {entries: {name: string, up_bytes: number, down_bytes: number}[], name: string | null, onPick: (name: string) => void}) {
	const {t, bytes} = useP();
	return <DataTable caption={t("traffic.usage")} rows={entries} rowKey={e => e.name} columns={[
		{id: "name", header: t("traffic.col.name"), cell: e => <button type="button" className="p-pick vw-code" aria-pressed={e.name === name} onClick={() => onPick(e.name)}>{e.name}</button>},
		{id: "down", header: t("chart.download"), align: "end", cell: e => <span className="vw-num">{bytes(e.down_bytes).text}</span>},
		{id: "up", header: t("chart.upload"), align: "end", cell: e => <span className="vw-num">{bytes(e.up_bytes).text}</span>},
		{id: "total", header: t("traffic.col.total"), align: "end", cell: e => <strong className="vw-num">{bytes(e.down_bytes + e.up_bytes).text}</strong>}
	]}/>;
}
