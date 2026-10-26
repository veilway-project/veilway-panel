import {Button, Glass, RadioGroup, StateBlock, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type ProfileOrder, type User, type UserPatch} from "../api.ts";
import {ErrorNote, useGuard, useLoad, useP, useReorder, useSay} from "../kit.tsx";

type Listed = ProfileOrder["profiles"][number];

// The profiles in the order the lists give first (the ids listed, in that order, with repeats and unknown ids dropped), then the rest as they came.
const arrange = (profiles: Listed[], ...orders: string[][]) => {
	const first = [...new Set(orders.flat())].flatMap(id => profiles.filter(profile => profile.id === id));
	return [...first, ...profiles.filter(profile => !first.includes(profile))];
};

// One row per profile of every server, moved by its handle or its two step buttons.
function OrderList({rows, label, onChange}: {rows: Listed[], label: string, onChange: (rows: Listed[]) => void}) {
	const reorder = useReorder(rows.length, index => `${rows[index]!.name} (${rows[index]!.node})`, (from, to) => { const next = rows.filter((_, i) => i !== from); next.splice(to, 0, rows[from]!); onChange(next); });
	return <>
		<ol className="p-order-list" aria-label={label}>{rows.map((row, i) => <li key={row.id} className="p-order-item" data-order-row>
			<span className="p-order">{reorder.handle(i)}<span className="p-row-text"><strong>{row.name}</strong><span className="vw-small vw-muted">{row.node}</span></span></span>
			<span className="p-cluster">{reorder.steps(i)}</span>
		</li>)}</ol>
		{reorder.live}
	</>;
}

// The order of the profiles in every subscription. It saves on its own, apart from the settings form.
export function GlobalOrder() {
	const {t} = useP(), say = useSay(), toast = useToast(), loaded = useLoad(() => api("get", "/profiles/order"), []), [rows, setRows] = useState<Listed[] | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null);
	const send = async (order: string[]) => {
		setBusy(true);
		setError(null);
		try {
			loaded.set(await api("put", "/profiles/order", {body: {order}}));
			setRows(null);
			toast({tone: "success", title: t("profiles.orderSaved")});
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const data = loaded.data, shown = data ? rows ?? arrange(data.profiles, data.order) : [];
	return <Glass className="p-panel">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t("profiles.orderTitle")}</h2><p>{t("profiles.orderLead")}</p></div></div>
		{loaded.error && !data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={loaded.reload}>{t("action.retry")}</Button>}>{say(loaded.error)}</StateBlock>
		: !data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: data.profiles.length < 2 ? <p className="vw-muted vw-small">{t("profiles.orderNone")}</p>
		: <>
			<OrderList rows={shown} label={t("profiles.orderList")} onChange={setRows}/>
			<p className="vw-muted vw-small">{t("profiles.orderDefault")}</p>
			<ErrorNote error={error}/>
			<div className="p-form-foot">
				{data.order.length > 0 && !rows && <Button variant="quiet" disabled={busy} onClick={() => void send([])}>{t("profiles.orderReset")}</Button>}
				{rows && <Button variant="quiet" disabled={busy} onClick={() => { setRows(null); setError(null); }}>{t("action.cancel")}</Button>}
				{rows && <Button variant="primary" disabled={busy} onClick={() => void send(rows.map(row => row.id))}>{t("profiles.orderSave")}</Button>}
			</div>
		</>}
	</Glass>;
}

// One account's own order: follow the global one, or list the profiles in an order of its own.
export function UserOrder({user, onSaved}: {user: User, onSaved: () => void}) {
	const {t} = useP(), guard = useGuard(), say = useSay(), toast = useToast(), loaded = useLoad(() => api("get", "/profiles/order"), []), [mode, setMode] = useState<"follow" | "custom" | null>(null), [rows, setRows] = useState<Listed[] | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null);
	const send = async (order: string[] | null) => {
		setBusy(true);
		setError(null);
		try {
			await guard(() => api("patch", "/users/{id}", {params: {id: user.id}, body: {profile_order: order} as UserPatch}));
			setMode(null);
			setRows(null);
			toast({tone: "success", title: t("user.orderSaved")});
			onSaved();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const data = loaded.data, own = user.profile_order ?? null, current = mode ?? (own ? "custom" : "follow");
	const shown = data ? rows ?? arrange(data.profiles, own ?? [], data.order) : [];
	const changed = current === "custom" ? rows !== null || own === null : own !== null;
	return <Glass className="p-panel">
		<div className="p-sheet-head"><div><h2 className="vw-h2">{t("user.orderTitle")}</h2><p>{t("user.orderLead")}</p></div></div>
		{loaded.error && !data ? <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={loaded.reload}>{t("action.retry")}</Button>}>{say(loaded.error)}</StateBlock>
		: !data ? <StateBlock kind="loading" title={t("common.loading")}/>
		: data.profiles.length < 2 ? <p className="vw-muted vw-small">{t("profiles.orderNone")}</p>
		: <>
			<RadioGroup label={t("user.orderTitle")} value={current} onChange={value => setMode(value as "follow" | "custom")} options={[{value: "follow", label: t("user.orderFollow"), detail: t("user.orderFollowDetail")}, {value: "custom", label: t("user.orderCustom"), detail: t("user.orderCustomDetail")}]}/>
			{current === "custom" && <OrderList rows={shown} label={t("user.orderTitle")} onChange={setRows}/>}
			<ErrorNote error={error}/>
			<div className="p-form-foot">
				{own !== null && !changed && <Button variant="quiet" disabled={busy} onClick={() => void send(null)}>{t("user.orderReset")}</Button>}
				{changed && <Button variant="quiet" disabled={busy} onClick={() => { setMode(null); setRows(null); setError(null); }}>{t("action.cancel")}</Button>}
				{changed && <Button variant="primary" disabled={busy} onClick={() => void send(current === "custom" ? shown.map(row => row.id) : null)}>{t("user.orderSave")}</Button>}
			</div>
		</>}
	</Glass>;
}
