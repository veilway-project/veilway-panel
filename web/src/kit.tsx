import {Banner, Button, Dialog, Field, Icon, IconButton, TextField, useI18n, useToast, type Tone} from "@veilway/ui";
import qrcode from "qrcode-generator";
import {createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode} from "react";
import {api, ApiError, flags, type NodeState, type Totp} from "./api.ts";
import {en, type PanelKey} from "./locales/en.ts";

export const useP = () => useI18n<PanelKey>();

// Server messages are English only, so a code the pack knows is said in the reader's language. bad_request and conflict carry a rule the server words best.
export function useSay() {
	const {t} = useP();
	return useCallback((error: unknown) => {
		if (!(error instanceof ApiError)) return error instanceof Error && error.message ? error.message : t("error.unknown");
		const key = "error." + error.code;
		return key in en ? t(key as PanelKey) : error.message || t("error.unknown");
	}, [t]);
}

export function ErrorNote({error}: {error: unknown}) {
	const say = useSay();
	return error ? <Banner tone="danger" title={say(error)}/> : null;
}

// What the node made of a change. The panel keeps the change either way, so this is a warning, not a failure.
export function NodeNote({node}: {node: NodeState | null | undefined}) {
	const {t} = useP();
	return node && !node.synced ? <Banner tone="warning" title={t("node.notSynced")}>{t("node.notSyncedBody", {error: node.error ?? ""})}</Banner> : null;
}

export function useLoad<T>(load: () => Promise<T>, deps: unknown[]) {
	const [state, setState] = useState<{data: T | null, error: unknown, loading: boolean}>({data: null, error: null, loading: true}), turn = useRef(0);
	const reload = useCallback(() => {
		const mine = ++turn.current;
		setState(s => ({...s, loading: true}));
		load().then(data => { if (mine === turn.current) setState({data, error: null, loading: false}); }, error => { if (mine === turn.current) setState(s => ({...s, error, loading: false})); });
	}, deps);
	useEffect(reload, [reload]);
	return {...state, reload, set: (data: T) => setState({data, error: null, loading: false})};
}

// Routes marked for re-authentication answer reauth_required. run() asks for password and code once and retries the same call, so no page handles it on its own.
const GuardContext = createContext<<T>(work: () => Promise<T>) => Promise<T>>(work => work());
export const useGuard = () => useContext(GuardContext);

export function GuardProvider({children}: {children: ReactNode}) {
	const {t} = useP(), [ask, setAsk] = useState<{resolve: () => void, reject: (error: unknown) => void} | null>(null);
	const [password, setPassword] = useState(""), [totp, setTotp] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const run = useCallback(async <T,>(work: () => Promise<T>): Promise<T> => {
		try {
			return await work();
		} catch (error) {
			if (!(error instanceof ApiError) || error.code !== "reauth_required") throw error;
			await new Promise<void>((resolve, reject) => { setPassword(""); setTotp(""); setError(null); setAsk({resolve, reject}); });
			return await work();
		}
	}, []);
	const confirm = async () => {
		if (!ask) return;
		setBusy(true);
		try {
			await api("post", "/session/reauth", {body: {password, totp: flags.twoStep ? totp.trim() : ""}});
			setAsk(null);
			ask.resolve();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <GuardContext.Provider value={run}>
		{children}
		<Dialog open={ask !== null} onOpenChange={open => { if (!open && ask) { ask.reject(new ApiError(403, "reauth_required", "")); setAsk(null); } }} title={t("reauth.title")} description={t("reauth.body")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void confirm(); }}>
				<TextField label={t("login.password")} type="password" autoComplete="current-password" value={password} onChange={setPassword} required/>
				{flags.twoStep && <TextField label={t("login.code")} hint={t("login.codeHint")} inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={totp} onChange={setTotp} technical required/>}
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button type="submit" variant="primary" disabled={busy}>{t("reauth.submit")}</Button></div>
			</form>
		</Dialog>
	</GuardContext.Provider>;
}

export function PageHead({title, lead, children}: {title: string, lead?: ReactNode, children?: ReactNode}) {
	return <header className="p-head"><div><h1 className="vw-h1">{title}</h1>{lead && <p className="vw-muted">{lead}</p>}</div>{children && <div className="p-cluster">{children}</div>}</header>;
}

// A QR code on a light tile whatever the scheme, since scanners need dark modules on light ground. svg is the server's own rendering; text is drawn here.
export function Qr({text, svg, label}: {text?: string, svg?: string, label: string}) {
	let markup = svg ?? "";
	if (text) {
		const code = qrcode(0, "M");
		code.addData(text);
		code.make();
		markup = code.createSvgTag({cellSize: 4, margin: 0, scalable: true});
	}
	return <div className="p-qr"><img alt={label} src={"data:image/svg+xml;charset=utf-8," + encodeURIComponent(markup)}/></div>;
}

export function useCopy() {
	const {t} = useI18n(), {t: p} = useP(), toast = useToast();
	return (value: string) => navigator.clipboard?.writeText(value).then(() => toast({tone: "success", title: t("action.copied")}), () => toast({tone: "danger", title: p("common.copyFailed")})) ?? toast({tone: "danger", title: p("common.copyFailed")});
}

// A value to hand on: shown in full, selectable, with a copy button. multiline for a document that does not fit one line.
export function Copyable({label, value, multiline}: {label: string, value: string, multiline?: boolean}) {
	const {t} = useI18n(), copy = useCopy();
	return <Field label={label}>{ids => <div className="vw-input-group">
		{multiline ? <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" readOnly rows={6} value={value} onFocus={event => event.target.select()}/> : <input {...ids} className="vw-input vw-code" dir="ltr" readOnly value={value} onFocus={event => event.target.select()}/>}
		<IconButton className="vw-input-action" icon="copy" label={t("action.copy")} onClick={() => copy(value)}/>
	</div>}</Field>;
}

export function TotpShown({totp, done, onDone}: {totp: Totp, done: string, onDone: () => void}) {
	const {t} = useP();
	return <div className="p-stack">
		<div><h2 className="vw-h2">{t("totp.title")}</h2><p className="vw-muted">{t("totp.lead")}</p>{!flags.twoStep && <p className="vw-small vw-muted">{t("totp.later")}</p>}</div>
		<Qr text={totp.otpauth} label={t("totp.qr")}/>
		<Copyable label={t("totp.key")} value={totp.totp_secret}/>
		<div><Button variant="primary" onClick={onDone}>{done}</Button></div>
	</div>;
}

// A field whose value is a list, one item per line.
export function LinesField({label, hint, value, onChange, rows = 3, optional = true, error}: {label: string, hint?: string, value: string, onChange: (value: string) => void, rows?: number, optional?: boolean, error?: string}) {
	return <Field label={label} hint={hint} optional={optional} error={error}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={rows} value={value} onChange={event => onChange(event.target.value)}/>}</Field>;
}

export const lines = (text: string) => text.split("\n").map(line => line.trim()).filter(Boolean);
// A DNS name as the node reads it: lowercase, no wildcard, and a last label that is not an address.
export const dnsName = (name: string) => name.length <= 253 && /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(name) && !/^(\d+|0x[0-9a-f]*)$/.test(name.split(".").pop()!);
export const toDay = (seconds: number | null | undefined) => seconds ? new Date(seconds * 1000).toISOString().slice(0, 10) : "";
// The end of the chosen day in UTC, so a user set to expire on a day can use all of it.
export const fromDay = (day: string) => day ? Math.floor(Date.parse(day + "T23:59:59Z") / 1000) : null;

// A state word after an icon in its tone. The word says it on its own; the icon and its color repeat it.
export function Mark({tone, title, children}: {tone?: Tone | "muted", title?: string, children: ReactNode}) {
	return <span className="p-flag" data-tone={tone} title={title}><Icon name={tone === "success" ? "check" : tone === "warning" ? "warning" : tone === "danger" ? "error" : "info"}/>{children}</span>;
}

const DIGITS = /[۰-۹٠-٩]/g;
const latin = (text: string) => text.replace(DIGITS, digit => String("۰۱۲۳۴۵۶۷۸۹".includes(digit) ? "۰۱۲۳۴۵۶۷۸۹".indexOf(digit) : "٠١٢٣٤٥٦٧٨٩".indexOf(digit)));
const jalali = (time: number) => Object.fromEntries(new Intl.DateTimeFormat("en-u-ca-persian-nu-latn", {timeZone: "UTC", year: "numeric", month: "numeric", day: "numeric"}).formatToParts(new Date(time)).filter(part => part.type === "year" || part.type === "month" || part.type === "day").map(part => [part.type, Number.parseInt(part.value, 10)])) as {year: number, month: number, day: number};
const dayOfYear = (month: number, day: number) => (month <= 6 ? (month - 1) * 31 : 186 + (month - 7) * 30) + day - 1;
// A Jalali day as an ISO day. Intl only formats into the Persian calendar, so a guess near Nowruz is moved by the gap it reports, twice, and checked. null for a day that does not exist.
export function fromJalali(year: number, month: number, day: number) {
	let guess = Date.UTC(year + 621, 2, 21) + dayOfYear(month, day) * 86400000;
	for (let turn = 0; turn < 2; turn++) { const seen = jalali(guess); guess += ((year - seen.year) * 365 + dayOfYear(month, day) - dayOfYear(seen.month, seen.day)) * 86400000; }
	const seen = jalali(guess);
	return month >= 1 && month <= 12 && seen.year === year && seen.month === month && seen.day === day ? new Date(guess).toISOString().slice(0, 10) : null;
}

// A day input. In Persian it takes and shows a Jalali year/month/day, since the browser's own date picker only knows the Gregorian calendar. value stays an ISO day either way.
export function DayField({label, hint, value, onChange, optional}: {label: string, hint?: string, value: string, onChange: (value: string) => void, optional?: boolean}) {
	const {t, locale, number} = useP(), shown = (iso: string) => { if (!iso) return ""; const j = jalali(Date.parse(iso + "T12:00:00Z")); return `${number(j.year, {useGrouping: false})}/${number(j.month, {minimumIntegerDigits: 2})}/${number(j.day, {minimumIntegerDigits: 2})}`; };
	const [text, setText] = useState(() => shown(value)), [wrong, setWrong] = useState(false);
	if (locale !== "fa") return <TextField label={label} hint={hint} type="date" value={value} onChange={onChange} optional={optional}/>;
	const type = (next: string) => {
		setText(next);
		const parts = latin(next.trim()).match(/^(\d{4})[/.-](\d{1,2})[/.-](\d{1,2})$/), iso = parts ? fromJalali(Number(parts[1]), Number(parts[2]), Number(parts[3])) : null;
		setWrong(next.trim() !== "" && !iso);
		if (iso || !next.trim()) onChange(iso ?? "");
	};
	return <TextField label={label} hint={[hint, t("day.hint")].filter(Boolean).join(" ")} error={wrong ? t("day.wrong") : undefined} inputMode="numeric" placeholder={t("day.placeholder")} value={text} onChange={type} optional={optional}/>;
}

// What a check found, said first, then where it is in small type. Paths are the document's own words, so they stay in code type.
export function Issues({issues}: {issues: {path: string, text: string, action?: ReactNode}[]}) {
	const {t} = useP();
	if (!issues.length) return null;
	return <ul className="p-issues" aria-label={t("config.problems")}>{issues.map((issue, i) => <li key={i}><span>{issue.text}</span>{issue.path && <span className="vw-code" dir="ltr">{issue.path}</span>}{issue.action}</li>)}</ul>;
}

export const ago = (seconds: number) => seconds < 120 ? {key: "time.seconds" as const, count: Math.round(seconds)} : seconds < 7200 ? {key: "time.minutes" as const, count: Math.round(seconds / 60)} : seconds < 172800 ? {key: "time.hours" as const, count: Math.round(seconds / 3600)} : {key: "time.days" as const, count: Math.round(seconds / 86400)};

// Which items of a reordered list moved, as few as possible: those outside the longest run that kept its relative order. Between equal runs the later one is kept, so a swap reads as the item that went up. order holds each item's old index at its new place, -1 for an item that is new.
export function moved(order: number[]) {
	const runs: number[][] = [];
	order.forEach((old, at) => runs.push(old < 0 ? [] : [...(runs.filter(run => run.length && order[run[run.length - 1]!]! < old).sort((a, b) => b.length - a.length)[0] ?? []), at]));
	const kept = new Set(runs.sort((a, b) => b.length - a.length || (b[b.length - 1] ?? 0) - (a[a.length - 1] ?? 0))[0] ?? []);
	return order.flatMap((old, at) => old < 0 || kept.has(at) ? [] : [{from: old, to: at}]);
}

type Held = {from: number, to: number, rows: HTMLElement[], host: HTMLElement, line: HTMLElement, pointer?: number, y0: number, y: number, scroller: HTMLElement, top0: number, live: boolean, timer?: number, frame?: number};
const ORDER_PATHS = {handle: "M7.5 5v.01M12.5 5v.01M7.5 10v.01M12.5 10v.01M7.5 15v.01M12.5 15v.01", up: "M10 15.5v-11M5.5 9L10 4.5 14.5 9", down: "M10 4.5v11M5.5 11l4.5 4.5 4.5-4.5"};

// Reordering for a list whose order means something. A row moves by its handle: dragged with a mouse or pen at once, with a finger after a short press so a swipe still scrolls, or picked up with Space or Enter and moved with the arrow keys. Rows stay put until the drop, when onMove gets the old and the new index. A row is the handle's nearest [data-order-row] or table row, and its list is the siblings that hold a handle.
export function useReorder(count: number, name: (index: number) => string, onMove: (from: number, to: number) => void) {
	const {t, number} = useP(), hint = useId(), [said, setSaid] = useState(""), held = useRef<Held | null>(null), refocus = useRef<{list: HTMLElement, index: number, part: string} | null>(null);
	const rowOf = (from: Element) => (from.closest("[data-order-row]") ?? from.closest("tr")) as HTMLElement;
	const show = (state: Held) => {
		const rest = state.rows.filter((_, i) => i !== state.from), box = state.host.getBoundingClientRect(), above = rest[state.to - 1]?.getBoundingClientRect(), below = rest[state.to]?.getBoundingClientRect(), edge = (below ?? above)!;
		state.rows.forEach((row, i) => row.toggleAttribute("data-lifted", i === state.from));
		state.line.hidden = state.to === state.from;
		Object.assign(state.line.style, {top: `${(above && below ? (above.bottom + below.top) / 2 : below ? below.top - 2 : edge.bottom + 2) - box.top + state.host.scrollTop - 1}px`, left: `${edge.left - box.left + state.host.scrollLeft}px`, width: `${edge.width}px`});
	};
	// The lifted row follows the pointer and the scroll under it; the target is how many other rows have their middle above the pointer.
	const follow = (state: Held) => {
		state.rows[state.from]!.style.transform = `translateY(${state.y - state.y0 + state.scroller.scrollTop - state.top0}px)`;
		state.to = state.rows.filter((row, i) => { const box = row.getBoundingClientRect(); return i !== state.from && box.top + box.height / 2 < state.y; }).length;
		show(state);
	};
	const scroll = () => {
		const state = held.current;
		if (!state?.live || state.pointer === undefined) return;
		const box = state.scroller === document.scrollingElement ? {top: 0, bottom: innerHeight} : state.scroller.getBoundingClientRect(), edge = 56, by = state.y < box.top + edge ? state.y - box.top - edge : state.y > box.bottom - edge ? state.y - box.bottom + edge : 0;
		if (by) { state.scroller.scrollTop += Math.max(-20, Math.min(20, by / 3)); follow(state); }
		state.frame = requestAnimationFrame(scroll);
	};
	const pick = (handle: HTMLElement, index: number, pointer?: number, y = 0): Held => {
		const row = rowOf(handle), rows = Array.from(row.parentElement!.children).filter(el => el.querySelector("[data-order=handle]")) as HTMLElement[];
		let scroller = row.parentElement;
		while (scroller && !(/(auto|scroll)/.test(getComputedStyle(scroller).overflowY) && scroller.scrollHeight > scroller.clientHeight)) scroller = scroller.parentElement;
		const box = scroller ?? document.scrollingElement as HTMLElement, host = (row.closest("table")?.parentElement ?? row.parentElement)!, line = document.createElement("div");
		// The line lives beside the rows, not on them: a pseudo-element on a table row turns into a cell and shifts the columns.
		line.className = "p-drop";
		line.hidden = true;
		host.append(line);
		return {from: index, to: index, rows, host, line, pointer, y0: y, y, scroller: box, top0: box.scrollTop, live: false};
	};
	const lift = (state: Held) => { state.live = true; show(state); state.frame = requestAnimationFrame(scroll); };
	const end = (drop: boolean) => {
		const state = held.current;
		if (!state) return;
		held.current = null;
		clearTimeout(state.timer);
		cancelAnimationFrame(state.frame ?? 0);
		state.line.remove();
		state.rows.forEach(row => { row.removeAttribute("data-lifted"); row.style.removeProperty("transform"); });
		if (!state.live) return;
		if (drop && state.to !== state.from) { onMove(state.from, state.to); setSaid(t("order.moved", {name: name(state.from), position: number(state.to + 1)})); }
		else setSaid(t("order.cancelled", {name: name(state.from), position: number(state.from + 1)}));
	};
	const step = (button: HTMLElement, index: number, by: number) => {
		const to = index + by;
		refocus.current = {list: rowOf(button).parentElement!, index: to, part: to === 0 || to === count - 1 ? "handle" : by < 0 ? "up" : "down"};
		onMove(index, to);
		setSaid(t("order.moved", {name: name(index), position: number(to + 1)}));
	};
	// Escape is caught on the way down, before a dialog around the list takes it as "close". A touch drag holds the page still once it has started.
	useEffect(() => {
		const key = (event: KeyboardEvent) => { if (event.key === "Escape" && held.current?.live) { event.preventDefault(); event.stopImmediatePropagation(); end(false); } };
		const touch = (event: TouchEvent) => { if (held.current?.live) event.preventDefault(); };
		addEventListener("keydown", key, true);
		document.addEventListener("touchmove", touch, {passive: false});
		return () => { removeEventListener("keydown", key, true); document.removeEventListener("touchmove", touch); };
	});
	useEffect(() => { const at = refocus.current; if (!at) return; refocus.current = null; at.list.querySelectorAll<HTMLElement>(`[data-order=${at.part}]`)[at.index]?.focus(); });
	return {
		live: <><p className="vw-sr" id={hint}>{t("order.hint")}</p><p className="vw-sr" aria-live="assertive">{said}</p></>,
		handle: (index: number) => count < 2 ? null : <button type="button" className="p-grip" data-order="handle" aria-label={t("order.handle", {name: name(index)})} aria-describedby={hint} onContextMenu={event => event.preventDefault()}
			onPointerDown={event => {
				if (event.button !== 0 || held.current) return;
				if (event.pointerType !== "touch") event.preventDefault();
				event.currentTarget.setPointerCapture(event.pointerId);
				const state = held.current = pick(event.currentTarget, index, event.pointerId, event.clientY);
				if (event.pointerType === "touch") state.timer = window.setTimeout(() => { navigator.vibrate?.(8); lift(state); }, 260);
			}}
			onPointerMove={event => {
				const state = held.current;
				if (!state || state.pointer !== event.pointerId) return;
				state.y = event.clientY;
				if (!state.live) { if (Math.abs(state.y - state.y0) <= (event.pointerType === "touch" ? 10 : 4)) return; if (event.pointerType === "touch") return end(false); lift(state); }
				follow(state);
			}}
			onPointerUp={event => { if (held.current?.pointer === event.pointerId) end(true); }}
			onPointerCancel={event => { if (held.current?.pointer === event.pointerId) end(false); }}
			onBlur={() => { if (held.current && held.current.pointer === undefined) end(false); }}
			onKeyDown={event => {
				const state = held.current, key = event.key, arrow = key === "ArrowUp" || key === "ArrowDown";
				if (!arrow && key !== " " && key !== "Enter") return;
				if (!state) { if (arrow) return; event.preventDefault(); lift(held.current = pick(event.currentTarget, index)); return setSaid(t("order.picked", {name: name(index), position: number(index + 1), count: number(count)})); }
				if (state.pointer !== undefined) return;
				event.preventDefault();
				if (!arrow) { refocus.current = {list: state.rows[0]!.parentElement!, index: state.to, part: "handle"}; return end(true); }
				state.to = Math.max(0, Math.min(count - 1, state.to + (key === "ArrowUp" ? -1 : 1)));
				show(state);
				setSaid(t("order.over", {name: name(state.from), position: number(state.to + 1), count: number(count)}));
			}}><svg className="vw-icon" viewBox="0 0 20 20" aria-hidden="true"><path d={ORDER_PATHS.handle}/></svg></button>,
		steps: (index: number) => count < 2 ? null : (["up", "down"] as const).map(part => <button key={part} type="button" className="vw-icon-button p-step" data-order={part} aria-label={t(`order.${part}`, {name: name(index)})} title={t(`order.${part}`, {name: name(index)})} disabled={part === "up" ? index === 0 : index === count - 1} onClick={event => step(event.currentTarget, index, part === "up" ? -1 : 1)}><svg className="vw-icon" viewBox="0 0 20 20" aria-hidden="true"><path d={ORDER_PATHS[part]}/></svg></button>)
	};
}
