import {Banner, Button, Dialog, Field, Icon, IconButton, TextField, useI18n, useToast, type Tone} from "@veilway/ui";
import qrcode from "qrcode-generator";
import {createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode} from "react";
import {api, ApiError, type NodeState, type Totp} from "./api.ts";
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
			await api("post", "/session/reauth", {body: {password, totp: totp.trim()}});
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
				<TextField label={t("login.code")} hint={t("login.codeHint")} inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={totp} onChange={setTotp} technical required/>
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
		<div><h2 className="vw-h2">{t("totp.title")}</h2><p className="vw-muted">{t("totp.lead")}</p></div>
		<Qr text={totp.otpauth} label={t("totp.qr")}/>
		<Copyable label={t("totp.key")} value={totp.totp_secret}/>
		<div><Button variant="primary" onClick={onDone}>{done}</Button></div>
	</div>;
}

// A field whose value is a list, one item per line.
export function LinesField({label, hint, value, onChange, rows = 3, optional = true}: {label: string, hint?: string, value: string, onChange: (value: string) => void, rows?: number, optional?: boolean}) {
	return <Field label={label} hint={hint} optional={optional}>{ids => <textarea {...ids} className="vw-input vw-code p-textarea" dir="ltr" spellCheck={false} rows={rows} value={value} onChange={event => onChange(event.target.value)}/>}</Field>;
}

export const lines = (text: string) => text.split("\n").map(line => line.trim()).filter(Boolean);
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

// What a check found, each with where it is. Paths are the document's own words, so they stay in code type.
export function Issues({issues}: {issues: {path: string, text: string}[]}) {
	const {t} = useP();
	if (!issues.length) return null;
	return <ul className="p-issues" aria-label={t("config.problems")}>{issues.map((issue, i) => <li key={i}>{issue.path && <span className="vw-code">{issue.path}</span>}<span>{issue.text}</span></li>)}</ul>;
}

export const ago = (seconds: number) => seconds < 120 ? {key: "time.seconds" as const, count: Math.round(seconds)} : seconds < 7200 ? {key: "time.minutes" as const, count: Math.round(seconds / 60)} : seconds < 172800 ? {key: "time.hours" as const, count: Math.round(seconds / 3600)} : {key: "time.days" as const, count: Math.round(seconds / 86400)};
