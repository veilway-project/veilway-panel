import {Backdrop, Banner, Button, DEFAULT_SETTINGS, Glass, Nav, PRODUCT, Segmented, Shell, StateBlock, ToastProvider, UiProvider, useToast, type NavItem} from "@veilway/ui";
import {useEffect, useMemo, useState} from "react";
import {api, session, type Settings} from "./api.ts";
import {en} from "./locales/en.ts";
import {fa} from "./locales/fa.ts";
import {GuardProvider, useLoad, useP, useSay} from "./kit.tsx";
import {AccountPage, type Prefs} from "./pages/account.tsx";
import {Login, Setup} from "./pages/auth.tsx";
import {SubscriptionsPage} from "./pages/subscriptions.tsx";
import {TokensPage} from "./pages/tokens.tsx";
import {UserPage} from "./pages/user.tsx";
import {UsersPage} from "./pages/users.tsx";
import {SettingsContext} from "./settings.ts";

const PACKS = {en, fa};
const PREFS = "veilway-panel-display";

export function App() {
	const [prefs, setPrefs] = useState<Prefs>(() => {
		const query = new URLSearchParams(location.search), stored = (() => { try { return JSON.parse(localStorage.getItem(PREFS) ?? "{}") as Partial<Prefs>; } catch { return {}; } })();
		const locale = query.get("lang") ?? stored.locale, scheme = query.get("scheme") ?? stored.scheme;
		return {locale: locale === "fa" ? "fa" : "en", scheme: scheme === "dark" || scheme === "light" ? scheme : "system"};
	});
	const settings = useMemo(() => ({...DEFAULT_SETTINGS, locale: prefs.locale, scheme: prefs.scheme}), [prefs]);
	const change = (next: Prefs) => { setPrefs(next); try { localStorage.setItem(PREFS, JSON.stringify(next)); } catch { /* the choice lasts for this visit only */ } };
	return <UiProvider settings={settings} extra={PACKS}><ToastProvider><GuardProvider><Root prefs={prefs} onPrefs={change}/></GuardProvider></ToastProvider></UiProvider>;
}

function Brand() {
	const {t} = useP();
	return <div className="p-brand">
		<svg viewBox="0 0 1024 1024" aria-hidden="true"><defs><linearGradient id="p-tile" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#22795A"/><stop offset="1" stopColor="#145540"/></linearGradient><clipPath id="p-band"><rect x="0" y="262" width="1024" height="500"/></clipPath><mask id="p-behind" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024"><rect width="1024" height="1024" fill="#fff"/><path d="M242.2 200L543.7 828" stroke="#000" strokeWidth="152"/></mask></defs><rect x="64" y="64" width="896" height="896" rx="150" fill="url(#p-tile)"/><g clipPath="url(#p-band)" fill="none" stroke="#F1F8F4"><g mask="url(#p-behind)"><path d="M734.1 200L432.6 828" strokeWidth="34"/><path d="M781.8 200L480.3 828" strokeWidth="34" strokeOpacity="0.6"/><path d="M829.5 200L528 828" strokeWidth="34" strokeOpacity="0.32"/></g><path d="M242.2 200L543.7 828" strokeWidth="120"/></g></svg>
		<div><strong>{PRODUCT}</strong><span className="vw-muted vw-small">{t("app.subtitle")}</span></div>
	</div>;
}

type Auth = {kind: "loading"} | {kind: "failed", error: unknown} | {kind: "setup"} | {kind: "login"} | {kind: "in", username: string};

function Root({prefs, onPrefs}: {prefs: Prefs, onPrefs: (prefs: Prefs) => void}) {
	const {t} = useP(), say = useSay(), toast = useToast(), [auth, setAuth] = useState<Auth>({kind: "loading"}), [hash, setHash] = useState(location.hash), [wide, setWide] = useState(() => matchMedia("(min-width: 760px)").matches);
	const [settings, setSettings] = useState<Settings | null>(null);
	const start = () => {
		setAuth({kind: "loading"});
		api("get", "/status").then(status => status.setup_needed ? setAuth({kind: "setup"}) : api("get", "/session").then(info => { session.set(info.csrf); setAuth({kind: "in", username: info.username}); }, () => setAuth({kind: "login"})), error => setAuth({kind: "failed", error}));
	};
	useEffect(() => {
		start();
		session.onExpired(() => { setAuth({kind: "login"}); toast({tone: "warning", title: t("error.unauthorized")}); });
		const onHash = () => setHash(location.hash), media = matchMedia("(min-width: 760px)"), onMedia = () => setWide(media.matches);
		addEventListener("hashchange", onHash);
		media.addEventListener("change", onMedia);
		return () => { removeEventListener("hashchange", onHash); media.removeEventListener("change", onMedia); };
	}, []);
	useEffect(() => { document.title = t("app.title"); }, [t]);
	useEffect(() => { if (auth.kind === "in") api("get", "/settings").then(setSettings, () => setSettings(null)); }, [auth.kind]);
	// Logins and keys cross the network in the clear on plain HTTP anywhere but this machine.
	const http = location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
	const httpBanner = http ? <Banner tone="warning" title={t("banner.http.title")}>{t("banner.http.body")}</Banner> : null;
	if (auth.kind !== "in") return <Backdrop fixed className="p-gate">
		<main className="p-gate-main">
			{httpBanner}
			<div className="p-gate-top"><Brand/><Segmented label={t("display.language")} value={prefs.locale} onChange={locale => onPrefs({...prefs, locale: locale as Prefs["locale"]})} options={[{value: "en", label: "English"}, {value: "fa", label: "فارسی"}]}/></div>
			<Glass className="p-gate-card">
				{auth.kind === "loading" && <StateBlock kind="loading" title={t("common.loading")}/>}
				{auth.kind === "failed" && <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={start}>{t("action.retry")}</Button>}>{say(auth.error)}</StateBlock>}
				{auth.kind === "setup" && <Setup onDone={() => setAuth({kind: "login"})}/>}
				{auth.kind === "login" && <Login onDone={username => setAuth({kind: "in", username})}/>}
			</Glass>
		</main>
	</Backdrop>;
	const parts = hash.replace(/^#\/?/, "").split("/"), page = parts[0] || "users", userId = page === "users" && parts[1] ? Number(parts[1]) : null;
	// On a phone the bar has room for four items; the two sections still to come only appear in the wide rail.
	const items: NavItem[] = [{id: "users", label: t("nav.users"), icon: "users"}, {id: "subscriptions", label: t("nav.subscriptions"), icon: "globe"}, ...(wide ? [{id: "config", label: t("nav.config"), icon: "settings"}, {id: "traffic", label: t("nav.traffic"), icon: "chart"}] as NavItem[] : []), {id: "tokens", label: t("nav.tokens"), icon: "lock"}, {id: "account", label: t("nav.account"), icon: "device"}];
	const logout = () => void api("post", "/logout").finally(() => { session.set(""); setAuth({kind: "login"}); });
	return <SettingsContext.Provider value={{settings, set: setSettings}}><Backdrop fixed className="p-app">
		<Shell nav={<Nav value={page} onChange={id => { location.hash = "#/" + id; }} items={items} header={<Brand/>}/>} banner={<>{httpBanner}<NodeBanner/></>}>
			<div className="p-page" key={hash}>
				{page === "users" && (userId !== null && Number.isFinite(userId) ? <UserPage id={userId}/> : <UsersPage/>)}
				{page === "subscriptions" && <SubscriptionsPage/>}
				{page === "config" && <StateBlock kind="empty" title={t("coming.config")}>{t("coming.configBody")}</StateBlock>}
				{page === "traffic" && <StateBlock kind="empty" title={t("coming.traffic")} action={<Button onClick={() => { location.hash = "#/users"; }}>{t("nav.users")}</Button>}>{t("coming.trafficBody")}</StateBlock>}
				{page === "tokens" && <TokensPage/>}
				{page === "account" && <AccountPage username={auth.username} prefs={prefs} onPrefs={onPrefs} onLogout={logout}/>}
			</div>
		</Shell>
	</Backdrop></SettingsContext.Provider>;
}

// The node's health in one line at the top of every page, with the one action that can fix a missed push.
function NodeBanner() {
	const {t} = useP(), say = useSay(), toast = useToast(), node = useLoad(() => api("get", "/node"), []), [busy, setBusy] = useState(false);
	if (!node.data) return null;
	if (node.data.keys_missing) return <Banner tone="danger" title={t("error.keys_missing")}>{t("banner.node.keys")}</Banner>;
	if (node.data.reachable) return null;
	return <Banner tone="warning" title={t("banner.node.title")} action={<Button size="sm" icon="refresh" disabled={busy} onClick={() => { setBusy(true); void api("post", "/node/sync").then(answer => { toast(answer.synced ? {tone: "success", title: t("banner.node.pushed")} : {tone: "danger", title: say(new Error(answer.error ?? t("error.node_unreachable")))}); node.reload(); }, failure => toast({tone: "danger", title: say(failure)})).finally(() => setBusy(false)); }}>{t("banner.node.push")}</Button>}>{t("banner.node.body")}</Banner>;
}
