import {Backdrop, Banner, Button, DEFAULT_SETTINGS, Glass, Icon, IconButton, PRODUCT, Segmented, StateBlock, ToastProvider, UiProvider, useToast, type IconName} from "@veilway/ui";
import {useEffect, useMemo, useRef, useState, type ReactNode} from "react";
import {api, flags, session, type NodeLink, type Part, type Settings} from "./api.ts";
import {en, type PanelKey} from "./locales/en.ts";
import {fa} from "./locales/fa.ts";
import {ago, ErrorNote, GuardProvider, useGuard, useLoad, useP, useSay} from "./kit.tsx";
import {AccountPage, type Prefs} from "./pages/account.tsx";
import {ChangePassword, Login, Setup} from "./pages/auth.tsx";
import {InboundsPage, loadRunning, RoutingPage} from "./pages/config.tsx";
import {DashboardPage} from "./pages/dashboard.tsx";
import {DnsPage} from "./pages/dns.tsx";
import {NodesPage} from "./pages/links.tsx";
import {ProfilesPage} from "./pages/profiles.tsx";
import {SettingsPage} from "./pages/subscriptions.tsx";
import {TokensPage} from "./pages/tokens.tsx";
import {TrafficPage} from "./pages/traffic.tsx";
import {UserPage} from "./pages/user.tsx";
import {UsersPage} from "./pages/users.tsx";
import {SettingsContext} from "./settings.ts";

const PACKS = {en, fa};
const PREFS = "veilway-panel-display";
const SIDEBAR = "veilway-panel-sidebar";
// Addresses from before the pages were split, so bookmarks keep working.
const MOVED: Record<string, string> = {"": "dashboard", node: "inbounds", "node/inbounds": "inbounds", "node/xray": "inbounds", "node/outbounds": "routing/outbounds", "node/exits": "routing/exits", "node/routing": "routing/routing", "node/profiles": "profiles", "node/links": "nodes", subscriptions: "settings", more: "dashboard"};
type NodeStatus = {version?: string, generation?: number, uptime_secs?: number, public_addresses?: string[]};
type Entry = {id: string, icon: IconName, count?: number, warn?: boolean};
const PAGES = ["dashboard", "traffic", "users", "inbounds", "routing", "dns", "profiles", "nodes", "tokens", "settings", "account"];

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
		<div><strong>{PRODUCT}</strong><span>{t("app.subtitle")}</span></div>
	</div>;
}

type Auth = {kind: "loading"} | {kind: "failed", error: unknown} | {kind: "setup"} | {kind: "login"} | {kind: "password"} | {kind: "in", username: string};

function Root({prefs, onPrefs}: {prefs: Prefs, onPrefs: (prefs: Prefs) => void}) {
	const {t} = useP(), say = useSay(), toast = useToast(), [auth, setAuth] = useState<Auth>({kind: "loading"}), [hash, setHash] = useState(location.hash);
	const [settings, setSettings] = useState<Settings | null>(null), [twoStep, setTwoStep] = useState(true);
	const start = () => {
		setAuth({kind: "loading"});
		api("get", "/status").then(status => { setTwoStep(flags.twoStep = status.two_step); return status.setup_needed ? setAuth({kind: "setup"}) : api("get", "/session").then(info => { session.set(info.csrf); setAuth(info.password_change_required ? {kind: "password"} : {kind: "in", username: info.username}); }, () => setAuth({kind: "login"})); }, error => setAuth({kind: "failed", error}));
	};
	useEffect(() => {
		start();
		session.onExpired(() => { setAuth({kind: "login"}); toast({tone: "warning", title: t("error.unauthorized")}); });
		const onHash = () => setHash(location.hash);
		addEventListener("hashchange", onHash);
		return () => removeEventListener("hashchange", onHash);
	}, []);
	useEffect(() => { document.title = t("app.title"); }, [t]);
	useEffect(() => { if (auth.kind === "in") api("get", "/settings").then(setSettings, () => setSettings(null)); }, [auth.kind]);
	// Logins and keys cross the network in the clear on plain HTTP anywhere but this machine.
	const http = location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
	const httpBanner = http ? <Banner tone="warning" title={t("banner.http.title")}>{t("banner.http.body")}</Banner> : null;
	const enter = () => api("get", "/session").then(info => setAuth({kind: "in", username: info.username}), () => setAuth({kind: "login"}));
	const logout = () => void api("post", "/logout").finally(() => { session.set(""); setAuth({kind: "login"}); });
	if (auth.kind !== "in") return <Backdrop fixed className="p-gate">
		<main className="p-gate-main">
			{httpBanner}
			<div className="p-gate-top"><Brand/><Segmented label={t("display.language")} value={prefs.locale} onChange={locale => onPrefs({...prefs, locale: locale as Prefs["locale"]})} options={[{value: "en", label: "English"}, {value: "fa", label: "فارسی"}]}/></div>
			<Glass className="p-gate-card">
				{auth.kind === "loading" && <StateBlock kind="loading" title={t("common.loading")}/>}
				{auth.kind === "failed" && <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={start}>{t("action.retry")}</Button>}>{say(auth.error)}</StateBlock>}
				{auth.kind === "setup" && <Setup onDone={() => setAuth({kind: "login"})}/>}
				{auth.kind === "login" && <Login onDone={(username, step) => setAuth(step ? {kind: step} : {kind: "in", username})}/>}
				{auth.kind === "password" && <ChangePassword onDone={() => void enter()} onLogout={logout}/>}
			</Glass>
		</main>
	</Backdrop>;
	return <SettingsContext.Provider value={{settings, set: setSettings}}><Frame hash={hash} username={auth.username} httpBanner={httpBanner} twoStep={twoStep} prefs={prefs} onPrefs={onPrefs} onLogout={logout}/></SettingsContext.Provider>;
}

// The signed-in frame: sidebar, banners and the page the address names.
function Frame({hash, username, httpBanner, twoStep, prefs, onPrefs, onLogout}: {hash: string, username: string, httpBanner: ReactNode, twoStep: boolean, prefs: Prefs, onPrefs: (prefs: Prefs) => void, onLogout: () => void}) {
	const {t, number} = useP(), path = hash.replace(/^#\/?/, ""), parts = path.split("/"), page = PAGES.includes(parts[0]!) ? parts[0]! : "dashboard", sub = parts[1] ?? "";
	const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem(SIDEBAR) === "collapsed"; } catch { return false; } }), [open, setOpen] = useState(false), menu = useRef<HTMLButtonElement>(null), side = useRef<HTMLElement>(null);
	const node = useLoad(() => api("get", "/node"), []), live = useLoad(() => api("get", "/stats/now"), []), links = useLoad(() => api("get", "/links") as Promise<{links: NodeLink[] | null}>, []);
	const counts = useLoad(() => Promise.allSettled([api("get", "/users"), loadRunning(), api("get", "/xray")]).then(([users, running, xray]) => ({users: users.status === "fulfilled" ? users.value.users.length : undefined, inbounds: running.status === "fulfilled" ? ((running.value.document.inbounds as unknown[] | undefined)?.length ?? 0) + (xray.status === "fulfilled" ? xray.value.inbounds.length : 0) : undefined})), []);
	useEffect(() => { const moved = MOVED[path] ?? MOVED[parts[0]!]; if (moved) location.replace("#/" + moved); }, [path]);
	useEffect(() => { const timer = setInterval(() => { node.reload(); live.reload(); links.reload(); counts.reload(); }, 30000); return () => clearInterval(timer); }, [node.reload, live.reload, links.reload, counts.reload]);
	useEffect(() => setOpen(false), [hash]);
	// Newer browsers answer scrollTo with a promise, which an effect must not return.
	useEffect(() => { scrollTo({top: 0}); }, [page, page === "users" ? sub : ""]);
	useEffect(() => {
		if (!open) return;
		side.current?.querySelector<HTMLElement>("a, button")?.focus();
		const key = (event: KeyboardEvent) => { if (event.key === "Escape") setOpen(false); };
		document.addEventListener("keydown", key);
		return () => { document.removeEventListener("keydown", key); menu.current?.focus(); };
	}, [open]);
	const fold = () => { const next = !collapsed; setCollapsed(next); try { localStorage.setItem(SIDEBAR, next ? "collapsed" : "open"); } catch { /* remembered for this visit only */ } };
	const status = (node.data?.status ?? null) as NodeStatus | null, list = links.data?.links ?? [], up = list.filter(l => l.state === "up").length, online = live.data?.online_users.length;
	const tone = !node.data ? "muted" : node.data.keys_missing || node.data.gateway_missing || !node.data.reachable ? "danger" : "success", host = status?.public_addresses?.[0] ?? t("side.thisNode");
	const stateWord = !node.data ? t("common.loading") : node.data.keys_missing ? t("side.keysMissing") : node.data.gateway_missing ? t("side.gatewayMissing") : node.data.reachable ? t("side.running") : t("side.unreachable");
	const bars = <span className="p-bars" data-off={tone === "success" ? undefined : ""} aria-hidden="true"><i/><i/><i/></span>;
	const groups: {label?: PanelKey, items: Entry[]}[] = [
		{items: [{id: "dashboard", icon: "overview"}, {id: "traffic", icon: "chart"}]},
		{label: "nav.group.people", items: [{id: "users", icon: "users", count: counts.data?.users}]},
		{label: "nav.group.network", items: [{id: "nodes", icon: "device", count: list.length - up || undefined, warn: true}, {id: "inbounds", icon: "inbox", count: counts.data?.inbounds}, {id: "routing", icon: "upload"}, {id: "dns", icon: "globe"}, {id: "profiles", icon: "components"}]},
		{label: "nav.group.panel", items: [{id: "tokens", icon: "lock"}, {id: "settings", icon: "settings"}]}
	];
	const initials = username.split(/[-._]/).filter(Boolean).map(part => part[0]).join("").slice(0, 2).toUpperCase() || username.slice(0, 2).toUpperCase();
	return <Backdrop fixed className="p-app">
		<header className="vw-glass p-phone-bar" data-layer="chrome" inert={open}>
			<button ref={menu} type="button" className="vw-icon-button" aria-label={t("side.open")} aria-expanded={open} onClick={() => setOpen(true)}><svg className="vw-icon" viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14M3 10h14M3 14.5h14"/></svg></button>
			<strong>{t(`nav.${page}` as PanelKey)}</strong>
			<span className="p-state" data-tone={tone}>{bars}<span className="vw-code">{host}</span></span>
			<a className="p-avatar" data-size="sm" href="#/account" aria-label={t("nav.account")}>{initials}</a>
		</header>
		<div className="p-frame">
			<button type="button" className="p-scrim" data-open={open ? "" : undefined} aria-label={t("side.close")} tabIndex={-1} onClick={() => setOpen(false)}/>
			<aside ref={side} className="vw-glass p-side" data-layer={open ? "popover" : "chrome"} data-collapsed={collapsed && !open ? "" : undefined} data-open={open ? "" : undefined} role={open ? "dialog" : undefined} aria-modal={open || undefined} aria-label={t(open ? "side.menu" : "side.label")}>
				<div className="p-side-top">
					<Brand/>
					{open ? <IconButton icon="close" label={t("side.close")} onClick={() => setOpen(false)}/> : <IconButton className="p-collapse" icon="chevronForward" label={t(collapsed ? "side.expand" : "side.collapse")} aria-expanded={!collapsed} onClick={fold}/>}
				</div>
				<div className="p-side-scroll">
					<div className="p-node vw-well" title={collapsed && !open ? host + ", " + stateWord : undefined}>
						<div className="p-node-head"><span className="p-state" data-tone={tone}>{bars}</span><strong className="vw-code">{host}</strong><span className="p-state" data-tone={tone}>{stateWord}</span></div>
						{status?.version && <span className="p-node-host vw-small vw-muted">{t("side.version", {version: status.version})}</span>}
						{node.data?.reachable && <dl className="p-node-meta">
							<div><dt>{t("side.online")}</dt><dd className="vw-num">{online === undefined ? "" : t("count.users", {count: online})}</dd></div>
							{status?.generation !== undefined && <div><dt>{t("side.config")}</dt><dd className="vw-num">{t("side.configNo", {generation: number(status.generation)})}</dd></div>}
							{list.length > 0 && <div><dt>{t("side.links")}</dt><dd className="vw-num">{t("side.linksUp", {up: number(up), total: number(list.length)})}</dd></div>}
							{status?.uptime_secs !== undefined && <div><dt>{t("side.uptime")}</dt><dd className="vw-num">{(span => t(span.key, {count: span.count}))(ago(status.uptime_secs))}</dd></div>}
						</dl>}
					</div>
					<nav className="vw-nav p-nav" data-layout="rail" aria-label={t("side.nav")}>
						{groups.map((group, i) => <div key={i} className="p-nav-group" role="group" aria-label={group.label ? t(group.label) : undefined}>
							{group.label && <span className="p-nav-label" aria-hidden="true">{t(group.label)}</span>}
							{group.items.map(item => <a key={item.id} className="vw-nav-item" href={"#/" + item.id} aria-current={item.id === page ? "page" : undefined} title={collapsed && !open ? t(`nav.${item.id}` as PanelKey) : undefined}><Icon name={item.icon}/><span>{t(`nav.${item.id}` as PanelKey)}</span>{item.count !== undefined && item.count > 0 && <span className="p-count" data-tone={item.warn ? "warning" : undefined} aria-label={t(item.warn ? "side.down" : "side.count", {count: item.count})}>{number(item.count)}</span>}</a>)}
						</div>)}
					</nav>
				</div>
				<div className="p-account">
					<a className="p-account-link" href="#/account" aria-current={page === "account" ? "page" : undefined} title={collapsed && !open ? username : undefined}><span className="p-avatar" aria-hidden="true">{initials}</span><span className="p-account-text"><strong><bdi className="vw-code">{username}</bdi></strong><span>{t("nav.account")}</span></span></a>
					<IconButton icon="power" label={t("account.logout")} onClick={onLogout}/>
				</div>
			</aside>
			<main className="p-main" inert={open}>
				{httpBanner}
				{!twoStep && <Banner tone="danger" title={t("twostep.banner.title")}>{t("twostep.banner.body")}</Banner>}
				<UpdateBanner/>
				<NodeBanner node={node.data} onPushed={node.reload}/>
				{node.data?.gateway_missing && <Banner tone="danger" title={t("banner.gateway.missing")} action={<Button size="sm" onClick={() => { location.hash = "#/settings/gateway"; }}>{t("banner.gateway.open")}</Button>}>{t("banner.gateway.missingBody")}</Banner>}
				{node.data?.gateway_switch_due && !node.data.gateway_missing && <Banner tone="info" title={t("banner.gateway.due")} action={<Button size="sm" onClick={() => { location.hash = "#/settings/gateway"; }}>{t("banner.gateway.open")}</Button>}>{t("banner.gateway.dueBody")}</Banner>}
				{node.data?.clock_synchronized === false && <Banner tone="warning" title={t("banner.clock.title")}>{t("banner.clock.body")}</Banner>}
				<div className="p-page" key={page === "users" ? page + "/" + sub : page}>
					{page === "dashboard" && <DashboardPage live={live.data} onLive={live.reload}/>}
					{page === "traffic" && <TrafficPage/>}
					{page === "users" && (sub && sub !== "new" && Number.isFinite(Number(sub)) ? <UserPage id={Number(sub)}/> : <UsersPage adding={sub === "new"}/>)}
					{page === "inbounds" && <InboundsPage/>}
					{page === "routing" && <RoutingPage tab={sub}/>}
					{page === "dns" && <DnsPage/>}
					{page === "profiles" && <ProfilesPage/>}
					{page === "nodes" && <NodesPage status={status} reachable={node.data?.reachable ?? false} online={online}/>}
					{page === "tokens" && <TokensPage/>}
					{page === "settings" && <SettingsPage at={sub}/>}
					{page === "account" && <AccountPage tab={sub} username={username} prefs={prefs} onPrefs={onPrefs} onLogout={onLogout}/>}
				</div>
			</main>
		</div>
	</Backdrop>;
}

// Newer releases of the panel and the node, each with its notes and the action that asks the host to install it. The host answers the request itself: the panel goes away and comes back as the new version, and the node restarts, which drops its live tunnels for a moment.
function UpdateBanner() {
	const {t} = useP(), guard = useGuard(), info = useLoad(() => api("get", "/update"), []), [asked, setAsked] = useState<Part | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null);
	const data = info.data, from = data?.current, nodeFrom = data?.node_current, start = useLoad(() => api("get", "/status"), []), startId = start.data?.start_id;
	const panelBusy = asked === "panel" || asked === "both" || !!data?.updating, nodeBusy = asked === "node" || asked === "both" || !!data?.node_updating, updating = panelBusy || nodeBusy;
	useEffect(() => {
		if (!updating || !from || !startId) return;
		const started = Date.now(), timer = setInterval(() => {
			if (Date.now() - started > 15 * 60_000) { clearInterval(timer); setAsked(null); setError(new Error(t("banner.update.slow"))); return; }
			// Done when the server restarted (a new start id), the panel reports another version, or the node is back with another one.
			void api("get", "/status").then(next => { if (next.start_id !== startId) location.reload(); }, () => {});
			void api("get", "/update").then(next => { if (next.current !== from || (next.node_current && next.node_current !== nodeFrom)) location.reload(); }, () => {});
		}, 3000);
		return () => clearInterval(timer);
	}, [updating, from, nodeFrom, startId, t]);
	if (!data || (!data.latest && !data.node_latest && !updating)) return null;
	if (updating) return <Banner tone="info" title={panelBusy ? t("banner.update.running", {version: data.latest ?? ""}) : t("banner.update.runningNode", {version: data.node_latest ?? ""})}>{error ? <ErrorNote error={error}/> : panelBusy ? t("banner.update.runningBody") : t("banner.update.runningNodeBody")}</Banner>;
	const panel = !!data.latest, node = !!data.node_latest, both = panel && node, can = data.can_update;
	const title = both ? t("banner.update.bothTitle", {panel: data.latest ?? "", node: data.node_latest ?? ""}) : panel ? t("banner.update.title", {version: data.latest ?? ""}) : t("banner.update.nodeTitle", {version: data.node_latest ?? ""});
	const ask = (part: Part) => { setBusy(true); setError(null); void guard(() => api("post", "/update/request", {body: {part}})).then(() => setAsked(part), setError).finally(() => setBusy(false)); };
	return <Banner tone="info" title={title} action={<div className="p-cluster">
		{panel && data.notes_url && <Button size="sm" onClick={() => { window.open(data.notes_url!, "_blank", "noopener,noreferrer"); }}>{t("banner.update.notes")}</Button>}
		{node && data.node_notes_url && <Button size="sm" onClick={() => { window.open(data.node_notes_url!, "_blank", "noopener,noreferrer"); }}>{t("banner.update.nodeNotes")}</Button>}
		{can && panel && <Button size="sm" variant={both ? "secondary" : "primary"} disabled={busy} onClick={() => ask("panel")}>{t("banner.update.panelButton")}</Button>}
		{can && node && <Button size="sm" variant={both ? "secondary" : "primary"} disabled={busy} onClick={() => ask("node")}>{t("banner.update.nodeButton")}</Button>}
		{can && both && <Button size="sm" variant="primary" disabled={busy} onClick={() => ask("both")}>{t("banner.update.bothButton")}</Button>}
	</div>}>{error ? <ErrorNote error={error}/> : !can ? t("banner.update.manual") : node ? t("banner.update.nodeWarning") : null}</Banner>;
}

// The node's health in one line at the top of every page, with the one action that can fix a missed push.
function NodeBanner({node, onPushed}: {node: {keys_missing: boolean, reachable: boolean} | null, onPushed: () => void}) {
	const {t} = useP(), say = useSay(), toast = useToast(), [busy, setBusy] = useState(false);
	if (!node) return null;
	if (node.keys_missing) return <Banner tone="danger" title={t("error.keys_missing")}>{t("banner.node.keys")}</Banner>;
	if (node.reachable) return null;
	return <Banner tone="warning" title={t("banner.node.title")} action={<Button size="sm" icon="refresh" disabled={busy} onClick={() => { setBusy(true); void api("post", "/node/sync").then(answer => { toast(answer.synced ? {tone: "success", title: t("banner.node.pushed")} : {tone: "danger", title: say(new Error(answer.error ?? t("error.node_unreachable")))}); onPushed(); }, failure => toast({tone: "danger", title: say(failure)})).finally(() => setBusy(false)); }}>{t("banner.node.push")}</Button>}>{t("banner.node.body")}</Banner>;
}
