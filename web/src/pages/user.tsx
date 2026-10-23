import {Banner, Button, Checkbox, ConfirmDialog, DataTable, Dialog, Glass, Icon, IconButton, SecretField, StatRow, StatTile, StateBlock, TextField, useToast} from "@veilway/ui";
import {useEffect, useState} from "react";
import {api, type Device, type LinkView, type NodeState, type NodeUser, type UserPatch, type XrayLink} from "../api.ts";
import {Copyable, ErrorNote, Mark, NodeNote, Qr, useCopy, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {useSettings} from "../settings.ts";
import {EndpointPick, PlainNote} from "./endpoints.tsx";
import {ProxyLogin} from "./proxy.tsx";
import {ExitPicker, type Exits, handoff, keptExits, keptFallback, useExits, useExpiry, UserForm} from "./users.tsx";
import {XrayLinksDialog} from "./xray.tsx";

export function UserPage({id}: {id: number}) {
	const {t, date, time, bytes, number, percent} = useP(), toast = useToast(), say = useSay(), guard = useGuard(), expiry = useExpiry(), settings = useSettings(), copy = useCopy();
	const page = useLoad(() => Promise.all([api("get", "/users/{id}", {params: {id}}), api("get", "/users/{id}/devices", {params: {id}}), api("get", "/users/{id}/subscription", {params: {id}}), api("get", "/users/{id}/endpoint", {params: {id}})]), [id]);
	const [editing, setEditing] = useState(false), [dialog, setDialog] = useState<"delete" | "usage" | "link" | "device" | "xray" | "sealed" | null>(null), [removing, setRemoving] = useState<Device | null>(null);
	const [totals, setTotals] = useState(false), [removeOld, setRemoveOld] = useState(false), [deviceName, setDeviceName] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [linkError, setLinkError] = useState<unknown>(null), [sealPass, setSealPass] = useState(""), [sealAgain, setSealAgain] = useState(""), [sealTried, setSealTried] = useState(false);
	// fresh is a link made just now, by adding the user or resetting the link; otherwise it is the panel's copy, opened after re-authentication.
	const [shown, setShown] = useState<{link: LinkView, once: boolean, fresh: boolean} | null>(() => { const made = handoff.current?.id === id ? handoff.current : null; handoff.current = null; return made && {link: made.link, once: settings?.show_links_once ?? false, fresh: true}; });
	const [exported, setExported] = useState<{name: string, file: string, link?: string | null} | null>(null), [node, setNode] = useState<NodeState | null>(null), [xray, setXray] = useState<XrayLink[] | null>(null);
	const nodeExits = useExits(), [exits, setExits] = useState<Exits | null>(null), [exitsTried, setExitsTried] = useState(false), [exitsBusy, setExitsBusy] = useState(false), [exitsError, setExitsError] = useState<unknown>(null), [fallback, setFallback] = useState<string | null | undefined>(undefined), [ownEndpoint, setOwnEndpoint] = useState<string | undefined>(undefined), [endpointBusy, setEndpointBusy] = useState(false), [endpointError, setEndpointError] = useState<unknown>(null);
	useEffect(() => { if (shown) document.getElementById("link-title")?.scrollIntoView({block: "nearest"}); }, [shown]);
	if (page.error && !page.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={page.reload}>{t("action.retry")}</Button>}>{say(page.error)}</StateBlock>;
	if (!page.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const [user, {devices}, sub, where] = page.data, usage = user.node as NodeUser | null, current = devices.filter(d => d.token_gen === sub.token_generation);
	const fresh = new Set((usage?.devices ?? []).filter(d => typeof d.handshake_age_secs === "number" && d.handshake_age_secs < 180).map(d => d.public_key)), online = devices.filter(d => fresh.has(d.public_key)).length;
	const act = async (work: () => Promise<unknown>, after?: () => void) => {
		setBusy(true);
		setError(null);
		try {
			await guard(work);
			setDialog(null);
			after?.();
			page.reload();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const open = (next: typeof dialog) => { setError(null); setDialog(next); };
	const showLink = async () => { setLinkError(null); try { setShown({link: await guard(() => api("post", "/users/{id}/subscription/show", {params: {id}})), once: false, fresh: false}); } catch (failure) { setLinkError(failure); } };
	const sealProblem = [...sealPass].length < 10 ? t("sealed.length") : sealPass !== sealAgain ? t("sealed.match") : undefined;
	const sealFile = () => {
		setSealTried(true);
		if (sealProblem) return;
		// A link the panel keeps no copy of is sent back, and the server takes it only when it is this user's current one.
		void act(async () => {
			const made = await api("post", "/users/{id}/subscription/sealed", {params: {id}, body: {password: sealPass, link: shown?.fresh ? shown.link.veilway : undefined}});
			const link = document.createElement("a");
			link.href = URL.createObjectURL(new Blob([Uint8Array.from(atob(made.file), char => char.charCodeAt(0))], {type: "application/vnd.veilway.sealed-subscription"}));
			link.download = made.filename;
			link.click();
			URL.revokeObjectURL(link.href);
			setSealPass("");
			setSealAgain("");
			setSealTried(false);
			toast({tone: "success", title: t("sealed.done")});
		});
	};
	const openSealed = () => { setSealPass(""); setSealAgain(""); setSealTried(false); open("sealed"); };
	const held = (exits ?? user.exits) as Exits, kept = keptExits(held, nodeExits.data), keptDefault = keptFallback(held, fallback === undefined ? user.exit : fallback, nodeExits.data), exitsChanged = JSON.stringify(kept) !== JSON.stringify(user.exits) || keptDefault !== (user.exit ?? null), exitsEdited = exits !== null || fallback !== undefined, exitsProblem = kept.length === 0 ? t("exits.pick") : undefined;
	const saveExits = async () => {
		setExitsTried(true);
		if (exitsProblem) return;
		setExitsBusy(true);
		setExitsError(null);
		try {
			// The schema lists the nullable fields as required, but the server leaves out what is not sent.
			const answer = await guard(() => api("patch", "/users/{id}", {params: {id}, body: {exits: kept, exit: keptDefault} as UserPatch}));
			setNode(answer.node);
			setExits(null);
			setFallback(undefined);
			setExitsTried(false);
			toast({tone: "success", title: t("exits.saved")});
			page.reload();
		} catch (failure) {
			setExitsError(failure);
		} finally {
			setExitsBusy(false);
		}
	};
	const saveEndpoint = async () => {
		setEndpointBusy(true);
		setEndpointError(null);
		try {
			setNode((await guard(() => api("patch", "/users/{id}", {params: {id}, body: {endpoint: ownEndpoint || null} as UserPatch}))).node);
			setOwnEndpoint(undefined);
			toast({tone: "success", title: t("endpoint.saved")});
			page.reload();
		} catch (failure) {
			setEndpointError(failure);
		} finally {
			setEndpointBusy(false);
		}
	};
	const total = usage?.traffic ? (usage.traffic.up_bytes ?? 0) + (usage.traffic.down_bytes ?? 0) : null, amount = usage?.used_bytes === undefined ? null : bytes(usage.used_bytes);
	return <>
		<header className="p-head">
			<div>
				<a className="p-crumb" href="#/users"><Icon name="chevronForward"/>{t("common.back")}</a>
				<div className="p-title-row">
					<h1 className="vw-h1 vw-code">{user.name}</h1>
					<span className="p-flags"><Mark tone={user.enabled ? "success" : "muted"}>{t(user.enabled ? "user.state.enabled" : "user.state.disabled")}</Mark>{online > 0 && <Mark tone="success">{t("user.online", {count: online})}</Mark>}</span>
				</div>
				<p>{[user.note, t("user.added", {date: date(new Date(user.created * 1000))})].filter(Boolean).join(". ")}</p>
			</div>
			<div className="p-cluster">
				<Button onClick={() => setEditing(true)}>{t("user.edit")}</Button>
				<Button onClick={() => { setTotals(false); open("usage"); }}>{t("user.resetUsage")}</Button>
				<Button variant="danger" onClick={() => open("delete")}>{t("user.delete")}</Button>
			</div>
		</header>
		<NodeNote node={node}/>
		<div className="p-grid-main">
			<div className="p-stack">
				<Glass className="p-panel">
					<div className="p-sheet-head"><div><h2 className="vw-h2">{t("user.usage")}</h2><p>{usage?.period_start ? t("user.usageSince", {date: date(new Date(usage.period_start * 1000))}) : t("user.usageLabel")}</p></div></div>
					{amount === null ? <p className="vw-muted">{t("users.usageUnknown")}</p> : <div className="p-big-usage">
						<div><span className="vw-figure p-figure-big">{amount.value}</span><span className="vw-muted">{user.quota_bytes ? t("user.ofQuota", {unit: amount.unit, total: bytes(user.quota_bytes).text, percent: percent(usage!.used_bytes! / user.quota_bytes)}) : amount.unit + ". " + t("users.noLimit")}</span></div>
						{user.quota_bytes ? <div className="vw-usage" data-level={usage!.used_bytes! >= user.quota_bytes ? "over" : usage!.used_bytes! / user.quota_bytes >= 0.8 ? "near" : "ok"}><div className="vw-meter" role="meter" aria-label={t("user.usageLabel")} aria-valuemin={0} aria-valuemax={user.quota_bytes} aria-valuenow={usage!.used_bytes}><span style={{inlineSize: Math.min(100, usage!.used_bytes! / user.quota_bytes * 100) + "%"}}/></div></div> : null}
					</div>}
					<div className="p-stat-sm"><StatRow>
						<StatTile label={t("form.period")} value={t(`form.period.${(user.quota_period ?? "none") as "none"}`)}/>
						<StatTile label={t("form.expiry")} value={user.expires_at ? date(new Date(user.expires_at * 1000)) : t("users.noExpiry")} detail={user.expires_at ? expiry(user.expires_at) : undefined}/>
						{total !== null && <StatTile label={t("user.totalLabel")} value={bytes(total).text}/>}
						<StatTile label={t("users.col.groups")} value={user.groups.length ? user.groups.join(", ") : t("common.none")}/>
					</StatRow></div>
				</Glass>
				<Glass className="p-panel">
					<div className="p-sheet-head">
						<div><h2 className="vw-h2">{t("user.devices")}</h2><p>{user.device_limit ? t("user.devicesLead", {used: number(user.devices), limit: number(user.device_limit)}) : t("user.devicesLeadNoLimit", {used: number(user.devices)})}</p></div>
						<Button size="sm" icon="plus" onClick={() => { setDeviceName(""); open("device"); }}>{t("device.add")}</Button>
					</div>
					{devices.length === 0 ? <StateBlock kind="empty" title={t("user.noDevices")}>{t("user.noDevicesBody")}</StateBlock> : <DataTable caption={t("user.devices")} rows={devices} rowKey={d => String(d.id)} columns={[
						{id: "name", header: t("device.col.device"), cell: d => <span className="p-user"><span className="vw-code">{d.name}</span><span>{d.state === "pending" ? t("device.pending") : t("device.enrolledOn", {date: date(new Date((d.confirmed_at ?? d.created) * 1000), {month: "short", day: "numeric"})})}</span></span>},
						{id: "address", header: t("device.col.address"), cell: d => <span className="vw-code" dir="ltr">{d.address}</span>},
						{id: "key", header: t("device.col.key"), cell: d => <span className="vw-small">{t(d.key_origin === "panel" ? "device.keyPanel" : "device.keyOwn")}</span>},
						{id: "seen", header: t("device.col.seen"), cell: d => fresh.has(d.public_key) ? <Mark tone="success">{t("device.online")}</Mark> : d.last_seen ? <span className="vw-small vw-muted vw-num">{date(new Date(d.last_seen * 1000), {month: "short", day: "numeric"}) + " " + time(new Date(d.last_seen * 1000))}</span> : <span className="vw-small vw-muted">{t("device.neverSeen")}</span>},
						{id: "actions", header: "", align: "end", cell: d => <span className="p-cluster p-end">
							{d.key_origin === "panel" && <IconButton icon="download" label={t("device.export", {name: d.name})} onClick={async () => { setError(null); try { setExported({name: d.name, ...await guard(() => api("post", "/users/{id}/devices/{did}/export", {params: {id, did: d.id}}))}); } catch (failure) { setError(failure); } }}/>}
							<IconButton icon="close" label={t("device.remove", {name: d.name})} onClick={() => setRemoving(d)}/>
						</span>}
					]}/>}
					{!dialog && <ErrorNote error={error}/>}
				</Glass>
				<Glass className="p-panel">
					<div className="p-sheet-head">
						<div><h2 className="vw-h2">{t("xray.userTitle")}</h2><p>{t("xray.userLead")}</p></div>
						<div className="p-cluster">
							<Button size="sm" icon="eye" onClick={async () => { setLinkError(null); try { setXray((await guard(() => api("get", "/users/{id}/xray", {params: {id}}))).links); } catch (failure) { setLinkError(failure); } }}>{t("xray.showLinks")}</Button>
							<Button size="sm" onClick={() => open("xray")}>{t("xray.rotate")}</Button>
						</div>
					</div>
				</Glass>
				<ProxyLogin user={user} onChanged={page.reload}/>
			</div>
			<div className="p-stack">
				{shown ? <Glass className="p-panel p-sheet-new" aria-labelledby="link-title">
					<div className="p-sheet-head"><div><h2 className="vw-h2" id="link-title">{t(shown.fresh ? "user.linkNew" : "user.link")}</h2><p>{t(shown.fresh ? "user.linkNewLead" : "link.body")}</p></div></div>
					{shown.fresh && (shown.once ? <Banner tone="warning" title={t("link.once")}/> : <Banner tone="info" title={t("user.linkSendNow")}>{t("user.linkLater")}</Banner>)}
					<Qr svg={shown.link.qr_svg} label={t("link.qr")}/>
					<Copyable label={t("link.native")} value={shown.link.veilway}/>
					<Copyable label={t("link.https")} value={shown.link.https}/>
					<div className="p-form-foot"><Button variant="quiet" onClick={() => setShown(null)}>{t(shown.fresh ? "user.linkDone" : "user.linkHide")}</Button><Button icon="download" onClick={openSealed}>{t("sealed.button")}</Button><Button variant="primary" icon="copy" onClick={() => copy(shown.link.veilway)}>{t("user.copyNative")}</Button></div>
				</Glass> : <Glass className="p-panel">
					<div className="p-sheet-head"><div><h2 className="vw-h2">{t("user.link")}</h2><p>{t("user.linkLead", {name: user.name})}</p></div></div>
					<div className="vw-well p-hidden-link">
						<div className="vw-input-group"><input className="vw-input vw-code" dir="ltr" readOnly value={(sub.endpoint_url || "https://") + "#" + "•".repeat(16)} aria-label={t("user.linkHidden")}/><span className="vw-unit">{t("user.hidden")}</span></div>
						{sub.can_show ? <div className="p-cluster"><Button variant="primary" icon="eye" onClick={() => void showLink()}>{t("user.showLink")}</Button><Button icon="download" onClick={openSealed}>{t("sealed.button")}</Button><span className="vw-small vw-muted">{t("user.showNote")}</span></div> : <p className="vw-small vw-muted">{t("user.noCopy")}</p>}
						<ErrorNote error={linkError}/>
					</div>
					<dl className="p-kv">
						<dt>{t("user.linkGen")}</dt><dd>{t("user.linkMade", {generation: number(sub.token_generation), date: date(new Date(sub.token_created * 1000))})}</dd>
						<dt>{t("user.linkDevices")}</dt><dd className="vw-num">{number(current.length)}</dd>
						{sub.key_fingerprints.length > 0 && <><dt>{t("user.keys")}</dt><dd>{sub.key_fingerprints.map(f => <span key={f} className="vw-code p-block">{f}</span>)}</dd></>}
						<dt>{t("user.subId")}</dt><dd><span className="vw-code">{sub.subscription_id}</span><span className="p-sub">{t("user.subIdNote")}</span></dd>
					</dl>
					<div className="p-form-foot"><p>{t("user.resetNote")}</p><Button variant="danger" onClick={() => { setRemoveOld(false); open("link"); }}>{t("user.resetLink")}</Button></div>
				</Glass>}
				{shown && <ErrorNote error={linkError}/>}
				<Glass className="p-panel">
					<div className="p-sheet-head"><div><h2 className="vw-h2">{t("exits.title")}</h2><p>{t("exits.lead")}</p></div></div>
					<ExitPicker value={held} onChange={setExits} exits={nodeExits} problem={exitsTried ? exitsProblem : undefined} fallback={fallback === undefined ? user.exit : fallback} onFallback={setFallback}/>
					<ErrorNote error={exitsError}/>
					{(exitsChanged || exitsEdited) && <div className="p-form-foot">{exitsEdited && <Button variant="quiet" onClick={() => { setExits(null); setFallback(undefined); setExitsTried(false); }}>{t("action.cancel")}</Button>}<Button variant="primary" disabled={exitsBusy || !exitsChanged} onClick={() => void saveExits()}>{t("exits.save")}</Button></div>}
				</Glass>
				<Glass className="p-panel">
					<div className="p-sheet-head"><div><h2 className="vw-h2">{t("endpoint.title")}</h2><p>{t("endpoint.lead")}</p></div></div>
					<dl className="p-kv">
						<dt>{t("endpoint.inUse")}</dt><dd>{where.resolved ? <><strong className="vw-code">{where.resolved}</strong>{where.url && <span className="p-block vw-code" dir="ltr">{where.url}</span>}</> : t("endpoint.unset")}</dd>
						<dt>{t("endpoint.source")}</dt><dd>{t(`endpoint.source.${where.source as "user"}`)}</dd>
						<dt>{t("relays.reach")}</dt><dd>{where.relays.length ? where.relays.join(", ") : t("common.none")}</dd>
					</dl>
					{where.plain && <PlainNote/>}
					<EndpointPick label={t("endpoint.label")} hint={t("endpoint.hint")} value={ownEndpoint ?? where.own ?? ""} onChange={setOwnEndpoint} followLabel={t("endpoint.follow")}/>
					<ErrorNote error={endpointError}/>
					{ownEndpoint !== undefined && ownEndpoint !== (where.own ?? "") && <div className="p-form-foot"><Button variant="quiet" onClick={() => setOwnEndpoint(undefined)}>{t("action.cancel")}</Button><Button variant="primary" disabled={endpointBusy} onClick={() => void saveEndpoint()}>{t("endpoint.save")}</Button></div>}
				</Glass>
			</div>
		</div>
		{editing && <UserForm user={user} defaultLimit={settings?.default_device_limit ?? 3} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); page.reload(); }}/>}
		<ConfirmDialog open={dialog === "delete"} onOpenChange={o => { if (!o) setDialog(null); }} danger title={t("user.deleteTitle", {name: user.name})} body={t("user.deleteBody")} confirmLabel={t("user.delete")} onConfirm={() => void guard(() => api("delete", "/users/{id}", {params: {id}})).then(() => { toast({tone: "success", title: t("user.deleted", {name: user.name})}); location.hash = "#/users"; }, failure => toast({tone: "danger", title: say(failure)}))}/>
		<ConfirmDialog open={removing !== null} onOpenChange={o => { if (!o) setRemoving(null); }} danger title={t("device.removeTitle", {name: removing?.name ?? ""})} body={t("device.removeBody")} confirmLabel={t("common.remove")} onConfirm={() => { const d = removing!; void guard(() => api("delete", "/users/{id}/devices/{did}", {params: {id, did: d.id}})).then(answer => { setNode(answer.node); toast({tone: "success", title: t("device.removed", {name: d.name})}); page.reload(); }, failure => toast({tone: "danger", title: say(failure)})); }}/>
		<Dialog open={dialog === "usage"} onOpenChange={o => { if (!o) setDialog(null); }} title={t("user.resetTitle", {name: user.name})} description={t("user.resetBody", {name: user.name})}>
			<Checkbox label={t("user.resetTotals")} checked={totals} onChange={setTotals}/>
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={() => setDialog(null)}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => void act(() => api("post", "/users/{id}/usage/reset", {params: {id}, body: {totals}}), () => toast({tone: "success", title: t("user.resetDone")}))}>{t("user.resetUsage")}</Button></div>
		</Dialog>
		<ConfirmDialog open={dialog === "xray"} onOpenChange={o => { if (!o) setDialog(null); }} title={t("xray.rotateTitle", {name: user.name})} body={t("xray.rotateBody", {name: user.name})} confirmLabel={t("xray.rotateConfirm")} onConfirm={() => void guard(() => api("post", "/users/{id}/xray/rotate", {params: {id}})).then(answer => { setNode(answer.node); toast({tone: "success", title: t("xray.rotated")}); }, failure => toast({tone: "danger", title: say(failure)}))}/>
		<Dialog open={dialog === "link"} onOpenChange={o => { if (!o) setDialog(null); }} title={t("user.resetLinkTitle", {name: user.name})} description={t("user.resetLinkBody")}>
			<p>{t("user.resetLinkDevices", {count: current.length, names: current.map(d => d.name).join(", ")})}</p>
			{current.length > 0 && <Checkbox label={t("user.removeOld")} checked={removeOld} onChange={setRemoveOld}/>}
			<ErrorNote error={error}/>
			<div className="vw-dialog-foot"><Button onClick={() => setDialog(null)}>{t("action.cancel")}</Button><Button variant="danger" disabled={busy} onClick={() => void act(async () => {
				const answer = await api("post", "/users/{id}/subscription/reset", {params: {id}, body: {remove_devices: removeOld}});
				setNode(answer.node);
				toast({tone: "success", title: t(answer.removed ? "user.resetLinkRemoved" : "user.resetLinkKept", {count: answer.old_devices.length})});
				if (answer.link) setShown({link: answer.link, once: settings?.show_links_once ?? !sub.can_show, fresh: true});
				if (answer.link_error) toast({tone: "warning", title: t("link.failed", {error: answer.link_error})});
			})}>{t("user.resetLinkConfirm")}</Button></div>
		</Dialog>
		<Dialog open={dialog === "sealed"} onOpenChange={o => { if (!o) setDialog(null); }} title={t("sealed.title", {name: user.name})} description={t("sealed.lead")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); sealFile(); }}>
				<Banner tone="warning" title={t("sealed.warn")}>{t("sealed.warnBody")}</Banner>
				<SecretField label={t("sealed.password")} hint={t("sealed.hint")} value={sealPass} onChange={setSealPass} autoComplete="new-password"/>
				<SecretField label={t("sealed.passwordAgain")} value={sealAgain} onChange={setSealAgain} autoComplete="new-password" error={sealTried ? sealProblem : undefined}/>
				<p className="vw-small vw-muted">{t("sealed.audit")}</p>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setDialog(null)}>{t("action.cancel")}</Button><Button type="submit" variant="primary" icon="download" disabled={busy}>{t("sealed.download")}</Button></div>
			</form>
		</Dialog>
		<Dialog open={dialog === "device"} onOpenChange={o => { if (!o) setDialog(null); }} title={t("device.addTitle")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void act(async () => { const answer = await api("post", "/users/{id}/devices", {params: {id}, body: {name: deviceName.trim()}}); setNode(answer.node); }); }}>
				<Banner tone="warning" title={t("device.addBody")}/>
				<TextField label={t("device.name")} value={deviceName} onChange={setDeviceName} maxLength={32} required/>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setDialog(null)}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy}>{t("device.create")}</Button></div>
			</form>
		</Dialog>
		<Dialog open={exported !== null} onOpenChange={o => { if (!o) setExported(null); }} title={t("device.exportTitle", {name: exported?.name ?? ""})} description={t("device.exportBody")}>
			{exported && <div className="p-stack">
				<Copyable label={t("device.file")} value={exported.file} multiline/>
				{exported.link && <Copyable label={t("device.exportLink")} value={exported.link}/>}
			</div>}
		</Dialog>
		<XrayLinksDialog name={user.name} links={xray} onClose={() => setXray(null)}/>
	</>;
}
