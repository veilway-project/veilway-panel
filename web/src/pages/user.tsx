import {Banner, Button, Checkbox, ConfirmDialog, Dialog, Glass, Icon, IconButton, List, ListRow, StateBlock, TextField, UsageBar, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type Device, type LinkView, type NodeState, type NodeUser, type XrayLink} from "../api.ts";
import {Copyable, ErrorNote, LinkDialog, NodeNote, PageHead, useGuard, useLoad, useP, useSay} from "../kit.tsx";
import {useSettings} from "../settings.ts";
import {useExpiry, UserForm} from "./users.tsx";
import {XrayLinksDialog} from "./xray.tsx";

export function UserPage({id}: {id: number}) {
	const {t, date, bytes, number} = useP(), toast = useToast(), say = useSay(), guard = useGuard(), expiry = useExpiry(), settings = useSettings();
	const page = useLoad(() => Promise.all([api("get", "/users/{id}", {params: {id}}), api("get", "/users/{id}/devices", {params: {id}}), api("get", "/users/{id}/subscription", {params: {id}})]), [id]);
	const [editing, setEditing] = useState(false), [dialog, setDialog] = useState<"delete" | "usage" | "link" | "device" | "xray" | null>(null), [removing, setRemoving] = useState<Device | null>(null);
	const [totals, setTotals] = useState(false), [removeOld, setRemoveOld] = useState(false), [deviceName, setDeviceName] = useState(""), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [linkError, setLinkError] = useState<unknown>(null);
	const [shown, setShown] = useState<{link: LinkView, once: boolean} | null>(null), [exported, setExported] = useState<{name: string, file: string, link?: string | null} | null>(null), [node, setNode] = useState<NodeState | null>(null), [xray, setXray] = useState<XrayLink[] | null>(null);
	if (page.error && !page.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={page.reload}>{t("action.retry")}</Button>}>{say(page.error)}</StateBlock>;
	if (!page.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const [user, {devices}, sub] = page.data, usage = user.node as NodeUser | null, current = devices.filter(d => d.token_gen === sub.token_generation);
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
	return <>
		<a className="p-back" href="#/users"><Icon name="chevronForward"/>{t("common.back")}</a>
		<PageHead title={user.name} lead={t(user.enabled ? "user.state.enabled" : "user.state.disabled") + (user.groups.length ? ". " + t("users.col.groups") + ": " + user.groups.join(", ") : "")}>
			<Button onClick={() => setEditing(true)}>{t("user.edit")}</Button>
			<Button variant="danger" onClick={() => open("delete")}>{t("user.delete")}</Button>
		</PageHead>
		<NodeNote node={node}/>
		<div className="p-columns">
			<Glass className="p-panel">
				<h2 className="vw-h2">{t("user.usage")}</h2>
				{usage?.used_bytes === undefined ? <p className="vw-muted">{t("users.usageUnknown")}</p> : <UsageBar label={t("user.usageLabel")} used={usage.used_bytes} total={user.quota_bytes ?? null}/>}
				<ul className="p-facts">
					{user.quota_period && <li>{t("user.period", {period: t(`user.period.${user.quota_period as "daily" | "weekly" | "monthly"}`)})}</li>}
					{usage?.period_start ? <li>{t("user.usageSince", {date: date(new Date(usage.period_start * 1000))})}</li> : null}
					{usage?.traffic && <li>{t("user.total", {amount: bytes((usage.traffic.up_bytes ?? 0) + (usage.traffic.down_bytes ?? 0)).text})}</li>}
					<li>{user.expires_at ? t("user.expires", {date: date(new Date(user.expires_at * 1000))}) + ". " + expiry(user.expires_at) : t("users.noExpiry")}</li>
				</ul>
				<div><Button icon="refresh" onClick={() => { setTotals(false); open("usage"); }}>{t("user.resetUsage")}</Button></div>
			</Glass>
			<Glass className="p-panel">
				<div><h2 className="vw-h2">{t("user.link")}</h2><p className="vw-muted">{t("user.linkLead", {name: user.name})}</p></div>
				<dl className="p-dl">
					<div><dt>{t("user.subId")}</dt><dd className="vw-code">{sub.subscription_id}</dd></div>
					<div><dt>{t("user.linkGen")}</dt><dd>{t("user.linkMade", {generation: number(sub.token_generation), date: date(new Date(sub.token_created * 1000))})}</dd></div>
					{sub.key_fingerprints.length > 0 && <div><dt>{t("user.keys")}</dt><dd>{sub.key_fingerprints.map(f => <span key={f} className="vw-code vw-small p-block">{f}</span>)}</dd></div>}
				</dl>
				{!sub.can_show && <p className="vw-muted vw-small">{t("user.noCopy")}</p>}
				<ErrorNote error={linkError}/>
				<div className="p-cluster">
					{sub.can_show && <Button variant="primary" icon="eye" onClick={async () => { setLinkError(null); try { setShown({link: await guard(() => api("post", "/users/{id}/subscription/show", {params: {id}})), once: false}); } catch (failure) { setLinkError(failure); } }}>{t("user.showLink")}</Button>}
					<Button onClick={() => { setRemoveOld(false); open("link"); }}>{t("user.resetLink")}</Button>
					<Button variant="quiet" icon="eye" onClick={async () => { setLinkError(null); try { setXray((await guard(() => api("get", "/users/{id}/xray", {params: {id}}))).links); } catch (failure) { setLinkError(failure); } }}>{t("xray.showLinks")}</Button>
					<Button variant="quiet" onClick={() => open("xray")}>{t("xray.rotate")}</Button>
				</div>
			</Glass>
		</div>
		<Glass className="p-panel">
			<div className="p-row">
				<div><h2 className="vw-h2">{t("user.devices")}</h2><p className="vw-muted">{user.device_limit ? t("user.devicesLead", {used: number(user.devices), limit: number(user.device_limit)}) : t("user.devicesLeadNoLimit", {used: number(user.devices)})}</p></div>
				<Button variant="quiet" icon="plus" onClick={() => { setDeviceName(""); open("device"); }}>{t("device.add")}</Button>
			</div>
			{devices.length === 0 ? <StateBlock kind="empty" title={t("user.noDevices")}>{t("user.noDevicesBody")}</StateBlock> : <List label={t("user.devices")}>{devices.map(d => <ListRow key={d.id} leading={<Icon name="device"/>} title={d.name} detail={<span className="p-meta">
				<span>{t(d.state === "pending" ? "device.pending" : "device.enrolled")}</span>
				<span className="vw-code">{d.address}</span>
				<span>{t(d.key_origin === "panel" ? "device.panelKey" : "device.ownKey")}</span>
				<span>{d.last_seen ? t("device.lastSeen", {date: date(new Date(d.last_seen * 1000))}) : t("device.neverSeen")}</span>
			</span>} trailing={<span className="p-cluster">
				{d.key_origin === "panel" && <IconButton icon="download" label={t("device.export", {name: d.name})} onClick={async () => { setError(null); try { setExported({name: d.name, ...await guard(() => api("post", "/users/{id}/devices/{did}/export", {params: {id, did: d.id}}))}); } catch (failure) { setError(failure); } }}/>}
				<IconButton icon="close" label={t("device.remove", {name: d.name})} onClick={() => setRemoving(d)}/>
			</span>}/>)}</List>}
			{!dialog && <ErrorNote error={error}/>}
		</Glass>
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
				if (answer.link) setShown({link: answer.link, once: settings?.show_links_once ?? !sub.can_show});
				if (answer.link_error) toast({tone: "warning", title: t("link.failed", {error: answer.link_error})});
			})}>{t("user.resetLinkConfirm")}</Button></div>
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
		<LinkDialog name={user.name} link={shown?.link ?? null} once={shown?.once ?? false} onClose={() => setShown(null)}/>
		<XrayLinksDialog name={user.name} links={xray} onClose={() => setXray(null)}/>
	</>;
}
