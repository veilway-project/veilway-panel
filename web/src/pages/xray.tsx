import {Banner, Button, DataTable, Dialog, Glass, NumberField, SelectField, StateBlock, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type XrayLink} from "../api.ts";
import {Copyable, ErrorNote, Mark, Qr, useGuard, useLoad, useP, useSay} from "../kit.tsx";

const PROTOCOLS = ["vless", "trojan", "shadowsocks"] as const;

// Xray inbounds live in the node's config like the others, but the panel makes them so that it holds every user's credential and can hand out links.
export function XrayTab() {
	const {t} = useP(), say = useSay(), guard = useGuard(), toast = useToast(), xray = useLoad(() => api("get", "/xray"), []);
	const [adding, setAdding] = useState(false), [protocol, setProtocol] = useState<string>("vless"), [tag, setTag] = useState(""), [port, setPort] = useState<number | "">(443), [cert, setCert] = useState(""), [key, setKey] = useState(""), [host, setHost] = useState("");
	const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null);
	if (xray.error && !xray.data) return <StateBlock kind="error" title={t("common.loadFailed")} action={<Button icon="refresh" onClick={xray.reload}>{t("action.retry")}</Button>}>{say(xray.error)}</StateBlock>;
	if (!xray.data) return <StateBlock kind="loading" title={t("common.loading")}/>;
	const {installed, release, inbounds} = xray.data, tls = protocol !== "shadowsocks";
	if (!installed) return <StateBlock kind="empty" title={t("xray.missing")}>{t("xray.missingBody")} <span className="vw-code" dir="ltr">scripts/veilway.sh addon xray install</span></StateBlock>;
	const run = async (work: () => Promise<unknown>, done: string) => {
		setBusy(true);
		setError(null);
		try {
			await guard(work);
			toast({tone: "success", title: done});
			setAdding(false);
			xray.reload();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	const create = () => run(() => api("post", "/xray/inbounds", {body: {tag: tag.trim(), protocol, port: port === "" ? 0 : port, cert: tls ? cert.trim() : null, key: tls ? key.trim() : null, host: host.trim() || null}}), t("xray.created", {tag: tag.trim()}));
	return <div className="p-stack">
		<div className="p-row"><p className="vw-muted p-lead">{t("xray.lead", {release: release ?? ""})}</p><Button size="sm" icon="plus" onClick={() => { setError(null); setAdding(true); }}>{t("xray.add")}</Button></div>
		{!adding && <ErrorNote error={error}/>}
		<Glass className="p-pad p-stack">
			<DataTable caption={t("node.tab.xray")} rows={inbounds} rowKey={row => row.tag} empty={<StateBlock kind="empty" title={t("xray.empty")}>{t("xray.emptyBody")}</StateBlock>} columns={[
				{id: "tag", header: t("config.col.tag"), cell: row => <span className="p-user"><span className="vw-code">{row.tag}</span><span className="vw-muted vw-small">{row.protocol}</span></span>},
				{id: "listen", header: t("xray.col.listen"), cell: row => <span className="vw-code" dir="ltr">{row.host ? `${row.host}:${row.port}` : row.listen}</span>},
				{id: "security", header: t("xray.col.security"), cell: row => row.certificate_missing ? <Mark tone="warning">{t("xray.noCertificate")}</Mark> : <span>{row.security === "tls" ? "TLS" : t("xray.ownEncryption")}</span>},
				{id: "clients", header: t("xray.col.clients"), cell: row => row.managed ? String(row.clients) : <Mark tone="warning" title={t("xray.unmanagedHint")}>{t("xray.unmanaged")}</Mark>},
				{id: "remove", header: "", align: "end", cell: row => <div className="p-cluster p-end"><Button size="sm" variant="quiet" disabled={busy} aria-label={t("config.removeName", {name: row.tag})} onClick={() => void run(() => api("delete", "/xray/inbounds/{tag}", {params: {tag: row.tag}}), t("xray.removed", {tag: row.tag}))}>{t("common.remove")}</Button></div>}
			]}/>
		</Glass>
		<Dialog open={adding} onOpenChange={open => { if (!open) setAdding(false); }} title={t("xray.add")} description={t("xray.addBody")}>
			<form className="p-stack" onSubmit={event => { event.preventDefault(); void create(); }}>
				<SelectField label={t("xray.protocol")} value={protocol} onChange={setProtocol} options={PROTOCOLS.map(value => ({value, label: value, detail: t(`xray.protocol.${value}`)}))}/>
				<TextField label={t("config.col.tag")} hint={t("config.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} technical required autoFocus/>
				<NumberField label={t("xray.port")} unit="TCP" min={1} max={65535} value={port} onChange={setPort}/>
				{tls && <TextField label={t("xray.cert")} hint={t("xray.certHint")} placeholder="/etc/ssl/node/fullchain.pem" value={cert} onChange={setCert} technical required/>}
				{tls && <TextField label={t("xray.key")} placeholder="/etc/ssl/node/privkey.pem" value={key} onChange={setKey} technical required/>}
				<TextField label={t("xray.host")} hint={t("xray.hostHint")} value={host} onChange={setHost} technical optional/>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setAdding(false)}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={busy || !tag.trim() || port === ""}>{t("xray.create")}</Button></div>
			</form>
		</Dialog>
	</div>;
}

export function XrayLinksDialog({name, links, onClose}: {name: string, links: XrayLink[] | null, onClose: () => void}) {
	const {t} = useP();
	return <Dialog open={links !== null} onOpenChange={open => { if (!open) onClose(); }} title={t("xray.linksTitle", {name})} description={t("xray.linksBody")}>
		{links && (links.length === 0 ? <Banner tone="info" title={t("xray.noLinks")}/> : <div className="p-stack">{links.map(link => <div key={link.tag} className="p-stack">
			<h3 className="vw-h3"><span className="vw-code">{link.tag}</span> <span className="vw-muted vw-small">{link.protocol}</span></h3>
			<Qr svg={link.qr_svg} label={t("link.qr")}/>
			<Copyable label={t("xray.link")} value={link.link}/>
		</div>)}</div>)}
	</Dialog>;
}
