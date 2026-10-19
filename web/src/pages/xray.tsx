import {Banner, Button, Dialog, Glass, Icon, IconButton, NumberField, Switch, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type XrayInbound, type XrayLink} from "../api.ts";
import {Copyable, ErrorNote, Mark, Qr, useGuard, useP} from "../kit.tsx";

const PROTOCOLS = ["vless", "trojan", "shadowsocks"] as const;
export type XrayState = {installed: boolean, release?: string | null, inbounds: ({tag: string, managed: boolean} & Partial<XrayInbound>)[]};

// The address part of a listen value, "0.0.0.0:8443" or "[::]:8443". Every address is shown as empty, as create leaves it out.
const listenAddress = (listen: string) => { const address = listen.slice(0, listen.lastIndexOf(":")).replace(/^\[|\]$/g, ""); return address === "0.0.0.0" ? "" : address; };

// The add-on itself: whether the node has it, the inbounds the panel made with their edit action, and the one way to add an inbound. Editing replaces the sheet with the form, in the same place.
export function XraySheet({xray, onAdd, onChanged}: {xray: XrayState, onAdd: () => void, onChanged?: () => void}) {
	const {t, number} = useP(), made = xray.inbounds.filter(inbound => inbound.managed), [editing, setEditing] = useState<XrayInbound | null>(null);
	if (editing) return <XrayForm inbound={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); if (onChanged) onChanged(); else location.reload(); }}/>;
	return <Glass className="p-panel">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2">{t("xray.title")}</h2><p>{xray.installed ? t("xray.lead") : t("xray.missingBody")}</p></div>
			{xray.installed ? <Mark tone="success">{t("xray.installed")}</Mark> : <Mark tone="muted">{t("xray.missing")}</Mark>}
		</div>
		{xray.installed ? <>
			<dl className="p-kv">
				{xray.release && <><dt>{t("xray.release")}</dt><dd><span className="vw-code">{xray.release}</span></dd></>}
				<dt>{t("xray.credentials")}</dt><dd>{t("xray.credentialsBody")}</dd>
				<dt>{t("xray.made")}</dt><dd className="vw-num">{number(made.length)}</dd>
			</dl>
			{made.length > 0 && <ul className="p-row-list" aria-label={t("xray.made")}>{made.map(inbound => <li key={inbound.tag}>
				<span className="vw-code">{inbound.tag}</span>
				<span className="vw-muted vw-small">{t(`xray.name.${PROTOCOLS.includes(inbound.protocol as "vless") ? inbound.protocol as "vless" : "vless"}`)} <span className="vw-code" dir="ltr">{inbound.port}</span></span>
				<Button size="sm" variant="quiet" aria-label={t("xray.editName", {tag: inbound.tag})} disabled={inbound.port === undefined} onClick={() => setEditing(inbound as XrayInbound)}>{t("user.edit")}</Button>
			</li>)}</ul>}
			<div><Button icon="plus" onClick={onAdd}>{t("xray.add")}</Button></div>
		</> : <span className="vw-code" dir="ltr">sudo bash veilway.sh addon xray install</span>}
	</Glass>;
}

// The form sits beside the list, to add an inbound or, given one, to change it. Review shows what applying does before the node is asked, since Xray inbounds go to the node in one step.
export function XrayForm({inbound, onClose, onDone}: {inbound?: XrayInbound, onClose: () => void, onDone: () => void}) {
	const {t, number} = useP(), guard = useGuard(), toast = useToast();
	const [protocol, setProtocol] = useState<string>(inbound?.protocol ?? "vless"), [tag, setTag] = useState(inbound?.tag ?? ""), [port, setPort] = useState<number | "">(inbound?.port ?? 443), [listen, setListen] = useState(inbound ? listenAddress(inbound.listen) : ""), [cert, setCert] = useState(inbound?.cert ?? ""), [key, setKey] = useState(inbound?.key ?? ""), [host, setHost] = useState(inbound?.own_host ?? ""), [decoy, setDecoy] = useState(inbound?.decoy ?? ""), [newKey, setNewKey] = useState(false);
	const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [review, setReview] = useState(false), tls = protocol !== "shadowsocks";
	const linksChange = !!inbound && (port !== inbound.port || host.trim() !== inbound.own_host || newKey);
	const body = {port: port === "" ? 0 : port, listen: listen.trim() || null, cert: tls ? cert.trim() : null, key: tls ? key.trim() : null, host: host.trim() || null, decoy: tls ? decoy.trim() || null : null};
	const apply = async () => {
		setBusy(true);
		setError(null);
		try {
			await guard(() => inbound ? api("patch", "/xray/inbounds/{tag}", {params: {tag: inbound.tag}, body: {...body, new_server_key: newKey}}) : api("post", "/xray/inbounds", {body: {...body, tag: tag.trim(), protocol}}));
			toast({tone: "success", title: t(inbound ? "xray.edited" : "xray.created", {tag: tag.trim()})});
			setReview(false);
			onDone();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <Glass className="p-panel" aria-labelledby="xray-form-title">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2" id="xray-form-title">{inbound ? t("xray.editTitle", {tag: inbound.tag}) : t("xray.add")}</h2><p>{inbound ? t("xray.editBody") : t("xray.addBody")}</p></div>
			<IconButton icon="close" label={t("xray.closeForm")} onClick={onClose}/>
		</div>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); setError(null); setReview(true); }}>
			{inbound ? <dl className="p-kv"><dt>{t("xray.protocol")}</dt><dd>{t(`xray.name.${PROTOCOLS.includes(protocol as "vless") ? protocol as "vless" : "vless"}`)}</dd><dt>{t("config.col.tag")}</dt><dd><span className="vw-code">{inbound.tag}</span></dd></dl> : <fieldset className="p-choices">
				<legend className="vw-label">{t("xray.protocol")}</legend>
				{PROTOCOLS.map(value => <label key={value} className="p-choice"><input type="radio" name="xray-protocol" value={value} checked={protocol === value} onChange={() => setProtocol(value)}/><span className="p-choice-head">{t(`xray.name.${value}`)}{protocol === value && <Icon name="check"/>}</span><span>{t(`xray.protocol.${value}`)}</span></label>)}
			</fieldset>}
			<div className="p-pair">
				{!inbound && <TextField label={t("config.col.tag")} hint={t("xray.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} technical required/>}
				<NumberField label={t("xray.port")} hint={t("xray.portHint")} unit={tls ? "TCP" : "TCP+UDP"} min={1} max={65535} value={port} onChange={setPort}/>
				<TextField label={t("xray.listen")} hint={t("xray.listenHint")} placeholder="0.0.0.0" value={listen} onChange={setListen} technical optional/>
			</div>
			{tls && <TextField label={t("xray.cert")} hint={t("xray.certHint")} placeholder="/etc/ssl/node/fullchain.pem" value={cert} onChange={setCert} technical required/>}
			{tls && <TextField label={t("xray.key")} placeholder="/etc/ssl/node/privkey.pem" value={key} onChange={setKey} technical required/>}
			<TextField label={t("xray.host")} hint={t("xray.hostHint")} value={host} onChange={setHost} technical optional/>
			{tls && <TextField label={t("xray.decoy")} hint={t(inbound ? "xray.decoyEditHint" : "xray.decoyHint")} placeholder="http://127.0.0.1:8080" value={decoy} onChange={setDecoy} technical optional/>}
			{inbound && !tls && <Switch label={t("xray.newKey")} hint={t("xray.newKeyHint")} checked={newKey} onChange={setNewKey}/>}
			{inbound ? <Banner tone={linksChange ? "warning" : "info"} title={t("xray.linksChangeTitle")}>{t("xray.linksChangeBody")}</Banner> : <Banner tone="warning" title={t("xray.sharedTitle")}>{t("xray.sharedBody")}</Banner>}
			{!review && <ErrorNote error={error}/>}
			<div className="p-form-foot"><Button variant="quiet" onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={!tag.trim() || port === "" || (tls && (!cert.trim() || !key.trim()))}>{t("xray.review")}</Button></div>
		</form>
		<Dialog open={review} onOpenChange={setReview} title={t("review.title")} description={t("xray.reviewBody")}>
			<div className="p-stack">
				<ul className="p-changes">
					<li><Mark tone={inbound ? "info" : "success"}>{t(inbound ? "review.changed" : "review.added")}</Mark><span>{t("xray.reviewInbound", {protocol: t(`xray.name.${protocol as "vless"}`), port: port === "" ? "" : number(port, {useGrouping: false})})}</span><span className="vw-code">{tag.trim()}</span></li>
					<li><Mark tone="info">{t(inbound ? "review.kept" : "review.changed")}</Mark><span>{t(inbound ? "xray.reviewKept" : "xray.reviewUsers")}</span></li>
					{inbound ? linksChange && <li><Mark tone={newKey ? "danger" : "warning"}>{t("review.changed")}</Mark><span>{t(newKey ? "xray.reviewNewKey" : "xray.reviewLinks")}</span></li> : <li><Mark tone="warning">{t("review.changed")}</Mark><span>{t("xray.reviewCap")}</span></li>}
				</ul>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setReview(false)}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => void apply()}>{t("review.apply")}</Button></div>
			</div>
		</Dialog>
	</Glass>;
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
