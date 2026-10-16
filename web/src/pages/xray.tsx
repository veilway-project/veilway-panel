import {Banner, Button, Dialog, Glass, Icon, IconButton, NumberField, TextField, useToast} from "@veilway/ui";
import {useState} from "react";
import {api, type XrayLink} from "../api.ts";
import {Copyable, ErrorNote, Mark, Qr, useGuard, useP} from "../kit.tsx";

const PROTOCOLS = ["vless", "trojan", "shadowsocks"] as const;
export type XrayState = {installed: boolean, release?: string | null, inbounds: {tag: string, managed: boolean}[]};

// The add-on itself: whether the node has it, and the one way to add an inbound to it.
export function XraySheet({xray, onAdd}: {xray: XrayState, onAdd: () => void}) {
	const {t, number} = useP(), made = xray.inbounds.filter(inbound => inbound.managed).length;
	return <Glass className="p-panel">
		<div className="p-sheet-head">
			<div><h2 className="vw-h2">{t("xray.title")}</h2><p>{xray.installed ? t("xray.lead") : t("xray.missingBody")}</p></div>
			{xray.installed ? <Mark tone="success">{t("xray.installed")}</Mark> : <Mark tone="muted">{t("xray.missing")}</Mark>}
		</div>
		{xray.installed ? <>
			<dl className="p-kv">
				{xray.release && <><dt>{t("xray.release")}</dt><dd><span className="vw-code">{xray.release}</span></dd></>}
				<dt>{t("xray.credentials")}</dt><dd>{t("xray.credentialsBody")}</dd>
				<dt>{t("xray.made")}</dt><dd className="vw-num">{number(made)}</dd>
			</dl>
			<div><Button icon="plus" onClick={onAdd}>{t("xray.add")}</Button></div>
		</> : <span className="vw-code" dir="ltr">scripts/veilway.sh addon xray install</span>}
	</Glass>;
}

// The form sits beside the list. Review shows what applying does before the node is asked, since Xray inbounds go to the node in one step.
export function XrayForm({onClose, onDone}: {onClose: () => void, onDone: () => void}) {
	const {t, number} = useP(), guard = useGuard(), toast = useToast();
	const [protocol, setProtocol] = useState<string>("vless"), [tag, setTag] = useState(""), [port, setPort] = useState<number | "">(443), [cert, setCert] = useState(""), [key, setKey] = useState(""), [host, setHost] = useState(""), [decoy, setDecoy] = useState("");
	const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null), [review, setReview] = useState(false), tls = protocol !== "shadowsocks";
	const create = async () => {
		setBusy(true);
		setError(null);
		try {
			await guard(() => api("post", "/xray/inbounds", {body: {tag: tag.trim(), protocol, port: port === "" ? 0 : port, cert: tls ? cert.trim() : null, key: tls ? key.trim() : null, host: host.trim() || null, decoy: tls ? decoy.trim() || null : null}}));
			toast({tone: "success", title: t("xray.created", {tag: tag.trim()})});
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
			<div><h2 className="vw-h2" id="xray-form-title">{t("xray.add")}</h2><p>{t("xray.addBody")}</p></div>
			<IconButton icon="close" label={t("xray.closeForm")} onClick={onClose}/>
		</div>
		<form className="p-stack" onSubmit={event => { event.preventDefault(); setError(null); setReview(true); }}>
			<fieldset className="p-choices">
				<legend className="vw-label">{t("xray.protocol")}</legend>
				{PROTOCOLS.map(value => <label key={value} className="p-choice"><input type="radio" name="xray-protocol" value={value} checked={protocol === value} onChange={() => setProtocol(value)}/><span className="p-choice-head">{t(`xray.name.${value}`)}{protocol === value && <Icon name="check"/>}</span><span>{t(`xray.protocol.${value}`)}</span></label>)}
			</fieldset>
			<div className="p-pair">
				<TextField label={t("config.col.tag")} hint={t("xray.tagHint")} value={tag} onChange={value => setTag(value.toLowerCase())} technical required/>
				<NumberField label={t("xray.port")} hint={t("xray.portHint")} unit="TCP" min={1} max={65535} value={port} onChange={setPort}/>
			</div>
			{tls && <TextField label={t("xray.cert")} hint={t("xray.certHint")} placeholder="/etc/ssl/node/fullchain.pem" value={cert} onChange={setCert} technical required/>}
			{tls && <TextField label={t("xray.key")} placeholder="/etc/ssl/node/privkey.pem" value={key} onChange={setKey} technical required/>}
			<TextField label={t("xray.host")} hint={t("xray.hostHint")} value={host} onChange={setHost} technical optional/>
			{tls && <TextField label={t("xray.decoy")} hint={t("xray.decoyHint")} placeholder="http://127.0.0.1:8080" value={decoy} onChange={setDecoy} technical optional/>}
			<Banner tone="warning" title={t("xray.sharedTitle")}>{t("xray.sharedBody")}</Banner>
			{!review && <ErrorNote error={error}/>}
			<div className="p-form-foot"><Button variant="quiet" onClick={onClose}>{t("action.cancel")}</Button><Button type="submit" variant="primary" disabled={!tag.trim() || port === "" || (tls && (!cert.trim() || !key.trim()))}>{t("xray.review")}</Button></div>
		</form>
		<Dialog open={review} onOpenChange={setReview} title={t("review.title")} description={t("xray.reviewBody")}>
			<div className="p-stack">
				<ul className="p-changes">
					<li><Mark tone="success">{t("review.added")}</Mark><span>{t("xray.reviewInbound", {protocol: t(`xray.name.${protocol as "vless"}`), port: port === "" ? "" : number(port, {useGrouping: false})})}</span><span className="vw-code">{tag.trim()}</span></li>
					<li><Mark tone="info">{t("review.changed")}</Mark><span>{t("xray.reviewUsers")}</span></li>
					<li><Mark tone="warning">{t("review.changed")}</Mark><span>{t("xray.reviewCap")}</span></li>
				</ul>
				<ErrorNote error={error}/>
				<div className="vw-dialog-foot"><Button onClick={() => setReview(false)}>{t("action.cancel")}</Button><Button variant="primary" disabled={busy} onClick={() => void create()}>{t("review.apply")}</Button></div>
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
