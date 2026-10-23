import {Banner, SecretField, Segmented, SelectField, Switch, TextField} from "@veilway/ui";
import {useState} from "react";
import {useP} from "../kit.tsx";
import type {PanelKey} from "../locales/en.ts";

type Item = Record<string, unknown>;
export const XRAY_NAMES: Record<string, string> = {vless: "VLESS", vmess: "VMess", trojan: "Trojan", shadowsocks: "Shadowsocks"};
const TRANSPORTS = ["tcp", "ws", "grpc", "httpupgrade", "xhttp"], XHTTP_MODES = ["auto", "packet-up", "stream-up", "stream-one"], FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "randomized"];
const VMESS_CIPHERS = ["auto", "aes-128-gcm", "chacha20-poly1305"], SHADOWSOCKS_CIPHERS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];
const marker = (text: string) => text.startsWith("<redacted");
const str = (value: unknown) => typeof value === "string" ? value : "";
const compact = (item: Item) => Object.fromEntries(Object.entries(item).filter(([, value]) => value !== undefined && value !== ""));

// The refusal codes of the node's link reader, in the reader's words. A node answers with the code inside its own English sentence.
export const refusalKey = (message: string): PanelKey | null => { const code = message.match(/profile_refused\.([a-z]+)/)?.[1]; return code ? `xo.refused.${code}` as PanelKey : null; };

// What the node would refuse in the fields as typed, keyed by the field. The node stays the authority; this says it before the review. Mirrors the xray arm of the node's config validation.
export function xrayProblems(draft: Item, link: boolean): Record<string, PanelKey> {
	const found: Record<string, PanelKey> = {};
	if (link) { if (!/^(vless|vmess|trojan|ss):\/\/\S+$/i.test(str(draft.link))) found.link = "xo.err.link"; return found; }
	const protocol = str(draft.protocol), server = str(draft.server), tr = (draft.transport ?? {}) as Item, sec = (draft.security ?? {}) as Item, kind = str(sec.type) || "none", stream = str(tr.type) || "tcp", cipher = str(draft.cipher);
	const usesId = protocol === "vless" || protocol === "vmess", secret = str(usesId ? draft.id : draft.password), secured = kind === "tls" || kind === "reality";
	if (!/^(\[[0-9a-f:.]+\]|[^\s:/[\]]+):\d{1,5}$/i.test(server) || Number(server.slice(server.lastIndexOf(":") + 1)) > 65535 || Number(server.slice(server.lastIndexOf(":") + 1)) < 1) found.server = "xo.err.server";
	if (!secret) found[usesId ? "id" : "password"] = usesId ? "xo.err.needId" : "xo.err.needPassword";
	else if (!marker(secret) && usesId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(secret)) found.id = "xo.err.uuid";
	if (protocol === "shadowsocks") {
		if (!cipher) found.cipher = "xo.err.needMethod";
		else if (!cipher.startsWith("2022-") && !marker(secret) && secret && secret.length < 16) found.password = "xo.err.ssShort";
	}
	if ((protocol === "vless" || protocol === "trojan") && !secured) found.security = "xo.err.needSecurity";
	if (draft.flow && !(stream === "tcp" && secured)) found.flow = "xo.err.flow";
	if (stream === "ws" || stream === "httpupgrade" || stream === "xhttp") {
		const path = str(tr.path);
		if (path.includes("?")) found.path = "xo.err.pathQuery";
		else if (path && !/^\/[A-Za-z0-9\-._~!$&()*+,;=:@/%]{0,255}$/.test(path)) found.path = "xo.err.path";
		if (kind === "reality" && stream !== "xhttp") found.transport = "xo.err.realityTransport";
	}
	if (kind === "tls" && !str(sec.server_name) && /^(\d{1,3}\.){3}\d{1,3}:|^\[/.test(server)) found.sni = "xo.err.sniAddress";
	if (kind === "reality") {
		if (!str(sec.server_name)) found.sni = "xo.err.sni";
		if (!/^[A-Za-z0-9_-]{43}$/.test(str(sec.public_key))) found.publicKey = "xo.err.publicKey";
		if (!/^([0-9a-f]{2}){0,8}$/.test(str(sec.short_id))) found.shortId = "xo.err.shortId";
	}
	return found;
}

// The fields of one of the outbounds of type xray, written into the draft of the outbound form: a pasted link, or the typed form the node keeps. Secrets arrive as the node's marker and go back as it, which keeps the saved one.
export function XrayOutboundFields({draft, setDraft, set, installed, problems, tried}: {draft: Item, setDraft: (item: Item) => void, set: (key: string, next: unknown) => void, installed: boolean, problems: Record<string, PanelKey>, tried: boolean}) {
	const {t} = useP(), [link, setLink] = useState(draft.protocol === undefined), protocol = str(draft.protocol), usesId = protocol === "vless" || protocol === "vmess";
	const tr = (draft.transport ?? {}) as Item, sec = (draft.security ?? {}) as Item, stream = str(tr.type) || "tcp", kind = str(sec.type) || "none", flowable = protocol === "vless" && stream === "tcp" && (kind === "tls" || kind === "reality");
	const why = (field: string) => tried && problems[field] ? t(problems[field]!) : undefined, fix = (value: string) => value.trim().toLowerCase();
	const setStream = (key: string, next: unknown) => set("transport", compact({...tr, type: stream, [key]: next}));
	const setSecurity = (key: string, next: unknown) => set("security", compact({...sec, type: kind, [key]: next}));
	const pick = (value: string) => { const copy: Item = {...draft, protocol: value}; delete copy.id; delete copy.password; delete copy.flow; delete copy.cipher; if (value === "shadowsocks") copy.cipher = "aes-256-gcm"; setDraft(copy); };
	return <>
		<Segmented label={t("xo.how")} value={link ? "link" : "typed"} onChange={value => { setLink(value === "link"); setDraft(compact({type: "xray", tag: draft.tag, ...(value === "typed" ? {protocol: "vless", server: ""} : {})})); }} options={[{value: "link", label: t("xo.how.link")}, {value: "typed", label: t("xo.how.typed")}]}/>
		{!installed && <Banner tone="warning" title={t("xo.missingTitle")}>{t("xo.missingBody")} <a href="#/inbounds">{t("xo.install")}</a></Banner>}
		{link ? <TextField label={t("xo.link")} hint={t("xo.linkHint")} placeholder="vless://" value={str(draft.link)} onChange={value => set("link", value.trim())} error={why("link")} technical/> : <>
			<div className="p-pair">
				<SelectField label={t("xo.protocol")} value={protocol} onChange={pick} options={Object.entries(XRAY_NAMES).map(([value, label]) => ({value, label}))}/>
				<TextField label={t("config.server")} hint={t("xo.serverHint")} placeholder="vpn.example.com:443" value={str(draft.server)} onChange={value => set("server", fix(value))} error={why("server")} technical/>
			</div>
			{usesId ? <SecretField label={t("xo.id")} hint={t("xo.secretHint")} value={str(draft.id)} onChange={value => set("id", value.trim())} error={why("id")}/> : <SecretField label={t("config.password")} hint={t("xo.secretHint")} value={str(draft.password)} onChange={value => set("password", value)} error={why("password")}/>}
			{protocol === "vmess" && <SelectField label={t("xo.cipher")} value={str(draft.cipher) || "auto"} onChange={value => set("cipher", value === "auto" ? undefined : value)} options={VMESS_CIPHERS.map(value => ({value, label: value}))}/>}
			{protocol === "shadowsocks" && <SelectField label={t("xo.method")} value={str(draft.cipher)} onChange={value => set("cipher", value)} error={why("cipher")} options={SHADOWSOCKS_CIPHERS.map(value => ({value, label: value}))}/>}
			<div className="p-pair">
				<SelectField label={t("xo.transport")} value={stream} onChange={value => set("transport", value === "tcp" ? undefined : {type: value})} error={why("transport")} options={TRANSPORTS.map(value => ({value, label: t(`xo.transport.${value}` as PanelKey)}))}/>
				<SelectField label={t("xo.security")} value={kind} onChange={value => set("security", value === "none" ? undefined : value === "tls" ? {type: "tls"} : {type: "reality", server_name: ""})} error={why("security")} options={["none", "tls", "reality"].map(value => ({value, label: t(`xo.security.${value}` as PanelKey)}))}/>
			</div>
			{(stream === "ws" || stream === "httpupgrade" || stream === "xhttp") && <div className="p-pair">
				<TextField label={t("xo.path")} hint={t("xo.pathHint")} placeholder="/" value={str(tr.path)} onChange={value => setStream("path", value.trim())} error={why("path")} technical optional/>
				<TextField label={t("xo.host")} hint={t("xo.hostHint")} value={str(tr.host)} onChange={value => setStream("host", fix(value))} technical optional/>
			</div>}
			{stream === "xhttp" && <SelectField label={t("xo.xhttpMode")} value={str(tr.mode) || "auto"} onChange={value => setStream("mode", value === "auto" ? undefined : value)} options={XHTTP_MODES.map(value => ({value, label: value}))}/>}
			{stream === "grpc" && <div className="p-pair">
				<TextField label={t("xo.service")} hint={t("xo.serviceHint")} value={str(tr.service)} onChange={value => setStream("service", value.trim())} technical optional/>
				<TextField label={t("xo.authority")} hint={t("xo.authorityHint")} value={str(tr.authority)} onChange={value => setStream("authority", fix(value))} technical optional/>
			</div>}
			{kind !== "none" && <div className="p-pair">
				<TextField label={t(kind === "reality" ? "xo.borrowed" : "xo.sni")} hint={t(kind === "reality" ? "xo.borrowedHint" : "xo.sniHint")} value={str(sec.server_name)} onChange={value => setSecurity("server_name", fix(value))} error={why("sni")} technical optional={kind === "tls"}/>
				<SelectField label={t("xo.fingerprint")} hint={t("xo.fingerprintHint")} value={str(sec.fingerprint) || "chrome"} onChange={value => setSecurity("fingerprint", value === "chrome" ? undefined : value)} options={FINGERPRINTS.map(value => ({value, label: value}))}/>
			</div>}
			{kind === "tls" && <SelectField label={t("xo.alpn")} hint={t("xo.alpnHint")} value={((sec.alpn ?? []) as string[]).join(",")} onChange={value => setSecurity("alpn", value ? value.split(",") : undefined)} options={[{value: "", label: t("xo.alpn.default")}, {value: "h2", label: "h2"}, {value: "http/1.1", label: "http/1.1"}, {value: "h2,http/1.1", label: "h2, http/1.1"}, {value: "http/1.1,h2", label: "http/1.1, h2"}]}/>}
			{kind === "reality" && <div className="p-pair">
				<TextField label={t("xo.publicKey")} value={str(sec.public_key)} onChange={value => setSecurity("public_key", value.trim())} error={why("publicKey")} technical/>
				<TextField label={t("xo.shortId")} hint={t("xo.shortIdHint")} value={str(sec.short_id)} onChange={value => setSecurity("short_id", fix(value))} error={why("shortId")} technical optional/>
			</div>}
			{protocol === "vless" && <SelectField label={t("xo.flow")} hint={t("xo.flowHint")} value={str(draft.flow) ? "vision" : "none"} onChange={value => set("flow", value === "vision" ? "xtls-rprx-vision" : undefined)} error={why("flow")} options={[{value: "none", label: t("xo.flow.none")}, ...(flowable || draft.flow ? [{value: "vision", label: "Vision"}] : [])]}/>}
			<Switch label={t("xo.allowPrivate")} hint={t("xo.allowPrivateHint")} checked={draft.allow_private === true} onChange={value => set("allow_private", value ? true : undefined)}/>
		</>}
		<Banner tone="warning" title={t("xo.trustTitle")}>{t("xo.trustBody")}</Banner>
		<p className="vw-muted vw-small">{t("xo.restart")}</p>
	</>;
}
