import {Button, SecretField, TextField} from "@veilway/ui";
import {useState} from "react";
import {api, session, type Totp} from "../api.ts";
import {ErrorNote, TotpShown, useP} from "../kit.tsx";

export const USERNAME = /^[a-z0-9._-]{3,32}$/;

export function Setup({onDone}: {onDone: () => void}) {
	const {t} = useP(), [token, setToken] = useState(""), [username, setUsername] = useState(""), [password, setPassword] = useState(""), [again, setAgain] = useState("");
	const [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [totp, setTotp] = useState<Totp | null>(null), [tried, setTried] = useState(false);
	const problems = {username: USERNAME.test(username) ? undefined : t("error.username"), password: password.length >= 12 && password.length <= 256 ? undefined : t("error.password"), again: again === password ? undefined : t("error.passwordMatch")};
	const submit = async () => {
		setTried(true);
		if (problems.username || problems.password || problems.again) return;
		setBusy(true);
		setError(null);
		try {
			setTotp(await api("post", "/setup", {body: {token: token.trim(), username, password}}));
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	if (totp) return <TotpShown totp={totp} done={t("totp.done")} onDone={onDone}/>;
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }} noValidate>
		<div><h1 className="vw-h1">{t("setup.title")}</h1><p className="vw-muted">{t("setup.lead")}</p></div>
		<SecretField label={t("setup.token")} value={token} onChange={setToken} required/>
		<TextField label={t("setup.username")} autoComplete="username" value={username} onChange={value => setUsername(value.toLowerCase())} error={tried ? problems.username : undefined} technical required/>
		<TextField label={t("setup.password")} type="password" autoComplete="new-password" hint={t("setup.passwordHint")} value={password} onChange={setPassword} error={tried ? problems.password : undefined} required/>
		<TextField label={t("setup.confirm")} type="password" autoComplete="new-password" value={again} onChange={setAgain} error={tried ? problems.again : undefined} required/>
		<ErrorNote error={error}/>
		<div><Button type="submit" variant="primary" disabled={busy}>{t("setup.submit")}</Button></div>
	</form>;
}

export function Login({onDone}: {onDone: (username: string) => void}) {
	const {t} = useP(), [username, setUsername] = useState(""), [password, setPassword] = useState(""), [code, setCode] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			const answer = await api("post", "/login", {body: {username: username.trim(), password, totp: code.replace(/\s/g, "")}});
			session.set(answer.csrf);
			onDone(answer.username);
		} catch (failure) {
			setError(failure);
			setCode("");
		} finally {
			setBusy(false);
		}
	};
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }}>
		<div><h1 className="vw-h1">{t("login.title")}</h1><p className="vw-muted">{t("login.lead")}</p></div>
		<TextField label={t("login.username")} autoComplete="username" value={username} onChange={setUsername} technical required autoFocus/>
		<TextField label={t("login.password")} type="password" autoComplete="current-password" value={password} onChange={setPassword} required/>
		<TextField label={t("login.code")} hint={t("login.codeHint")} inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={code} onChange={setCode} technical required/>
		<ErrorNote error={error}/>
		<div><Button type="submit" variant="primary" disabled={busy}>{t("login.submit")}</Button></div>
	</form>;
}
