import {Button, SecretField, TextField} from "@veilway/ui";
import {useState} from "react";
import {api, flags, session, type Totp} from "../api.ts";
import {ErrorNote, TotpShown, useGuard, useP} from "../kit.tsx";

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
			const made = await api("post", "/setup", {body: {token: token.trim(), username, password}});
			if (made.totp_secret) setTotp(made); else onDone();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	if (totp) return <TotpShown totp={totp} done={t("totp.done")} onDone={onDone}/>;
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }} noValidate>
		<div><h1 className="vw-h1">{t("setup.title")}</h1><p className="vw-muted">{t("setup.lead")}</p></div>
		{!flags.twoStep && <p className="vw-small p-danger-note" role="alert">{t("twostep.note")}</p>}
		<SecretField label={t("setup.token")} value={token} onChange={setToken} required/>
		<TextField label={t("setup.username")} autoComplete="username" value={username} onChange={value => setUsername(value.toLowerCase())} error={tried ? problems.username : undefined} technical required/>
		<TextField label={t("setup.password")} type="password" autoComplete="new-password" hint={t("setup.passwordHint")} value={password} onChange={setPassword} error={tried ? problems.password : undefined} required/>
		<TextField label={t("setup.confirm")} type="password" autoComplete="new-password" value={again} onChange={setAgain} error={tried ? problems.again : undefined} required/>
		<ErrorNote error={error}/>
		<div><Button type="submit" variant="primary" disabled={busy}>{t("setup.submit")}</Button></div>
	</form>;
}

export function Login({onDone}: {onDone: (username: string, step: "enroll" | "password" | null) => void}) {
	const {t} = useP(), [username, setUsername] = useState(""), [password, setPassword] = useState(""), [code, setCode] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false);
	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			const answer = await api("post", "/login", {body: {username: username.trim(), password, totp: flags.twoStep ? code.replace(/\s/g, "") : ""}});
			session.set(answer.csrf);
			onDone(answer.username, answer.enroll_required ? "enroll" : answer.password_change_required ? "password" : null);
		} catch (failure) {
			setError(failure);
			setCode("");
		} finally {
			setBusy(false);
		}
	};
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }}>
		{/* The code is not required here: an account made while two-step was off has none to type, and the server decides. */}
		<div><h1 className="vw-h1">{t("login.title")}</h1><p className="vw-muted">{t(flags.twoStep ? "login.lead" : "twostep.lead")}</p></div>
		{!flags.twoStep && <p className="vw-small p-danger-note" role="alert">{t("twostep.note")}</p>}
		<TextField label={t("login.username")} autoComplete="username" value={username} onChange={setUsername} technical required autoFocus/>
		<TextField label={t("login.password")} type="password" autoComplete="current-password" value={password} onChange={setPassword} required/>
		{flags.twoStep && <TextField label={t("login.code")} hint={t("login.codeHint")} inputMode="numeric" autoComplete="one-time-code" maxLength={8} value={code} onChange={setCode} technical/>}
		<ErrorNote error={error}/>
		<div><Button type="submit" variant="primary" disabled={busy}>{t("login.submit")}</Button></div>
	</form>;
}

// The forced step after two-step sign-in was turned back on for an account made while it was off: the server refuses every other call until this is done.
export function Enroll({onDone, onLogout}: {onDone: () => void, onLogout: () => void}) {
	const {t} = useP(), [password, setPassword] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [totp, setTotp] = useState<Totp | null>(null);
	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			setTotp(await api("post", "/account/enroll", {body: {password}}));
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	if (totp) return <TotpShown totp={totp} done={t("totp.doneAccount")} onDone={onDone}/>;
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }}>
		<div><h1 className="vw-h1">{t("enroll.title")}</h1><p className="vw-muted">{t("enroll.lead")}</p></div>
		<TextField label={t("login.password")} type="password" autoComplete="current-password" value={password} onChange={setPassword} required autoFocus/>
		<ErrorNote error={error}/>
		<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy}>{t("enroll.submit")}</Button><Button onClick={onLogout}>{t("account.logout")}</Button></div>
	</form>;
}

// The forced step for a password shorter than the rule, found at sign-in while two-step is off. The server refuses every other call until it is changed.
export function ChangePassword({onDone, onLogout}: {onDone: () => void, onLogout: () => void}) {
	const {t} = useP(), guard = useGuard(), [password, setPassword] = useState(""), [again, setAgain] = useState(""), [error, setError] = useState<unknown>(null), [busy, setBusy] = useState(false), [tried, setTried] = useState(false);
	const problems = {password: password.length >= 12 && password.length <= 256 ? undefined : t("error.password"), again: again === password ? undefined : t("error.passwordMatch")};
	const submit = async () => {
		setTried(true);
		if (problems.password || problems.again) return;
		setBusy(true);
		setError(null);
		try {
			await guard(() => api("post", "/account/password", {body: {new_password: password}}));
			onDone();
		} catch (failure) {
			setError(failure);
		} finally {
			setBusy(false);
		}
	};
	return <form className="p-stack" onSubmit={event => { event.preventDefault(); void submit(); }} noValidate>
		<div><h1 className="vw-h1">{t("change.title")}</h1><p className="vw-muted">{t("change.lead")}</p></div>
		<TextField label={t("setup.password")} type="password" autoComplete="new-password" hint={t("setup.passwordHint")} value={password} onChange={setPassword} error={tried ? problems.password : undefined} required autoFocus/>
		<TextField label={t("setup.confirm")} type="password" autoComplete="new-password" value={again} onChange={setAgain} error={tried ? problems.again : undefined} required/>
		<ErrorNote error={error}/>
		<div className="p-cluster"><Button type="submit" variant="primary" disabled={busy}>{t("change.submit")}</Button><Button onClick={onLogout}>{t("account.logout")}</Button></div>
	</form>;
}
