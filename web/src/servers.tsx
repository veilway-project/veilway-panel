import {SelectField} from "@veilway/ui";
import {createContext, useContext} from "react";
import type {NodeRow} from "./api.ts";
import {useP} from "./kit.tsx";

type Servers = {nodes: NodeRow[], selected: number, select: (id: number) => void, reload: () => void};

// The servers this panel manages and the one the settings pages edit now. Server 1 is the panel's own; a panel with only that one has nothing to choose.
export const ServersContext = createContext<Servers>({nodes: [], selected: 1, select: () => {}, reload: () => {}});
export const useServers = () => useContext(ServersContext);
// A remote server is offline while the link that reaches it is not up. Server 1 is always the panel's own socket.
export const offline = (node: NodeRow) => node.id !== 1 && node.link_state !== "up";

// disabled keeps the choice in view while a flow that belongs to one server is open.
export function ServerPicker({disabled}: {disabled?: boolean}) {
	const {t} = useP(), {nodes, selected, select} = useServers();
	if (nodes.length < 2) return null;
	return <div className="p-server-pick"><SelectField label={t("servers.pick")} hint={t("servers.pickHint")} value={String(selected)} onChange={value => select(Number(value))} disabled={disabled} options={nodes.map(node => ({value: String(node.id), label: (node.id === 1 ? t("servers.this") : node.name) + (offline(node) ? " (" + t("servers.offline") + ")" : "")}))}/></div>;
}
