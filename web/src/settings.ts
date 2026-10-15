import {createContext, useContext} from "react";
import type {Settings} from "./api.ts";

// The panel settings, loaded once after login. Pages read show_links_once and the default device limit from here; the subscriptions page replaces them when it saves.
export const SettingsContext = createContext<{settings: Settings | null, set: (settings: Settings) => void}>({settings: null, set: () => {}});
export const useSettings = () => useContext(SettingsContext).settings;
