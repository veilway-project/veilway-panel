import react from "@vitejs/plugin-react";
import {defineConfig} from "vite";

// The design system is linked from ../../veilway-ui, so React must resolve to one copy. The server's CSP allows no data: fonts or scripts, so nothing is inlined, and asset paths are relative because the operator picks the panel's path prefix.
export default defineConfig({
	base: "./",
	plugins: [react()],
	resolve: {dedupe: ["react", "react-dom"]},
	server: {port: 5174, strictPort: true, fs: {allow: ["..", "../../veilway-ui"]}},
	build: {outDir: "dist", emptyOutDir: false, target: "es2022", assetsInlineLimit: 0}
});
