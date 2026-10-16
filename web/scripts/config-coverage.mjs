// Fails when a key of the node's config has no form in the web app and is not listed in config-coverage.txt as JSON only on purpose.
// A path counts as covered when one source file of the app names both its key and the key above it, which is a heuristic: it finds keys nobody wrote a form for, not forms that are wrong.
import {readFileSync, readdirSync} from "node:fs";
import {join} from "node:path";
const here = import.meta.dirname, schema = JSON.parse(readFileSync(join(here, "../../server/config.schema.json"), "utf8"));
const paths = new Set();
const walk = (node, path, seen) => {
	if (!node || typeof node !== "object") return;
	if (node.$ref) { const name = node.$ref.split("/").pop(); if (seen.includes(name)) return; return walk(schema.$defs[name], path, [...seen, name]); }
	for (const branch of [...(node.oneOf ?? []), ...(node.anyOf ?? []), ...(node.allOf ?? [])]) walk(branch, path, seen);
	if (node.items) walk(node.items, path + "[]", seen);
	for (const [key, child] of Object.entries(node.properties ?? {})) { const next = path ? path + "." + key : key; paths.add(next); walk(child, next, seen); }
};
walk(schema, "", []);
const files = (dir) => readdirSync(dir, {withFileTypes: true}).flatMap(entry => entry.isDirectory() ? (entry.name === "locales" ? [] : files(join(dir, entry.name))) : entry.name.endsWith(".tsx") || entry.name === "check.ts" ? [readFileSync(join(dir, entry.name), "utf8")] : []);
const sources = files(join(here, "../src"));
const keys = path => path.replace(/\[\]/g, "").split(".");
const named = (text, key) => new RegExp("\\b" + key + "\\b").test(text);
const covered = path => { const parts = keys(path), leaf = parts.at(-1), parent = parts.at(-2) ?? leaf; return sources.some(text => named(text, leaf) && named(text, parent)); };
const allowed = readFileSync(join(here, "config-coverage.txt"), "utf8").split("\n").map(line => line.replace(/#.*/, "").trim()).filter(Boolean);
const listed = path => allowed.some(entry => path === entry || path.startsWith(entry + ".") || path.startsWith(entry + "[]"));
const missing = [...paths].filter(path => !covered(path) && !listed(path)), stale = allowed.filter(entry => ![...paths].some(path => path === entry || path.startsWith(entry + ".") || path.startsWith(entry + "[]")));
for (const path of missing) console.error("no form and not listed as JSON only: " + path);
for (const entry of stale) console.error("listed but not in the schema: " + entry);
console.log(`${paths.size} config paths, ${missing.length} uncovered, ${stale.length} stale entries`);
process.exit(missing.length || stale.length ? 1 : 0);
