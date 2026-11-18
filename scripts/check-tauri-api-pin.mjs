#!/usr/bin/env node
/**
 * Tauri API version-freeze guard.
 *
 * The daemon work (plan set `.pi/plans/261117-web-daemon-option-b`, decision
 * `WDA-D02`) delivers a browser shim that reimplements the `__TAURI_INTERNALS__`
 * surface `@tauri-apps/api` calls into. That surface is only a contract because
 * the package version is frozen: the Rust side is pinned `tauri = "=2.12.4"`,
 * so the JS side must pin the exact same release. A caret range here would let
 * any dependency refresh silently change the internals the shim fakes.
 *
 * The rule is not "this version forever": if the api package ever must move,
 * bump both pins together and re-run the shim conformance suite before any
 * daemon-mode work ships. This guard exists so that drift is a loud CI
 * failure, not a silent runtime surprise.
 */
import { readFileSync } from "node:fs";

const EXPECTED = "2.12.4";
const failures = [];

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const declared =
	manifest.dependencies?.["@tauri-apps/api"] ??
	manifest.devDependencies?.["@tauri-apps/api"];
if (declared !== EXPECTED) {
	failures.push(
		`package.json declares @tauri-apps/api "${declared ?? "(missing)"}"; expected the exact pin "${EXPECTED}" (no range).`,
	);
}

const lock = readFileSync(new URL("../pnpm-lock.yaml", import.meta.url), "utf8");
const locked = [...lock.matchAll(/@tauri-apps\/api@([0-9][\w.-]*)/g)].map((m) => m[1]);
const unexpected = [...new Set(locked.filter((v) => v !== EXPECTED))];
if (locked.length === 0) {
	failures.push("pnpm-lock.yaml has no @tauri-apps/api resolution; run an install first.");
}
if (unexpected.length > 0) {
	failures.push(
		`pnpm-lock.yaml resolves @tauri-apps/api to ${unexpected.join(", ")}; expected only ${EXPECTED}.`,
	);
}

if (failures.length > 0) {
	console.error("@tauri-apps/api version freeze violated:");
	for (const failure of failures) console.error(`  - ${failure}`);
	console.error(
		`\nThe shim conformance contract depends on api ${EXPECTED}. If an upgrade is truly required, bump both tauri pins together and re-run the daemon shim conformance suite first.`,
	);
	process.exit(1);
}

console.log(`@tauri-apps/api pinned at ${EXPECTED} (manifest + lockfile agree).`);
