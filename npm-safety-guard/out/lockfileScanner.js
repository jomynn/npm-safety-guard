"use strict";
/**
 * NPM Safety Guard — Lockfile Scanner
 *
 * Parses package-lock.json (npm v2/v3) and yarn.lock (classic v1) to
 * expand the full dependency tree — every resolved name@version.
 *
 * This is how we catch compromised TRANSITIVE dependencies like
 * `flatmap-stream@0.1.1` that was bundled via `event-stream@3.3.6`:
 * your package.json only lists event-stream, but the lockfile pins
 * flatmap-stream deep in the tree.
 *
 * Pure built-in deps (fs + path). Skips yarn v2+ berry format and
 * pnpm (both YAML) — those can be added when the need arises.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseLockfile = parseLockfile;
const fs = require("fs");
// ─── npm package-lock.json ────────────────────────────────────────────────────
function parseNpmLockfile(raw) {
    if (!raw || typeof raw !== "object")
        return null;
    const obj = raw;
    const lfv = obj.lockfileVersion;
    // v2/v3 share the `packages` block. v1 only has `dependencies`.
    if (obj.packages && typeof obj.packages === "object") {
        const format = lfv === 3 ? "npm-v3" : "npm-v2";
        const deps = [];
        for (const [key, meta] of Object.entries(obj.packages)) {
            // Skip the root entry (key === "")
            if (!key)
                continue;
            // Path format: "node_modules/foo" or "node_modules/foo/node_modules/bar"
            // or "node_modules/@scope/name"
            const m = key.match(/(?:^|\/)node_modules\/(@[^/]+\/[^/]+|[^/]+)(?:\/|$)(?!.*\/node_modules\/)/);
            const extractedName = m ? m[1] : null;
            if (!extractedName || !meta?.version || typeof meta.version !== "string")
                continue;
            deps.push({ name: extractedName, version: meta.version, path: key });
        }
        return { format, totalEntries: deps.length, uniqueDeps: dedupe(deps) };
    }
    if (obj.dependencies && typeof obj.dependencies === "object") {
        const deps = [];
        const walk = (tree, prefix = "") => {
            for (const [name, meta] of Object.entries(tree)) {
                if (!meta?.version)
                    continue;
                const path = prefix ? `${prefix}/node_modules/${name}` : `node_modules/${name}`;
                deps.push({ name, version: meta.version, path });
                if (meta.dependencies)
                    walk(meta.dependencies, path);
            }
        };
        walk(obj.dependencies);
        return { format: "npm-v1", totalEntries: deps.length, uniqueDeps: dedupe(deps) };
    }
    return null;
}
// ─── yarn.lock v1 (classic) ───────────────────────────────────────────────────
function parseYarnLockV1(content) {
    // yarn.lock v1 has the comment-header "# yarn lockfile v1".
    if (!/^#\s*yarn lockfile v1/mi.test(content))
        return null;
    const deps = [];
    // Entries are separated by blank lines. First non-blank line is the
    // quoted key (one or more "name@spec, name@spec" selectors). The
    // `version "x.y.z"` line follows.
    const blocks = content.split(/\n\s*\n/);
    for (const block of blocks) {
        if (!block.trim() || block.trimStart().startsWith("#"))
            continue;
        const lines = block.split("\n");
        const header = lines[0]?.trim().replace(/:$/, "");
        if (!header)
            continue;
        // Extract names from the selector list. Format: "foo@^1.0.0" or
        // "foo@npm:^1.0.0" or "@scope/foo@^1.0.0".
        const selectors = header.split(/\s*,\s*/).map((s) => s.replace(/^"|"$/g, ""));
        const names = new Set();
        for (const sel of selectors) {
            // Scoped: @scope/name@spec — split on the LAST "@"
            const atIdx = sel.lastIndexOf("@");
            if (atIdx <= 0)
                continue;
            const name = sel.slice(0, atIdx);
            if (name)
                names.add(name);
        }
        // Find the version line.
        let version = null;
        for (const ln of lines.slice(1)) {
            const m = ln.match(/^\s*version\s+"([^"]+)"/);
            if (m) {
                version = m[1];
                break;
            }
        }
        if (!version)
            continue;
        for (const name of names) {
            deps.push({ name, version });
        }
    }
    return { format: "yarn-v1", totalEntries: deps.length, uniqueDeps: dedupe(deps) };
}
// ─── de-dup + entry point ─────────────────────────────────────────────────────
function dedupe(deps) {
    const seen = new Map();
    for (const d of deps) {
        const key = `${d.name}@${d.version}`;
        if (!seen.has(key))
            seen.set(key, d);
    }
    return [...seen.values()];
}
async function parseLockfile(filePath) {
    let content;
    try {
        content = await fs.promises.readFile(filePath, "utf8");
    }
    catch {
        return null;
    }
    if (filePath.endsWith("package-lock.json") || filePath.endsWith("npm-shrinkwrap.json")) {
        try {
            return parseNpmLockfile(JSON.parse(content));
        }
        catch {
            return null;
        }
    }
    if (filePath.endsWith("yarn.lock")) {
        return parseYarnLockV1(content);
    }
    return null;
}
//# sourceMappingURL=lockfileScanner.js.map