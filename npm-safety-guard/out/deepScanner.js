"use strict";
/**
 * NPM Safety Guard — Deep Tarball Scanner
 *
 * Downloads each package's published tarball from registry.npmjs.org,
 * decompresses gzip, parses tar, and runs regex-based detectors against
 * every JS/TS file. Catches the patterns that signature-based scanners
 * miss: split-file payloads merged at runtime, eval'd base64 blobs,
 * String.fromCharCode reconstruction, install-time exfil to webhooks,
 * Shai-Hulud-style self-propagation via `npm publish`, etc.
 *
 * Pure built-in deps (https + zlib + Buffer). No native modules, no
 * @babel/parser bloat. Regex-based detection trades cross-file taint
 * tracking for speed and zero install size.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.deepScanPackage = deepScanPackage;
exports.deepScanAll = deepScanAll;
exports.clearDeepScanCache = clearDeepScanCache;
const https = require("https");
const zlib = require("zlib");
const REGISTRY_HOST = "registry.npmjs.org";
const MAX_TARBALL_BYTES = 8 * 1024 * 1024; // 8 MB safety cap
const MAX_FILE_SCAN_BYTES = 512 * 1024; // skip files larger than 512 KB
const TARBALL_TIMEOUT_MS = 10000;
// ─── HTTPS download ──────────────────────────────────────────────────────────
function tarballUrl(name, version) {
    // Basename is the unscoped final segment (npm convention).
    const basename = name.split("/").pop() ?? name;
    // Scoped name path keeps the `/` so registry routes correctly.
    return `https://${REGISTRY_HOST}/${name}/-/${basename}-${version}.tgz`;
}
function downloadTarball(url) {
    return new Promise((resolve) => {
        const req = https.get(url, { timeout: TARBALL_TIMEOUT_MS }, (res) => {
            // Handle 30x redirects from CDN
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                downloadTarball(res.headers.location).then(resolve, () => resolve(null));
                res.resume();
                return;
            }
            if (res.statusCode !== 200) {
                res.resume();
                resolve(null);
                return;
            }
            const chunks = [];
            let total = 0;
            res.on("data", (chunk) => {
                total += chunk.length;
                if (total > MAX_TARBALL_BYTES) {
                    req.destroy();
                    resolve(null);
                    return;
                }
                chunks.push(chunk);
            });
            res.on("end", () => resolve(Buffer.concat(chunks)));
            res.on("error", () => resolve(null));
        });
        req.on("error", () => resolve(null));
        req.on("timeout", () => { req.destroy(); resolve(null); });
    });
}
function parseTar(buf) {
    const files = [];
    let offset = 0;
    let longName = null;
    while (offset + 512 <= buf.length) {
        // Empty record (zero header) marks end-of-archive
        if (buf.readUInt8(offset) === 0)
            break;
        const rawName = buf.slice(offset, offset + 100).toString("utf8").replace(/\0+$/, "");
        const sizeOctal = buf.slice(offset + 124, offset + 136).toString("utf8").replace(/[\0\s]+$/, "");
        const size = parseInt(sizeOctal, 8) || 0;
        const type = String.fromCharCode(buf.readUInt8(offset + 156));
        const prefix = buf.slice(offset + 345, offset + 500).toString("utf8").replace(/\0+$/, "");
        const fullName = longName ?? (prefix ? `${prefix}/${rawName}` : rawName);
        longName = null;
        offset += 512;
        if (offset + size > buf.length)
            break;
        if (size > 0) {
            const data = buf.slice(offset, offset + size);
            if (type === "L") {
                // GNU long file name — name lives in the data section
                longName = data.toString("utf8").replace(/\0+$/, "");
            }
            else if (type === "x" || type === "g") {
                // PAX extended header — parse `path` if present
                const pax = data.toString("utf8");
                const m = pax.match(/\d+ path=([^\n]+)\n/);
                if (m)
                    longName = m[1];
            }
            else if (type === "0" || type === "" || type === "\0") {
                files.push({ name: fullName, size, data });
            }
            offset += Math.ceil(size / 512) * 512;
        }
    }
    return files;
}
// ─── Detectors ───────────────────────────────────────────────────────────────
function lineOf(content, index) {
    let line = 1;
    for (let i = 0; i < index && i < content.length; i++) {
        if (content.charCodeAt(i) === 10)
            line++;
    }
    return line;
}
function snippet(content, index, len = 80) {
    const start = Math.max(0, index - 20);
    const end = Math.min(content.length, index + len);
    return content.slice(start, end).replace(/\s+/g, " ").trim();
}
function detect(file, content) {
    const found = [];
    const isInstallScript = /^package\/(install|preinstall|postinstall|prepare)\b/i.test(file)
        || /\b(install|preinstall|postinstall|prepare)\.(js|cjs|mjs)$/i.test(file);
    const detectors = [
        {
            type: "eval",
            severity: "critical",
            pattern: /\beval\s*\(/g,
            description: "Direct eval() call — executes arbitrary strings as code. Almost never legitimate.",
        },
        {
            type: "new_function",
            severity: "critical",
            pattern: /\bnew\s+Function\s*\(/g,
            description: "new Function() — alternate eval, executes string as code.",
        },
        {
            type: "vm_exec",
            severity: "critical",
            pattern: /\bvm\s*\.\s*(runInNewContext|runInThisContext|runInContext|compileFunction)/g,
            description: "Node vm module used to execute strings as code.",
        },
        {
            type: "dynamic_require",
            severity: "high",
            pattern: /\brequire\s*\(\s*(?!['"`][^"'`]+['"`]\s*\))/g,
            description: "require() called with a non-literal argument — common obfuscation to hide which module is loaded.",
        },
        {
            type: "fromCharCode_blob",
            severity: "high",
            pattern: /String\.fromCharCode\s*\(([^)]{120,})\)/g,
            description: "Large String.fromCharCode call — character-code reconstruction, common malware obfuscation.",
        },
        {
            type: "base64_blob",
            severity: "high",
            pattern: /["'`]([A-Za-z0-9+/]{500,}={0,2})["'`]/g,
            description: "Hard-coded base64 blob > 500 chars — likely an encoded payload.",
        },
        {
            type: "string_concat_eval",
            severity: "high",
            pattern: /\[\s*(['"`][^'"`,]{1,12}['"`]\s*,\s*){4,}['"`][^'"`,]{1,12}['"`]\s*\]\s*\.\s*join/g,
            description: "Array of short strings with .join() — suspicious if the result feeds eval/Function (split-payload pattern).",
        },
        {
            type: "fs_write_secret_path",
            severity: "critical",
            pattern: /fs\s*\.\s*(append|write)\w*Sync?\s*\([^)]*['"`][^"'`]*(\.ssh|\.aws|\.bashrc|\.zshrc|\.npmrc|\.gitconfig|\.profile|authorized_keys|crontab)/gi,
            description: "Write to a credential / shell-config file — persistence or credential-theft signal.",
        },
        {
            type: "network_exfil",
            severity: "high",
            pattern: /(discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services|api\.ipify\.org|ipinfo\.io|ip-api\.com|httpbin\.org)/gi,
            description: "Hard-coded webhook / IP-lookup endpoint — common exfil channel.",
        },
        {
            type: "self_publish",
            severity: "critical",
            pattern: /(child_process|exec|spawn)[^"'`]*['"`][^"'`]*npm\s+publish\b/g,
            description: "Code shells out to `npm publish` — Shai-Hulud-style worm propagation signature.",
        },
        {
            type: "shell_download",
            severity: "high",
            pattern: /(child_process|exec|spawn)[^"'`]*['"`][^"'`]*\b(curl|wget|powershell|bitsadmin|certutil)\s+[-a-zA-Z]*\s*['"`]?https?:\/\//gi,
            description: "Shell-out to curl/wget/powershell with an HTTPS URL — runtime payload download.",
        },
        {
            type: "obfuscated_ids",
            severity: "medium",
            pattern: /\b_0x[a-f0-9]{4,}\b/g,
            description: "Hex-prefixed identifiers (_0xabcd) — fingerprint of obfuscation tools like obfuscator.io.",
        },
        {
            type: "zero_width_chars",
            severity: "medium",
            pattern: /[\u200B-\u200D\uFEFF\u202A-\u202E]/g,
            description: "Zero-width / RTL-override Unicode in source — bidi/homoglyph attack vector.",
        },
        {
            type: "child_process",
            severity: "medium",
            pattern: /\bchild_process[^.\w]*\.\s*(exec|spawn|fork|execSync|spawnSync)/g,
            description: "child_process API used (informational — common in build tools).",
        },
    ];
    for (const det of detectors) {
        let m;
        let count = 0;
        const re = new RegExp(det.pattern.source, det.pattern.flags);
        while ((m = re.exec(content)) !== null && count < 5) {
            // Promote severity for child_process inside install scripts
            let severity = typeof det.severity === "function" ? det.severity(m) : det.severity;
            if (det.type === "child_process" && isInstallScript)
                severity = "high";
            found.push({
                type: det.type,
                severity,
                file,
                line: lineOf(content, m.index),
                snippet: snippet(content, m.index),
                description: det.description,
            });
            count++;
            if (m.index === re.lastIndex)
                re.lastIndex++; // avoid zero-length infinite loop
        }
    }
    return found;
}
// ─── Public API ──────────────────────────────────────────────────────────────
const SCANNABLE_EXT = /\.(c?js|mjs|ts|cts|mts)$/i;
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
function topSeverity(findings) {
    if (findings.length === 0)
        return "none";
    return findings.reduce((acc, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc), "low");
}
function gunzipBuffer(buf) {
    return new Promise((resolve) => {
        zlib.gunzip(buf, (err, out) => resolve(err ? null : out));
    });
}
const cache = new Map();
function cleanVersion(v) {
    return v.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}
async function deepScanPackage(name, version) {
    const ver = cleanVersion(version);
    if (!ver)
        return null;
    const key = `${name}@${ver}`;
    const cached = cache.get(key);
    if (cached)
        return cached;
    const url = tarballUrl(name, ver);
    const tgz = await downloadTarball(url);
    if (!tgz) {
        return { package: name, version: ver, filesScanned: 0, totalFiles: 0, findings: [], topSeverity: "none", scriptsPresent: false, error: "download_failed" };
    }
    const tar = await gunzipBuffer(tgz);
    if (!tar) {
        return { package: name, version: ver, filesScanned: 0, totalFiles: 0, findings: [], topSeverity: "none", scriptsPresent: false, error: "gunzip_failed" };
    }
    const entries = parseTar(tar);
    const findings = [];
    let scriptsPresent = false;
    let scanned = 0;
    for (const entry of entries) {
        // Strip the leading "package/" wrapper that npm tarballs always include
        const display = entry.name.startsWith("package/") ? entry.name.slice("package/".length) : entry.name;
        if (display === "package.json") {
            try {
                const pkg = JSON.parse(entry.data.toString("utf8"));
                const s = pkg?.scripts;
                if (s && (s.preinstall || s.install || s.postinstall || s.prepare)) {
                    scriptsPresent = true;
                }
            }
            catch { /* ignore */ }
            continue;
        }
        if (!SCANNABLE_EXT.test(display))
            continue;
        if (entry.size > MAX_FILE_SCAN_BYTES)
            continue;
        scanned++;
        const content = entry.data.toString("utf8");
        findings.push(...detect(display, content));
    }
    const result = {
        package: name,
        version: ver,
        filesScanned: scanned,
        totalFiles: entries.length,
        findings,
        topSeverity: topSeverity(findings),
        scriptsPresent,
    };
    cache.set(key, result);
    return result;
}
async function deepScanAll(deps, onProgress) {
    const entries = Object.entries(deps);
    const results = [];
    const CONCURRENCY = 4; // be polite to the registry CDN
    let done = 0;
    for (let i = 0; i < entries.length; i += CONCURRENCY) {
        const slice = entries.slice(i, i + CONCURRENCY);
        const settled = await Promise.all(slice.map(async ([name, ver]) => {
            const r = await deepScanPackage(name, ver);
            done++;
            onProgress?.(done, entries.length, name);
            return r;
        }));
        for (const r of settled) {
            if (r && (r.findings.length > 0 || r.scriptsPresent))
                results.push(r);
        }
    }
    return results;
}
function clearDeepScanCache() {
    cache.clear();
}
//# sourceMappingURL=deepScanner.js.map