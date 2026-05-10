"use strict";
/**
 * NPM Safety Guard — Registry Heuristics
 *
 * Computes a per-package risk score from npm registry metadata:
 *   - Package age (days since first publish)
 *   - Version age (days since this version was published)
 *   - Pinned-version-vs-latest drift
 *   - Maintainer count
 *   - Maintainer takeover (latest version published by a different account
 *     than the previous version — the axios/@ctrl-tinycolor pattern)
 *   - Deprecation flag
 *   - Weekly download velocity
 *
 * Zero external deps. Fetches full package metadata + download stats and
 * caches results in-memory (package metadata is effectively stable).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkRegistryHeuristics = checkRegistryHeuristics;
exports.checkAllHeuristics = checkAllHeuristics;
exports.clearHeuristicsCache = clearHeuristicsCache;
const https = require("https");
const REGISTRY_HOST = "registry.npmjs.org";
const DOWNLOADS_HOST = "api.npmjs.org";
const cache = new Map();
// ─── HTTPS helpers ───────────────────────────────────────────────────────────
function get(host, path, accept = "application/json") {
    return new Promise((resolve) => {
        const req = https.request({ hostname: host, path, method: "GET", headers: { Accept: accept } }, (res) => {
            let data = "";
            res.on("data", (c) => (data += c));
            res.on("end", () => {
                if (res.statusCode === 200) {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch {
                        resolve(null);
                    }
                }
                else {
                    resolve(null);
                }
            });
        });
        req.on("error", () => resolve(null));
        req.setTimeout(6000, () => { req.destroy(); resolve(null); });
        req.end();
    });
}
function packagePath(name) {
    const encoded = encodeURIComponent(name).replace(/^%40/, "@");
    return `/${encoded}`;
}
// ─── Semver compare (minimal; no ranges) ─────────────────────────────────────
function parseSemver(v) {
    // Strip pre-release/build metadata
    const [core] = v.split(/[-+]/);
    return core.split(".").map((n) => parseInt(n, 10) || 0);
}
function cmpSemver(a, b) {
    const pa = parseSemver(a);
    const pb = parseSemver(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const da = pa[i] ?? 0;
        const db = pb[i] ?? 0;
        if (da !== db)
            return da - db;
    }
    return 0;
}
// ─── Risk scoring ────────────────────────────────────────────────────────────
function scoreRisk(s) {
    let score = 0;
    const reasons = [];
    if (s.packageAgeDays !== undefined) {
        if (s.packageAgeDays < 30) {
            score += 35;
            reasons.push(`Package only ${Math.floor(s.packageAgeDays)} days old`);
        }
        else if (s.packageAgeDays < 90) {
            score += 15;
            reasons.push(`Package ${Math.floor(s.packageAgeDays)} days old (< 90)`);
        }
    }
    if (s.versionAgeDays !== undefined && s.versionAgeDays < 7) {
        score += 10;
        reasons.push(`This version published ${Math.floor(s.versionAgeDays)} day(s) ago`);
    }
    if (s.isLatestVersion === false) {
        // pinned to an older release — mild noise, not necessarily risky
        score += 3;
    }
    if (s.maintainerCount === 1) {
        score += 5;
        reasons.push("Single maintainer (no bus-factor protection)");
    }
    if (s.maintainerTakeover) {
        if (s.publisherIsMaintainer === false) {
            // Publisher is NOT in the maintainers list — strong takeover signal
            score += 40;
            reasons.push(`Latest version published by "${s.takeoverTo}" who is NOT in the maintainers list — possible account takeover`);
        }
        else {
            // Publisher rotated but is a known maintainer — normal in healthy multi-maintainer projects
            score += 5;
            reasons.push(`Publisher rotated from "${s.takeoverFrom}" to "${s.takeoverTo}" (both known maintainers)`);
        }
    }
    if (s.deprecated) {
        score += 40;
        reasons.push(`Deprecated by maintainer${s.deprecationMessage ? `: "${s.deprecationMessage.slice(0, 100)}"` : ""}`);
    }
    if (s.downloadsLastWeek !== undefined) {
        if (s.downloadsLastWeek < 100) {
            score += 20;
            reasons.push(`Only ${s.downloadsLastWeek} downloads last week`);
        }
        else if (s.downloadsLastWeek < 1000) {
            score += 8;
            reasons.push(`${s.downloadsLastWeek} downloads/week (low adoption)`);
        }
    }
    if (s.unpackedSizeKB !== undefined) {
        const mb = s.unpackedSizeKB / 1024;
        if (mb > 50) {
            score += 30;
            reasons.push(`Unusually large package: ${mb.toFixed(0)} MB unpacked — possible payload or bundled binary`);
        }
        else if (mb > 10) {
            score += 15;
            reasons.push(`Large package: ${mb.toFixed(0)} MB unpacked`);
        }
        else if (mb > 5) {
            score += 8;
            reasons.push(`Package is ${mb.toFixed(1)} MB unpacked — above typical size`);
        }
    }
    score = Math.min(100, score);
    const level = score >= 80 ? "critical"
        : score >= 60 ? "high"
            : score >= 30 ? "medium"
                : "low";
    return { riskScore: score, riskLevel: level, reasons };
}
// ─── Public API ──────────────────────────────────────────────────────────────
function cleanVersion(v) {
    return v.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}
function daysBetween(iso, now = Date.now()) {
    const t = Date.parse(iso);
    if (!isFinite(t))
        return NaN;
    return (now - t) / (1000 * 60 * 60 * 24);
}
async function checkRegistryHeuristics(name, version) {
    const ver = cleanVersion(version);
    if (!ver)
        return null;
    const key = `${name}@${ver}`;
    if (cache.has(key))
        return cache.get(key);
    const [meta, downloads] = await Promise.all([
        get(REGISTRY_HOST, packagePath(name)),
        get(DOWNLOADS_HOST, `/downloads/point/last-week/${encodeURIComponent(name).replace(/^%40/, "@")}`),
    ]);
    if (!meta || typeof meta !== "object") {
        cache.set(key, null);
        return null;
    }
    const time = meta.time ?? {};
    const versions = meta.versions ?? {};
    const distTags = meta["dist-tags"] ?? {};
    const latestVersion = distTags.latest;
    const packageCreated = time.created;
    const versionPublished = time[ver];
    const versionMeta = versions[ver] ?? {};
    const latestMeta = latestVersion ? versions[latestVersion] : undefined;
    const maintainers = Array.isArray(versionMeta.maintainers) ? versionMeta.maintainers
        : Array.isArray(meta.maintainers) ? meta.maintainers
            : [];
    const deprecated = typeof versionMeta.deprecated === "string" && versionMeta.deprecated.length > 0;
    // Maintainer takeover: compare latest version's _npmUser against the
    // previous version's (by semver order).
    let takeover = false;
    let takeoverFrom;
    let takeoverTo;
    let publisherIsMaintainer = true;
    if (latestVersion && latestMeta) {
        const allVers = Object.keys(versions).filter((v) => v !== latestVersion);
        allVers.sort(cmpSemver);
        const prevVersion = allVers[allVers.length - 1];
        const prevMeta = prevVersion ? versions[prevVersion] : undefined;
        const prevPublisher = prevMeta?._npmUser?.name;
        const currPublisher = latestMeta?._npmUser?.name;
        if (prevPublisher && currPublisher && prevPublisher !== currPublisher) {
            takeover = true;
            takeoverFrom = prevPublisher;
            takeoverTo = currPublisher;
            // Critical refinement: is the new publisher actually a listed maintainer?
            const maintainerNames = new Set(maintainers.map((m) => m.name));
            publisherIsMaintainer = maintainerNames.has(currPublisher);
        }
    }
    const downloadsLastWeek = downloads && typeof downloads.downloads === "number"
        ? downloads.downloads
        : undefined;
    const rawSize = versionMeta?.dist?.unpackedSize;
    const unpackedSizeKB = typeof rawSize === "number" && rawSize > 0 ? rawSize / 1024 : undefined;
    const partial = {
        package: name,
        version: ver,
        packageAgeDays: packageCreated ? daysBetween(packageCreated) : undefined,
        versionAgeDays: versionPublished ? daysBetween(versionPublished) : undefined,
        isLatestVersion: latestVersion === ver,
        latestVersion,
        maintainerCount: maintainers.length,
        publisher: versionMeta?._npmUser?.name,
        maintainerTakeover: takeover,
        takeoverFrom,
        takeoverTo,
        publisherIsMaintainer,
        deprecated,
        deprecationMessage: deprecated ? versionMeta.deprecated : undefined,
        downloadsLastWeek,
        unpackedSizeKB,
    };
    const { riskScore, riskLevel, reasons } = scoreRisk(partial);
    const full = {
        ...partial,
        riskScore,
        riskLevel,
        reasons,
    };
    cache.set(key, full);
    return full;
}
async function checkAllHeuristics(deps, onProgress) {
    const entries = Object.entries(deps);
    const results = [];
    const CONCURRENCY = 6; // full-metadata fetches — keep modest
    let done = 0;
    for (let i = 0; i < entries.length; i += CONCURRENCY) {
        const slice = entries.slice(i, i + CONCURRENCY);
        const settled = await Promise.all(slice.map(async ([name, ver]) => {
            const r = await checkRegistryHeuristics(name, ver);
            done++;
            onProgress?.(done, entries.length, name);
            return r;
        }));
        for (const r of settled) {
            if (r && r.riskScore >= 30)
                results.push(r);
        }
    }
    return results;
}
function clearHeuristicsCache() {
    cache.clear();
}
//# sourceMappingURL=registryHeuristics.js.map