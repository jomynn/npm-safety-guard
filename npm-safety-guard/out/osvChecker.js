"use strict";
/**
 * NPM Safety Guard — OSV.dev Checker
 * Queries Google's OSV.dev for known vulnerabilities in npm packages.
 * Free, unauthenticated, no rate limit. https://google.github.io/osv.dev/api/
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkPackageOSV = checkPackageOSV;
exports.checkAllPackagesOSV = checkAllPackagesOSV;
exports.clearOSVCache = clearOSVCache;
const https = require("https");
const OSV_HOST = "api.osv.dev";
const OSV_PATH = "/v1/query";
const cache = new Map();
function cleanVersion(version) {
    return version.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}
function mapSeverityLabel(label) {
    if (!label)
        return "unknown";
    const l = label.toUpperCase();
    if (l === "CRITICAL")
        return "critical";
    if (l === "HIGH")
        return "high";
    if (l === "MODERATE" || l === "MEDIUM")
        return "medium";
    if (l === "LOW")
        return "low";
    return "unknown";
}
function extractSeverity(vuln) {
    const dbSeverity = vuln?.database_specific?.severity;
    if (typeof dbSeverity === "string")
        return mapSeverityLabel(dbSeverity);
    const cvssScore = vuln?.database_specific?.cvss?.score;
    if (typeof cvssScore === "number") {
        if (cvssScore >= 9)
            return "critical";
        if (cvssScore >= 7)
            return "high";
        if (cvssScore >= 4)
            return "medium";
        if (cvssScore > 0)
            return "low";
    }
    return "unknown";
}
function extractFixedVersion(vuln, pkgName) {
    const affected = vuln?.affected;
    if (!Array.isArray(affected))
        return undefined;
    for (const a of affected) {
        if (a?.package?.ecosystem !== "npm")
            continue;
        if (a?.package?.name !== pkgName)
            continue;
        for (const range of a?.ranges ?? []) {
            for (const event of range?.events ?? []) {
                if (event?.fixed)
                    return String(event.fixed);
            }
        }
    }
    return undefined;
}
function extractAdvisoryUrl(vuln) {
    const refs = vuln?.references;
    if (!Array.isArray(refs) || refs.length === 0)
        return undefined;
    const advisory = refs.find((r) => r?.type === "ADVISORY");
    return advisory?.url ?? refs[0]?.url;
}
function osvFetch(packageName, version) {
    return new Promise((resolve) => {
        const body = JSON.stringify({
            package: { name: packageName, ecosystem: "npm" },
            version,
        });
        const options = {
            hostname: OSV_HOST,
            path: OSV_PATH,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(body),
                Accept: "application/json",
            },
        };
        const req = https.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
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
        req.setTimeout(8000, () => { req.destroy(); resolve(null); });
        req.write(body);
        req.end();
    });
}
async function checkPackageOSV(name, version) {
    const ver = cleanVersion(version);
    if (!ver)
        return null;
    const key = `${name}@${ver}`;
    if (cache.has(key))
        return cache.get(key);
    const data = await osvFetch(name, ver);
    const vulnsRaw = data?.vulns ?? [];
    const vulnerabilities = vulnsRaw.map((v) => ({
        id: v?.id ?? "UNKNOWN",
        summary: v?.summary ?? (typeof v?.details === "string" ? v.details.slice(0, 240) : ""),
        severity: extractSeverity(v),
        aliases: Array.isArray(v?.aliases) ? v.aliases : [],
        fixedVersion: extractFixedVersion(v, name),
        advisoryUrl: extractAdvisoryUrl(v),
    }));
    const severityOrder = {
        critical: 4, high: 3, medium: 2, low: 1, unknown: 0,
    };
    const maxSeverity = vulnerabilities.reduce((acc, v) => (severityOrder[v.severity] > severityOrder[acc] ? v.severity : acc), "unknown");
    const riskLevel = vulnerabilities.length === 0 ? "none"
        : maxSeverity === "critical" ? "critical"
            : maxSeverity === "high" ? "high"
                : maxSeverity === "medium" ? "medium"
                    : "low";
    const result = {
        package: name,
        version: ver,
        riskLevel,
        vulnerabilities,
    };
    cache.set(key, result);
    return result;
}
async function checkAllPackagesOSV(deps, onProgress) {
    const entries = Object.entries(deps);
    const results = [];
    const CONCURRENCY = 16;
    for (let i = 0; i < entries.length; i += CONCURRENCY) {
        const slice = entries.slice(i, i + CONCURRENCY);
        const settled = await Promise.all(slice.map(([name, ver]) => checkPackageOSV(name, ver)));
        settled.forEach((r) => { if (r && r.riskLevel !== "none")
            results.push(r); });
        onProgress?.(Math.min(i + CONCURRENCY, entries.length), entries.length);
    }
    return results;
}
function clearOSVCache() {
    cache.clear();
}
//# sourceMappingURL=osvChecker.js.map