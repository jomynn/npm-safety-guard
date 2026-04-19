"use strict";
/**
 * NPM Safety Guard — Remote DB fetcher
 * Pulls the community malicious-packages feed from GitHub so the extension
 * stays current without a republish. Caches to globalStorageUri with ETag.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_DB_URL = void 0;
exports.fetchRemoteEntries = fetchRemoteEntries;
const https = require("https");
const fs = require("fs");
const path = require("path");
const url_1 = require("url");
exports.DEFAULT_DB_URL = "https://raw.githubusercontent.com/jomynn/npm-safety-guard/main/db/malicious-packages.json";
const CACHE_FILENAME = "malicious-packages.cache.json";
const META_FILENAME = "malicious-packages.cache.meta.json";
const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h
function httpGet(url, etag) {
    return new Promise((resolve) => {
        let parsed;
        try {
            parsed = new url_1.URL(url);
        }
        catch {
            resolve(null);
            return;
        }
        const headers = { Accept: "application/json" };
        if (etag)
            headers["If-None-Match"] = etag;
        const req = https.request({
            hostname: parsed.hostname,
            port: parsed.port || 443,
            path: parsed.pathname + parsed.search,
            method: "GET",
            headers,
        }, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                resolve({
                    status: res.statusCode ?? 0,
                    body: data,
                    etag: res.headers.etag ?? undefined,
                });
            });
        });
        req.on("error", () => resolve(null));
        req.setTimeout(6000, () => { req.destroy(); resolve(null); });
        req.end();
    });
}
function readCache(storageDir) {
    try {
        const cachePath = path.join(storageDir, CACHE_FILENAME);
        const metaPath = path.join(storageDir, META_FILENAME);
        if (!fs.existsSync(cachePath) || !fs.existsSync(metaPath))
            return null;
        const entries = JSON.parse(fs.readFileSync(cachePath, "utf8"));
        const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
        if (!Array.isArray(entries))
            return null;
        return { entries, meta };
    }
    catch {
        return null;
    }
}
function writeCache(storageDir, entries, meta) {
    try {
        fs.mkdirSync(storageDir, { recursive: true });
        fs.writeFileSync(path.join(storageDir, CACHE_FILENAME), JSON.stringify(entries));
        fs.writeFileSync(path.join(storageDir, META_FILENAME), JSON.stringify(meta));
    }
    catch {
        // Cache write failures are non-fatal
    }
}
function validateEntries(data) {
    if (!Array.isArray(data))
        return null;
    const valid = data.filter((e) => {
        return (e && typeof e === "object"
            && typeof e.package === "string"
            && Array.isArray(e.versions)
            && typeof e.title === "string"
            && typeof e.description === "string"
            && ["critical", "high", "medium"].includes(e.severity));
    });
    return valid;
}
/**
 * Returns the remote malicious-package entries, preferring a fresh network
 * copy, falling back to on-disk cache, finally returning empty. Never throws.
 */
async function fetchRemoteEntries(storageDir, url = exports.DEFAULT_DB_URL) {
    const cached = readCache(storageDir);
    // Use cache if fresh (<24h) and source URL matches
    if (cached && cached.meta.sourceUrl === url) {
        const age = Date.now() - cached.meta.fetchedAt;
        if (age < REFRESH_INTERVAL_MS) {
            return { entries: cached.entries, source: "cache", fetchedAt: cached.meta.fetchedAt };
        }
    }
    const etag = cached?.meta.sourceUrl === url ? cached.meta.etag : undefined;
    const res = await httpGet(url, etag);
    // Network failure → use any cache we have
    if (!res) {
        if (cached)
            return { entries: cached.entries, source: "cache", fetchedAt: cached.meta.fetchedAt };
        return { entries: [], source: "none" };
    }
    // Not modified → refresh timestamp and reuse cache
    if (res.status === 304 && cached) {
        const newMeta = { ...cached.meta, fetchedAt: Date.now() };
        writeCache(storageDir, cached.entries, newMeta);
        return { entries: cached.entries, source: "cache", fetchedAt: newMeta.fetchedAt };
    }
    if (res.status !== 200) {
        if (cached)
            return { entries: cached.entries, source: "cache", fetchedAt: cached.meta.fetchedAt };
        return { entries: [], source: "none" };
    }
    // Parse + validate
    let parsed;
    try {
        parsed = JSON.parse(res.body);
    }
    catch {
        if (cached)
            return { entries: cached.entries, source: "cache", fetchedAt: cached.meta.fetchedAt };
        return { entries: [], source: "none" };
    }
    const valid = validateEntries(parsed);
    if (!valid) {
        if (cached)
            return { entries: cached.entries, source: "cache", fetchedAt: cached.meta.fetchedAt };
        return { entries: [], source: "none" };
    }
    const meta = {
        etag: res.etag,
        fetchedAt: Date.now(),
        sourceUrl: url,
    };
    writeCache(storageDir, valid, meta);
    return { entries: valid, source: "network", fetchedAt: meta.fetchedAt };
}
//# sourceMappingURL=remoteDb.js.map