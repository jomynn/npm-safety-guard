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

import * as https from "https";

const REGISTRY_HOST = "registry.npmjs.org";
const DOWNLOADS_HOST = "api.npmjs.org";

const cache = new Map<string, RegistrySignals | null>();

export interface RegistrySignals {
  package: string;
  version: string;
  packageAgeDays?: number;
  versionAgeDays?: number;
  isLatestVersion: boolean;
  latestVersion?: string;
  maintainerCount: number;
  publisher?: string;
  maintainerTakeover: boolean; // latest version published by different account than previous
  takeoverFrom?: string;       // previous publisher
  takeoverTo?: string;         // current latest publisher
  publisherIsMaintainer: boolean; // false → publisher not in maintainers list (much stronger signal)
  deprecated: boolean;
  deprecationMessage?: string;
  downloadsLastWeek?: number;
  riskScore: number;           // 0–100
  riskLevel: "low" | "medium" | "high" | "critical";
  reasons: string[];
}

// ─── HTTPS helpers ───────────────────────────────────────────────────────────

function get(host: string, path: string, accept = "application/json"): Promise<any> {
  return new Promise((resolve) => {
    const req = https.request(
      { hostname: host, path, method: "GET", headers: { Accept: accept } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode === 200) {
            try { resolve(JSON.parse(data)); }
            catch { resolve(null); }
          } else {
            resolve(null);
          }
        });
      }
    );
    req.on("error", () => resolve(null));
    req.setTimeout(6000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function packagePath(name: string): string {
  const encoded = encodeURIComponent(name).replace(/^%40/, "@");
  return `/${encoded}`;
}

// ─── Semver compare (minimal; no ranges) ─────────────────────────────────────

function parseSemver(v: string): number[] {
  // Strip pre-release/build metadata
  const [core] = v.split(/[-+]/);
  return core.split(".").map((n) => parseInt(n, 10) || 0);
}

function cmpSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) return da - db;
  }
  return 0;
}

// ─── Risk scoring ────────────────────────────────────────────────────────────

function scoreRisk(s: Partial<RegistrySignals>): { riskScore: number; riskLevel: RegistrySignals["riskLevel"]; reasons: string[] } {
  let score = 0;
  const reasons: string[] = [];

  if (s.packageAgeDays !== undefined) {
    if (s.packageAgeDays < 30) { score += 35; reasons.push(`Package only ${Math.floor(s.packageAgeDays)} days old`); }
    else if (s.packageAgeDays < 90) { score += 15; reasons.push(`Package ${Math.floor(s.packageAgeDays)} days old (< 90)`); }
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
    } else {
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
    if (s.downloadsLastWeek < 100) { score += 20; reasons.push(`Only ${s.downloadsLastWeek} downloads last week`); }
    else if (s.downloadsLastWeek < 1000) { score += 8; reasons.push(`${s.downloadsLastWeek} downloads/week (low adoption)`); }
  }

  score = Math.min(100, score);
  const level: RegistrySignals["riskLevel"] =
    score >= 80 ? "critical"
    : score >= 60 ? "high"
    : score >= 30 ? "medium"
    : "low";

  return { riskScore: score, riskLevel: level, reasons };
}

// ─── Public API ──────────────────────────────────────────────────────────────

function cleanVersion(v: string): string {
  return v.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}

function daysBetween(iso: string, now = Date.now()): number {
  const t = Date.parse(iso);
  if (!isFinite(t)) return NaN;
  return (now - t) / (1000 * 60 * 60 * 24);
}

export async function checkRegistryHeuristics(
  name: string,
  version: string
): Promise<RegistrySignals | null> {
  const ver = cleanVersion(version);
  if (!ver) return null;
  const key = `${name}@${ver}`;
  if (cache.has(key)) return cache.get(key)!;

  const [meta, downloads] = await Promise.all([
    get(REGISTRY_HOST, packagePath(name)),
    get(DOWNLOADS_HOST, `/downloads/point/last-week/${encodeURIComponent(name).replace(/^%40/, "@")}`),
  ]);

  if (!meta || typeof meta !== "object") {
    cache.set(key, null);
    return null;
  }

  const time = (meta as any).time ?? {};
  const versions = (meta as any).versions ?? {};
  const distTags = (meta as any)["dist-tags"] ?? {};
  const latestVersion: string | undefined = distTags.latest;

  const packageCreated = time.created;
  const versionPublished = time[ver];

  const versionMeta = versions[ver] ?? {};
  const latestMeta = latestVersion ? versions[latestVersion] : undefined;

  const maintainers: Array<{ name: string }> =
    Array.isArray(versionMeta.maintainers) ? versionMeta.maintainers
    : Array.isArray((meta as any).maintainers) ? (meta as any).maintainers
    : [];

  const deprecated = typeof versionMeta.deprecated === "string" && versionMeta.deprecated.length > 0;

  // Maintainer takeover: compare latest version's _npmUser against the
  // previous version's (by semver order).
  let takeover = false;
  let takeoverFrom: string | undefined;
  let takeoverTo: string | undefined;
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

  const downloadsLastWeek: number | undefined =
    downloads && typeof (downloads as any).downloads === "number"
      ? (downloads as any).downloads
      : undefined;

  const partial: Partial<RegistrySignals> = {
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
  };

  const { riskScore, riskLevel, reasons } = scoreRisk(partial);

  const full: RegistrySignals = {
    ...(partial as Omit<RegistrySignals, "riskScore" | "riskLevel" | "reasons">),
    riskScore,
    riskLevel,
    reasons,
  };
  cache.set(key, full);
  return full;
}

export async function checkAllHeuristics(
  deps: Record<string, string>,
  onProgress?: (done: number, total: number, pkg: string) => void
): Promise<RegistrySignals[]> {
  const entries = Object.entries(deps);
  const results: RegistrySignals[] = [];
  const CONCURRENCY = 6; // full-metadata fetches — keep modest

  let done = 0;
  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const slice = entries.slice(i, i + CONCURRENCY);
    const settled = await Promise.all(
      slice.map(async ([name, ver]) => {
        const r = await checkRegistryHeuristics(name, ver);
        done++;
        onProgress?.(done, entries.length, name);
        return r;
      })
    );
    for (const r of settled) {
      if (r && r.riskScore >= 30) results.push(r);
    }
  }
  return results;
}

export function clearHeuristicsCache(): void {
  cache.clear();
}
