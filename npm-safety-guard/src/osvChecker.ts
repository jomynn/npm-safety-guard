/**
 * NPM Safety Guard — OSV.dev Checker
 * Queries Google's OSV.dev for known vulnerabilities in npm packages.
 * Free, unauthenticated, no rate limit. https://google.github.io/osv.dev/api/
 */

import * as https from "https";

const OSV_HOST = "api.osv.dev";
const OSV_PATH = "/v1/query";

const cache = new Map<string, OSVResult | null>();

export interface OSVVulnerability {
  id: string;
  summary: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  aliases: string[];
  fixedVersion?: string;
  advisoryUrl?: string;
}

export interface OSVResult {
  package: string;
  version: string;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  vulnerabilities: OSVVulnerability[];
}

function cleanVersion(version: string): string {
  return version.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}

function mapSeverityLabel(label: string | undefined): OSVVulnerability["severity"] {
  if (!label) return "unknown";
  const l = label.toUpperCase();
  if (l === "CRITICAL") return "critical";
  if (l === "HIGH") return "high";
  if (l === "MODERATE" || l === "MEDIUM") return "medium";
  if (l === "LOW") return "low";
  return "unknown";
}

function extractSeverity(vuln: any): OSVVulnerability["severity"] {
  const dbSeverity = vuln?.database_specific?.severity;
  if (typeof dbSeverity === "string") return mapSeverityLabel(dbSeverity);

  const cvssScore = vuln?.database_specific?.cvss?.score;
  if (typeof cvssScore === "number") {
    if (cvssScore >= 9) return "critical";
    if (cvssScore >= 7) return "high";
    if (cvssScore >= 4) return "medium";
    if (cvssScore > 0) return "low";
  }

  return "unknown";
}

function extractFixedVersion(vuln: any, pkgName: string): string | undefined {
  const affected = vuln?.affected;
  if (!Array.isArray(affected)) return undefined;
  for (const a of affected) {
    if (a?.package?.ecosystem !== "npm") continue;
    if (a?.package?.name !== pkgName) continue;
    for (const range of a?.ranges ?? []) {
      for (const event of range?.events ?? []) {
        if (event?.fixed) return String(event.fixed);
      }
    }
  }
  return undefined;
}

function extractAdvisoryUrl(vuln: any): string | undefined {
  const refs = vuln?.references;
  if (!Array.isArray(refs) || refs.length === 0) return undefined;
  const advisory = refs.find((r) => r?.type === "ADVISORY");
  return advisory?.url ?? refs[0]?.url;
}

function osvFetch(packageName: string, version: string): Promise<any> {
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
          try { resolve(JSON.parse(data)); }
          catch { resolve(null); }
        } else {
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

export async function checkPackageOSV(
  name: string,
  version: string
): Promise<OSVResult | null> {
  const ver = cleanVersion(version);
  if (!ver) return null;
  const key = `${name}@${ver}`;

  if (cache.has(key)) return cache.get(key)!;

  const data = await osvFetch(name, ver);
  const vulnsRaw: any[] = data?.vulns ?? [];

  const vulnerabilities: OSVVulnerability[] = vulnsRaw.map((v) => ({
    id: v?.id ?? "UNKNOWN",
    summary: v?.summary ?? (typeof v?.details === "string" ? v.details.slice(0, 240) : ""),
    severity: extractSeverity(v),
    aliases: Array.isArray(v?.aliases) ? v.aliases : [],
    fixedVersion: extractFixedVersion(v, name),
    advisoryUrl: extractAdvisoryUrl(v),
  }));

  const severityOrder: Record<OSVVulnerability["severity"], number> = {
    critical: 4, high: 3, medium: 2, low: 1, unknown: 0,
  };
  const maxSeverity = vulnerabilities.reduce<OSVVulnerability["severity"]>(
    (acc, v) => (severityOrder[v.severity] > severityOrder[acc] ? v.severity : acc),
    "unknown"
  );

  const riskLevel: OSVResult["riskLevel"] =
    vulnerabilities.length === 0 ? "none"
    : maxSeverity === "critical" ? "critical"
    : maxSeverity === "high" ? "high"
    : maxSeverity === "medium" ? "medium"
    : "low";

  const result: OSVResult = {
    package: name,
    version: ver,
    riskLevel,
    vulnerabilities,
  };

  cache.set(key, result);
  return result;
}

export async function checkAllPackagesOSV(
  deps: Record<string, string>,
  onProgress?: (done: number, total: number) => void
): Promise<OSVResult[]> {
  const entries = Object.entries(deps);
  const results: OSVResult[] = [];
  const CONCURRENCY = 16;

  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const slice = entries.slice(i, i + CONCURRENCY);
    const settled = await Promise.all(
      slice.map(([name, ver]) => checkPackageOSV(name, ver))
    );
    settled.forEach((r) => { if (r && r.riskLevel !== "none") results.push(r); });
    onProgress?.(Math.min(i + CONCURRENCY, entries.length), entries.length);
  }

  return results;
}

export function clearOSVCache(): void {
  cache.clear();
}
