import * as https from "https";

const RL_API_BASE = "data.reversinglabs.com";
const RL_PATH_PREFIX = "/api/oss/community/v2/free/report/pkg:npm/";

const cache = new Map<string, RLResult | null>();

export interface RLVulnerability {
  cve: string;
  cvss: number;
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  fixAvailable: boolean;
}

export interface RLResult {
  package: string;
  version: string;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  malware: boolean;
  tampered: boolean;
  vulnerabilities: RLVulnerability[];
  reportUrl: string;
}

function mapSeverity(cvss: number): RLVulnerability["severity"] {
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
}

function cleanVersion(version: string): string {
  return version.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}

function rlFetch(packageName: string, version: string, token: string): Promise<any> {
  return new Promise((resolve, reject) => {
    // encode scoped packages: @scope/name → %40scope%2Fname
    const encoded = encodeURIComponent(`${packageName}@${version}`);
    const path = RL_PATH_PREFIX + encoded;

    const options = {
      hostname: RL_API_BASE,
      path,
      method: "GET",
      headers: {
        Authorization: `Token ${token}`,
        Accept: "application/json",
      },
    };

    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        if (res.statusCode === 200) {
          try { resolve(JSON.parse(body)); }
          catch { resolve(null); }
        } else {
          resolve(null);
        }
      });
    });

    req.on("error", () => resolve(null));
    req.setTimeout(8000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

export async function checkPackageRL(
  name: string,
  version: string,
  token: string
): Promise<RLResult | null> {
  const ver = cleanVersion(version);
  const key = `${name}@${ver}`;

  if (cache.has(key)) return cache.get(key)!;

  const data = await rlFetch(name, ver, token);
  if (!data) { cache.set(key, null); return null; }

  const vulnsRaw: any[] = data?.report?.vulnerabilities ?? [];
  const vulns: RLVulnerability[] = vulnsRaw.map((v) => ({
    cve: v.id ?? "N/A",
    cvss: typeof v.cvss_score === "number" ? v.cvss_score : 0,
    severity: mapSeverity(typeof v.cvss_score === "number" ? v.cvss_score : 0),
    summary: v.summary ?? "",
    fixAvailable: v.fix_available === true,
  }));

  const hasMalware  = data?.report?.threats?.malware?.detected === true;
  const hasTampered = data?.report?.threats?.tampering?.detected === true;
  const maxCvss     = vulns.reduce((m, v) => Math.max(m, v.cvss), 0);

  const riskLevel =
    hasMalware        ? "critical"
    : hasTampered     ? "high"
    : maxCvss >= 9    ? "critical"
    : maxCvss >= 7    ? "high"
    : maxCvss >= 4    ? "medium"
    : maxCvss > 0     ? "low"
    : "none";

  const result: RLResult = {
    package: name,
    version: ver,
    riskLevel,
    malware: hasMalware,
    tampered: hasTampered,
    vulnerabilities: vulns,
    reportUrl: `https://secure.software/npm/packages/${name}/vulnerabilities/${ver}`,
  };

  cache.set(key, result);
  return result;
}

export async function checkAllPackagesRL(
  deps: Record<string, string>,
  token: string,
  onProgress?: (done: number, total: number) => void
): Promise<RLResult[]> {
  const entries = Object.entries(deps);
  const results: RLResult[] = [];
  const BATCH = 8;

  for (let i = 0; i < entries.length; i += BATCH) {
    const slice = entries.slice(i, i + BATCH);
    const settled = await Promise.all(
      slice.map(([name, ver]) => checkPackageRL(name, ver, token))
    );
    settled.forEach((r) => { if (r && r.riskLevel !== "none") results.push(r); });
    onProgress?.(Math.min(i + BATCH, entries.length), entries.length);
  }

  return results;
}

export function clearRLCache(): void {
  cache.clear();
}