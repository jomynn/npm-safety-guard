/**
 * NPM Safety Guard — Malicious Package Database
 * Community-maintained list of known supply chain attacks.
 * Add entries as new attacks are discovered.
 */

export interface MaliciousEntry {
  package: string;
  versions: string[];       // exact bad versions, or ["*"] for all
  severity: "critical" | "high" | "medium";
  title: string;
  description: string;
  safeVersion?: string;     // recommended safe version
  cve?: string;
  reportedAt: string;       // ISO date
  sources: string[];
}

export const MALICIOUS_DB: MaliciousEntry[] = [
  // ─── Axios Supply Chain Attack (2026-03-31) ───────────────────────────────
  {
    package: "axios",
    versions: ["1.14.1", "0.30.4"],
    severity: "critical",
    title: "Axios Supply Chain — RAT via plain-crypto-js",
    description:
      "Maintainer account compromised (Sapphire Sleet / North Korea). " +
      "These versions inject plain-crypto-js@4.2.1 which runs a postinstall " +
      "script that deploys a cross-platform Remote Access Trojan (RAT) on " +
      "macOS, Windows, and Linux. Malware phones home to sfrclak.com:8000 " +
      "and self-deletes to evade forensics. Rotate ALL credentials if installed.",
    safeVersion: "1.14.0",
    reportedAt: "2026-03-31",
    sources: [
      "https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan",
      "https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package",
      "https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise"
    ]
  },

  // ─── plain-crypto-js (the dropper itself) ─────────────────────────────────
  {
    package: "plain-crypto-js",
    versions: ["4.2.1"],
    severity: "critical",
    title: "plain-crypto-js — Malicious RAT Dropper",
    description:
      "Not a legitimate package. Created by Sapphire Sleet as a delivery " +
      "vehicle for the Axios supply chain attack. Contains postinstall hook " +
      "that deploys WAVESHAPER.V2 backdoor. Never a dependency of real Axios. " +
      "If found in node_modules, assume the host is fully compromised.",
    reportedAt: "2026-03-31",
    sources: [
      "https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/"
    ]
  },

  // ─── @shadanai/openclaw (secondary vector) ────────────────────────────────
  {
    package: "@shadanai/openclaw",
    versions: ["2026.3.28-2", "2026.3.28-3", "2026.3.31-1", "2026.3.31-2"],
    severity: "critical",
    title: "@shadanai/openclaw — Vendors plain-crypto-js payload",
    description:
      "Found to vendor the malicious plain-crypto-js payload directly. " +
      "Part of the same Axios supply chain attack campaign.",
    reportedAt: "2026-03-31",
    sources: [
      "https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html"
    ]
  },

  // ─── @qqbrowser/openclaw-qbot ─────────────────────────────────────────────
  {
    package: "@qqbrowser/openclaw-qbot",
    versions: ["0.0.130"],
    severity: "critical",
    title: "@qqbrowser/openclaw-qbot — Ships tampered axios@1.14.1",
    description:
      "Bundles a tampered axios@1.14.1 with plain-crypto-js injected as a " +
      "dependency in its node_modules folder. Same RAT campaign.",
    reportedAt: "2026-03-31",
    sources: [
      "https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html"
    ]
  },

  // ─── Classic / Historical Attacks (examples) ──────────────────────────────
  {
    package: "event-stream",
    versions: ["3.3.6"],
    severity: "high",
    title: "event-stream — Crypto wallet theft (2018)",
    description:
      "Malicious maintainer added flatmap-stream dependency targeting Copay " +
      "Bitcoin wallets. Historic supply chain attack.",
    safeVersion: "3.3.5",
    reportedAt: "2018-11-26",
    sources: ["https://github.com/dominictarr/event-stream/issues/116"]
  },
  {
    package: "node-ipc",
    versions: ["10.1.1", "10.1.2", "11.0.0"],
    severity: "high",
    title: "node-ipc — Protestware targeting Russian/Belarusian IPs (2022)",
    description:
      "Maintainer intentionally introduced code that wiped files on systems " +
      "with Russian or Belarusian IP addresses.",
    safeVersion: "9.2.2",
    reportedAt: "2022-03-15",
    sources: ["https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/"]
  }
];

// Remote entries fetched from the community feed. Merged with the bundled DB
// at scan time. Updated by extension activation; safe-default empty.
let REMOTE_ENTRIES: MaliciousEntry[] = [];

export function setRemoteEntries(entries: MaliciousEntry[]): void {
  REMOTE_ENTRIES = entries ?? [];
}

export function getAllEntries(): MaliciousEntry[] {
  // Bundled first so its sources/messages take precedence on duplicates
  const seen = new Set(MALICIOUS_DB.map((e) => `${e.package}|${e.versions.join(",")}`));
  const extras = REMOTE_ENTRIES.filter(
    (e) => !seen.has(`${e.package}|${e.versions.join(",")}`)
  );
  return [...MALICIOUS_DB, ...extras];
}

/**
 * Check if a specific package@version is in the malicious database
 * (bundled + remote feed). Returns the matching entry or null.
 */
export function checkPackage(name: string, version: string): MaliciousEntry | null {
  const cleanVersion = version.replace(/[\^~>=<]/g, "").trim();

  for (const entry of getAllEntries()) {
    if (entry.package !== name) continue;
    if (entry.versions.includes("*")) return entry;
    if (entry.versions.includes(cleanVersion)) return entry;
    if (entry.versions.some((v) => cleanVersion.startsWith(v))) return entry;
  }
  return null;
}

/**
 * Check all dependencies object { name: version } and return hits.
 */
export function checkDependencies(
  deps: Record<string, string>
): Array<{ name: string; version: string; entry: MaliciousEntry }> {
  const hits: Array<{ name: string; version: string; entry: MaliciousEntry }> = [];
  for (const [name, version] of Object.entries(deps)) {
    const entry = checkPackage(name, version);
    if (entry) hits.push({ name, version, entry });
  }
  return hits;
}
