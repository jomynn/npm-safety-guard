/**
 * NPM Safety Guard — Install-Script Auditor
 * Flags packages whose published metadata declares preinstall / install /
 * postinstall / prepare scripts. These hooks run BEFORE any application
 * code and are the single most common malware delivery vector.
 *
 * Whitelists well-known packages that legitimately need install scripts
 * (native bindings, image optimisers, native deps, etc.).
 *
 * Source: https://docs.npmjs.com/cli/v10/using-npm/scripts#npm-install
 */

import * as https from "https";

const REGISTRY_HOST = "registry.npmjs.org";

// Per-version package metadata is immutable, so a process-lifetime cache
// is safe and sized at most O(deps).
const cache = new Map<string, ScriptCheckResult | null>();

export interface ScriptCheckResult {
  package: string;
  version: string;
  scripts: {
    preinstall?: string;
    install?: string;
    postinstall?: string;
    prepare?: string;
  };
  hasInstallScript: boolean;
  whitelisted: boolean;
}

// Curated list of packages that legitimately ship install scripts.
// Add to this rather than creating false positives.
const DEFAULT_WHITELIST = new Set<string>([
  // Native crypto
  "bcrypt",
  "node-bcrypt",
  // Image / media
  "sharp",
  "canvas",
  "gifsicle",
  "mozjpeg",
  "optipng",
  "pngquant-bin",
  "jpegtran-bin",
  // Build tooling
  "esbuild",
  "@swc/core",
  "@swc/cli",
  "node-sass",
  "sass",
  // Native DBs
  "sqlite3",
  "better-sqlite3",
  // File watchers / native bindings
  "fsevents",
  "node-gyp",
  "node-pre-gyp",
  // Browsers / engines
  "puppeteer",
  "puppeteer-core",
  "playwright",
  "playwright-core",
  "electron",
  // ORMs
  "prisma",
  "@prisma/client",
  "@prisma/engines",
  // OS bindings
  "robotjs",
  "serialport",
  "usb",
  "bufferutil",
  "utf-8-validate",
  // Git / CI
  "husky",
  "pre-commit",
  "semantic-release",
  // gRPC / protobuf
  "@grpc/grpc-js",
  "protobufjs",
  // Misc legitimate
  "nodemon",
  "@sentry/cli",
  "cypress",
]);

function cleanVersion(v: string): string {
  return v.replace(/[\^~>=<\s]/g, "").split("||")[0].trim();
}

function registryFetch(packageName: string, version: string): Promise<any> {
  return new Promise((resolve) => {
    // encodeURIComponent("@scope/name") = "%40scope%2Fname" — keep the leading @ so
    // the registry treats it as a scoped name.
    const encodedName = encodeURIComponent(packageName).replace(/^%40/, "@");
    const path = `/${encodedName}/${encodeURIComponent(version)}`;

    const req = https.request(
      {
        hostname: REGISTRY_HOST,
        path,
        method: "GET",
        headers: { Accept: "application/json" },
      },
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
    req.setTimeout(5000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

export async function checkInstallScripts(
  name: string,
  version: string,
  customWhitelist: Set<string> = new Set()
): Promise<ScriptCheckResult | null> {
  const ver = cleanVersion(version);
  if (!ver) return null;
  const key = `${name}@${ver}`;

  let cached = cache.get(key);
  if (cached !== undefined) {
    if (!cached) return null;
    // Re-evaluate whitelist on every call (custom whitelist may have changed)
    return { ...cached, whitelisted: DEFAULT_WHITELIST.has(name) || customWhitelist.has(name) };
  }

  const data = await registryFetch(name, ver);
  if (!data || typeof data !== "object") { cache.set(key, null); return null; }

  const scripts = (data as any).scripts ?? {};
  const dangerous: ScriptCheckResult["scripts"] = {};
  if (typeof scripts.preinstall === "string")  dangerous.preinstall  = scripts.preinstall;
  if (typeof scripts.install === "string")     dangerous.install     = scripts.install;
  if (typeof scripts.postinstall === "string") dangerous.postinstall = scripts.postinstall;
  if (typeof scripts.prepare === "string")     dangerous.prepare     = scripts.prepare;

  const hasInstallScript = Object.keys(dangerous).length > 0;
  const whitelisted = DEFAULT_WHITELIST.has(name) || customWhitelist.has(name);

  const result: ScriptCheckResult = {
    package: name,
    version: ver,
    scripts: dangerous,
    hasInstallScript,
    whitelisted,
  };

  cache.set(key, result);
  return result;
}

export async function checkAllInstallScripts(
  deps: Record<string, string>,
  customWhitelist: string[] = [],
  onProgress?: (done: number, total: number) => void
): Promise<ScriptCheckResult[]> {
  const wlSet = new Set(customWhitelist);
  const entries = Object.entries(deps);
  const results: ScriptCheckResult[] = [];
  const CONCURRENCY = 12;

  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const slice = entries.slice(i, i + CONCURRENCY);
    const settled = await Promise.all(
      slice.map(([name, ver]) => checkInstallScripts(name, ver, wlSet))
    );
    for (const r of settled) {
      // Only return the actionable hits: install scripts present AND not whitelisted.
      if (r && r.hasInstallScript && !r.whitelisted) results.push(r);
    }
    onProgress?.(Math.min(i + CONCURRENCY, entries.length), entries.length);
  }

  return results;
}

export function clearScriptCache(): void {
  cache.clear();
}

export function isWhitelisted(name: string, customWhitelist: string[] = []): boolean {
  return DEFAULT_WHITELIST.has(name) || customWhitelist.includes(name);
}

/**
 * True if the only install-time hook a package ships is `prepare`.
 *
 * Per the npm docs, `prepare` runs (a) before `npm publish`/`npm pack` on
 * the maintainer's machine and (b) when installing from a git URL or a
 * local folder. It does NOT run when `npm install <name>` pulls from the
 * npm registry — which is the overwhelmingly common case. So a package
 * with only a `prepare` hook is NOT an install-time attack vector for
 * registry installs and flagging it generates false-positive noise.
 *
 * `preinstall`/`install`/`postinstall` run on every registry install and
 * remain the real attack surface.
 */
export function isPrepareOnly(result: ScriptCheckResult): boolean {
  const keys = Object.keys(result.scripts);
  if (keys.length === 0) return false;
  return keys.length === 1 && keys[0] === "prepare";
}
