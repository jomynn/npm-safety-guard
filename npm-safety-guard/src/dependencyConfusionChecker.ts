/**
 * NPM Safety Guard — Dependency Confusion Detector (Layer 9)
 *
 * Dependency confusion attacks publish a malicious package to the PUBLIC npm
 * registry under a scoped name that mirrors a private internal package (e.g.
 * @mycompany/auth). npm resolves the HIGHEST version, so an attacker publishing
 * @mycompany/auth@99.0.0 beats your private registry's @mycompany/auth@1.0.0.
 *
 * Detection heuristics (both conditions must hold):
 *  1. The package scope is NOT in the well-known-public list.
 *  2. The package EXISTS on the public npm registry.
 *  Then EITHER:
 *   a. Version inflation: public latest is ≥10 major versions ahead of pinned.
 *   b. Fresh plant: package created < 90 days ago, same-or-higher major,
 *      and < 50 weekly downloads (attacker just planted it).
 *
 * Returns null for packages that do not hit either signal. Zero false positives
 * for well-known scopes. Results are cached in-memory.
 */

import * as https from "https";

const REGISTRY_HOST = "registry.npmjs.org";
const DOWNLOADS_HOST = "api.npmjs.org";

const cache = new Map<string, ConfusionResult | null>();

export interface ConfusionResult {
  package: string;
  version: string;       // pinned version in package.json
  publicLatest: string;  // latest version on public npm
  riskLevel: "high" | "critical";
  reason: string;
}

// ─── Well-known public scopes — always skip (legitimately on npm) ─────────────

const KNOWN_PUBLIC_SCOPES = new Set([
  "@angular", "@angular-devkit", "@schematics",
  "@vue", "@vueuse", "@nuxt",
  "@nestjs",
  "@babel",
  "@types",
  "@jest-community",
  "@swc",
  "@storybook",
  "@aws-sdk", "@aws-amplify",
  "@google-cloud", "@googleapis",
  "@microsoft", "@azure",
  "@firebase",
  "@mui", "@emotion",
  "@tanstack",
  "@reduxjs",
  "@testing-library",
  "@apollo",
  "@prisma",
  "@sentry",
  "@stripe", "@sendgrid", "@twilio", "@paypal",
  "@opentelemetry",
  "@rollup", "@vitejs", "@esbuild",
  "@electron",
  "@capacitor", "@ionic",
  "@nrwl", "@nx",
  "@typescript-eslint", "@eslint", "@prettier",
  "@commitlint", "@semantic-release",
  "@vercel", "@netlify",
  "@trpc",
  "@remix-run", "@sveltejs", "@astrojs",
  "@hapi", "@fastify",
  "@radix-ui", "@headlessui", "@tailwindcss", "@chakra-ui", "@mantine",
  "@shopify",
  "@datadog",
  "@codemirror", "@lezer",
  "@octokit", "@actions",
  "@tensorflow",
  "@langchain", "@anthropic-ai", "@openai", "@huggingface",
  "@supabase", "@clerk", "@auth0",
  "@nextui-org", "@shadcn",
  "@floating-ui", "@dnd-kit",
  "@framer",
  "@uiw", "@ant-design", "@arco-design",
  "@element-plus", "@vant", "@quasar",
  "@expo", "@react-native-community",
  "@socket.io",
  "@ethersproject", "@metamask", "@openzeppelin",
]);

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function get(host: string, path: string): Promise<any> {
  return new Promise((resolve) => {
    const req = https.request(
      { hostname: host, path, method: "GET", headers: { Accept: "application/json" } },
      (res) => {
        if (res.statusCode === 404) { res.resume(); resolve(null); return; }
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode === 200) {
            try { resolve(JSON.parse(data)); } catch { resolve(null); }
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
  return `/${encodeURIComponent(name).replace(/^%40/, "@")}`;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseMajor(v: string): number {
  const clean = v.replace(/[\^~>=<\s*]/g, "").split(/[-+]/)[0];
  return parseInt(clean.split(".")[0], 10) || 0;
}

function daysSince(iso: string): number {
  const t = Date.parse(iso);
  if (!isFinite(t)) return Infinity;
  return (Date.now() - t) / 86_400_000;
}

// ─── Core check ───────────────────────────────────────────────────────────────

export async function checkDependencyConfusion(
  name: string,
  version: string
): Promise<ConfusionResult | null> {
  if (!name.startsWith("@")) return null;
  const slash = name.indexOf("/");
  if (slash < 0) return null;

  const scope = name.slice(0, slash);
  if (KNOWN_PUBLIC_SCOPES.has(scope)) return null;

  const cacheKey = `${name}@${version}`;
  if (cache.has(cacheKey)) return cache.get(cacheKey)!;

  const meta = await get(REGISTRY_HOST, packagePath(name));
  if (!meta || typeof meta !== "object") {
    // Package not on public npm — no confusion risk
    cache.set(cacheKey, null);
    return null;
  }

  const distTags = (meta as any)["dist-tags"] ?? {};
  const latestPublic: string | undefined = distTags.latest;
  if (!latestPublic) {
    cache.set(cacheKey, null);
    return null;
  }

  const pinnedMajor = parseMajor(version);
  const publicMajor = parseMajor(latestPublic);

  // Signal 1: Version inflation — attacker publishes 99.0.0 to beat your 1.x
  if (publicMajor >= 10 && publicMajor > pinnedMajor + 9) {
    const result: ConfusionResult = {
      package: name,
      version,
      publicLatest: latestPublic,
      riskLevel: "critical",
      reason:
        `Public npm has ${name}@${latestPublic} (major ${publicMajor}) but you are pinned to ${version} (major ${pinnedMajor}). ` +
        `A gap of ${publicMajor - pinnedMajor} major versions is the dependency confusion version-inflation pattern. ` +
        `If you use a private registry, npm may resolve the public version instead.`,
    };
    cache.set(cacheKey, result);
    return result;
  }

  // Signal 2: Freshly planted clone — new package, low downloads
  const time = (meta as any).time ?? {};
  const created: string | undefined = time.created;
  const ageDays = created ? daysSince(created) : Infinity;

  if (ageDays < 90 && publicMajor >= pinnedMajor) {
    const dlData = await get(
      DOWNLOADS_HOST,
      `/downloads/point/last-week/${encodeURIComponent(name).replace(/^%40/, "@")}`
    );
    const weeklyDownloads: number | undefined =
      dlData && typeof (dlData as any).downloads === "number"
        ? (dlData as any).downloads
        : undefined;

    if (weeklyDownloads !== undefined && weeklyDownloads < 50) {
      const result: ConfusionResult = {
        package: name,
        version,
        publicLatest: latestPublic,
        riskLevel: "high",
        reason:
          `"${name}" exists on public npm (@${latestPublic}), was created ${Math.floor(ageDays)} days ago, ` +
          `and has only ${weeklyDownloads} downloads/week. ` +
          `This matches a freshly planted dependency confusion package. Verify this is a legitimate public release.`,
      };
      cache.set(cacheKey, result);
      return result;
    }
  }

  cache.set(cacheKey, null);
  return null;
}

// ─── Batch check ─────────────────────────────────────────────────────────────

export async function checkAllDependencyConfusion(
  deps: Record<string, string>,
  onProgress?: (done: number, total: number) => void
): Promise<ConfusionResult[]> {
  const entries = Object.entries(deps).filter(([name]) => name.startsWith("@"));
  const results: ConfusionResult[] = [];
  const CONCURRENCY = 4; // two HTTP calls per package — be conservative

  let done = 0;
  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const slice = entries.slice(i, i + CONCURRENCY);
    const settled = await Promise.all(
      slice.map(([name, ver]) => checkDependencyConfusion(name, ver))
    );
    for (const r of settled) {
      done++;
      if (r) results.push(r);
    }
    onProgress?.(Math.min(done, entries.length), entries.length);
  }

  return results;
}

export function clearConfusionCache(): void {
  cache.clear();
}
