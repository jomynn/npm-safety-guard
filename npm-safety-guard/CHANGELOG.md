# Changelog

All notable changes to NPM Safety Guard will be documented here.

## [1.3.0] — 2026-04-19

### Added
- **Install-script auditor** — every dependency's published `preinstall` / `install` / `postinstall` / `prepare` script is fetched from the npm registry and flagged. These hooks run before any of your code with full filesystem and network access — the #1 supply-chain attack vector (Shai-Hulud, Lazarus, Axios all use them).
- **Curated whitelist** of ~30 packages that legitimately need install scripts (bcrypt, sharp, esbuild, husky, prisma, sqlite3, electron, puppeteer, etc.) — these are silenced by default.
- **Gold dashed inline decoration** with `⚠ install script` marker; hover shows the actual hook command(s) and mitigations (`npm install --ignore-scripts`).
- **New settings:** `npmSafetyGuard.enableScriptCheck` (default on), `npmSafetyGuard.scriptWhitelist` (string array for custom whitelisting).
- **New command:** `NPM Safety Guard: Audit Install Scripts (preinstall/postinstall)`.

## [1.2.1] — 2026-04-19

### Changed
- Refreshed README and added this CHANGELOG for the Marketplace listing.

## [1.2.0] — 2026-04-19

### Added
- **Remote malware feed** — the extension now fetches a community-maintained list from GitHub on activation (cached 24h, ETag-aware). New supply-chain attacks show up in all installs without a republish.
- **New settings:** `npmSafetyGuard.enableRemoteDb`, `npmSafetyGuard.remoteDbUrl`.
- **New command:** `NPM Safety Guard: Refresh Malware Database`.
- **Four new malware entries** seeded into the feed:
  - `@ctrl/tinycolor` 4.1.1–4.1.2 — Shai-Hulud worm (Sept 2025, ~$50M in crypto stolen)
  - `rxnt-authentication` — Shai-Hulud propagation target
  - `ngx-toastr` 19.0.1–19.0.2 — Shai-Hulud 2.0 preinstall payload (Nov 2025)
  - `bigmathutils` — Lazarus/Marstech Mayhem DPRK campaign

### Changed
- `checkPackage()` and `checkDependencies()` now consult the bundled DB **plus** the remote feed.

## [1.1.0] — 2026-04-19

### Added
- **Always-on OSV.dev CVE scanning** — every open/save queries Google's OSV.dev for known CVEs. Free, unauthenticated, no rate limit.
- **New setting:** `npmSafetyGuard.enableOSV` (default on).
- **New command:** `NPM Safety Guard: Scan with OSV.dev (CVEs)`.
- Blue inline decorations for OSV CVE hits, distinct from red (bundled malware) and amber (ReversingLabs).
- Hover cards showing CVE IDs, aliases (CVE/GHSA), fixed versions, and advisory links.

## [1.0.0] — 2026-04-12

### Added
- Initial release.
- Bundled database of 6 known supply-chain attacks: axios, plain-crypto-js, @shadanai/openclaw, @qqbrowser/openclaw-qbot, event-stream, node-ipc.
- Inline warnings on `package.json`, Problems-panel diagnostics, status-bar shield indicator, security-report webview.
- Optional ReversingLabs Spectra Assure Community integration for deep CVE + malware analysis.
