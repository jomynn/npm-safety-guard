# Changelog

All notable changes to NPM Safety Guard will be documented here.

## [1.4.0] — 2026-04-19

### Added
- **Deep scanner** — new command `NPM Safety Guard: Deep Scan All Dependencies (tarball AST)` fetches each package's published tarball from registry.npmjs.org, gunzips, parses tar, and runs 14 regex-based detectors against every JS/TS file inside.
- **Detectors:** `eval`, `new Function`, `vm.runInContext`, dynamic `require(variable)`, `child_process`, `String.fromCharCode` reconstruction, large base64 blobs (>500 chars), array-of-strings `.join('')` patterns (split-file payload signature), filesystem writes to credential paths (`.ssh`, `.aws`, `.bashrc`, `.npmrc`), network exfil endpoints (Discord webhooks, Telegram bot API, Slack hooks, IP lookup services), Shai-Hulud-style `npm publish` shell-out, `curl`/`wget`/`powershell` runtime payload download, `_0x`-prefixed obfuscated identifiers, and zero-width/RTL Unicode in source.
- **Dedicated webview report** with per-package severity cards, finding snippets, file:line locations, and npm links.
- Scan capped at 50 dependencies per run (4-way concurrent, 10s timeout per tarball). Process-lifetime cache.
- **Zero new runtime dependencies** — pure built-in (`https` + `zlib`). Custom tar parser supports USTAR, GNU long-name, and PAX extended headers.

### Why this matters
- Catches the split-file payload assembly attack (code split across multiple files and merged+eval'd at runtime) that signature-based scanners miss.
- Catches Shai-Hulud's self-propagation signature before install.
- Catches `eval(Buffer.from(base64Blob).toString())` patterns regardless of which CVE database knows about them.

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
