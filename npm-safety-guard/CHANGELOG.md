# Changelog

All notable changes to NPM Safety Guard will be documented here.

## [1.7.0] — 2026-04-19

### Added
- **Typosquat detector** — Damerau-Levenshtein distance against a curated 250-package top-popular list. Catches `axioss → axios`, `loadash → lodash`, `expres → express`, `raect → react` (transposition handled), `chal-k → chalk`, and `mongose → mongoose`. Length pre-filter keeps the comparison ~O(n) per dep.
- **Homoglyph detector** — recognises 30+ Cyrillic and Greek lookalikes (`а`/`a`, `с`/`c`, `е`/`e`, `о`/`o`, `р`/`p`, `х`/`x`, `α`, `ε`, `ο`, `ρ`, etc.). After mapping to ASCII, if the normalised name hits a popular package, raises ERROR severity. Catches `rеact` (Cyrillic 'е') and `аxios` (Cyrillic 'а').
- **Non-ASCII package name flag** — packages with Unicode chars that don't normalise to a known popular name still get a warning with the exact code points (`U+65E5 U+672C U+8A9E`).
- **Purple inline decoration** with `⚠ TYPOSQUAT?` marker; hover shows the closest match plus a ready-to-paste `npm uninstall` + `npm install` fix snippet.
- New setting `npmSafetyGuard.enableTyposquat` (default on) and command `NPM Safety Guard: Check Typosquats / Homoglyphs`.
- Pure offline — zero HTTP, runs synchronously inside auto-scan.

## [1.6.0] — 2026-04-19

### Added
- **Registry heuristics scanner** — new command `NPM Safety Guard: Compute Risk Heuristics (age / maintainers / downloads)` queries npm registry metadata and scores each dependency 0–100 on:
  - Package age (< 30 days = +35, < 90 = +15)
  - Version age (< 7 days = +10)
  - Maintainer takeover — latest version published by an account NOT in the maintainers list (+40, strong signal). Same publisher rotated to a known co-maintainer is downgraded to +5 (normal).
  - Single-maintainer projects (+5, low bus-factor)
  - Deprecated flag (+40, with the deprecation message)
  - Weekly download velocity (< 100 = +20, < 1000 = +8)
- Dedicated webview report sorted by score, with metric line per-package (age, maintainers, publisher, downloads).
- Tested against `axios`, `lodash`, `chalk`, `request`, `left-pad`, `ms`, `is-thirteen`. Correctly flags `request` and `left-pad` as DEPRECATED. False-positive prevention: `ms` no longer flagged as takeover because publisher rotation between known maintainers is treated as benign.

## [1.5.0] — 2026-04-19

### Added
- **Lockfile scanner** — new command `NPM Safety Guard: Scan Lockfile (full resolved tree)` parses `package-lock.json` (npm v1/v2/v3) and `yarn.lock` (classic v1), extracts every resolved `name@version` in the full dependency tree, and runs the bundled DB + remote feed + OSV.dev CVE lookup + install-script audit against each.
- **Closes the transitive-compromise gap** surfaced during v1.4.0 test-drive: a package.json-only scan misses bundled malware like `flatmap-stream@0.1.1` (shipped via `event-stream@3.3.6`). The lockfile scan walks every pinned version.
- **Dedicated webview report** with summary stats, per-layer hit blocks, and a "Multiple Versions Resolved" section that flags duplicate-version oddities (dep-confusion signal).

## [1.4.1] — 2026-04-19

### Fixed
- **False-positive removed:** `new Function('return this')()` / `new Function('return globalThis')()` (the ubiquitous globalThis polyfill used by lodash, jQuery, axios, core-js, etc.) is no longer flagged. Post-match benign-pattern filter in the detector loop.
- **Download failures now visible:** packages whose tarball returns 404 (unpublished, typo, or network error) are now surfaced in the Deep Scan report with a dedicated "Unreachable" stat. Previously they were silently dropped, making failed scans look "clean".

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
