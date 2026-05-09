# Changelog

All notable changes to NPM Safety Guard will be documented here.

## [1.8.9] — 2026-05-09

### Fixed
- **Relative edit-distance threshold** — the typosquat detector now gates on `distance / max(nameLen, targetLen) ≤ 30%` instead of the previous absolute `≤ 2 edits`. Short-named packages that happened to be within 2 edits of a popular package by coincidence (e.g. `konva → koa`: 2 edits but 40% different) are no longer flagged. True typosquats like `axioss → axios` (1 edit, 17%) still trigger correctly.
- **JS/TS suffix stripping** — packages that are legitimate wrappers or typed variants of a popular package (e.g. `expressjs`, `vue-js`, `ts-node`) are now silenced automatically before the DL comparison. The suffix/prefix patterns stripped: `-js`, `.js`, `js-`, `js.`, `-ts`, `.ts`, `ts-`, `ts.`.

### Added
- **"Add to typosquat whitelist" lightbulb action** — every typosquat warning now shows a one-click `➕ Add "<name>" to typosquat whitelist (false positive)` code action. Clicking it writes to your workspace (or user) `settings.json` and immediately rescans — no manual settings editing required.
- **"Verify on npmjs" link in hover card** — the typosquat hover now shows two links side by side: `View "<closest>" on npmjs.com · Verify "<flagged>" on npmjs.com`. Previously only the closest-match package was linked; the flagged package itself had no direct link, making it awkward to verify a false positive.

## [1.8.8] — 2026-05-09

### Fixed
- **Typosquat false positives on well-known short-named packages.** Packages like `konva` (HTML5 Canvas), `pug`, `ejs`, `mitt`, `pinia`, `swiper`, `execa`, and ~25 others were incorrectly flagged because their short names happen to land within edit-distance 2 of a popular package (e.g. `konva` → `koa`). All have been added to the built-in known-good list and are now silenced automatically.

### Added
- **`npmSafetyGuard.typosquatWhitelist`** — new setting (string array, default `[]`). Add any package name here to permanently suppress its typosquat / homoglyph warning. Useful for internal or niche packages not covered by the built-in list. Works identically to `scriptWhitelist`.

## [1.8.7] — 2026-04-21

### Added
- **Bulk CVE auto-fix.** Two new commands let you clear every OSV CVE finding in one keystroke — previously you had to click the lightbulb on each diagnostic individually, which doesn't scale when `npm audit` finds 30+ CVEs across a monorepo.
  - `NPM Safety Guard: Fix All CVEs in This File` — pins every vulnerable package in the current `package.json` to its highest known fix version (caret range `^X.Y.Z`).
  - `NPM Safety Guard: Fix All CVEs in Workspace` — walks every `package.json` with OSV diagnostics in the workspace and applies fixes across all of them in a single atomic edit.
- **Post-fix prompt** with two actions:
  - **Run npm install** — spawns one terminal per affected workspace folder with the correct `cwd`, so monorepos install each project in its own directory.
  - **Show diff** — opens the Git diff view for the changed file (single-file fix only).
- De-duplication per file: if a package has multiple CVE diagnostics, the highest fix version wins — one bump covers every advisory.

### Changed
- `parseNameVersion`, `extractHighestFixVersion`, and `findVersionRange` are now exported from `codeActions.ts` for reuse by the bulk fixer. No behavior change for the per-line lightbulb fixes.

### Docs
- `.github/FUNDING.yml` added — repo now shows a GitHub "Sponsor" button.
- README gains a Sponsors & Support section with GitHub Sponsors, Open Collective, and Ko-fi links.

## [1.8.3] — 2026-04-19

### Fixed
- **No more `prepare`-hook false positives.** The install-script auditor previously flagged every package that declared *any* install hook, including `prepare`. Per the [npm docs](https://docs.npmjs.com/cli/v10/using-npm/scripts#npm-install), `prepare` only runs when installing from a git URL or local folder — NOT when installing from the npm registry (the common case). So flagging packages like `axios`, `zod`, `uuid`, `bullmq`, `posthog-js`, `recharts`, `@anthropic-ai/sdk`, `expo-av`, `expo-camera`, and friends was noise. They're now silenced by default.
- `preinstall`, `install`, and `postinstall` — the hooks that actually run on every registry install — remain flagged as the real attack surface.

### Added
- New setting `npmSafetyGuard.flagPrepareHooks` (default `false`). Set to `true` if you install dependencies via `npm install git+https://...` or from local folders, where `prepare` does execute.

## [1.8.2] — 2026-04-19

### Fixed
- **Status bar shield now reflects the full workspace.** Previously it only showed bundled-malware hits from the *last-scanned file* — so a workspace with 70 real findings (32 CVEs + 38 install hooks) could still display "NPM Safe" because the last file had no known-malicious entries. The shield now aggregates every NPM Safety Guard diagnostic across every open file and shows a compact breakdown:
  - `🛡 NPM Safe` when truly nothing flagged
  - `⚠ 3 THREATS +12 more` when malware or homoglyphs are present (red background)
  - `⚠ 32 CVEs · 38 hooks` when only CVEs / scripts flagged (yellow background)
  - Hover reveals a full per-layer breakdown (🔴 Malware / 🔵 CVE / 🟣 Typosquat / 🟡 Install hook / 🟠 RL) and the affected-file count.
- Every async layer (OSV, install-scripts, typosquat, RL) now triggers a status-bar refresh after writing diagnostics, so the shield stays accurate as scans complete in the background.

## [1.8.1] — 2026-04-19

### Changed
- README now lists the quick-fix code actions row in the detection-layer table so the Marketplace listing reflects v1.8 capabilities.

## [1.8.0] — 2026-04-19

### Added
- **Quick-fix code actions** on every flagged dependency. Click the lightbulb (or `Cmd+.` / `Ctrl+.`) on a red / blue / purple / gold line to get one-click fixes:
  - 🔴 **Malware:** `Pin to safe version X.Y.Z` + `Remove ... from dependencies`
  - 🔵 **CVE:** `Upgrade to CVE fix version X.Y.Z` — picks the **highest** fix version across all listed CVEs so one bump covers every advisory in the diagnostic
  - 🟣 **Typosquat / homoglyph:** `Replace "<typo>" with "<correct name>"` — in-place name edit, version preserved
  - 🟡 **Install script:** `Add "<name>" to install-script whitelist` — writes to workspace `settings.json` (or user settings if no workspace) and immediately re-scans so the warning drops
- **Caret range on pin actions** (`^X.Y.Z`) so future patch/minor releases still update with `npm install`, but any fixed version unlocks at the right floor.
- All actions include `isPreferred: true` where unambiguous so they rank first in the lightbulb menu.

## [1.7.3] — 2026-04-19

### Fixed
- **Race condition in Security Report.** v1.7.2 aggregated diagnostics from all layers, but `scanDocument` fires OSV and install-script checks as fire-and-forget promises — so a first-time click on "Show Report" read the diagnostic collection before those async scans had landed, still showing partial or empty data. The report now **awaits** OSV + install-script scans per file and shows a progress notification (`Building security report from N package.json files…`) so the user knows it's working. By the time the webview renders, every layer's diagnostics have been collected.

## [1.7.2] — 2026-04-19

### Fixed
- **Security Report webview now aggregates ALL detection layers.** Previously it only queried the bundled malware DB, so workspaces with dozens of real OSV CVE findings or install-script warnings in the Problems panel would still see a misleading "All Clear ✅" in the report. The report now pulls every diagnostic from every source (malware / CVE / typosquat / install-script / ReversingLabs), groups them by package, and shows per-layer counts in the summary stats.
- **Summary stats expanded** from 3 tiles to 6: Total Findings / Malware / CVEs / Typosquats / Install Hooks / Files Scanned — so the one-glance view matches the Problems panel.

## [1.7.1] — 2026-04-19

### Changed
- README rewritten with the complete 8-layer matrix, live-attack coverage table, all 10 commands, and a clean privacy section. The Marketplace listing now reflects everything shipped between v1.0 and v1.7.

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
