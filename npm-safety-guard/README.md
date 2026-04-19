# 🛡 NPM Safety Guard

> Built by [SendWaveHub](https://sendwavehub.tech) — SaaS tools for developers

Stops malicious npm packages, supply chain attacks, and known CVEs **before** `npm install` ever runs. Eight detection layers, zero signup, offline-capable.

```
$ code --install-extension Sendwavehubtech.npm-safety-guard
```

Or open the **Extensions** sidebar and search "NPM Safety Guard".

## Why

The npm ecosystem ships ~1 supply chain attack per week ([Shai-Hulud worm](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/), [Axios DPRK RAT](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/), [Lazarus/Marstech](https://thehackernews.com/2026/02/lazarus-campaign-plants-malicious.html), [event-stream](https://github.com/dominictarr/event-stream/issues/116)). Most discovery happens *after* developers have already run `npm install`. NPM Safety Guard catches them at the moment you open `package.json`.

## What it catches

| Layer | When it runs | Cost | Catches |
|---|---|---|---|
| 🔴 **Bundled malware DB** | every save | offline | Curated supply-chain attacks (Shai-Hulud, Axios, Lazarus, event-stream, node-ipc) |
| 🔴 **Remote feed** | every 24h | 1 HTTP/day | Community-maintained additions, no extension republish |
| 🔵 **OSV.dev CVE scan** | every save | 1 HTTP/dep | Every known CVE in the npm ecosystem |
| 🟡 **Install-script audit** | every save | 1 HTTP/dep | Packages with `preinstall`/`postinstall`/`prepare` hooks (the #1 attack vector) |
| 🟣 **Typosquat + homoglyph** | every save | offline, instant | `axioss → axios`, `rеact` (Cyrillic 'е'), Damerau-Levenshtein vs top-250 |
| 🔬 **Deep tarball AST scan** | command | N downloads | `eval`, `new Function`, base64 blobs, `String.fromCharCode` reconstruction, split-file payloads, Shai-Hulud `npm publish` self-propagation |
| 📋 **Lockfile walk** | command | 0 | Transitive compromises (catches `flatmap-stream@0.1.1` shipped via `event-stream@3.3.6`) |
| 📊 **Risk heuristics** | command | 2 HTTP/dep | 0–100 score from package age, maintainer takeover, deprecation, download velocity |
| 🟠 **ReversingLabs deep scan** | command (opt-in) | needs token | Binary tampering analysis ([free token](https://secure.software)) |

## Real attacks covered out of the box

| Package | Versions | Campaign |
|---|---|---|
| `axios` | 1.14.1, 0.30.4 | 🔴 Sapphire Sleet (DPRK) RAT, Mar 2026 |
| `plain-crypto-js` | 4.2.1 | 🔴 RAT dropper (WAVESHAPER.V2) |
| `@shadanai/openclaw` | 2026.3.x | 🔴 Axios campaign vector |
| `@qqbrowser/openclaw-qbot` | 0.0.130 | 🔴 Axios campaign vector |
| `@ctrl/tinycolor` | 4.1.1, 4.1.2 | 🔴 Shai-Hulud worm, Sept 2025 |
| `rxnt-authentication` | all | 🔴 Shai-Hulud worm propagation |
| `ngx-toastr` | 19.0.1, 19.0.2 | 🔴 Shai-Hulud 2.0 (preinstall), Nov 2025 |
| `bigmathutils` | all | 🔴 Lazarus / Marstech Mayhem (DPRK) |
| `event-stream` | 3.3.6 | 🟠 Crypto wallet theft (2018) |
| `node-ipc` | 10.1.1-11.0.0 | 🟠 Protestware (2022) |

Plus every CVE in the npm ecosystem via OSV.dev — and the [community feed](https://github.com/jomynn/npm-safety-guard/blob/main/db/malicious-packages.json) grows without extension updates.

## How it looks in your editor

Open any `package.json`. Within ~1 second you see:

- 🔴 **Red highlight** on lines with known-malicious packages
- 🟣 **Purple highlight** on typosquats / homoglyphs (`axioss`, `rеact` with Cyrillic 'е')
- 🟡 **Gold dashed** on packages with install hooks (with mitigation: `npm install --ignore-scripts`)
- 🔵 **Blue highlight** on packages with active CVEs (hover shows fix version)
- 📌 **Status bar** shield indicator with threat count

Hover any flagged line for the full report — CVE IDs, advisory links, fix commands.

## Commands

Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and type "NPM Safety Guard":

| Command | What it does |
|---|---|
| **Scan package.json Now** | Re-run all auto-scan layers |
| **Show Security Report** | Open the bundled-DB findings webview |
| **Scan with OSV.dev** | Force-refresh CVE results |
| **Audit Install Scripts** | Force-refresh install-hook check |
| **Refresh Malware Database** | Pull the latest community feed now |
| **Check Typosquats / Homoglyphs** | Force-refresh name-similarity check |
| **Compute Risk Heuristics** | 0–100 risk score per dep (age/maintainers/downloads) |
| **Deep Scan All Dependencies** | Tarball download + AST scan, opens detailed webview |
| **Scan Lockfile** | Walk `package-lock.json` / `yarn.lock`, check every transitive dep |
| **Check ReversingLabs** | Premium binary analysis (needs free token) |

## Settings

| Setting | Default | Description |
|---|---|---|
| `npmSafetyGuard.enableAutoScan` | `true` | Scan on open/save |
| `npmSafetyGuard.showInlineDecorations` | `true` | Inline highlights in package.json |
| `npmSafetyGuard.enableOSV` | `true` | Free CVE scan via OSV.dev |
| `npmSafetyGuard.enableRemoteDb` | `true` | Pull community malware feed every 24h |
| `npmSafetyGuard.remoteDbUrl` | *blank* | Override the malware feed URL |
| `npmSafetyGuard.enableScriptCheck` | `true` | Audit dependencies for install hooks |
| `npmSafetyGuard.scriptWhitelist` | `[]` | Extra packages to silence from script warnings |
| `npmSafetyGuard.enableTyposquat` | `true` | Name-similarity + homoglyph detection |
| `npmSafetyGuard.rlToken` | *blank* | ReversingLabs Spectra Assure token ([free at secure.software](https://secure.software)) |

## Privacy

- The **bundled DB**, **typosquat / homoglyph**, and **lockfile** layers are 100% offline.
- The **OSV.dev scanner** sends `<package-name>@<version>` over HTTPS to `api.osv.dev`. Package names are public metadata.
- The **remote feed** is a plain HTTPS GET to `raw.githubusercontent.com`. No request body, no tracking.
- The **install-script auditor** and **registry heuristics** call `registry.npmjs.org` and `api.npmjs.org` — same as `npm install` does.
- The **deep tarball scanner** downloads `.tgz` files from `registry.npmjs.org` (the same artifacts npm fetches).
- **ReversingLabs** is opt-in and only runs when you set a token and invoke the command.

All network calls are fail-open — if anything is unreachable, every other layer keeps working.

## Reporting a new malicious package

1. Edit [`db/malicious-packages.json`](https://github.com/jomynn/npm-safety-guard/blob/main/db/malicious-packages.json) on GitHub
2. Open a PR
3. Once merged, every install picks it up within 24h

## Credits

- CVE data from [OSV.dev](https://osv.dev) (Google)
- Premium deep scan via [ReversingLabs Spectra Assure](https://secure.software)
- Inspired by [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) and [OSSF malicious-packages](https://github.com/ossf/malicious-packages)

## About

Maintained by [SendWaveHub](https://sendwavehub.tech). Check out our other developer tools at **[sendwavehub.tech](https://sendwavehub.tech)**.

Found this useful? ⭐️ the [GitHub repo](https://github.com/jomynn/npm-safety-guard) and leave a review on the [Marketplace](https://marketplace.visualstudio.com/items?itemName=Sendwavehubtech.npm-safety-guard).
