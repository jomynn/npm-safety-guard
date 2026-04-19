# 🛡 NPM Safety Guard

> Built by [SendWaveHub](https://sendwavehub.tech) — SaaS tools for developers

Detects malicious npm packages and CVE vulnerabilities in your `package.json` **before** you run `npm install`. Zero config, zero signup, works offline.

## Features

- 🔴 **Live malware DB** — bundled list of known supply chain attacks (Shai-Hulud, Axios/DPRK RAT, Lazarus/Marstech, event-stream, node-ipc, more), auto-refreshed daily from a community feed on GitHub
- 🟡 **Install-script auditor** — flags every dependency that ships `preinstall` / `install` / `postinstall` / `prepare` hooks (the #1 attack vector). Curated whitelist for legit packages
- 🔵 **OSV.dev CVE scanning** — every save queries Google's OSV.dev for every known CVE in the npm ecosystem. Free, no API key required
- 🟠 **ReversingLabs deep scan** — optional premium CVE + malware analysis (free token at [secure.software](https://secure.software))
- 📋 **Security Report** webview with fix instructions and copy-ready `npm install` commands
- 💡 **Inline warnings** on the exact line of the bad dependency, with hover cards showing CVE IDs, fixed versions, and advisory links
- 📌 **Status bar** shield indicator — always visible
- 🔌 **Offline-first** — bundled DB works without network; remote feed and OSV are fail-open

## Detection layers

| Layer | Default | What it catches | Needs network? |
|---|---|---|---|
| Bundled malware DB | ✅ on | Known supply-chain attacks (curated) | No |
| Remote malware feed | ✅ on | Community feed, refreshed every 24h | Yes (fail-open) |
| OSV.dev CVE scan | ✅ on | Every known CVE across npm ecosystem | Yes (fail-open) |
| Install-script audit | ✅ on | Packages with preinstall/postinstall hooks | Yes (fail-open) |
| ReversingLabs deep scan | Opt-in | Binary analysis, tampering detection | Yes (token required) |

## Covered attacks (bundled + remote)

| Package | Versions | Campaign |
|---|---|---|
| `axios` | 1.14.1, 0.30.4 | 🔴 Sapphire Sleet (DPRK) RAT drop, Mar 2026 |
| `plain-crypto-js` | 4.2.1 | 🔴 RAT dropper (WAVESHAPER.V2) |
| `@shadanai/openclaw` | 2026.3.x | 🔴 Axios campaign vector |
| `@qqbrowser/openclaw-qbot` | 0.0.130 | 🔴 Axios campaign vector |
| `@ctrl/tinycolor` | 4.1.1, 4.1.2 | 🔴 Shai-Hulud worm, Sept 2025 |
| `rxnt-authentication` | all | 🔴 Shai-Hulud worm propagation |
| `ngx-toastr` | 19.0.1, 19.0.2 | 🔴 Shai-Hulud 2.0 (preinstall), Nov 2025 |
| `bigmathutils` | all | 🔴 Lazarus / Marstech Mayhem (DPRK) |
| `event-stream` | 3.3.6 | 🟠 Crypto wallet theft (2018) |
| `node-ipc` | 10.1.1-11.0.0 | 🟠 Protestware (2022) |

Plus every CVE in the npm ecosystem via OSV.dev — and the remote feed grows without extension updates.

## Commands

Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):

- **NPM Safety Guard: Scan package.json Now** — rerun the bundled + OSV scan
- **NPM Safety Guard: Show Security Report** — open the webview report
- **NPM Safety Guard: Scan with OSV.dev (CVEs)** — force-refresh OSV results
- **NPM Safety Guard: Check ReversingLabs (CVE + Malware)** — premium scan (needs token)
- **NPM Safety Guard: Refresh Malware Database** — pull the latest remote feed now
- **NPM Safety Guard: Audit Install Scripts (preinstall/postinstall)** — re-fetch and flag dependency install hooks

Or click the 🛡 shield in the status bar to open the security report.

## Settings

| Setting | Default | Description |
|---|---|---|
| `npmSafetyGuard.enableAutoScan` | `true` | Scan on open/save |
| `npmSafetyGuard.showInlineDecorations` | `true` | Show red/blue inline highlights |
| `npmSafetyGuard.enableOSV` | `true` | Query OSV.dev for CVEs (free, auto) |
| `npmSafetyGuard.enableRemoteDb` | `true` | Pull community malware feed every 24h |
| `npmSafetyGuard.remoteDbUrl` | *blank* | Override the malware feed URL |
| `npmSafetyGuard.enableScriptCheck` | `true` | Audit dependencies for install-time hooks |
| `npmSafetyGuard.scriptWhitelist` | `[]` | Extra package names to silence from script warnings |
| `npmSafetyGuard.rlToken` | *blank* | ReversingLabs Spectra Assure token ([get one free](https://secure.software)) |

## Privacy

- The **bundled DB** is 100% offline.
- The **OSV.dev scanner** sends `<package-name>@<version>` over HTTPS to `api.osv.dev`. Package names are public metadata from the npm registry.
- The **remote feed** is a plain HTTPS GET to `raw.githubusercontent.com`. No request body, no tracking.
- **ReversingLabs** calls happen only when you set a token and run the command.

All network calls are fail-open — if anything is unreachable, the extension keeps working with its offline layers.

## Reporting a new malicious package

Edit [`db/malicious-packages.json`](https://github.com/jomynn/npm-safety-guard/blob/main/db/malicious-packages.json) and open a PR. Entries go live in every install within 24h — no extension republish needed.

## Credits

- CVE data from [OSV.dev](https://osv.dev)
- Premium deep scan via [ReversingLabs Spectra Assure](https://secure.software)
- Inspired by [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) and [OSSF malicious-packages](https://github.com/ossf/malicious-packages)

## About

Maintained by [SendWaveHub](https://sendwavehub.tech). Check out our other developer tools at **[sendwavehub.tech](https://sendwavehub.tech)**.
