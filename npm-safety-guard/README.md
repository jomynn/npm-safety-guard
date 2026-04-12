# NPM Safety Guard

Scans your `package.json` for known malicious npm packages **before** you install them.

## Features

- 🔴 **Inline warnings** directly in `package.json` with hover details
- 🔔 **Notification popup** when threats are detected on open/save  
- 📋 **Security Report** webview with fix instructions
- 📌 **Status bar indicator** — always visible shield icon
- 🗄️ **Extensible DB** — add new malicious packages as they are discovered

## Detected Threats

| Package | Bad Versions | Severity |
|---|---|---|
| `axios` | 1.14.1, 0.30.4 | 🔴 CRITICAL |
| `plain-crypto-js` | 4.2.1 | 🔴 CRITICAL |
| `@shadanai/openclaw` | 2026.3.x | 🔴 CRITICAL |
| `event-stream` | 3.3.6 | 🟠 HIGH |
| `node-ipc` | 10.1.1-11.0.0 | 🟠 HIGH |

## Usage

- Open any `package.json` — auto-scan runs immediately
- `Ctrl+Shift+P` → **NPM Safety Guard: Scan Now**
- `Ctrl+Shift+P` → **NPM Safety Guard: Show Security Report**
- Click the shield icon in the status bar

## Settings

| Setting | Default | Description |
|---|---|---|
| `npmSafetyGuard.enableAutoScan` | `true` | Scan on open/save |
| `npmSafetyGuard.showInlineDecorations` | `true` | Show red highlights |

## Adding New Malicious Packages

Edit `src/maliciousDb.ts` and add entries to `MALICIOUS_DB`.
