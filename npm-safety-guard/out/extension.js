"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const maliciousDb_1 = require("./maliciousDb");
const rlChecker_1 = require("./rlChecker");
const osvChecker_1 = require("./osvChecker");
const remoteDb_1 = require("./remoteDb");
// ─── Globals ──────────────────────────────────────────────────────────────────
let diagnosticCollection;
let statusBarItem;
let decorationType;
let osvDecorationType;
// ─── Activation ───────────────────────────────────────────────────────────────
function activate(context) {
    console.log("NPM Safety Guard is active");
    // Pull the remote malicious-package feed in the background — non-blocking.
    void refreshRemoteDb(context);
    // Diagnostic collection (Problems panel)
    diagnosticCollection = vscode.languages.createDiagnosticCollection("npm-safety-guard");
    context.subscriptions.push(diagnosticCollection);
    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = "npmSafetyGuard.showReport";
    context.subscriptions.push(statusBarItem);
    // Inline decoration type (red gutter icon + highlight)
    decorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: "rgba(220, 38, 38, 0.15)",
        border: "1px solid rgba(220, 38, 38, 0.5)",
        borderRadius: "2px",
        gutterIconPath: context.asAbsolutePath("images/warning.svg"),
        gutterIconSize: "contain",
        overviewRulerColor: "rgba(220, 38, 38, 0.8)",
        overviewRulerLane: vscode.OverviewRulerLane.Right,
        after: {
            contentText: "  ⚠ MALICIOUS PACKAGE",
            color: "rgba(220, 38, 38, 0.9)",
            fontWeight: "bold",
            fontStyle: "normal"
        }
    });
    // CVE decoration type (amber highlight for ReversingLabs findings)
    const cveDecorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: "rgba(217, 119, 6, 0.12)",
        border: "1px solid rgba(217, 119, 6, 0.4)",
        borderRadius: "2px",
        overviewRulerColor: "rgba(217, 119, 6, 0.8)",
        overviewRulerLane: vscode.OverviewRulerLane.Right,
        after: {
            contentText: "  ⚠ CVE VULNERABILITY",
            color: "rgba(217, 119, 6, 0.9)",
            fontWeight: "bold",
        },
    });
    context.subscriptions.push(cveDecorationType);
    // OSV.dev decoration type (blue highlight — free CVE feed, always-on)
    osvDecorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: "rgba(56, 139, 253, 0.10)",
        border: "1px solid rgba(56, 139, 253, 0.35)",
        borderRadius: "2px",
        overviewRulerColor: "rgba(56, 139, 253, 0.8)",
        overviewRulerLane: vscode.OverviewRulerLane.Right,
        after: {
            contentText: "  ⚠ CVE (OSV)",
            color: "rgba(56, 139, 253, 0.95)",
            fontWeight: "bold",
        },
    });
    context.subscriptions.push(osvDecorationType);
    // Commands
    context.subscriptions.push(vscode.commands.registerCommand("npmSafetyGuard.scanNow", () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && isPackageJson(editor.document)) {
            scanDocument(editor.document, editor);
        }
        else {
            // Try to find package.json in workspace
            vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 10).then(uris => {
                if (uris.length === 0) {
                    vscode.window.showInformationMessage("No package.json found in workspace.");
                    return;
                }
                uris.forEach(uri => {
                    vscode.workspace.openTextDocument(uri).then(doc => scanDocument(doc));
                });
                vscode.window.showInformationMessage(`Scanned ${uris.length} package.json file(s).`);
            });
        }
    }), vscode.commands.registerCommand("npmSafetyGuard.showReport", () => {
        showWebviewReport(context);
    }));
    context.subscriptions.push(vscode.commands.registerCommand("npmSafetyGuard.refreshDb", async () => {
        const result = await refreshRemoteDb(context, /*force*/ true);
        const msg = result.source === "network"
            ? `NPM Safety Guard: Fetched ${result.entries.length} remote entries.`
            : result.source === "cache"
                ? `NPM Safety Guard: Network unreachable — using cached ${result.entries.length} entries.`
                : "NPM Safety Guard: No remote entries available.";
        vscode.window.showInformationMessage(msg);
    }));
    context.subscriptions.push(vscode.commands.registerCommand("npmSafetyGuard.scanOSV", async () => {
        (0, osvChecker_1.clearOSVCache)();
        const editor = vscode.window.activeTextEditor;
        if (editor && isPackageJson(editor.document)) {
            await scanWithOSV(editor.document, editor);
        }
        else {
            const uris = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 20);
            for (const uri of uris) {
                const doc = await vscode.workspace.openTextDocument(uri);
                await scanWithOSV(doc);
            }
            vscode.window.showInformationMessage(`NPM Safety Guard (OSV): Scanned ${uris.length} file(s).`);
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand("npmSafetyGuard.checkRL", async () => {
        const token = vscode.workspace.getConfiguration("npmSafetyGuard")
            .get("rlToken", "");
        if (!token) {
            const action = await vscode.window.showWarningMessage("NPM Safety Guard: No ReversingLabs token configured.", "Open Settings");
            if (action === "Open Settings") {
                vscode.commands.executeCommand("workbench.action.openSettings", "npmSafetyGuard.rlToken");
            }
            return;
        }
        (0, rlChecker_1.clearRLCache)();
        const editor = vscode.window.activeTextEditor;
        if (editor && isPackageJson(editor.document)) {
            await scanWithRL(editor.document, editor, cveDecorationType, token);
        }
        else {
            const uris = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 20);
            for (const uri of uris) {
                const doc = await vscode.workspace.openTextDocument(uri);
                await scanWithRL(doc, undefined, cveDecorationType, token);
            }
            vscode.window.showInformationMessage(`NPM Safety Guard: RL scan complete for ${uris.length} file(s).`);
        }
    }));
    // Auto-scan on open / save
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(doc => {
        if (isPackageJson(doc) && getConfig("enableAutoScan")) {
            scanDocument(doc);
        }
    }), vscode.workspace.onDidSaveTextDocument(doc => {
        if (isPackageJson(doc) && getConfig("enableAutoScan")) {
            scanDocument(doc);
        }
    }), vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor && isPackageJson(editor.document) && getConfig("enableAutoScan")) {
            scanDocument(editor.document, editor);
        }
    }));
    // Scan already-open package.json on startup
    vscode.workspace.textDocuments.forEach(doc => {
        if (isPackageJson(doc) && getConfig("enableAutoScan")) {
            scanDocument(doc);
        }
    });
    updateStatusBar(0);
}
function deactivate() {
    diagnosticCollection?.dispose();
    statusBarItem?.dispose();
    decorationType?.dispose();
}
// ─── Core Scanner ─────────────────────────────────────────────────────────────
function scanDocument(doc, editor) {
    if (!isPackageJson(doc))
        return;
    let parsed;
    try {
        parsed = JSON.parse(doc.getText());
    }
    catch {
        return; // Invalid JSON — let VSCode's JSON linter handle it
    }
    const allDeps = {
        ...(parsed.dependencies || {}),
        ...(parsed.devDependencies || {}),
        ...(parsed.peerDependencies || {}),
        ...(parsed.optionalDependencies || {})
    };
    const rawHits = (0, maliciousDb_1.checkDependencies)(allDeps);
    // Find line numbers by searching in document text
    const hits = rawHits.map(h => ({
        ...h,
        line: findLineForPackage(doc, h.name, h.version)
    }));
    applyDiagnostics(doc, hits);
    if (editor && getConfig("showInlineDecorations")) {
        applyDecorations(editor, hits);
    }
    updateStatusBar(hits.length, doc.uri);
    // Fire-and-forget OSV scan in background (free, no auth, unlimited)
    if (vscode.workspace.getConfiguration("npmSafetyGuard").get("enableOSV", true)) {
        void scanWithOSV(doc, editor, { silent: true });
    }
    // Show notification for critical findings
    if (hits.length > 0) {
        const criticals = hits.filter(h => h.entry.severity === "critical");
        vscode.window.showErrorMessage(`🚨 NPM Safety Guard: ${criticals.length} CRITICAL threat(s) found!`, "View Report", "sendwavehub.tech").then((choice) => {
            if (choice === "View Report") {
                vscode.commands.executeCommand("npmSafetyGuard.showReport");
            }
            if (choice === "sendwavehub.tech") {
                vscode.env.openExternal(vscode.Uri.parse("https://sendwavehub.tech"));
            }
        });
    }
}
// ─── Diagnostics ──────────────────────────────────────────────────────────────
function applyDiagnostics(doc, hits) {
    const diagnostics = hits.map(hit => {
        const line = Math.max(0, hit.line);
        const lineText = doc.lineAt(line).text;
        const range = new vscode.Range(line, 0, line, lineText.length);
        const severity = hit.entry.severity === "critical" ? vscode.DiagnosticSeverity.Error
            : hit.entry.severity === "high" ? vscode.DiagnosticSeverity.Warning
                : vscode.DiagnosticSeverity.Information;
        const d = new vscode.Diagnostic(range, `[NPM Safety Guard] ${hit.entry.title}\n${hit.entry.description}` +
            (hit.entry.safeVersion ? `\nSafe version: ${hit.entry.safeVersion}` : ""), severity);
        d.source = "npm-safety-guard";
        d.code = {
            value: `${hit.name}@${hit.version}`,
            target: vscode.Uri.parse(hit.entry.sources[0])
        };
        return d;
    });
    diagnosticCollection.set(doc.uri, diagnostics);
}
// ─── Inline Decorations ───────────────────────────────────────────────────────
function applyDecorations(editor, hits) {
    const ranges = hits.map(hit => {
        const line = Math.max(0, hit.line);
        const lineText = editor.document.lineAt(line).text;
        return {
            range: new vscode.Range(line, 0, line, lineText.length),
            hoverMessage: new vscode.MarkdownString(buildHoverMarkdown(hit))
        };
    });
    editor.setDecorations(decorationType, ranges);
}
function buildHoverMarkdown(hit) {
    const { entry } = hit;
    const badge = entry.severity === "critical" ? "🔴 CRITICAL"
        : entry.severity === "high" ? "🟠 HIGH" : "🟡 MEDIUM";
    let md = `### ${badge} — ${entry.title}\n\n`;
    md += `**Package:** \`${hit.name}@${hit.version}\`\n\n`;
    md += `${entry.description}\n\n`;
    if (entry.safeVersion) {
        md += `✅ **Safe version:** \`${entry.safeVersion}\`\n\n`;
        md += `\`\`\`bash\nnpm install ${hit.name}@${entry.safeVersion}\n\`\`\`\n\n`;
    }
    md += `**Reported:** ${entry.reportedAt}\n\n`;
    md += entry.sources.map(s => `[Source](${s})`).join(" · ");
    return md;
}
// ─── Status Bar ───────────────────────────────────────────────────────────────
function updateStatusBar(hitCount, _uri) {
    if (hitCount === 0) {
        statusBarItem.text = "$(shield) NPM Safe";
        statusBarItem.backgroundColor = undefined;
    }
    else {
        statusBarItem.text = `$(warning) ${hitCount} THREAT${hitCount > 1 ? "S" : ""} FOUND`;
        statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    }
    statusBarItem.tooltip =
        `NPM Safety Guard by sendwavehub.tech\n` +
            `${hitCount === 0 ? "No threats detected" : `${hitCount} threat(s) found!`}`;
    statusBarItem.show();
}
// ─── Webview Report ───────────────────────────────────────────────────────────
let reportPanel;
async function showWebviewReport(context) {
    // Collect all current diagnostics
    const allHits = [];
    diagnosticCollection.forEach((uri, diags) => {
        diags.forEach(d => {
            // Reconstruct minimal hit from diagnostic
            allHits.push({ file: uri.fsPath, hit: { name: "", version: "", entry: {}, line: d.range.start.line } });
        });
    });
    // Re-scan all open package.json files fresh for report data
    const freshHits = [];
    const pkgFiles = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 20);
    for (const uri of pkgFiles) {
        try {
            const doc = await vscode.workspace.openTextDocument(uri);
            const parsed = JSON.parse(doc.getText());
            const allDeps = {
                ...(parsed.dependencies || {}),
                ...(parsed.devDependencies || {}),
                ...(parsed.peerDependencies || {}),
                ...(parsed.optionalDependencies || {})
            };
            const rawHits = (0, maliciousDb_1.checkDependencies)(allDeps);
            if (rawHits.length > 0) {
                freshHits.push({
                    file: uri.fsPath,
                    hits: rawHits.map(h => ({ ...h, line: findLineForPackage(doc, h.name, h.version) }))
                });
            }
        }
        catch { /* skip */ }
    }
    if (reportPanel) {
        reportPanel.reveal(vscode.ViewColumn.One);
    }
    else {
        reportPanel = vscode.window.createWebviewPanel("npmSafetyGuardReport", "NPM Safety Guard — Security Report", vscode.ViewColumn.One, { enableScripts: false });
        reportPanel.onDidDispose(() => { reportPanel = undefined; });
    }
    reportPanel.webview.html = buildReportHtml(freshHits, pkgFiles.length);
}
function buildReportHtml(results, scanned) {
    const totalHits = results.reduce((a, r) => a + r.hits.length, 0);
    const criticals = results.flatMap(r => r.hits).filter(h => h.entry.severity === "critical").length;
    const now = new Date().toLocaleString();
    const resultsHtml = results.length === 0
        ? `<div class="clean"><span class="icon">✅</span><h2>All Clear</h2><p>No known malicious packages detected in ${scanned} scanned file(s).</p></div>`
        : results.map(r => `
        <div class="file-block">
          <div class="file-path">📄 ${r.file}</div>
          ${r.hits.map(hit => `
            <div class="hit ${hit.entry.severity}">
              <div class="hit-header">
                <span class="badge ${hit.entry.severity}">${hit.entry.severity.toUpperCase()}</span>
                <strong>${hit.entry.title}</strong>
              </div>
              <div class="pkg-line">
                <code>${hit.name}@${hit.version}</code>
                ${hit.entry.safeVersion ? `<span class="safe">→ Safe: <code>${hit.name}@${hit.entry.safeVersion}</code></span>` : ""}
              </div>
              <p class="desc">${hit.entry.description}</p>
              <div class="fix-box">
                <strong>Fix:</strong><br>
                ${hit.entry.safeVersion
            ? `<code>npm install ${hit.name}@${hit.entry.safeVersion}</code>`
            : `<code>npm uninstall ${hit.name}</code>`}
              </div>
              <div class="reported">Reported: ${hit.entry.reportedAt} · 
                ${hit.entry.sources.map((s, i) => `<a href="${s}">Source ${i + 1}</a>`).join(" ")}
              </div>
            </div>
          `).join("")}
        </div>
      `).join("");
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NPM Safety Guard Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    padding: 24px;
    line-height: 1.6;
  }
  h1 { font-size: 1.4rem; font-weight: 700; color: #f0f6fc; margin-bottom: 4px; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }
  .summary {
    display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap;
  }
  .stat {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px 20px;
    min-width: 120px;
    text-align: center;
  }
  .stat .num { font-size: 2rem; font-weight: 800; }
  .stat .lbl { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat.danger .num { color: #f85149; }
  .stat.warn .num { color: #d29922; }
  .stat.ok .num { color: #3fb950; }
  .file-block { margin-bottom: 20px; }
  .file-path {
    font-size: 0.82rem; color: #8b949e;
    padding: 6px 10px;
    background: #161b22;
    border-radius: 6px 6px 0 0;
    border: 1px solid #30363d;
    border-bottom: none;
    font-family: monospace;
  }
  .hit {
    border: 1px solid #30363d;
    border-radius: 0 0 8px 8px;
    padding: 16px;
    margin-bottom: 8px;
    background: #161b22;
  }
  .hit.critical { border-left: 4px solid #f85149; background: #1c0f0f; }
  .hit.high     { border-left: 4px solid #d29922; background: #1c1600; }
  .hit.medium   { border-left: 4px solid #388bfd; background: #0d1e40; }
  .hit-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .badge {
    font-size: 0.7rem; font-weight: 700; padding: 2px 8px;
    border-radius: 99px; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .badge.critical { background: #f85149; color: #fff; }
  .badge.high     { background: #d29922; color: #000; }
  .badge.medium   { background: #388bfd; color: #fff; }
  .pkg-line { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .pkg-line code { background: #0d1117; padding: 2px 8px; border-radius: 4px; font-size: 0.9rem; }
  .safe { color: #3fb950; font-size: 0.85rem; }
  .safe code { background: #0d1117; padding: 2px 8px; border-radius: 4px; }
  .desc { color: #8b949e; font-size: 0.88rem; margin-bottom: 12px; }
  .fix-box {
    background: #0d1117; border: 1px solid #30363d;
    border-radius: 6px; padding: 10px 14px;
    font-size: 0.85rem; margin-bottom: 10px;
  }
  .fix-box code { color: #3fb950; }
  .reported { font-size: 0.78rem; color: #8b949e; }
  .reported a { color: #388bfd; text-decoration: none; }
  .clean {
    text-align: center; padding: 60px 20px;
    border: 1px dashed #30363d; border-radius: 12px;
    color: #3fb950;
  }
  .clean .icon { font-size: 3rem; display: block; margin-bottom: 12px; }
  .clean h2 { font-size: 1.4rem; margin-bottom: 8px; }
  .clean p { color: #8b949e; }
  h2.section { font-size: 1rem; color: #8b949e; margin-bottom: 12px; 
    text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
</style>
</head>
<body>
  <h1>🛡 NPM Safety Guard — Security Report</h1>
  <p class="meta">Scanned ${scanned} package.json file(s) · ${now}</p>

  <div class="summary">
    <div class="stat ${totalHits === 0 ? 'ok' : 'danger'}">
      <div class="num">${totalHits}</div>
      <div class="lbl">Threats Found</div>
    </div>
    <div class="stat ${criticals === 0 ? 'ok' : 'danger'}">
      <div class="num">${criticals}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat ok">
      <div class="num">${scanned}</div>
      <div class="lbl">Files Scanned</div>
    </div>
  </div>

  ${totalHits > 0 ? '<h2 class="section">Findings</h2>' : ""}
  ${resultsHtml}

  <div style="
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid #30363d;
    font-family: sans-serif;
    font-size: 12px;
    color: #8b949e;
    text-align: center;
  ">
    Built by
    <a href="https://sendwavehub.tech"
       style="color: #388bfd; text-decoration: none;">
      SendWaveHub
    </a>
    &nbsp;·&nbsp;
    <a href="https://sendwavehub.tech/products"
       style="color: #388bfd; text-decoration: none;">
      More tools
    </a>
  </div>
</body>
</html>`;
}
// ─── Helpers ──────────────────────────────────────────────────────────────────
function isPackageJson(doc) {
    return doc.fileName.endsWith("package.json") &&
        !doc.fileName.includes("node_modules");
}
function findLineForPackage(doc, name, _version) {
    const text = doc.getText();
    const lines = text.split("\n");
    // Search for the package name string in the file
    const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`"${escapedName}"\\s*:`);
    for (let i = 0; i < lines.length; i++) {
        if (re.test(lines[i]))
            return i;
    }
    return 0;
}
function getConfig(key) {
    return vscode.workspace.getConfiguration("npmSafetyGuard").get(key, true);
}
// ─── ReversingLabs Scanner ────────────────────────────────────────────────────
async function scanWithRL(doc, editor, cveDecorationType, token) {
    let parsed;
    try {
        parsed = JSON.parse(doc.getText());
    }
    catch {
        return;
    }
    const allDeps = {
        ...(parsed.dependencies || {}),
        ...(parsed.devDependencies || {}),
        ...(parsed.peerDependencies || {}),
        ...(parsed.optionalDependencies || {}),
    };
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Window,
        title: "NPM Safety Guard: Scanning via ReversingLabs...",
        cancellable: false,
    }, async (progress) => {
        const total = Object.keys(allDeps).length;
        const rlHits = await (0, rlChecker_1.checkAllPackagesRL)(allDeps, token, (done) => {
            progress.report({
                message: `${done}/${total} packages`,
                increment: (1 / total) * 100,
            });
        });
        // Apply CVE diagnostics to Problems panel
        const rlDiagnostics = rlHits.map((hit) => {
            const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
            const lineText = doc.lineAt(line).text;
            const range = new vscode.Range(line, 0, line, lineText.length);
            const severity = hit.riskLevel === "critical" || hit.riskLevel === "high"
                ? vscode.DiagnosticSeverity.Error
                : vscode.DiagnosticSeverity.Warning;
            const vulnSummary = hit.vulnerabilities
                .map((v) => `${v.cve} (CVSS ${v.cvss.toFixed(1)}): ${v.summary}`)
                .join("\n");
            const d = new vscode.Diagnostic(range, `[NPM Safety Guard / RL] ${hit.package}@${hit.version}\n` +
                (hit.malware ? "⚠ MALWARE DETECTED\n" : "") +
                (hit.tampered ? "⚠ TAMPERING DETECTED\n" : "") +
                (vulnSummary || "Vulnerability detected — see RL report"), severity);
            d.source = "npm-safety-guard(RL)";
            d.code = {
                value: `${hit.package}@${hit.version}`,
                target: vscode.Uri.parse(hit.reportUrl),
            };
            return d;
        });
        // Merge with existing static diagnostics
        const existing = diagnosticCollection.get(doc.uri) ?? [];
        diagnosticCollection.set(doc.uri, [...existing, ...rlDiagnostics]);
        // Apply amber inline decorations for CVE hits
        if (editor) {
            const decorations = rlHits.map((hit) => {
                const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
                const lineText = editor.document.lineAt(line).text;
                const md = new vscode.MarkdownString(buildRLHoverMarkdown(hit));
                md.isTrusted = true;
                return { range: new vscode.Range(line, 0, line, lineText.length), hoverMessage: md };
            });
            editor.setDecorations(cveDecorationType, decorations);
        }
        // Notify user
        if (rlHits.length === 0) {
            vscode.window.showInformationMessage("NPM Safety Guard (RL): No vulnerabilities found.");
        }
        else {
            const criticals = rlHits.filter((h) => h.riskLevel === "critical" || h.riskLevel === "high");
            vscode.window.showErrorMessage(`NPM Safety Guard (RL): ${rlHits.length} vulnerable package(s) — ${criticals.length} critical/high`, "View Report").then((choice) => {
                if (choice === "View Report") {
                    vscode.commands.executeCommand("npmSafetyGuard.showReport");
                }
            });
        }
    });
}
function buildRLHoverMarkdown(hit) {
    const badge = hit.riskLevel === "critical" ? "🔴 CRITICAL"
        : hit.riskLevel === "high" ? "🟠 HIGH"
            : hit.riskLevel === "medium" ? "🟡 MEDIUM"
                : "🔵 LOW";
    let md = `### ${badge} — ReversingLabs Report\n\n`;
    md += `**Package:** \`${hit.package}@${hit.version}\`\n\n`;
    if (hit.malware) {
        md += `🚨 **Malware detected**\n\n`;
    }
    if (hit.tampered) {
        md += `⚠️ **Tampering detected**\n\n`;
    }
    if (hit.vulnerabilities.length > 0) {
        md += `**Vulnerabilities:**\n`;
        hit.vulnerabilities.forEach((v) => {
            md += `- \`${v.cve}\` CVSS ${v.cvss.toFixed(1)} — ${v.summary}`;
            if (v.fixAvailable) {
                md += ` ✅ fix available`;
            }
            md += `\n`;
        });
        md += "\n";
    }
    md += `[View full report on secure.software](${hit.reportUrl})`;
    return md;
}
// ─── OSV.dev Scanner ──────────────────────────────────────────────────────────
async function scanWithOSV(doc, editor, opts = {}) {
    if (!isPackageJson(doc))
        return;
    let parsed;
    try {
        parsed = JSON.parse(doc.getText());
    }
    catch {
        return;
    }
    const allDeps = {
        ...(parsed.dependencies || {}),
        ...(parsed.devDependencies || {}),
        ...(parsed.peerDependencies || {}),
        ...(parsed.optionalDependencies || {}),
    };
    if (Object.keys(allDeps).length === 0)
        return;
    const runScan = async (report) => {
        const total = Object.keys(allDeps).length;
        const hits = await (0, osvChecker_1.checkAllPackagesOSV)(allDeps, (done) => {
            report?.(done, total);
        });
        const osvDiagnostics = hits.map((hit) => {
            const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
            const lineText = doc.lineAt(line).text;
            const range = new vscode.Range(line, 0, line, lineText.length);
            const severity = hit.riskLevel === "critical" || hit.riskLevel === "high"
                ? vscode.DiagnosticSeverity.Error
                : hit.riskLevel === "medium"
                    ? vscode.DiagnosticSeverity.Warning
                    : vscode.DiagnosticSeverity.Information;
            const summary = hit.vulnerabilities
                .slice(0, 3)
                .map((v) => `${v.id}${v.fixedVersion ? ` (fix: ${v.fixedVersion})` : ""}: ${v.summary}`)
                .join("\n");
            const more = hit.vulnerabilities.length > 3 ? `\n…and ${hit.vulnerabilities.length - 3} more` : "";
            const d = new vscode.Diagnostic(range, `[NPM Safety Guard / OSV] ${hit.package}@${hit.version}\n${summary}${more}`, severity);
            d.source = "npm-safety-guard(OSV)";
            const firstAdvisory = hit.vulnerabilities[0]?.advisoryUrl;
            d.code = {
                value: `${hit.package}@${hit.version}`,
                target: vscode.Uri.parse(firstAdvisory ?? `https://osv.dev/list?q=${encodeURIComponent(hit.package)}`),
            };
            return d;
        });
        // Merge with existing diagnostics (don't clobber bundled-DB or RL results)
        const existing = diagnosticCollection.get(doc.uri) ?? [];
        const nonOsv = existing.filter((d) => d.source !== "npm-safety-guard(OSV)");
        diagnosticCollection.set(doc.uri, [...nonOsv, ...osvDiagnostics]);
        // Inline blue decorations (skip packages already flagged by bundled DB — red wins)
        const activeEditor = editor ?? vscode.window.visibleTextEditors.find((e) => e.document.uri.toString() === doc.uri.toString());
        if (activeEditor && getConfig("showInlineDecorations")) {
            const flaggedByBundled = new Set((diagnosticCollection.get(doc.uri) ?? [])
                .filter((d) => d.source === "npm-safety-guard")
                .map((d) => typeof d.code === "object" ? d.code.value : undefined));
            const decorations = hits
                .filter((hit) => !flaggedByBundled.has(`${hit.package}@${hit.version}`))
                .map((hit) => {
                const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
                const lineText = activeEditor.document.lineAt(line).text;
                const md = new vscode.MarkdownString(buildOSVHoverMarkdown(hit));
                md.isTrusted = true;
                return { range: new vscode.Range(line, 0, line, lineText.length), hoverMessage: md };
            });
            activeEditor.setDecorations(osvDecorationType, decorations);
        }
        if (!opts.silent) {
            if (hits.length === 0) {
                vscode.window.showInformationMessage("NPM Safety Guard (OSV): No CVEs found.");
            }
            else {
                const criticals = hits.filter((h) => h.riskLevel === "critical" || h.riskLevel === "high").length;
                vscode.window.showWarningMessage(`NPM Safety Guard (OSV): ${hits.length} vulnerable package(s) — ${criticals} critical/high`, "View Report").then((choice) => {
                    if (choice === "View Report") {
                        vscode.commands.executeCommand("npmSafetyGuard.showReport");
                    }
                });
            }
        }
    };
    if (opts.silent) {
        await runScan();
    }
    else {
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: "NPM Safety Guard: Scanning via OSV.dev...",
            cancellable: false,
        }, async (progress) => {
            const total = Object.keys(allDeps).length;
            await runScan((done) => {
                progress.report({
                    message: `${done}/${total} packages`,
                    increment: (1 / total) * 100,
                });
            });
        });
    }
}
function buildOSVHoverMarkdown(hit) {
    const badge = hit.riskLevel === "critical" ? "🔴 CRITICAL"
        : hit.riskLevel === "high" ? "🟠 HIGH"
            : hit.riskLevel === "medium" ? "🟡 MEDIUM"
                : "🔵 LOW";
    let md = `### ${badge} — OSV.dev CVE Report\n\n`;
    md += `**Package:** \`${hit.package}@${hit.version}\`\n\n`;
    md += `**Vulnerabilities (${hit.vulnerabilities.length}):**\n`;
    hit.vulnerabilities.slice(0, 5).forEach((v) => {
        md += `- \`${v.id}\``;
        if (v.aliases.length > 0)
            md += ` (${v.aliases.slice(0, 2).join(", ")})`;
        md += ` — ${v.summary || "See advisory"}`;
        if (v.fixedVersion)
            md += `\n   ✅ Fixed in \`${v.fixedVersion}\``;
        if (v.advisoryUrl)
            md += `\n   [Advisory](${v.advisoryUrl})`;
        md += `\n`;
    });
    if (hit.vulnerabilities.length > 5) {
        md += `\n*…and ${hit.vulnerabilities.length - 5} more*\n`;
    }
    md += `\n[All advisories on osv.dev](https://osv.dev/list?q=${encodeURIComponent(hit.package)}&ecosystem=npm)`;
    return md;
}
// ─── Remote DB Refresh ────────────────────────────────────────────────────────
async function refreshRemoteDb(context, force = false) {
    const cfg = vscode.workspace.getConfiguration("npmSafetyGuard");
    if (!force && !cfg.get("enableRemoteDb", true)) {
        return { entries: [], source: "none" };
    }
    const url = cfg.get("remoteDbUrl", "") || remoteDb_1.DEFAULT_DB_URL;
    const storageDir = context.globalStorageUri.fsPath;
    const result = await (0, remoteDb_1.fetchRemoteEntries)(storageDir, url);
    (0, maliciousDb_1.setRemoteEntries)(result.entries);
    return result;
}
//# sourceMappingURL=extension.js.map