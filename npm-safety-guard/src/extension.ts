import * as vscode from "vscode";
import { checkDependencies, MaliciousEntry, setRemoteEntries } from "./maliciousDb";
import { checkAllPackagesRL, clearRLCache, RLResult } from "./rlChecker";
import { checkAllPackagesOSV, clearOSVCache, OSVResult } from "./osvChecker";
import { fetchRemoteEntries, DEFAULT_DB_URL } from "./remoteDb";
import { checkAllInstallScripts, clearScriptCache, ScriptCheckResult } from "./installScriptChecker";
import { deepScanAll, clearDeepScanCache, DeepScanResult, DeepScanFinding } from "./deepScanner";
import { parseLockfile, LockfileSummary } from "./lockfileScanner";
import { checkAllHeuristics, clearHeuristicsCache, RegistrySignals } from "./registryHeuristics";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScanHit {
  name: string;
  version: string;
  entry: MaliciousEntry;
  line: number;
}

// ─── Globals ──────────────────────────────────────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let decorationType: vscode.TextEditorDecorationType;
let osvDecorationType: vscode.TextEditorDecorationType;
let scriptDecorationType: vscode.TextEditorDecorationType;

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
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

  // Install-script decoration (gold dashed — behavioral concern, not malicious)
  scriptDecorationType = vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(234, 179, 8, 0.06)",
    border: "1px dashed rgba(234, 179, 8, 0.40)",
    borderRadius: "2px",
    overviewRulerColor: "rgba(234, 179, 8, 0.7)",
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: "  ⚠ install script",
      color: "rgba(234, 179, 8, 0.95)",
      fontWeight: "bold",
    },
  });
  context.subscriptions.push(scriptDecorationType);

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
  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.scanNow", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor && isPackageJson(editor.document)) {
        scanDocument(editor.document, editor);
      } else {
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
    }),

    vscode.commands.registerCommand("npmSafetyGuard.showReport", () => {
      showWebviewReport(context);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.scanLockfile", async () => {
      await runLockfileScan();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.checkHeuristics", async () => {
      clearHeuristicsCache();
      const editor = vscode.window.activeTextEditor;
      let doc: vscode.TextDocument | undefined;
      if (editor && isPackageJson(editor.document)) {
        doc = editor.document;
      } else {
        const uris = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 1);
        if (uris.length > 0) doc = await vscode.workspace.openTextDocument(uris[0]);
      }
      if (!doc) {
        vscode.window.showInformationMessage("NPM Safety Guard: No package.json found.");
        return;
      }
      await runHeuristics(doc);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.deepScan", async () => {
      clearDeepScanCache();
      const editor = vscode.window.activeTextEditor;
      let doc: vscode.TextDocument | undefined;
      if (editor && isPackageJson(editor.document)) {
        doc = editor.document;
      } else {
        const uris = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 1);
        if (uris.length > 0) doc = await vscode.workspace.openTextDocument(uris[0]);
      }
      if (!doc) {
        vscode.window.showInformationMessage("NPM Safety Guard: No package.json found.");
        return;
      }
      await runDeepScan(doc, context);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.scanInstallScripts", async () => {
      clearScriptCache();
      const editor = vscode.window.activeTextEditor;
      if (editor && isPackageJson(editor.document)) {
        await scanInstallScripts(editor.document, editor);
      } else {
        const uris = await vscode.workspace.findFiles(
          "**/package.json",
          "**/node_modules/**",
          20
        );
        for (const uri of uris) {
          const doc = await vscode.workspace.openTextDocument(uri);
          await scanInstallScripts(doc);
        }
        vscode.window.showInformationMessage(
          `NPM Safety Guard (Install Scripts): Scanned ${uris.length} file(s).`
        );
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.refreshDb", async () => {
      const result = await refreshRemoteDb(context, /*force*/ true);
      const msg =
        result.source === "network"
          ? `NPM Safety Guard: Fetched ${result.entries.length} remote entries.`
          : result.source === "cache"
          ? `NPM Safety Guard: Network unreachable — using cached ${result.entries.length} entries.`
          : "NPM Safety Guard: No remote entries available.";
      vscode.window.showInformationMessage(msg);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.scanOSV", async () => {
      clearOSVCache();
      const editor = vscode.window.activeTextEditor;
      if (editor && isPackageJson(editor.document)) {
        await scanWithOSV(editor.document, editor);
      } else {
        const uris = await vscode.workspace.findFiles(
          "**/package.json",
          "**/node_modules/**",
          20
        );
        for (const uri of uris) {
          const doc = await vscode.workspace.openTextDocument(uri);
          await scanWithOSV(doc);
        }
        vscode.window.showInformationMessage(
          `NPM Safety Guard (OSV): Scanned ${uris.length} file(s).`
        );
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("npmSafetyGuard.checkRL", async () => {
      const token = vscode.workspace.getConfiguration("npmSafetyGuard")
        .get<string>("rlToken", "");
      if (!token) {
        const action = await vscode.window.showWarningMessage(
          "NPM Safety Guard: No ReversingLabs token configured.",
          "Open Settings"
        );
        if (action === "Open Settings") {
          vscode.commands.executeCommand(
            "workbench.action.openSettings",
            "npmSafetyGuard.rlToken"
          );
        }
        return;
      }
      clearRLCache();
      const editor = vscode.window.activeTextEditor;
      if (editor && isPackageJson(editor.document)) {
        await scanWithRL(editor.document, editor, cveDecorationType, token);
      } else {
        const uris = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 20);
        for (const uri of uris) {
          const doc = await vscode.workspace.openTextDocument(uri);
          await scanWithRL(doc, undefined, cveDecorationType, token);
        }
        vscode.window.showInformationMessage(
          `NPM Safety Guard: RL scan complete for ${uris.length} file(s).`
        );
      }
    })
  );

  // Auto-scan on open / save
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      if (isPackageJson(doc) && getConfig("enableAutoScan")) {
        scanDocument(doc);
      }
    }),
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (isPackageJson(doc) && getConfig("enableAutoScan")) {
        scanDocument(doc);
      }
    }),
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor && isPackageJson(editor.document) && getConfig("enableAutoScan")) {
        scanDocument(editor.document, editor);
      }
    })
  );

  // Scan already-open package.json on startup
  vscode.workspace.textDocuments.forEach(doc => {
    if (isPackageJson(doc) && getConfig("enableAutoScan")) {
      scanDocument(doc);
    }
  });

  updateStatusBar(0);
}

export function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
  decorationType?.dispose();
}

// ─── Core Scanner ─────────────────────────────────────────────────────────────

function scanDocument(doc: vscode.TextDocument, editor?: vscode.TextEditor) {
  if (!isPackageJson(doc)) return;

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(doc.getText());
  } catch {
    return; // Invalid JSON — let VSCode's JSON linter handle it
  }

  const allDeps: Record<string, string> = {
    ...(parsed.dependencies as Record<string, string> || {}),
    ...(parsed.devDependencies as Record<string, string> || {}),
    ...(parsed.peerDependencies as Record<string, string> || {}),
    ...(parsed.optionalDependencies as Record<string, string> || {})
  };

  const rawHits = checkDependencies(allDeps);

  // Find line numbers by searching in document text
  const hits: ScanHit[] = rawHits.map(h => ({
    ...h,
    line: findLineForPackage(doc, h.name, h.version)
  }));

  applyDiagnostics(doc, hits);

  if (editor && getConfig("showInlineDecorations")) {
    applyDecorations(editor, hits);
  }

  updateStatusBar(hits.length, doc.uri);

  // Fire-and-forget OSV scan in background (free, no auth, unlimited)
  if (vscode.workspace.getConfiguration("npmSafetyGuard").get<boolean>("enableOSV", true)) {
    void scanWithOSV(doc, editor, { silent: true });
  }

  // Fire-and-forget install-script audit (free, npm registry)
  if (vscode.workspace.getConfiguration("npmSafetyGuard").get<boolean>("enableScriptCheck", true)) {
    void scanInstallScripts(doc, editor, { silent: true });
  }

  // Show notification for critical findings
  if (hits.length > 0) {
    const criticals = hits.filter(h => h.entry.severity === "critical");
    vscode.window.showErrorMessage(
      `🚨 NPM Safety Guard: ${criticals.length} CRITICAL threat(s) found!`,
      "View Report",
      "sendwavehub.tech"
    ).then((choice: string | undefined) => {
      if (choice === "View Report") {
        vscode.commands.executeCommand("npmSafetyGuard.showReport");
      }
      if (choice === "sendwavehub.tech") {
        vscode.env.openExternal(
          vscode.Uri.parse("https://sendwavehub.tech")
        );
      }
    });
  }
}

// ─── Diagnostics ──────────────────────────────────────────────────────────────

function applyDiagnostics(doc: vscode.TextDocument, hits: ScanHit[]) {
  const diagnostics: vscode.Diagnostic[] = hits.map(hit => {
    const line = Math.max(0, hit.line);
    const lineText = doc.lineAt(line).text;
    const range = new vscode.Range(line, 0, line, lineText.length);

    const severity =
      hit.entry.severity === "critical" ? vscode.DiagnosticSeverity.Error
      : hit.entry.severity === "high" ? vscode.DiagnosticSeverity.Warning
      : vscode.DiagnosticSeverity.Information;

    const d = new vscode.Diagnostic(
      range,
      `[NPM Safety Guard] ${hit.entry.title}\n${hit.entry.description}` +
      (hit.entry.safeVersion ? `\nSafe version: ${hit.entry.safeVersion}` : ""),
      severity
    );
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

function applyDecorations(editor: vscode.TextEditor, hits: ScanHit[]) {
  const ranges: vscode.DecorationOptions[] = hits.map(hit => {
    const line = Math.max(0, hit.line);
    const lineText = editor.document.lineAt(line).text;
    return {
      range: new vscode.Range(line, 0, line, lineText.length),
      hoverMessage: new vscode.MarkdownString(buildHoverMarkdown(hit))
    };
  });
  editor.setDecorations(decorationType, ranges);
}

function buildHoverMarkdown(hit: ScanHit): string {
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

function updateStatusBar(hitCount: number, _uri?: vscode.Uri) {
  if (hitCount === 0) {
    statusBarItem.text = "$(shield) NPM Safe";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(warning) ${hitCount} THREAT${hitCount > 1 ? "S" : ""} FOUND`;
    statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  }
  statusBarItem.tooltip =
    `NPM Safety Guard by sendwavehub.tech\n` +
    `${hitCount === 0 ? "No threats detected" : `${hitCount} threat(s) found!`}`;
  statusBarItem.show();
}

// ─── Webview Report ───────────────────────────────────────────────────────────

let reportPanel: vscode.WebviewPanel | undefined;

async function showWebviewReport(context: vscode.ExtensionContext) {
  // Collect all current diagnostics
  const allHits: Array<{ file: string; hit: ScanHit }> = [];
  diagnosticCollection.forEach((uri, diags) => {
    diags.forEach(d => {
      // Reconstruct minimal hit from diagnostic
      allHits.push({ file: uri.fsPath, hit: { name: "", version: "", entry: {} as MaliciousEntry, line: d.range.start.line } });
    });
  });

  // Re-scan all open package.json files fresh for report data
  const freshHits: Array<{ file: string; hits: ScanHit[] }> = [];
  const pkgFiles = await vscode.workspace.findFiles("**/package.json", "**/node_modules/**", 20);
  
  for (const uri of pkgFiles) {
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const parsed = JSON.parse(doc.getText());
      const allDeps: Record<string, string> = {
        ...(parsed.dependencies || {}),
        ...(parsed.devDependencies || {}),
        ...(parsed.peerDependencies || {}),
        ...(parsed.optionalDependencies || {})
      };
      const rawHits = checkDependencies(allDeps);
      if (rawHits.length > 0) {
        freshHits.push({
          file: uri.fsPath,
          hits: rawHits.map(h => ({ ...h, line: findLineForPackage(doc, h.name, h.version) }))
        });
      }
    } catch { /* skip */ }
  }

  if (reportPanel) {
    reportPanel.reveal(vscode.ViewColumn.One);
  } else {
    reportPanel = vscode.window.createWebviewPanel(
      "npmSafetyGuardReport",
      "NPM Safety Guard — Security Report",
      vscode.ViewColumn.One,
      { enableScripts: false }
    );
    reportPanel.onDidDispose(() => { reportPanel = undefined; });
  }

  reportPanel.webview.html = buildReportHtml(freshHits, pkgFiles.length);
}

function buildReportHtml(
  results: Array<{ file: string; hits: ScanHit[] }>,
  scanned: number
): string {
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
                ${hit.entry.sources.map((s, i) => `<a href="${s}">Source ${i+1}</a>`).join(" ")}
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

function isPackageJson(doc: vscode.TextDocument): boolean {
  return doc.fileName.endsWith("package.json") &&
    !doc.fileName.includes("node_modules");
}

function findLineForPackage(doc: vscode.TextDocument, name: string, _version: string): number {
  const text = doc.getText();
  const lines = text.split("\n");
  // Search for the package name string in the file
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`"${escapedName}"\\s*:`);
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) return i;
  }
  return 0;
}

function getConfig(key: string): boolean {
  return vscode.workspace.getConfiguration("npmSafetyGuard").get<boolean>(key, true);
}

// ─── ReversingLabs Scanner ────────────────────────────────────────────────────

async function scanWithRL(
  doc: vscode.TextDocument,
  editor: vscode.TextEditor | undefined,
  cveDecorationType: vscode.TextEditorDecorationType,
  token: string
): Promise<void> {
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(doc.getText()); }
  catch { return; }

  const allDeps: Record<string, string> = {
    ...(parsed.dependencies as Record<string, string> || {}),
    ...(parsed.devDependencies as Record<string, string> || {}),
    ...(parsed.peerDependencies as Record<string, string> || {}),
    ...(parsed.optionalDependencies as Record<string, string> || {}),
  };

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Window,
      title: "NPM Safety Guard: Scanning via ReversingLabs...",
      cancellable: false,
    },
    async (progress) => {
      const total = Object.keys(allDeps).length;
      const rlHits = await checkAllPackagesRL(allDeps, token, (done) => {
        progress.report({
          message: `${done}/${total} packages`,
          increment: (1 / total) * 100,
        });
      });

      // Apply CVE diagnostics to Problems panel
      const rlDiagnostics: vscode.Diagnostic[] = rlHits.map((hit) => {
        const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
        const lineText = doc.lineAt(line).text;
        const range = new vscode.Range(line, 0, line, lineText.length);
        const severity =
          hit.riskLevel === "critical" || hit.riskLevel === "high"
            ? vscode.DiagnosticSeverity.Error
            : vscode.DiagnosticSeverity.Warning;

        const vulnSummary = hit.vulnerabilities
          .map((v) => `${v.cve} (CVSS ${v.cvss.toFixed(1)}): ${v.summary}`)
          .join("\n");

        const d = new vscode.Diagnostic(
          range,
          `[NPM Safety Guard / RL] ${hit.package}@${hit.version}\n` +
            (hit.malware ? "⚠ MALWARE DETECTED\n" : "") +
            (hit.tampered ? "⚠ TAMPERING DETECTED\n" : "") +
            (vulnSummary || "Vulnerability detected — see RL report"),
          severity
        );
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
        const decorations: vscode.DecorationOptions[] = rlHits.map((hit) => {
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
        vscode.window.showInformationMessage(
          "NPM Safety Guard (RL): No vulnerabilities found."
        );
      } else {
        const criticals = rlHits.filter((h) => h.riskLevel === "critical" || h.riskLevel === "high");
        vscode.window.showErrorMessage(
          `NPM Safety Guard (RL): ${rlHits.length} vulnerable package(s) — ${criticals.length} critical/high`,
          "View Report"
        ).then((choice) => {
          if (choice === "View Report") {
            vscode.commands.executeCommand("npmSafetyGuard.showReport");
          }
        });
      }
    }
  );
}

function buildRLHoverMarkdown(hit: RLResult): string {
  const badge =
    hit.riskLevel === "critical" ? "🔴 CRITICAL"
    : hit.riskLevel === "high"   ? "🟠 HIGH"
    : hit.riskLevel === "medium" ? "🟡 MEDIUM"
    : "🔵 LOW";

  let md = `### ${badge} — ReversingLabs Report\n\n`;
  md += `**Package:** \`${hit.package}@${hit.version}\`\n\n`;

  if (hit.malware)  { md += `🚨 **Malware detected**\n\n`; }
  if (hit.tampered) { md += `⚠️ **Tampering detected**\n\n`; }

  if (hit.vulnerabilities.length > 0) {
    md += `**Vulnerabilities:**\n`;
    hit.vulnerabilities.forEach((v) => {
      md += `- \`${v.cve}\` CVSS ${v.cvss.toFixed(1)} — ${v.summary}`;
      if (v.fixAvailable) { md += ` ✅ fix available`; }
      md += `\n`;
    });
    md += "\n";
  }

  md += `[View full report on secure.software](${hit.reportUrl})`;
  return md;
}

// ─── OSV.dev Scanner ──────────────────────────────────────────────────────────

async function scanWithOSV(
  doc: vscode.TextDocument,
  editor?: vscode.TextEditor,
  opts: { silent?: boolean } = {}
): Promise<void> {
  if (!isPackageJson(doc)) return;

  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(doc.getText()); }
  catch { return; }

  const allDeps: Record<string, string> = {
    ...(parsed.dependencies as Record<string, string> || {}),
    ...(parsed.devDependencies as Record<string, string> || {}),
    ...(parsed.peerDependencies as Record<string, string> || {}),
    ...(parsed.optionalDependencies as Record<string, string> || {}),
  };
  if (Object.keys(allDeps).length === 0) return;

  const runScan = async (report?: (d: number, t: number) => void) => {
    const total = Object.keys(allDeps).length;
    const hits = await checkAllPackagesOSV(allDeps, (done) => {
      report?.(done, total);
    });

    const osvDiagnostics: vscode.Diagnostic[] = hits.map((hit) => {
      const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
      const lineText = doc.lineAt(line).text;
      const range = new vscode.Range(line, 0, line, lineText.length);

      const severity =
        hit.riskLevel === "critical" || hit.riskLevel === "high"
          ? vscode.DiagnosticSeverity.Error
          : hit.riskLevel === "medium"
          ? vscode.DiagnosticSeverity.Warning
          : vscode.DiagnosticSeverity.Information;

      const summary = hit.vulnerabilities
        .slice(0, 3)
        .map((v) => `${v.id}${v.fixedVersion ? ` (fix: ${v.fixedVersion})` : ""}: ${v.summary}`)
        .join("\n");
      const more = hit.vulnerabilities.length > 3 ? `\n…and ${hit.vulnerabilities.length - 3} more` : "";

      const d = new vscode.Diagnostic(
        range,
        `[NPM Safety Guard / OSV] ${hit.package}@${hit.version}\n${summary}${more}`,
        severity
      );
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
    const activeEditor = editor ?? vscode.window.visibleTextEditors.find(
      (e) => e.document.uri.toString() === doc.uri.toString()
    );
    if (activeEditor && getConfig("showInlineDecorations")) {
      const flaggedByBundled = new Set(
        (diagnosticCollection.get(doc.uri) ?? [])
          .filter((d) => d.source === "npm-safety-guard")
          .map((d) => typeof d.code === "object" ? (d.code as any).value : undefined)
      );
      const decorations: vscode.DecorationOptions[] = hits
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
      } else {
        const criticals = hits.filter((h) => h.riskLevel === "critical" || h.riskLevel === "high").length;
        vscode.window.showWarningMessage(
          `NPM Safety Guard (OSV): ${hits.length} vulnerable package(s) — ${criticals} critical/high`,
          "View Report"
        ).then((choice) => {
          if (choice === "View Report") {
            vscode.commands.executeCommand("npmSafetyGuard.showReport");
          }
        });
      }
    }
  };

  if (opts.silent) {
    await runScan();
  } else {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Window,
        title: "NPM Safety Guard: Scanning via OSV.dev...",
        cancellable: false,
      },
      async (progress) => {
        const total = Object.keys(allDeps).length;
        await runScan((done) => {
          progress.report({
            message: `${done}/${total} packages`,
            increment: (1 / total) * 100,
          });
        });
      }
    );
  }
}

function buildOSVHoverMarkdown(hit: OSVResult): string {
  const badge =
    hit.riskLevel === "critical" ? "🔴 CRITICAL"
    : hit.riskLevel === "high"   ? "🟠 HIGH"
    : hit.riskLevel === "medium" ? "🟡 MEDIUM"
    : "🔵 LOW";

  let md = `### ${badge} — OSV.dev CVE Report\n\n`;
  md += `**Package:** \`${hit.package}@${hit.version}\`\n\n`;
  md += `**Vulnerabilities (${hit.vulnerabilities.length}):**\n`;
  hit.vulnerabilities.slice(0, 5).forEach((v) => {
    md += `- \`${v.id}\``;
    if (v.aliases.length > 0) md += ` (${v.aliases.slice(0, 2).join(", ")})`;
    md += ` — ${v.summary || "See advisory"}`;
    if (v.fixedVersion) md += `\n   ✅ Fixed in \`${v.fixedVersion}\``;
    if (v.advisoryUrl) md += `\n   [Advisory](${v.advisoryUrl})`;
    md += `\n`;
  });
  if (hit.vulnerabilities.length > 5) {
    md += `\n*…and ${hit.vulnerabilities.length - 5} more*\n`;
  }
  md += `\n[All advisories on osv.dev](https://osv.dev/list?q=${encodeURIComponent(hit.package)}&ecosystem=npm)`;
  return md;
}

// ─── Remote DB Refresh ────────────────────────────────────────────────────────

async function refreshRemoteDb(
  context: vscode.ExtensionContext,
  force = false
) {
  const cfg = vscode.workspace.getConfiguration("npmSafetyGuard");
  if (!force && !cfg.get<boolean>("enableRemoteDb", true)) {
    return { entries: [], source: "none" as const };
  }

  const url = cfg.get<string>("remoteDbUrl", "") || DEFAULT_DB_URL;
  const storageDir = context.globalStorageUri.fsPath;

  const result = await fetchRemoteEntries(storageDir, url);
  setRemoteEntries(result.entries);
  return result;
}

// ─── Install Script Auditor ───────────────────────────────────────────────────

async function scanInstallScripts(
  doc: vscode.TextDocument,
  editor?: vscode.TextEditor,
  opts: { silent?: boolean } = {}
): Promise<void> {
  if (!isPackageJson(doc)) return;

  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(doc.getText()); }
  catch { return; }

  const allDeps: Record<string, string> = {
    ...(parsed.dependencies as Record<string, string> || {}),
    ...(parsed.devDependencies as Record<string, string> || {}),
    ...(parsed.peerDependencies as Record<string, string> || {}),
    ...(parsed.optionalDependencies as Record<string, string> || {}),
  };
  if (Object.keys(allDeps).length === 0) return;

  const customWhitelist = vscode.workspace
    .getConfiguration("npmSafetyGuard")
    .get<string[]>("scriptWhitelist", []);

  const hits = await checkAllInstallScripts(allDeps, customWhitelist);

  // Diagnostics — keep at Information so they don't drown the Problems panel
  const scriptDiagnostics: vscode.Diagnostic[] = hits.map((hit) => {
    const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
    const lineText = doc.lineAt(line).text;
    const range = new vscode.Range(line, 0, line, lineText.length);

    const presentScripts = Object.keys(hit.scripts).join(", ");
    const d = new vscode.Diagnostic(
      range,
      `[NPM Safety Guard / Scripts] ${hit.package}@${hit.version} ships install hooks: ${presentScripts}.\n` +
        `Hooks run BEFORE your code and are the most common malware vector. ` +
        `Review the package source before installing.`,
      vscode.DiagnosticSeverity.Information
    );
    d.source = "npm-safety-guard(scripts)";
    d.code = {
      value: `${hit.package}@${hit.version}`,
      target: vscode.Uri.parse(`https://www.npmjs.com/package/${hit.package}/v/${hit.version}`),
    };
    return d;
  });

  // Merge with other diagnostics — replace only the script-source ones
  const existing = diagnosticCollection.get(doc.uri) ?? [];
  const nonScript = existing.filter((d) => d.source !== "npm-safety-guard(scripts)");
  diagnosticCollection.set(doc.uri, [...nonScript, ...scriptDiagnostics]);

  // Inline gold decorations — but skip packages already flagged red (malicious wins)
  const activeEditor = editor ?? vscode.window.visibleTextEditors.find(
    (e) => e.document.uri.toString() === doc.uri.toString()
  );
  if (activeEditor && getConfig("showInlineDecorations")) {
    const flaggedByBundled = new Set(
      (diagnosticCollection.get(doc.uri) ?? [])
        .filter((d) => d.source === "npm-safety-guard")
        .map((d) => typeof d.code === "object" ? (d.code as any).value : undefined)
    );
    const decorations: vscode.DecorationOptions[] = hits
      .filter((hit) => !flaggedByBundled.has(`${hit.package}@${hit.version}`))
      .map((hit) => {
        const line = Math.max(0, findLineForPackage(doc, hit.package, hit.version));
        const lineText = activeEditor.document.lineAt(line).text;
        const md = new vscode.MarkdownString(buildScriptHoverMarkdown(hit));
        md.isTrusted = true;
        return { range: new vscode.Range(line, 0, line, lineText.length), hoverMessage: md };
      });
    activeEditor.setDecorations(scriptDecorationType, decorations);
  }

  if (!opts.silent) {
    if (hits.length === 0) {
      vscode.window.showInformationMessage(
        "NPM Safety Guard (Scripts): No unfamiliar install hooks detected."
      );
    } else {
      vscode.window.showWarningMessage(
        `NPM Safety Guard (Scripts): ${hits.length} package(s) declare install hooks.`,
        "View Report"
      ).then((choice) => {
        if (choice === "View Report") {
          vscode.commands.executeCommand("npmSafetyGuard.showReport");
        }
      });
    }
  }
}

// ─── Registry Heuristics ──────────────────────────────────────────────────────

let heuristicsPanel: vscode.WebviewPanel | undefined;

async function runHeuristics(doc: vscode.TextDocument): Promise<void> {
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(doc.getText()); }
  catch {
    vscode.window.showErrorMessage("NPM Safety Guard: Cannot parse package.json.");
    return;
  }

  const allDeps: Record<string, string> = {
    ...(parsed.dependencies as Record<string, string> || {}),
    ...(parsed.devDependencies as Record<string, string> || {}),
    ...(parsed.peerDependencies as Record<string, string> || {}),
    ...(parsed.optionalDependencies as Record<string, string> || {}),
  };
  if (Object.keys(allDeps).length === 0) {
    vscode.window.showInformationMessage("NPM Safety Guard: No dependencies to check.");
    return;
  }

  const results = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `NPM Safety Guard: Computing risk heuristics for ${Object.keys(allDeps).length} packages…`,
      cancellable: false,
    },
    async (progress) => {
      return checkAllHeuristics(allDeps, (done, total, pkg) => {
        progress.report({
          message: `${done}/${total} — ${pkg}`,
          increment: (1 / total) * 100,
        });
      });
    }
  );

  showHeuristicsReport(doc.fileName, results, Object.keys(allDeps).length);
}

function showHeuristicsReport(
  filePath: string,
  results: RegistrySignals[],
  totalDeps: number
): void {
  if (heuristicsPanel) {
    heuristicsPanel.reveal(vscode.ViewColumn.One);
  } else {
    heuristicsPanel = vscode.window.createWebviewPanel(
      "npmSafetyGuardHeuristics",
      "NPM Safety Guard — Risk Heuristics",
      vscode.ViewColumn.One,
      { enableScripts: false }
    );
    heuristicsPanel.onDidDispose(() => { heuristicsPanel = undefined; });
  }
  heuristicsPanel.webview.html = buildHeuristicsHtml(filePath, results, totalDeps);
}

function buildHeuristicsHtml(
  filePath: string,
  results: RegistrySignals[],
  totalDeps: number
): string {
  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  const flagged = results.length;
  const critical = results.filter((r) => r.riskLevel === "critical").length;
  const high = results.filter((r) => r.riskLevel === "high").length;
  const now = new Date().toLocaleString();

  results.sort((a, b) => b.riskScore - a.riskScore);

  const cardsHtml = results.length === 0
    ? `<div class="clean"><span class="icon">✅</span><h2>No risky packages detected</h2><p>Computed heuristics for ${totalDeps} package(s). All cleared the score 30 threshold.</p></div>`
    : results.map((r) => `
        <div class="hit ${r.riskLevel}">
          <div class="hit-header">
            <span class="score-badge ${r.riskLevel}">${r.riskScore}</span>
            <strong>${escape(r.package)}</strong>
            <code>@${escape(r.version)}</code>
            ${r.deprecated ? '<span class="chip danger">DEPRECATED</span>' : ""}
            ${r.maintainerTakeover && r.publisherIsMaintainer === false ? '<span class="chip danger">TAKEOVER</span>' : ""}
            ${!r.isLatestVersion && r.latestVersion ? `<span class="chip">latest is ${escape(r.latestVersion)}</span>` : ""}
          </div>
          <div class="metrics">
            <span><b>Pkg age:</b> ${r.packageAgeDays !== undefined ? Math.floor(r.packageAgeDays) + "d" : "?"}</span>
            <span><b>Ver age:</b> ${r.versionAgeDays !== undefined ? Math.floor(r.versionAgeDays) + "d" : "?"}</span>
            <span><b>Maintainers:</b> ${r.maintainerCount}</span>
            <span><b>Publisher:</b> ${escape(r.publisher ?? "?")}</span>
            <span><b>Downloads/wk:</b> ${r.downloadsLastWeek?.toLocaleString() ?? "?"}</span>
          </div>
          ${r.deprecated && r.deprecationMessage ? `<div class="deprecation">⚠ ${escape(r.deprecationMessage)}</div>` : ""}
          <ul class="reasons">
            ${r.reasons.map((reason) => `<li>${escape(reason)}</li>`).join("")}
          </ul>
        </div>
      `).join("");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>NPM Safety Guard — Heuristics</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; line-height: 1.6; }
  h1 { font-size: 1.4rem; color: #f0f6fc; margin-bottom: 4px; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }
  .summary { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 20px; min-width: 140px; text-align: center; }
  .stat .num { font-size: 2rem; font-weight: 800; }
  .stat .lbl { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat.danger .num { color: #f85149; }
  .stat.warn .num { color: #d29922; }
  .stat.ok .num { color: #3fb950; }
  .hit { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; }
  .hit.critical { border-left: 4px solid #f85149; background: #1c0f0f; }
  .hit.high     { border-left: 4px solid #d29922; background: #1c1600; }
  .hit.medium   { border-left: 4px solid #388bfd; background: #0d1e40; }
  .hit.low      { border-left: 4px solid #3fb950; }
  .hit-header { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
  .hit-header strong { font-size: 1.05rem; color: #f0f6fc; }
  code { background: #0d1117; padding: 2px 6px; border-radius: 3px; font-family: 'Cascadia Code', monospace; font-size: 0.85rem; }
  .score-badge {
    display: inline-block; min-width: 36px; padding: 4px 8px;
    font-size: 0.85rem; font-weight: 800; text-align: center;
    border-radius: 6px; color: #fff;
  }
  .score-badge.critical { background: #f85149; }
  .score-badge.high     { background: #d29922; color: #000; }
  .score-badge.medium   { background: #388bfd; }
  .score-badge.low      { background: #3fb950; color: #000; }
  .chip {
    background: #21262d; color: #c9d1d9;
    padding: 2px 8px; border-radius: 99px; font-size: 0.7rem;
    text-transform: uppercase; letter-spacing: 0.04em;
  }
  .chip.danger { background: #f85149; color: #fff; }
  .metrics { display: flex; gap: 18px; flex-wrap: wrap; color: #8b949e; font-size: 0.82rem; margin-bottom: 8px; padding: 6px 0; border-top: 1px solid #21262d; border-bottom: 1px solid #21262d; }
  .metrics b { color: #c9d1d9; font-weight: 600; }
  .deprecation { background: #1c0f0f; color: #ff7b72; padding: 8px 12px; border-radius: 4px; font-size: 0.85rem; margin: 8px 0; }
  .reasons { list-style: none; font-size: 0.85rem; color: #c9d1d9; }
  .reasons li { padding: 3px 0 3px 14px; position: relative; }
  .reasons li:before { content: "•"; position: absolute; left: 0; color: #8b949e; }
  .clean { text-align: center; padding: 60px 20px; border: 1px dashed #30363d; border-radius: 12px; color: #3fb950; }
  .clean .icon { font-size: 3rem; display: block; margin-bottom: 12px; }
  .clean h2 { font-size: 1.4rem; margin-bottom: 8px; }
  .clean p { color: #8b949e; }
  .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #30363d; font-size: 12px; color: #8b949e; text-align: center; }
  .footer a { color: #388bfd; text-decoration: none; }
</style></head><body>
  <h1>📊 Risk Heuristics Report</h1>
  <p class="meta">${escape(filePath)} · ${now}</p>
  <div class="summary">
    <div class="stat ${flagged === 0 ? 'ok' : 'warn'}"><div class="num">${flagged}</div><div class="lbl">Flagged</div></div>
    <div class="stat ${critical === 0 ? 'ok' : 'danger'}"><div class="num">${critical}</div><div class="lbl">Critical (≥80)</div></div>
    <div class="stat ${high === 0 ? 'ok' : 'warn'}"><div class="num">${high}</div><div class="lbl">High (≥60)</div></div>
    <div class="stat ok"><div class="num">${totalDeps}</div><div class="lbl">Analyzed</div></div>
  </div>
  ${cardsHtml}
  <div class="footer">
    Heuristics scored 0–100 from npm registry metadata: package age, version age,
    deprecation, maintainer takeover (publisher not in maintainers list),
    weekly download velocity.
    <br>Built by <a href="https://sendwavehub.tech">SendWaveHub</a>
  </div>
</body></html>`;
}

// ─── Lockfile Scanner ─────────────────────────────────────────────────────────

let lockfilePanel: vscode.WebviewPanel | undefined;

async function runLockfileScan(): Promise<void> {
  // Find a lockfile in the workspace
  const candidates = await vscode.workspace.findFiles(
    "**/{package-lock.json,yarn.lock,npm-shrinkwrap.json}",
    "**/node_modules/**",
    5
  );
  if (candidates.length === 0) {
    vscode.window.showInformationMessage(
      "NPM Safety Guard: No package-lock.json or yarn.lock found in workspace."
    );
    return;
  }

  const pick = candidates.length === 1
    ? candidates[0]
    : await vscode.window.showQuickPick(
        candidates.map((u) => ({ label: vscode.workspace.asRelativePath(u), uri: u })),
        { placeHolder: "Choose a lockfile to scan" }
      ).then((p) => (p as any)?.uri);
  if (!pick) return;

  const summary = await parseLockfile(pick.fsPath);
  if (!summary) {
    vscode.window.showErrorMessage(
      `NPM Safety Guard: Could not parse ${vscode.workspace.asRelativePath(pick)}.`
    );
    return;
  }

  // Flatten to name→version map (keep one version per name — the first seen)
  const depsMap: Record<string, string> = {};
  const multiVersion = new Map<string, Set<string>>();
  for (const d of summary.uniqueDeps) {
    if (!depsMap[d.name]) depsMap[d.name] = d.version;
    if (!multiVersion.has(d.name)) multiVersion.set(d.name, new Set());
    multiVersion.get(d.name)!.add(d.version);
  }

  // Because bundled DB + OSV + install-script checks all take `name→version`,
  // we actually need to scan every UNIQUE name@version pair. Build a special
  // map where the "name" is the real name and we call each checker per pair.
  const pairs: Array<{ name: string; version: string }> = summary.uniqueDeps;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `NPM Safety Guard: Scanning ${pairs.length} resolved dependencies from ${summary.format}…`,
      cancellable: false,
    },
    async (progress) => {
      progress.report({ message: "Bundled DB + remote feed…" });
      const bundledHits: Array<{ name: string; version: string; entry: MaliciousEntry }> = [];
      for (const p of pairs) {
        const pair = checkDependencies({ [p.name]: p.version });
        bundledHits.push(...pair);
      }

      // OSV.dev per-pair lookup. Going one-by-one because multiple versions of
      // the same name share a key in the `checkAllPackagesOSV({name: ver})` map.
      const osvResults: OSVResult[] = [];
      const CONC = 16;
      for (let i = 0; i < pairs.length; i += CONC) {
        const slice = pairs.slice(i, i + CONC);
        const settled = await Promise.all(
          slice.map(({ name, version }) =>
            checkAllPackagesOSV({ [name]: version }).then((rs) => rs[0] ?? null)
          )
        );
        for (const r of settled) if (r) osvResults.push(r);
        progress.report({
          message: `OSV ${Math.min(i + CONC, pairs.length)}/${pairs.length}…`,
          increment: (CONC / pairs.length) * 100,
        });
      }

      progress.report({ message: "Install-script audit…" });
      const scriptDeps: Record<string, string> = {};
      for (const p of pairs) scriptDeps[`${p.name}`] = p.version;
      // install-script audit runs per unique name — acceptable loss for MVP
      const customWhitelist = vscode.workspace
        .getConfiguration("npmSafetyGuard")
        .get<string[]>("scriptWhitelist", []);
      const scriptHits = await checkAllInstallScripts(scriptDeps, customWhitelist);

      showLockfileReport(
        pick.fsPath,
        summary,
        bundledHits,
        osvResults,
        scriptHits,
        multiVersion
      );
    }
  );
}

function showLockfileReport(
  lockfilePath: string,
  summary: LockfileSummary,
  bundledHits: Array<{ name: string; version: string; entry: MaliciousEntry }>,
  osvHits: OSVResult[],
  scriptHits: ScriptCheckResult[],
  multiVersion: Map<string, Set<string>>
): void {
  if (lockfilePanel) {
    lockfilePanel.reveal(vscode.ViewColumn.One);
  } else {
    lockfilePanel = vscode.window.createWebviewPanel(
      "npmSafetyGuardLockfile",
      "NPM Safety Guard — Lockfile Scan",
      vscode.ViewColumn.One,
      { enableScripts: false }
    );
    lockfilePanel.onDidDispose(() => { lockfilePanel = undefined; });
  }
  lockfilePanel.webview.html = buildLockfileHtml(
    lockfilePath, summary, bundledHits, osvHits, scriptHits, multiVersion
  );
}

function buildLockfileHtml(
  lockfilePath: string,
  summary: LockfileSummary,
  bundledHits: Array<{ name: string; version: string; entry: MaliciousEntry }>,
  osvHits: OSVResult[],
  scriptHits: ScriptCheckResult[],
  multiVersion: Map<string, Set<string>>
): string {
  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  const totalUnique = summary.uniqueDeps.length;
  const totalBundled = bundledHits.length;
  const totalCVEs = osvHits.length;
  const totalScripts = scriptHits.length;
  const duplicated = [...multiVersion.entries()].filter(([, set]) => set.size > 1);
  const now = new Date().toLocaleString();

  const bundledHtml = bundledHits.length === 0 ? "" : `
    <h2 class="section">🔴 Known Malicious (${bundledHits.length})</h2>
    ${bundledHits.map((h) => `
      <div class="hit critical">
        <div class="hit-header">
          <span class="badge critical">${h.entry.severity.toUpperCase()}</span>
          <strong>${escape(h.entry.title)}</strong>
        </div>
        <code>${escape(h.name)}@${escape(h.version)}</code>
        ${h.entry.safeVersion ? `<span class="safe"> → safe: <code>${escape(h.name)}@${escape(h.entry.safeVersion)}</code></span>` : ""}
        <p class="desc">${escape(h.entry.description)}</p>
      </div>
    `).join("")}
  `;

  const cveHtml = osvHits.length === 0 ? "" : `
    <h2 class="section">🔵 CVEs (${osvHits.length})</h2>
    ${osvHits.map((h) => `
      <div class="hit ${h.riskLevel}">
        <div class="hit-header">
          <span class="badge ${h.riskLevel}">${h.riskLevel.toUpperCase()}</span>
          <code>${escape(h.package)}@${escape(h.version)}</code>
          <span class="meta">${h.vulnerabilities.length} vuln(s)</span>
        </div>
        <ul class="vulns">
          ${h.vulnerabilities.slice(0, 3).map((v) => `
            <li><code>${escape(v.id)}</code>${v.fixedVersion ? ` — fix in <code>${escape(v.fixedVersion)}</code>` : ""} — ${escape(v.summary || "")}</li>
          `).join("")}
          ${h.vulnerabilities.length > 3 ? `<li><em>…and ${h.vulnerabilities.length - 3} more</em></li>` : ""}
        </ul>
      </div>
    `).join("")}
  `;

  const scriptHtml = scriptHits.length === 0 ? "" : `
    <h2 class="section">🟡 Install Scripts (${scriptHits.length})</h2>
    ${scriptHits.map((h) => `
      <div class="hit medium">
        <div class="hit-header">
          <code>${escape(h.package)}@${escape(h.version)}</code>
          <span class="meta">${Object.keys(h.scripts).join(", ")}</span>
        </div>
      </div>
    `).join("")}
  `;

  const dupHtml = duplicated.length === 0 ? "" : `
    <h2 class="section">⚠ Multiple versions resolved (${duplicated.length})</h2>
    <p class="meta">Packages pinned to more than one version in the tree — unusual, sometimes a dep-confusion signal.</p>
    <div class="duplist">
      ${duplicated.slice(0, 20).map(([name, versions]) => `
        <div class="duprow">
          <code>${escape(name)}</code>
          <span class="dup-versions">${[...versions].map((v) => `<code>${escape(v)}</code>`).join(" ")}</span>
        </div>
      `).join("")}
    </div>
  `;

  const allClean = totalBundled + totalCVEs + totalScripts === 0;
  const cleanBlock = allClean
    ? `<div class="clean"><span class="icon">✅</span><h2>Lockfile is clean</h2><p>Scanned ${totalUnique} unique resolved packages from ${summary.format}. No known malicious, CVE, or install-script findings.</p></div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NPM Safety Guard — Lockfile Scan</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117; color: #c9d1d9;
    padding: 24px; line-height: 1.6;
  }
  h1 { font-size: 1.4rem; color: #f0f6fc; margin-bottom: 4px; }
  h2.section { font-size: 1rem; color: #8b949e; margin: 24px 0 12px;
    text-transform: uppercase; letter-spacing: 0.05em;
    border-bottom: 1px solid #21262d; padding-bottom: 6px; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }
  .summary { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
  .stat {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 14px 20px; min-width: 130px; text-align: center;
  }
  .stat .num { font-size: 2rem; font-weight: 800; }
  .stat .lbl { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat.danger .num { color: #f85149; }
  .stat.warn .num { color: #d29922; }
  .stat.ok .num { color: #3fb950; }
  .stat.info .num { color: #388bfd; }
  .hit {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
  }
  .hit.critical { border-left: 4px solid #f85149; }
  .hit.high     { border-left: 4px solid #d29922; }
  .hit.medium   { border-left: 4px solid #388bfd; }
  .hit.low      { border-left: 4px solid #3fb950; }
  .hit-header { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 6px; }
  .badge {
    font-size: 0.65rem; font-weight: 700; padding: 2px 7px;
    border-radius: 99px; text-transform: uppercase;
  }
  .badge.critical { background: #f85149; color: #fff; }
  .badge.high     { background: #d29922; color: #000; }
  .badge.medium   { background: #388bfd; color: #fff; }
  .badge.low      { background: #3fb950; color: #000; }
  code {
    background: #0d1117; padding: 2px 6px; border-radius: 3px;
    font-family: 'Cascadia Code', monospace; font-size: 0.85rem;
  }
  .safe { color: #3fb950; font-size: 0.85rem; }
  .desc { color: #8b949e; font-size: 0.85rem; margin-top: 4px; }
  .vulns { list-style: none; margin-top: 6px; font-size: 0.85rem; color: #c9d1d9; }
  .vulns li { margin-bottom: 3px; padding-left: 12px; position: relative; }
  .vulns li:before { content: "•"; position: absolute; left: 0; color: #8b949e; }
  .duplist { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; }
  .duprow { display: flex; justify-content: space-between; padding: 4px 0; gap: 10px; }
  .dup-versions code { margin-left: 4px; }
  .clean {
    text-align: center; padding: 60px 20px;
    border: 1px dashed #30363d; border-radius: 12px; color: #3fb950;
  }
  .clean .icon { font-size: 3rem; display: block; margin-bottom: 12px; }
  .clean h2 { font-size: 1.4rem; margin-bottom: 8px; }
  .clean p { color: #8b949e; }
  .footer {
    margin-top: 32px; padding-top: 16px;
    border-top: 1px solid #30363d;
    font-size: 12px; color: #8b949e; text-align: center;
  }
  .footer a { color: #388bfd; text-decoration: none; }
</style>
</head>
<body>
  <h1>📋 Lockfile Scan Report</h1>
  <p class="meta">${escape(lockfilePath)} · ${summary.format} · ${now}</p>

  <div class="summary">
    <div class="stat ok">
      <div class="num">${totalUnique}</div>
      <div class="lbl">Unique Resolved</div>
    </div>
    <div class="stat ${totalBundled === 0 ? 'ok' : 'danger'}">
      <div class="num">${totalBundled}</div>
      <div class="lbl">Known Malicious</div>
    </div>
    <div class="stat ${totalCVEs === 0 ? 'ok' : 'warn'}">
      <div class="num">${totalCVEs}</div>
      <div class="lbl">CVEs</div>
    </div>
    <div class="stat ${totalScripts === 0 ? 'ok' : 'info'}">
      <div class="num">${totalScripts}</div>
      <div class="lbl">Install Scripts</div>
    </div>
    <div class="stat ${duplicated.length === 0 ? 'ok' : 'info'}">
      <div class="num">${duplicated.length}</div>
      <div class="lbl">Dup Versions</div>
    </div>
  </div>

  ${cleanBlock}
  ${bundledHtml}
  ${cveHtml}
  ${scriptHtml}
  ${dupHtml}

  <div class="footer">
    Lockfile scanner walks every resolved version in package-lock.json / yarn.lock —
    catches transitive compromises like flatmap-stream-via-event-stream.
    <br>Built by <a href="https://sendwavehub.tech">SendWaveHub</a>
  </div>
</body>
</html>`;
}

// ─── Deep Scanner ─────────────────────────────────────────────────────────────

let deepScanPanel: vscode.WebviewPanel | undefined;

async function runDeepScan(
  doc: vscode.TextDocument,
  _context: vscode.ExtensionContext
): Promise<void> {
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(doc.getText()); }
  catch {
    vscode.window.showErrorMessage("NPM Safety Guard: Cannot parse package.json.");
    return;
  }

  const allDeps: Record<string, string> = {
    ...(parsed.dependencies as Record<string, string> || {}),
    ...(parsed.devDependencies as Record<string, string> || {}),
    ...(parsed.peerDependencies as Record<string, string> || {}),
    ...(parsed.optionalDependencies as Record<string, string> || {}),
  };
  const totalDeps = Object.keys(allDeps).length;
  if (totalDeps === 0) {
    vscode.window.showInformationMessage("NPM Safety Guard: No dependencies to deep-scan.");
    return;
  }

  // Cap at 50 deps to keep scan time bounded
  const capped: Record<string, string> = {};
  Object.entries(allDeps).slice(0, 50).forEach(([k, v]) => { capped[k] = v; });
  const cappedNote = totalDeps > 50 ? ` (capped from ${totalDeps})` : "";

  const results = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `NPM Safety Guard: Deep-scanning ${Object.keys(capped).length} packages${cappedNote}…`,
      cancellable: false,
    },
    async (progress) => {
      return deepScanAll(capped, (done, total, currentPkg) => {
        progress.report({
          message: `${done}/${total} — ${currentPkg}`,
          increment: (1 / total) * 100,
        });
      });
    }
  );

  showDeepScanReport(doc.fileName, results, totalDeps);
}

function showDeepScanReport(
  filePath: string,
  results: DeepScanResult[],
  totalDeps: number
): void {
  if (deepScanPanel) {
    deepScanPanel.reveal(vscode.ViewColumn.One);
  } else {
    deepScanPanel = vscode.window.createWebviewPanel(
      "npmSafetyGuardDeepScan",
      "NPM Safety Guard — Deep Scan",
      vscode.ViewColumn.One,
      { enableScripts: false }
    );
    deepScanPanel.onDidDispose(() => { deepScanPanel = undefined; });
  }
  deepScanPanel.webview.html = buildDeepScanHtml(filePath, results, totalDeps);
}

function buildDeepScanHtml(
  filePath: string,
  results: DeepScanResult[],
  totalDeps: number
): string {
  const flagged = results.filter((r) => r.findings.length > 0 || r.scriptsPresent).length;
  const errored = results.filter((r) => r.error).length;
  const totalFindings = results.reduce((a, r) => a + r.findings.length, 0);
  const criticals = results.flatMap((r) => r.findings).filter((f) => f.severity === "critical").length;
  const now = new Date().toLocaleString();

  const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  results.sort(
    (a, b) => SEV_RANK[b.topSeverity === "none" ? "low" : b.topSeverity]
            - SEV_RANK[a.topSeverity === "none" ? "low" : a.topSeverity]
  );

  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  const cardsHtml = results.length === 0
    ? `<div class="clean"><span class="icon">✅</span><h2>No suspicious patterns detected</h2><p>Deep scan checked ${totalDeps} package(s) and found no obfuscation, eval, payload-blob, exfil, or self-publish signatures.</p></div>`
    : results.map((r) => {
        const findingsBySeverity = [...r.findings].sort(
          (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]
        );
        const findingsHtml = findingsBySeverity.map((f) => `
          <div class="finding ${f.severity}">
            <div class="finding-header">
              <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
              <span class="ftype">${escape(f.type.replace(/_/g, " "))}</span>
              <span class="floc">${escape(f.file)}${f.line ? `:${f.line}` : ""}</span>
            </div>
            <div class="fdesc">${escape(f.description)}</div>
            <pre class="fsnippet">${escape(f.snippet)}</pre>
          </div>
        `).join("");

        const sevClass = r.topSeverity === "none" ? "low" : r.topSeverity;
        return `
          <div class="pkg-block ${sevClass}">
            <div class="pkg-header">
              <div>
                <span class="pkg-badge ${sevClass}">${(r.topSeverity === "none" ? "LOW" : r.topSeverity).toUpperCase()}</span>
                <strong>${escape(r.package)}</strong> <code>@${escape(r.version)}</code>
                ${r.scriptsPresent ? '<span class="chip">install hooks</span>' : ""}
              </div>
              <div class="meta">${r.findings.length} finding(s) · ${r.filesScanned}/${r.totalFiles} files scanned</div>
            </div>
            ${findingsHtml}
            <div class="pkg-footer">
              <a href="https://www.npmjs.com/package/${escape(r.package)}/v/${escape(r.version)}">view on npm</a>
              ${r.error ? `<span class="error">⚠ ${escape(r.error)}</span>` : ""}
            </div>
          </div>
        `;
      }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NPM Safety Guard — Deep Scan</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117; color: #c9d1d9;
    padding: 24px; line-height: 1.6;
  }
  h1 { font-size: 1.4rem; color: #f0f6fc; margin-bottom: 4px; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }
  .summary { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
  .stat {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 14px 20px; min-width: 140px; text-align: center;
  }
  .stat .num { font-size: 2rem; font-weight: 800; }
  .stat .lbl { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat.danger .num { color: #f85149; }
  .stat.warn .num { color: #d29922; }
  .stat.ok .num { color: #3fb950; }
  .pkg-block {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 16px; margin-bottom: 16px;
  }
  .pkg-block.critical { border-left: 4px solid #f85149; background: #1c0f0f; }
  .pkg-block.high     { border-left: 4px solid #d29922; background: #1c1600; }
  .pkg-block.medium   { border-left: 4px solid #388bfd; background: #0d1e40; }
  .pkg-block.low      { border-left: 4px solid #3fb950; }
  .pkg-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; flex-wrap: wrap; gap: 8px; }
  .pkg-header strong { font-size: 1.05rem; color: #f0f6fc; margin-left: 6px; }
  .pkg-header code { background: #0d1117; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }
  .pkg-header .meta { color: #8b949e; font-size: 0.78rem; margin: 0; }
  .pkg-badge {
    font-size: 0.7rem; font-weight: 800; padding: 3px 9px;
    border-radius: 99px; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .pkg-badge.critical { background: #f85149; color: #fff; }
  .pkg-badge.high     { background: #d29922; color: #000; }
  .pkg-badge.medium   { background: #388bfd; color: #fff; }
  .pkg-badge.low      { background: #3fb950; color: #000; }
  .chip {
    display: inline-block; margin-left: 8px;
    background: #21262d; color: #d29922;
    padding: 2px 8px; border-radius: 99px; font-size: 0.7rem;
  }
  .finding {
    background: #0d1117; border: 1px solid #21262d; border-radius: 6px;
    padding: 10px 12px; margin-bottom: 8px;
  }
  .finding.critical { border-left: 3px solid #f85149; }
  .finding.high     { border-left: 3px solid #d29922; }
  .finding.medium   { border-left: 3px solid #388bfd; }
  .finding.low      { border-left: 3px solid #3fb950; }
  .finding-header { display: flex; gap: 10px; align-items: center; margin-bottom: 6px; flex-wrap: wrap; }
  .badge {
    font-size: 0.65rem; font-weight: 700; padding: 2px 7px;
    border-radius: 99px; text-transform: uppercase;
  }
  .badge.critical { background: #f85149; color: #fff; }
  .badge.high     { background: #d29922; color: #000; }
  .badge.medium   { background: #388bfd; color: #fff; }
  .badge.low      { background: #3fb950; color: #000; }
  .ftype { color: #f0f6fc; font-weight: 600; font-size: 0.85rem; }
  .floc  { color: #8b949e; font-size: 0.78rem; font-family: monospace; }
  .fdesc { color: #c9d1d9; font-size: 0.85rem; margin-bottom: 6px; }
  .fsnippet {
    background: #010409; padding: 6px 10px; border-radius: 4px;
    font-family: 'Cascadia Code', monospace; font-size: 0.78rem;
    color: #ff7b72; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  }
  .pkg-footer {
    margin-top: 10px; padding-top: 8px;
    border-top: 1px solid #21262d;
    font-size: 0.78rem; color: #8b949e;
    display: flex; justify-content: space-between;
  }
  .pkg-footer a { color: #388bfd; text-decoration: none; }
  .pkg-footer .error { color: #f85149; }
  .clean {
    text-align: center; padding: 60px 20px;
    border: 1px dashed #30363d; border-radius: 12px; color: #3fb950;
  }
  .clean .icon { font-size: 3rem; display: block; margin-bottom: 12px; }
  .clean h2 { font-size: 1.4rem; margin-bottom: 8px; }
  .clean p { color: #8b949e; }
  .footer {
    margin-top: 32px; padding-top: 16px;
    border-top: 1px solid #30363d;
    font-size: 12px; color: #8b949e; text-align: center;
  }
  .footer a { color: #388bfd; text-decoration: none; }
</style>
</head>
<body>
  <h1>🔬 Deep Scan Report</h1>
  <p class="meta">${escape(filePath)} · ${now}</p>

  <div class="summary">
    <div class="stat ${flagged === 0 ? 'ok' : 'warn'}">
      <div class="num">${flagged}</div>
      <div class="lbl">Flagged Packages</div>
    </div>
    <div class="stat ${totalFindings === 0 ? 'ok' : 'warn'}">
      <div class="num">${totalFindings}</div>
      <div class="lbl">Total Findings</div>
    </div>
    <div class="stat ${criticals === 0 ? 'ok' : 'danger'}">
      <div class="num">${criticals}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="stat ${errored === 0 ? 'ok' : 'warn'}">
      <div class="num">${errored}</div>
      <div class="lbl">Unreachable</div>
    </div>
    <div class="stat ok">
      <div class="num">${totalDeps}</div>
      <div class="lbl">Deps Analyzed</div>
    </div>
  </div>

  ${cardsHtml}

  <div class="footer">
    Deep scanner inspects each package's published tarball for eval, base64 payloads,
    String.fromCharCode reconstruction, install-time exfil, and self-publish signatures.
    <br>Built by <a href="https://sendwavehub.tech">SendWaveHub</a>
  </div>
</body>
</html>`;
}

function buildScriptHoverMarkdown(hit: ScriptCheckResult): string {
  let md = `### ⚠️ Install Script Detected\n\n`;
  md += `**Package:** \`${hit.package}@${hit.version}\`\n\n`;
  md += `This package runs code at install time via the following hook(s):\n\n`;

  for (const [hook, cmd] of Object.entries(hit.scripts)) {
    if (!cmd) continue;
    const truncated = cmd.length > 120 ? cmd.slice(0, 120) + "…" : cmd;
    md += `- **\`${hook}\`** → \`${truncated.replace(/`/g, "\\`")}\`\n`;
  }

  md += `\n💡 Install hooks are the #1 supply-chain attack vector. They run BEFORE any of your code, with full filesystem and network access.\n\n`;
  md += `**Mitigations:**\n`;
  md += `- Run \`npm install --ignore-scripts\` to skip hooks\n`;
  md += `- Audit the script content on npm before installing\n`;
  md += `- If this package is trusted, add \`"${hit.package}"\` to \`npmSafetyGuard.scriptWhitelist\` in settings\n\n`;
  md += `[View on npmjs.com](https://www.npmjs.com/package/${hit.package}/v/${hit.version})`;
  return md;
}
