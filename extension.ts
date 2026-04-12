import * as vscode from "vscode";
import { checkDependencies, MaliciousEntry } from "./maliciousDb";

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

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  console.log("NPM Safety Guard is active");

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
