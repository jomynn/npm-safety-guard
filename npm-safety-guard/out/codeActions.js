"use strict";
/**
 * NPM Safety Guard — Quick-Fix Code Actions
 *
 * Registered as a CodeActionProvider for package.json files. When the
 * cursor sits on a line flagged by any of our diagnostic sources, the
 * little lightbulb offers one-click fixes:
 *
 *   - 🔴 Bundled malware  → "Pin to safe version X.Y.Z"
 *                         → "Remove dependency"
 *   - 🔵 OSV CVE          → "Pin to fix version X.Y.Z" (extracted from
 *                            the diagnostic message)
 *   - 🟣 Typosquat        → "Replace with <closest-match>"
 *   - 🟡 Install scripts  → "Add <name> to script whitelist"
 *
 * Keeps UX tight by only offering actions whose fix is unambiguous:
 * parse fix versions from messages and/or consult in-memory caches.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.NpmSafetyGuardCodeActionProvider = void 0;
exports.parseNameVersion = parseNameVersion;
exports.extractHighestFixVersion = extractHighestFixVersion;
exports.findVersionRange = findVersionRange;
const vscode = require("vscode");
const maliciousDb_1 = require("./maliciousDb");
const typosquatChecker_1 = require("./typosquatChecker");
const NPM_GUARD_SOURCES = new Set([
    "npm-safety-guard",
    "npm-safety-guard(OSV)",
    "npm-safety-guard(scripts)",
    "npm-safety-guard(typosquat)",
    "npm-safety-guard(RL)",
]);
function parseNameVersion(code) {
    // Handles "@scope/name@1.2.3" and "name@1.2.3" plus typosquat form "foo → bar"
    const arrowIdx = code.indexOf(" → ");
    const core = arrowIdx >= 0 ? code.slice(0, arrowIdx) : code;
    const m = core.match(/^(@?[^@]+)@(.+)$/);
    if (!m)
        return { name: core, version: "" };
    return { name: m[1], version: m[2] };
}
function extractHighestFixVersion(message) {
    // Messages embed "(fix: 1.15.0)" one or more times. Pick the highest so
    // one bump covers every CVE in the diagnostic.
    const matches = [...message.matchAll(/\(fix:\s*([^)]+)\)/g)].map((m) => m[1].trim());
    if (matches.length === 0)
        return null;
    matches.sort(compareSemver);
    return matches[matches.length - 1];
}
function compareSemver(a, b) {
    const pa = a.split(/[-+]/)[0].split(".").map((n) => parseInt(n, 10) || 0);
    const pb = b.split(/[-+]/)[0].split(".").map((n) => parseInt(n, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const da = pa[i] ?? 0;
        const db = pb[i] ?? 0;
        if (da !== db)
            return da - db;
    }
    return 0;
}
function findVersionRange(doc, line, packageName) {
    const lineText = doc.lineAt(line).text;
    // Match: "<name>": "<version>"  or  "<name>":"<version>"
    const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`"${escaped}"\\s*:\\s*"([^"]+)"`);
    const m = re.exec(lineText);
    if (!m)
        return null;
    const valueStart = lineText.indexOf(m[1], m.index + m[0].indexOf(":"));
    if (valueStart < 0)
        return null;
    return new vscode.Range(line, valueStart, line, valueStart + m[1].length);
}
function findDependencyLineRange(doc, line) {
    // Include the full line + its line break so removal doesn't leave a gap
    const lineText = doc.lineAt(line).text;
    const nextLineStart = doc.lineAt(Math.min(line + 1, doc.lineCount - 1)).range.start;
    return new vscode.Range(line, 0, nextLineStart.line, 0);
}
function findNameRange(doc, line, packageName) {
    const lineText = doc.lineAt(line).text;
    const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`"(${escaped})"\\s*:`);
    const m = re.exec(lineText);
    if (!m)
        return null;
    const nameStart = m.index + 1; // after opening quote
    return new vscode.Range(line, nameStart, line, nameStart + packageName.length);
}
class NpmSafetyGuardCodeActionProvider {
    provideCodeActions(doc, _range, context) {
        const actions = [];
        for (const diag of context.diagnostics) {
            if (!diag.source || !NPM_GUARD_SOURCES.has(diag.source))
                continue;
            const codeValue = typeof diag.code === "object" && diag.code !== null
                ? String(diag.code.value ?? "")
                : String(diag.code ?? "");
            const parsed = parseNameVersion(codeValue);
            if (!parsed)
                continue;
            const { name, version } = parsed;
            const line = diag.range.start.line;
            // 🔴 Bundled malware
            if (diag.source === "npm-safety-guard") {
                const entry = (0, maliciousDb_1.checkPackage)(name, version);
                if (entry?.safeVersion) {
                    actions.push(this.createPinAction(doc, line, name, version, entry.safeVersion, diag, "🛡 Pin to safe version"));
                }
                actions.push(this.createRemoveAction(doc, line, name, diag));
            }
            // 🔵 OSV CVE
            if (diag.source === "npm-safety-guard(OSV)") {
                const fix = extractHighestFixVersion(diag.message);
                if (fix) {
                    actions.push(this.createPinAction(doc, line, name, version, fix, diag, "⬆ Upgrade to CVE fix version"));
                }
            }
            // 🟣 Typosquat / homoglyph
            if (diag.source === "npm-safety-guard(typosquat)") {
                const hit = (0, typosquatChecker_1.checkPackageName)(name, version);
                if (hit?.closestMatch) {
                    actions.push(this.createReplaceNameAction(doc, line, name, hit.closestMatch, diag));
                }
            }
            // 🟡 Install script
            if (diag.source === "npm-safety-guard(scripts)") {
                actions.push(this.createWhitelistAction(name, diag));
            }
        }
        return actions;
    }
    createPinAction(doc, line, name, _oldVersion, newVersion, diag, label) {
        const action = new vscode.CodeAction(`${label}: ${name}@${newVersion}`, vscode.CodeActionKind.QuickFix);
        const verRange = findVersionRange(doc, line, name);
        if (verRange) {
            const edit = new vscode.WorkspaceEdit();
            edit.replace(doc.uri, verRange, `^${newVersion}`);
            action.edit = edit;
        }
        action.diagnostics = [diag];
        action.isPreferred = true;
        return action;
    }
    createRemoveAction(doc, line, name, diag) {
        const action = new vscode.CodeAction(`🗑 Remove ${name} from dependencies`, vscode.CodeActionKind.QuickFix);
        // Remove the full line including newline. Also strip trailing comma from
        // the previous non-empty line if this was the last dep in its object —
        // we skip that subtlety and rely on the JSON formatter to recover.
        const lineRange = findDependencyLineRange(doc, line);
        const edit = new vscode.WorkspaceEdit();
        edit.delete(doc.uri, lineRange);
        action.edit = edit;
        action.diagnostics = [diag];
        return action;
    }
    createReplaceNameAction(doc, line, oldName, newName, diag) {
        const action = new vscode.CodeAction(`✏ Replace "${oldName}" with "${newName}"`, vscode.CodeActionKind.QuickFix);
        const nameRange = findNameRange(doc, line, oldName);
        if (nameRange) {
            const edit = new vscode.WorkspaceEdit();
            edit.replace(doc.uri, nameRange, newName);
            action.edit = edit;
        }
        action.diagnostics = [diag];
        action.isPreferred = true;
        return action;
    }
    createWhitelistAction(name, diag) {
        const action = new vscode.CodeAction(`➕ Add "${name}" to install-script whitelist`, vscode.CodeActionKind.QuickFix);
        action.command = {
            title: "Add to whitelist",
            command: "npmSafetyGuard.addToScriptWhitelist",
            arguments: [name],
        };
        action.diagnostics = [diag];
        return action;
    }
}
exports.NpmSafetyGuardCodeActionProvider = NpmSafetyGuardCodeActionProvider;
NpmSafetyGuardCodeActionProvider.providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];
//# sourceMappingURL=codeActions.js.map