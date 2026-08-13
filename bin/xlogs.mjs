#!/usr/bin/env node
// xlogs — a free, read-only security scanner for AI-built web apps.
//
// Point it at a deployed URL. It finds the security mistakes that actually get
// exploited in vibe-coded apps, explains each in plain English with the evidence
// behind it, and hands you a fix you can paste into your AI coding tool.
//
// Zero dependencies. Node 18+ built-ins only.

import { writeFileSync } from "node:fs";
import { scanUrl } from "../lib/engine.mjs";
import { toSarif } from "../lib/sarif.mjs";
import { normalizeAndValidate } from "../lib/ssrf.mjs";

const VERSION = "0.1.0";
const GATE_ORDER = ["critical", "high", "medium", "low"];

const HELP = `xlogs ${VERSION} — read-only security scanner for AI-built apps

  xlogs <url>                          scan a deployed app
  xlogs <url> --fail-on high           exit 1 if anything high or above (CI gate)
  xlogs <url> --sarif out.sarif        write SARIF 2.1.0 for GitHub code scanning
  xlogs <url> --json                   machine-readable output
  xlogs <url> --agent cursor           tailor the fix for your coding tool

Options
  --fail-on <sev>  critical | high | medium | low
  --sarif <file>   write SARIF 2.1.0
  --json           print the full result as JSON
  --agent <name>   default | lovable | cursor | claude-code | manual
  --quiet          findings only, no banner
  -h, --help       this help
  -v, --version    print version

Exit codes
  0  no findings at or above --fail-on (or no critical findings when --fail-on is unused)
  1  a finding at or above --fail-on
  2  a critical finding (when --fail-on is not used)
  3  usage error, or the target could not be reached

What it checks
  publicly readable database (Supabase RLS) · secret keys shipped to the browser ·
  missing security headers · exposed source maps · private files (.env, .git) ·
  dangling DNS / subdomain takeover · email spoofing protection (SPF, DMARC)

Read-only, always. Every request is an ordinary GET. xlogs never writes, logs in, or
tries to exploit anything, and it needs no account and no repository access.
Scan only apps you own or are authorised to test.  https://xlogs.com`;

const C = process.stdout.isTTY
  ? { dim: "\x1b[2m", red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m", bold: "\x1b[1m", off: "\x1b[0m" }
  : { dim: "", red: "", yellow: "", green: "", cyan: "", bold: "", off: "" };

const SEV_COLOR = { critical: C.red, high: C.red, medium: C.yellow, low: C.dim };
const MARK = { clear: "✓", found: "!", inconclusive: "?", "n/a": "–" };

function parseArgs(argv) {
  const a = { url: "", failOn: "", sarif: "", json: false, agent: "default", quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--fail-on") a.failOn = (argv[++i] || "").toLowerCase();
    else if (k === "--url") a.url = argv[++i] || "";
    else if (k === "--sarif") a.sarif = argv[++i] || "";
    else if (k === "--agent") a.agent = argv[++i] || "default";
    else if (k === "--json") a.json = true;
    else if (k === "--quiet" || k === "-q") a.quiet = true;
    else if (k === "-h" || k === "--help") a.help = true;
    else if (k === "-v" || k === "--version") a.version = true;
    else if (!k.startsWith("-") && !a.url) a.url = k;
    else process.stderr.write(`xlogs: ignoring unknown argument ${k}\n`);
  }
  return a;
}

// Close undici's keep-alive pool before exiting. Calling process.exit() directly can
// race a closing socket and trip an assertion on Windows.
async function finish(code) {
  try {
    const d = globalThis[Symbol.for("undici.globalDispatcher.1")];
    if (d?.close) await d.close();
  } catch {}
  process.exitCode = code;
}

function render(r, agent) {
  const out = [];
  const n = r.findings.length;

  out.push("");
  out.push(`${C.bold}${r.url}${C.off} ${C.dim}scanned in ${(r.durationMs / 1000).toFixed(1)}s${C.off}`);
  out.push("");

  if (r.verdict && r.verdict.level !== "issues") {
    out.push(`${C.green}✓ ${r.verdict.headline}${C.off}`);
    out.push(`  ${r.verdict.summary}`);
    for (const res of r.verdict.residuals || []) {
      out.push(`  ${C.dim}· ${res.title}: ${res.why}${C.off}`);
    }
  } else {
    out.push(`${C.red}${C.bold}${r.verdict?.headline || `${n} issue${n === 1 ? "" : "s"} found`}${C.off}`);
  }
  out.push("");

  for (const f of r.findings) {
    const col = SEV_COLOR[f.severity] || "";
    out.push(`${col}${C.bold}[${f.severity.toUpperCase()}]${C.off} ${f.title}`);
    if (f.location) out.push(`  ${C.dim}where:${C.off} ${f.location}`);
    if (f.cwe || f.owasp) out.push(`  ${C.dim}${[f.cwe, f.owasp].filter(Boolean).join(" · ")}${C.off}`);
    if (f.plain) out.push(`  ${f.plain}`);
    if (f.observed) out.push(`  ${C.dim}evidence: ${f.observed}${C.off}`);
    const fix = f.fixes?.[agent] || f.fixes?.default;
    if (fix) {
      out.push(`  ${C.cyan}fix (paste to your AI tool):${C.off}`);
      for (const line of String(fix).split("\n")) out.push(`    ${line}`);
    }
    out.push("");
  }

  // The coverage receipt: what each check actually did, so a zero can never be
  // mistaken for "we did not look".
  out.push(`${C.dim}what we checked${C.off}`);
  for (const c of r.receipt || []) {
    out.push(`  ${MARK[c.status] || "·"} ${c.label} ${C.dim}${c.detail}${C.off}`);
  }
  out.push("");
  return out.join("\n");
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  if (a.version) { process.stdout.write(VERSION + "\n"); return; }
  if (a.help || !a.url) { process.stdout.write(HELP + "\n"); process.exitCode = a.url ? 0 : 3; return; }
  if (a.failOn && !GATE_ORDER.includes(a.failOn)) {
    process.stderr.write(`xlogs: --fail-on must be one of ${GATE_ORDER.join(" | ")}\n`);
    process.exitCode = 3;
    return;
  }

  const v = normalizeAndValidate(a.url);
  if (!v.ok) { process.stderr.write(`xlogs: ${v.reason}\n`); process.exitCode = 3; return; }

  if (!a.quiet && !a.json) process.stderr.write(`xlogs: scanning ${v.url} (read-only)\n`);
  const result = await scanUrl(v.url);

  if (!result.reachable) {
    process.stderr.write(`xlogs: could not reach ${v.url}. Is it deployed and public?\n`);
    return finish(3);
  }

  if (a.sarif) {
    writeFileSync(a.sarif, JSON.stringify(toSarif(result, { version: VERSION, scannedAt: new Date().toISOString() }), null, 2));
    if (!a.quiet) process.stderr.write(`xlogs: sarif written to ${a.sarif}\n`);
  }

  if (a.json) process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  else process.stdout.write(render(result, a.agent));

  if (a.failOn) {
    const idx = GATE_ORDER.indexOf(a.failOn);
    const allowed = new Set(GATE_ORDER.slice(0, idx + 1));
    const failures = result.findings.filter((f) => allowed.has(f.severity));
    if (failures.length) {
      process.stderr.write(`xlogs: GATE FAILED — ${failures.length} finding(s) at or above ${a.failOn}\n`);
      return finish(1);
    }
    if (!a.quiet) process.stderr.write(`xlogs: gate passed — nothing at or above ${a.failOn}\n`);
    return finish(0);
  }

  return finish((result.counts?.critical || 0) > 0 ? 2 : 0);
}

main().catch((e) => {
  process.stderr.write(`xlogs: ${e?.message || e}\n`);
  process.exitCode = 3;
});
