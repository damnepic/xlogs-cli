#!/usr/bin/env node
// xlogs: a free, read-only security scanner for AI-built web apps.
//
// Point it at a deployed URL. It finds the security mistakes that actually get
// exploited in vibe-coded apps, explains each in plain English with the evidence
// behind it, and hands you a fix you can paste into your AI coding tool.
//
// Zero dependencies. Node 18+ built-ins only.

import { writeFileSync } from "node:fs";
import { scanUrl } from "../lib/engine.mjs";
import { STACK_ONLY_SKIPS } from "../lib/live.mjs";
import { toSarif } from "../lib/sarif.mjs";
import { normalizeAndValidate } from "../lib/ssrf.mjs";
import { gateDecision } from "../lib/gate.mjs";

const VERSION = "0.2.0";
const GATE_ORDER = ["critical", "high", "medium", "low"];

const HELP = `xlogs ${VERSION}: read-only security scanner for AI-built apps

  xlogs <url>                          scan a deployed app
  xlogs <url> --fail-on high           exit 1 if anything high or above (CI gate)
  xlogs <url> --sarif out.sarif        write SARIF 2.1.0 for GitHub code scanning
  xlogs <url> --json                   machine-readable output
  xlogs <url> --agent cursor           tailor the fix for your coding tool
  xlogs mcp                            run as an MCP server over stdio, for a coding agent

Options
  --fail-on <sev>  critical | high | medium | low
  --sarif <file>   write SARIF 2.1.0
  --json           print the full result as JSON
  --agent <name>   default | lovable | cursor | claude-code | manual
  --stack-only     read only what a browser loading the page already fetches. Use this
                   on a site you do NOT own: it never requests the private-file paths,
                   never asks a database for rows, and follows no links. Those checks
                   are marked "not checked" in the receipt, never counted as passes.
  --allow-inconclusive  let the gate pass when a check could not run (each one is still
                   named). Off by default: a gate that could not test your database
                   has not passed it.
  --quiet          findings only, no banner
  -h, --help       this help
  -v, --version    print version

Exit codes
  0  no findings at or above --fail-on (or no critical findings when --fail-on is unused)
  1  a finding at or above --fail-on
  2  a critical finding (when --fail-on is not used)
  3  usage error, or the target could not be reached
  4  gate could not verify: nothing at or above --fail-on, but a check could not run

What it checks
  publicly readable database (Supabase RLS) · secret keys shipped to the browser ·
  missing security headers · exposed source maps · private files (.env, .git) ·
  dangling DNS / subdomain takeover · email spoofing protection (SPF, DMARC)

Read-only, always. Every request is an ordinary GET. xlogs never writes, logs in, or
tries to exploit anything, and it needs no account and no repository access.
Scan only apps you own or are authorised to test, and reach for --stack-only when you
are looking at somebody else's site.  https://xlogs.com`;

const C = process.stdout.isTTY
  ? { dim: "\x1b[2m", red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m", bold: "\x1b[1m", off: "\x1b[0m" }
  : { dim: "", red: "", yellow: "", green: "", cyan: "", bold: "", off: "" };

const SEV_COLOR = { critical: C.red, high: C.red, medium: C.yellow, low: C.dim };
const MARK = { clear: "✓", found: "!", inconclusive: "?", "n/a": "·" };

function parseArgs(argv) {
  const a = { url: "", failOn: "", sarif: "", json: false, agent: "default", quiet: false, stackOnly: false, allowInconclusive: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--fail-on") a.failOn = (argv[++i] || "").toLowerCase();
    else if (k === "--url") a.url = argv[++i] || "";
    else if (k === "--sarif") a.sarif = argv[++i] || "";
    else if (k === "--agent") a.agent = argv[++i] || "default";
    else if (k === "--json") a.json = true;
    else if (k === "--stack-only") a.stackOnly = true;
    else if (k === "--allow-inconclusive") a.allowInconclusive = true;
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

  // Say the mode before the verdict, not after it. A stack-only scan skips three checks, and a
  // reader who meets "nothing serious found" first has already drawn a conclusion the scan did
  // not earn. The receipt below marks each skipped check "not checked"; this is the headline.
  if (r.stackOnly) {
    out.push(`${C.yellow}stack-only scan: ${STACK_ONLY_SKIPS.length} checks did not run${C.off}`);
    for (const s of STACK_ONLY_SKIPS) out.push(`  ${C.dim}not checked: ${s.name}, ${s.why}${C.off}`);
    out.push(`  ${C.dim}This is the mode for a site you do not own. It is not a security verdict.${C.off}`);
    out.push("");
  }

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
  // `xlogs mcp`: the same read-only scanner as MCP tools over stdio, for Claude Code, Cursor and any
  // MCP client. Imported only here, so a normal scan never loads it.
  if (process.argv[2] === "mcp") {
    const { startStdio } = await import("../mcp-server.mjs");
    startStdio();
    return;
  }
  const a = parseArgs(process.argv.slice(2));
  if (a.version) { process.stdout.write(VERSION + "\n"); return; }
  if (a.help || !a.url) { process.stdout.write(HELP + "\n"); process.exitCode = a.url ? 0 : 3; return; }
  if (a.failOn && !GATE_ORDER.includes(a.failOn)) {
    process.stderr.write(`xlogs: --fail-on must be one of ${GATE_ORDER.join(" | ")}\n`);
    process.exitCode = 3;
    return;
  }

  // A GATE MUST NOT BE ABLE TO PASS BY NOT LOOKING. --stack-only drops the private-file and
  // database checks, so a CI gate running it would report "no findings at or above high" on an
  // app serving its own .env. The combination is also incoherent: a gate blocks YOUR deploy of
  // YOUR app, and stack-only exists for a site you do not own.
  if (a.stackOnly && (a.failOn || a.sarif)) {
    process.stderr.write("xlogs: --stack-only cannot be combined with --fail-on or --sarif.\n");
    process.stderr.write("       It skips the private-file and database checks, so a gate would pass\n");
    process.stderr.write("       because it did not look. Drop --stack-only to gate your own deploy.\n");
    process.exitCode = 3;
    return;
  }

  const v = normalizeAndValidate(a.url);
  if (!v.ok) { process.stderr.write(`xlogs: ${v.reason}\n`); process.exitCode = 3; return; }

  if (!a.quiet && !a.json) process.stderr.write(`xlogs: scanning ${v.url} (read-only${a.stackOnly ? ", stack-only" : ""})\n`);
  const result = await scanUrl(v.url, { stackOnly: a.stackOnly });

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
    // One decision for both CLIs (lib/gate.mjs): a finding fails, an untested check is not a pass.
    const d = gateDecision({ findings: result.findings, verdict: result.verdict }, a.failOn, { allowInconclusive: a.allowInconclusive });
    for (const line of d.lines) if (d.code !== 0 || !a.quiet) process.stderr.write(`xlogs: ${line}\n`);
    return finish(d.code);
  }

  return finish((result.counts?.critical || 0) > 0 ? 2 : 0);
}

main().catch((e) => {
  process.stderr.write(`xlogs: ${e?.message || e}\n`);
  process.exitCode = 3;
});
