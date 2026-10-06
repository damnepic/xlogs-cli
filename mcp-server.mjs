#!/usr/bin/env node
// ============================================================================
// xlogs-mcp (XL-186, INV-11) - the read-only scanner as MCP tools, on the free tier.
//
// The audience for xlogs is people whose apps were built by a coding agent. The agent is right
// there; asking it to open a browser, paste a URL and read a page back is the long way round. This
// lets Claude Code, Cursor, Windsurf or any MCP client run the scan itself and act on the result.
//
// WHY THE RECEIPT IS A TOOL OF ITS OWN (INV-11). Every scanner's integration returns findings.
// Findings alone are the half of the answer that cannot be checked: an agent handed three findings
// has no way to know whether thirty checks ran or three, or which ones could not complete. So
// `xlogs_receipt` returns what was CHECKED, with each check's status and the reason where it did
// not complete. An agent that can see the denominator can tell "nothing found" from "nothing
// looked", which is the distinction this whole product is built on.
//
// FREE, LIKE THE SCAN. No key, no account, no gate. It runs the same engine the website runs.
//
// SAFETY, INHERITED RATHER THAN RE-IMPLEMENTED. Every request goes through lib/safe-fetch.mjs, so
// the SSRF guards, the address pinning, the body caps and the per-origin ceiling all apply exactly
// as they do on the site. This server adds no network path of its own. It is read-only: it fetches
// and parses, and there is no tool here that writes anything anywhere.
//
// Speaks MCP over stdio (newline-delimited JSON-RPC 2.0). Zero dependencies, matching the rest of
// the codebase. It NEVER writes anything but protocol messages to stdout; diagnostics go to stderr.
//
// Register (.mcp.json in Claude Code / Cursor / Windsurf), from the public CLI repository:
//   { "mcpServers": { "xlogs": { "command": "npx", "args": ["-y", "github:damnepic/xlogs-cli#v0.2.2", "mcp"] } } }
// ============================================================================
import { scanUrl } from "./lib/engine.mjs";
import { normalizeAndValidate } from "./lib/ssrf.mjs";
import { consolidatedFix } from "./lib/fix-bundle.mjs";
import { surfaceCount } from "./lib/surface.mjs";
import { notChecked } from "./lib/cannot-check.mjs";
import { CATALOGUE_SQL } from "./lib/catalogue-audit.mjs";
import { MCP_TOOLS } from "./lib/mcp-tools.mjs";

const SERVER_VERSION = "1.0.0";
const log = (...a) => process.stderr.write("[xlogs-mcp] " + a.join(" ") + "\n");

// Defined in lib/mcp-tools.mjs (no imports), the same list /mcp publishes.
const TOOLS = MCP_TOOLS;

function severityLine(f) {
  const base = f.builderBaseline ? `\n    ${f.builderBaseline.text}` : "";
  return `[${String(f.severity || "").toUpperCase()}] ${f.title}${f.location ? ` at ${f.location}` : ""}\n    ${f.observed || f.plain || ""}${base}`.trimEnd();
}

// ONE RUN PER CONVERSATION (XL-324, 2026-09-30). Every tool used to call scanUrl, and
// xlogs_scan's own output tells the agent to "Call xlogs_receipt", so the natural sequence scanned
// the target twice: a second anonymous table read, a second round of dotfile requests, and a receipt
// that could describe a DIFFERENT run from the findings the agent was holding. xlogs_scan now always
// runs fresh and remembers the result; xlogs_receipt and xlogs_fix read that same run while it is
// recent, and every response says which run it describes. In memory only, for this process: nothing
// is persisted (ADR 0001 unchanged).
const RUN_TTL_MS = 15 * 60 * 1000;
const LAST_RUN = new Map(); // normalised url -> { result, at, stackOnly }
let runScanner = scanUrl;
export function __setScannerForTest(fn) { runScanner = fn || scanUrl; LAST_RUN.clear(); }

// STACK-ONLY (2026-10-06): the website and the CLI both offered it for a site you do not own; the
// agent path did not, so an agent asked about someone else's site could only run the full scan. A
// reused run keeps the mode it ran in, and every response says which mode that was, so an agent
// never reads a stack-only receipt as though the private-file and database checks had run.
async function scan(url, { fresh = false, stackOnly = false } = {}) {
  const v = normalizeAndValidate(url);
  if (!v.ok) return { error: v.reason || "That URL cannot be scanned." };
  const prior = LAST_RUN.get(v.url);
  if (!fresh && prior && Date.now() - prior.at < RUN_TTL_MS) return { result: prior.result, at: prior.at, reused: true, stackOnly: prior.stackOnly };
  const result = await runScanner(v.url, { stackOnly });
  if (!result.reachable) return { error: `Could not reach ${v.url}. Make sure it is deployed and publicly accessible.` };
  const at = Date.now();
  LAST_RUN.set(v.url, { result, at, stackOnly });
  return { result, at, reused: false, stackOnly };
}

function runLine({ at, reused, stackOnly }) {
  return `Scan run at ${new Date(at).toISOString()}${stackOnly ? ", stack-only (the private-file and database checks did not run)" : ""}${reused ? " (the same run xlogs_scan returned; no new requests were sent)" : ""}.`;
}

async function callTool(name, args = {}) {
  // THE NAME IS CHECKED BEFORE ANYTHING TOUCHES THE NETWORK. An earlier version scanned first and
  // rejected the unknown tool afterwards, so a typo or a hostile client could make this server send
  // a request the user never asked for. A tool that does not exist must cost nothing.
  if (!TOOLS.some((t) => t.name === name)) {
    return { isError: true, text: `unknown tool: ${name}. Available: ${TOOLS.map((t) => t.name).join(", ")}` };
  }

  if (name === "xlogs_supabase_audit_sql") {
    return { isError: false, text: `Run this in your own Supabase SQL editor. It reads system catalogues only and selects from no application table, so it cannot expose your data. xlogs never sees the output.\n\n${CATALOGUE_SQL}` };
  }

  const run = await scan(args.url, { fresh: name === "xlogs_scan", stackOnly: args.stack_only === true });
  const { error, result } = run;
  if (error) return { isError: true, text: error };
  const stamp = runLine(run);

  if (name === "xlogs_scan") {
    const findings = result.findings || [];
    const head = `${result.url}: ${result.verdict?.headline || "scan complete"}`;
    const counts = Object.entries(result.counts || {}).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(", ") || "no findings";
    const body = findings.length ? findings.map(severityLine).join("\n\n") : "No findings in the checks that ran.";
    // The bound travels with the result, always. A count without its denominator is the thing this
    // product refuses to ship.
    const ran = (result.receipt || []).filter((r) => r.status === "clear" || r.status === "found").length;
    const unresolved = (result.receipt || []).filter((r) => r.status === "inconclusive").length;
    const pagesRead = 1 + (result.pages || []).filter((p) => p.reachable).length;
    const bound = `\n\n${ran} checks completed across ${pagesRead} page${pagesRead === 1 ? "" : "s"}${unresolved ? `, ${unresolved} could NOT be completed (so this is not a clean bill of health)` : ""}. Call xlogs_receipt for the full list of what was and was not checked.`;
    // INV-33: the surface the code names, stated as inventory: referenced, never called.
    const s = result.surface;
    const surf = s && surfaceCount(s)
      ? `\n\nSURFACE YOUR CODE REFERENCES (not called): ${(s.routes || []).length} route(s)` +
        `${(s.graphql || []).length ? `, ${s.graphql.length} GraphQL endpoint(s)` : ""}` +
        `${s.trpc && s.trpc.procedures.length ? `, ${s.trpc.procedures.length} tRPC procedure(s)` : ""}` +
        `${(s.websockets || []).length ? `, ${s.websockets.length} WebSocket(s)` : ""}` +
        `${(s.specs || []).length ? `, API description ${s.specs[0]}` : ""}.` +
        `${s.spec && s.spec.status === "read" ? ` Its description declares ${s.spec.withoutAuthCount} of ${s.spec.operations} operation(s) with no authentication requirement; that can be intended, check each.` : ""}` +
        `\n${(s.routes || []).slice(0, 15).map((r) => `  ${r.methods.length ? r.methods.join("/") + " " : ""}${r.path}`).join("\n")}`
      : "";
    return { isError: false, text: `${head}\n${stamp}\n${counts}\n\n${body}${bound}${surf}` };
  }

  if (name === "xlogs_receipt") {
    const rows = result.receipt || [];
    const label = { clear: "clear", found: "FOUND", "n/a": "not applicable", inconclusive: "COULD NOT COMPLETE" };
    const lines = rows.map((r) => `- ${label[r.status] || r.status}: ${r.label}\n    ${r.detail || ""}`.trimEnd());
    const nc = notChecked(rows);
    const never = nc.structural.map((s) => `- ${s.label}\n    ${s.why}`).join("\n");
    return {
      isError: false,
      text: `${result.url}\n${stamp}\n\nWHAT THIS SCAN CHECKED (${rows.length} checks)\n${lines.join("\n")}\n\nWHAT XLOGS NEVER CHECKS, ON ANY SITE\n${never}\n\nA clean result means the completed checks did not find the specific signals they test for. It does not mean the app is secure.`,
    };
  }

  if (name === "xlogs_fix") {
    const agent = typeof args.agent === "string" && args.agent ? args.agent : "claude-code";
    const doc = consolidatedFix(result.findings || [], agent, result.url);
    return { isError: false, text: `${stamp}\n\n${doc || `No findings to fix on ${result.url} in the checks that ran. Call xlogs_receipt to see what was checked.`}` };
  }

  return { isError: true, text: `unknown tool: ${name}` };
}

// ---- JSON-RPC over stdio (newline-delimited) --------------------------------
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\n"); }
function reply(id, result) { send({ jsonrpc: "2.0", id, result }); }
function replyError(id, code, message) { send({ jsonrpc: "2.0", id, error: { code, message } }); }

let pending = 0;
let stdinEnded = false;
function maybeExit() { if (stdinEnded && pending === 0) process.exit(0); }

export async function handle(msg) {
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;
  switch (method) {
    case "initialize":
      reply(id, {
        protocolVersion: (params && params.protocolVersion) || "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "xlogs-mcp", version: SERVER_VERSION },
      });
      return;
    case "notifications/initialized":
    case "initialized":
      return;
    case "ping":
      if (!isNotification) reply(id, {});
      return;
    case "tools/list":
      reply(id, { tools: TOOLS });
      return;
    case "tools/call": {
      if (isNotification) return;
      pending++;
      try {
        const r = await callTool(params && params.name, (params && params.arguments) || {});
        reply(id, { content: [{ type: "text", text: r.text }], isError: !!r.isError });
      } catch (e) {
        reply(id, { content: [{ type: "text", text: `xlogs failed: ${e?.message || e}` }], isError: true });
      } finally {
        pending--;
        maybeExit();
      }
      return;
    }
    default:
      if (!isNotification) replyError(id, -32601, `method not found: ${method}`);
  }
}

export { TOOLS, callTool };

// The stdio transport. Exported so the packaged CLI can start it (`xlogs mcp`); run directly, this
// file starts it itself. Importing the module (tests, the site) starts nothing.
export function startStdio() {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { log("bad JSON line ignored"); continue; }
      handle(msg).catch((e) => log("handler error:", e?.message || String(e)));
    }
  });
  process.stdin.on("end", () => { stdinEnded = true; maybeExit(); });
  log(`ready (${TOOLS.length} tools, read-only, free)`);
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, "/")}`).href) startStdio();
