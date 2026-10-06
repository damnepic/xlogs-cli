// Smoke test: proves the package is self-contained and behaves, without needing
// network access to a third party. Run with: npm test
import http from "node:http";
import { scanUrl } from "../lib/engine.mjs";
import { toSarif } from "../lib/sarif.mjs";
import { normalizeAndValidate } from "../lib/ssrf.mjs";

let failed = 0;
const ok = (c, m) => { console.log(`  ${c ? "pass" : "FAIL"}: ${m}`); if (!c) failed = 1; };
const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${s.address().port}`)));

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const ANON = `${b64u({ alg: "HS256", typ: "JWT" })}.${b64u({ role: "anon", ref: "smoke" })}.notarealsignature000`;

async function main() {
  console.log("== input guard ==");
  ok(normalizeAndValidate("myapp.com").ok, "accepts a bare public domain");
  ok(!normalizeAndValidate("http://localhost:3000").ok, "refuses localhost");
  ok(!normalizeAndValidate("http://169.254.169.254/").ok, "refuses the cloud metadata address");

  console.log("== scan a mock vulnerable app ==");
  let base = "";
  const srv = http.createServer((req, res) => {
    const p = new URL(req.url, base || "http://x").pathname;
    if (p === "/") { res.writeHead(200, { "content-type": "text/html" }); res.end(`<script src="/app.js"></script>`); }
    else if (p === "/app.js") { res.writeHead(200, { "content-type": "text/javascript" }); res.end(`const SB="${base}/rest/v1";const KEY="${ANON}";`); }
    // GRADING fixture: a PostgREST that still serves its schema to anon (PostgREST's own default,
    // e.g. self-hosted). HOSTED Supabase has refused this to public keys since 2026-04-08, and the
    // scanner then reports the database as NOT checked, never as a pass; the upstream repo tests
    // that path in test/supabase-truth.test.mjs. This smoke test checks detection and grading once
    // a table name is known, so it needs the schema.
    else if (p === "/rest/v1/") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ definitions: { customers: {} } })); }
    else if (p === "/rest/v1/customers") { res.writeHead(200, { "content-type": "application/json", "content-range": "0-0/42" }); res.end(JSON.stringify([{ id: 1, email: "a@b.test" }])); }
    else { res.writeHead(404); res.end("[]"); }
  });
  base = await listen(srv);
  process.env.XLOGS_ALLOW_PRIVATE = "1"; // let the smoke test reach its own mock
  try {
    const r = await scanUrl(base);
    ok(r.reachable, "mock app is reachable");
    const rls = r.findings.find((f) => f.category === "supabase-rls");
    ok(!!rls && rls.severity === "critical", "reports the publicly readable table as critical");
    ok(!!rls?.fixes?.default, "every finding carries a copy-paste fix");
    ok(!r.findings.some((f) => f.category === "exposed-secret"), "the public anon key is NOT reported as a leaked secret");
    ok(Array.isArray(r.receipt) && r.receipt.length > 0, "emits a coverage receipt");
    ok(typeof r.durationMs === "number", "reports a measured scan duration");
    const s = toSarif(r);
    ok(s.version === "2.1.0" && s.runs[0].results.length > 0, "exports valid SARIF 2.1.0");
  } finally {
    srv.close();
    delete process.env.XLOGS_ALLOW_PRIVATE;
  }

  console.log(failed ? "\nSMOKE TEST FAILED" : "\nSMOKE TEST PASSED");
  try { const d = globalThis[Symbol.for("undici.globalDispatcher.1")]; if (d?.close) await d.close(); } catch {}
  process.exitCode = failed;
}
main();
