// Supabase RLS probe — the flagship check for the vibe-coder audience.
//
// The single most common serious mistake in AI-built apps: a Supabase database
// with Row Level Security off (or no policies), so anyone can read private tables.
// A vibe coder cannot see this; it looks fine in the browser.
//
// How it works (READ-ONLY, no destructive action — house doctrine):
//   1. Find the app's PUBLIC Supabase URL + public key (the same ones the frontend
//      already ships to every visitor's browser). We only reuse what is public.
//   2. Ask the database, as an anonymous user, for its table list (the PostgREST
//      OpenAPI doc).
//   3. For each table, do ONE read (select=* limit 1). If it returns rows to an
//      anonymous request, RLS is not protecting it. We record the table name, its
//      COLUMN names, and a row count as evidence — never the row VALUES (we do not
//      exfiltrate anyone's data into a report).
//
// No writes, no deletes, no auth bypass — only the reads a browser could already do.
//
// ⚠️ STEP 2 NO LONGER WORKS ON HOSTED SUPABASE (found 2026-09-30, P0).
// Supabase stopped serving the OpenAPI document to the anon key on 2026-03-11 for new projects
// and 2026-04-08 for all existing ones (supabase.com/changelog/42949). This file was written on
// 2026-08-09 against the old behaviour, and every fixture plus our production regression gate
// mocked the old behaviour, so nothing went red. On a hosted project the probe now finds the key, is refused
// the table list, and must say so: INCONCLUSIVE, never a pass. We do NOT guess table names to
// get around the refusal until a replacement is proven against a real owned project (INV-32).
// A PostgREST that still serves its schema to anon (PostgREST's own default, e.g. self-hosted)
// is still probed exactly as before.

import { safeFetch } from "./safe-fetch.mjs";

const FETCH_TIMEOUT_MS = 12000;
const MAX_TABLES = 25;
const UA = "xlogs/0.1 (+read-only security probe)";

// XL-310: every request this probe makes is counted in the SAME per-scan budget as the rest of the
// live layer. Until 2026-09-30 it used its own fetcher and was never counted, so the published cap
// of 60 requests per scan was false by up to 26. When the budget is spent the probe stops and says
// so; the receipt reports that as inconclusive, never as a pass.
async function getJson(url, headers, budget) {
  if (budget) {
    if (budget.used >= budget.max) { budget.exceeded = true; return { ok: false, status: 0, json: null, range: "", budgetSpent: true }; }
    budget.used++;
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await safeFetch(url, { signal: ctrl.signal, headers: { "user-agent": UA, ...headers } });
    const range = res.headers.get("content-range") || "";
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    return { ok: res.ok, status: res.status, json, range };
  } catch (e) {
    return { ok: false, status: 0, json: null, range: "", error: e?.message || String(e) };
  } finally {
    clearTimeout(t);
  }
}

// Decode a JWT payload without verifying (we only read public claims).
function decodeJwt(tok) {
  try {
    const seg = tok.split(".")[1];
    const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  } catch { return null; }
}

// Supabase's current public key format. It is not a JWT, so it goes in the `apikey` header only;
// the Authorization header is for a user's session token, and we never have one.
// Left-bounded so `xsb_publishable_` inside a longer identifier does not match.
export const PUBLISHABLE_KEY_RE = /(?<![A-Za-z0-9_-])sb_publishable_[A-Za-z0-9_-]{16,}/;

// Evidence that the served code TALKS to a Supabase database from the browser, as opposed to
// merely linking a file in Supabase Storage. Used only to decide between "no database visible"
// and "a database client is visible but we could not recognise its key".
const CLIENT_SIGNAL_RE = /\/rest\/v1\b|@supabase\/supabase-js|supabase-js\/|postgrest-js/;

// Find the Supabase base URL + public key inside the app's already-public code/bundles.
export function detectSupabase(text) {
  let anonKey = null;
  let keyKind = null;
  let ref = null;
  // 1. The legacy anon key: a JWT whose payload says role:"anon".
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
    const p = decodeJwt(m[0]);
    if (p && p.role === "anon") { anonKey = m[0]; keyKind = "legacy-anon"; ref = p.ref || null; break; }
  }
  // 2. The current publishable key. Checked second so an app shipping both is probed with the
  //    legacy key, which carries the project ref and has been the tested path.
  if (!anonKey) {
    const m = text.match(PUBLISHABLE_KEY_RE);
    if (m) { anonKey = m[0]; keyKind = "publishable"; }
  }
  // base URL: an explicit .../rest/v1 origin, a *.supabase.co URL, or derived from ref
  const bases = new Set();
  for (const m of text.matchAll(/(https?:\/\/[^/"'\s]+)\/rest\/v1/g)) bases.add(m[1]);
  for (const m of text.matchAll(/https?:\/\/[a-z0-9-]+\.supabase\.co/g)) bases.add(m[0]);
  if (ref) bases.add(`https://${ref}.supabase.co`);
  return { anonKey, keyKind, bases: [...bases], clientSignal: CLIENT_SIGNAL_RE.test(text) };
}

// Extract table names from a PostgREST OpenAPI (swagger 2.0) document.
function tablesFromOpenApi(doc) {
  if (!doc || typeof doc !== "object") return [];
  const names = new Set();
  if (doc.definitions) for (const k of Object.keys(doc.definitions)) names.add(k);
  if (doc.paths) for (const p of Object.keys(doc.paths)) {
    const t = p.replace(/^\//, "");
    if (t && !t.startsWith("rpc/") && !t.includes("{")) names.add(t);
  }
  return [...names];
}

// Hosted Supabase's refusal, as its changelog quotes it. The STATUS is not documented, so the
// refusal is recognised by the body; any 401/403 without that body is still a refusal, just an
// unexplained one.
function isSchemaRefusal(r) {
  const msg = r && r.json && typeof r.json === "object" ? String(r.json.message || "") : "";
  return /access to schema is forbidden/i.test(msg);
}

// Main probe. `text` is the concatenated HTML + JS the live layer already fetched.
export async function probeSupabase(text, log = () => {}, { budget = null } = {}) {
  const { anonKey, keyKind, bases, clientSignal } = detectSupabase(text || "");
  // Every field below feeds the coverage receipt: a zero must be able to say whether we looked
  // and found nothing, or never got to look at all.
  //   urlSeen          a Supabase address is in the served code
  //   clientSignal     the served code talks to a Supabase database, not just to Storage
  //   keyFound/keyKind a public key we recognise (legacy anon JWT, or sb_publishable_)
  //   detected         the API answered the table-list request
  //   schemaRefused    the API refused the table list (hosted Supabase since 2026-04-08)
  //   tablesFound      tables the list named, counted BEFORE the cap
  //   tablesProbed     tables we asked for one row
  //   tablesReadable / tablesEmpty / tablesRefused / tablesErrored   the outcome of each ask
  const out = {
    detected: false, base: null, findings: [], notes: [],
    urlSeen: bases.length > 0, clientSignal, keyFound: false, keyKind: null,
    schemaStatus: null, schemaRefused: false,
    tablesFound: 0, tablesProbed: 0, tablesReadable: 0, tablesEmpty: 0, tablesRefused: 0, tablesErrored: 0,
    budgetStopped: false,
  };
  if (!anonKey || bases.length === 0) return out; // no key we recognise, or no address to use it on
  out.keyFound = true;
  out.keyKind = keyKind;

  const auth = keyKind === "publishable"
    ? { apikey: anonKey }
    : { apikey: anonKey, authorization: `Bearer ${anonKey}` };
  // pick the first base whose OpenAPI root actually answers
  let base = null, openapi = null;
  for (const b of bases) {
    const r = await getJson(`${b}/rest/v1/`, auth, budget);
    if (r.budgetSpent) { out.budgetStopped = true; break; }
    if (r.ok && r.json) { base = b; openapi = r.json; break; }
    if (out.schemaStatus === null) out.schemaStatus = r.status;
    if (isSchemaRefusal(r)) out.schemaRefused = true;
  }
  if (!base) {
    out.notes.push(out.schemaRefused
      ? "Supabase public key found, but Supabase refused to list the tables to it (it has done so for every hosted project since April 2026)."
      : "Supabase public key found, but the API did not answer for enumeration.");
    return out;
  }
  out.detected = true;
  out.base = base;

  const all = tablesFromOpenApi(openapi);
  out.tablesFound = all.length; // counted BEFORE the cap, so the receipt can say "25 of 60"
  const tables = all.slice(0, MAX_TABLES);
  if (tables.length === 0) { out.notes.push(`Supabase detected at ${base}, but no tables were enumerable.`); return out; }
  log(`supabase: testing ${tables.length} of ${all.length} tables for anonymous read at ${base}`);

  for (const table of tables) {
    // one read, limit 1. XL-333: `count=estimated`, not `count=exact`. An exact count makes the
    // site's Postgres count every row of a table we already know is readable; the report only
    // needs scale, and PostgREST's estimate is exact on small tables and a planner figure on large
    // ones. Proof of exposure is the returned ROW, never the count.
    const r = await getJson(`${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, { ...auth, prefer: "count=estimated" }, budget);
    if (r.budgetSpent) { out.budgetStopped = true; break; }
    out.tablesProbed++;
    if (!r.ok) {
      if (r.status === 401 || r.status === 403) out.tablesRefused++;
      else out.tablesErrored++;
      continue;
    }
    if (Array.isArray(r.json) && r.json.length >= 1) {
      out.tablesReadable++;
      const columns = Object.keys(r.json[0] || {});
      const total = (r.range.match(/\/(\d+)$/) || [])[1]; // Content-Range: 0-0/1234
      out.findings.push({
        kind: "supabase-rls",
        table,
        columns,
        count: total ? Number(total) : undefined,
        endpoint: `${base}/rest/v1/${table}`,
      });
    } else if (Array.isArray(r.json)) {
      out.tablesEmpty++; // empty OR protected: from outside we cannot tell which
    } else {
      out.tablesErrored++;
    }
  }
  return out;
}
