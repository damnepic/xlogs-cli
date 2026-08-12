// Supabase RLS probe — the flagship check for the vibe-coder audience.
//
// The single most common serious mistake in AI-built apps: a Supabase database
// with Row Level Security off (or no policies), so anyone can read private tables.
// A vibe coder cannot see this; it looks fine in the browser.
//
// How it works (READ-ONLY, no destructive action — house doctrine):
//   1. Find the app's PUBLIC Supabase URL + anon key (the same ones the frontend
//      already ships to every visitor's browser). We only reuse what is public.
//   2. Ask the database, as an anonymous user, for its table list (the PostgREST
//      OpenAPI doc).
//   3. For each table, do ONE read (select=* limit 1). If it returns rows to an
//      anonymous request, RLS is not protecting it. We record the table name, its
//      COLUMN names, and an approximate row count as evidence — never the row
//      VALUES (we do not exfiltrate anyone's data into a report).
//
// No writes, no deletes, no auth bypass — only the reads a browser could already do.

import { safeFetch } from "./safe-fetch.mjs";

const FETCH_TIMEOUT_MS = 12000;
const MAX_TABLES = 25;
const UA = "xlogs/0.1 (+read-only security probe)";

async function getJson(url, headers) {
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

// Find the Supabase base URL + anon key inside the app's already-public code/bundles.
function detectSupabase(text) {
  // anon key: a JWT whose payload says role:"anon" (Supabase's public client key)
  let anonKey = null;
  let ref = null;
  for (const m of text.matchAll(/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
    const p = decodeJwt(m[0]);
    if (p && p.role === "anon") { anonKey = m[0]; ref = p.ref || null; break; }
  }
  // base URL: an explicit .../rest/v1 origin, a *.supabase.co URL, or derived from ref
  const bases = new Set();
  for (const m of text.matchAll(/(https?:\/\/[^/"'\s]+)\/rest\/v1/g)) bases.add(m[1]);
  for (const m of text.matchAll(/https?:\/\/[a-z0-9-]+\.supabase\.co/g)) bases.add(m[0]);
  if (ref) bases.add(`https://${ref}.supabase.co`);
  return { anonKey, bases: [...bases] };
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

// Main probe. `text` is the concatenated HTML + JS the live layer already fetched.
export async function probeSupabase(text, log = () => {}) {
  const { anonKey, bases } = detectSupabase(text || "");
  // tablesFound / tablesProbed feed the coverage receipt: a zero must be able to say
  // whether we looked and found nothing, or never got to look at all.
  const out = { detected: false, base: null, findings: [], notes: [], tablesFound: 0, tablesProbed: 0, keyFound: false };
  if (!anonKey || bases.length === 0) return out; // not a Supabase app (that we can see)
  out.keyFound = true;

  const auth = { apikey: anonKey, authorization: `Bearer ${anonKey}` };
  // pick the first base whose OpenAPI root actually answers
  let base = null, openapi = null;
  for (const b of bases) {
    const r = await getJson(`${b}/rest/v1/`, auth);
    if (r.ok && r.json) { base = b; openapi = r.json; break; }
  }
  if (!base) { out.notes.push("Supabase anon key found, but the API did not answer for enumeration."); return out; }
  out.detected = true;
  out.base = base;

  const tables = tablesFromOpenApi(openapi).slice(0, MAX_TABLES);
  out.tablesFound = tables.length;
  if (tables.length === 0) { out.notes.push(`Supabase detected at ${base}, but no tables were enumerable.`); return out; }
  log(`supabase: testing ${tables.length} tables for anonymous read at ${base}`);

  for (const table of tables) {
    out.tablesProbed++;
    // one read, limit 1, with an exact count so we can report scale without dumping data
    const r = await getJson(`${base}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, { ...auth, prefer: "count=exact" });
    if (!r.ok) continue;
    if (Array.isArray(r.json) && r.json.length >= 1) {
      const columns = Object.keys(r.json[0] || {});
      const total = (r.range.match(/\/(\d+)$/) || [])[1]; // Content-Range: 0-0/1234
      out.findings.push({
        kind: "supabase-rls",
        table,
        columns,
        count: total ? Number(total) : undefined,
        endpoint: `${base}/rest/v1/${table}`,
      });
    }
  }
  return out;
}
