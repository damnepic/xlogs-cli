// Live layer — read-only probe of a DEPLOYED app. This is the half no
// source-only scanner can do, and the half no live-only scanner correlates back
// to source. It only issues GET requests to the target origin and its own
// same-origin assets. No exploitation, no writes, no auth bypass attempts — the
// same read-only posture the category's live scanners advertise.
//
// It surfaces: secrets actually shipped in HTML/JS bundles, missing security
// headers, exposed source maps (source disclosure), and a tiny set of classic
// exposed paths (/.env, /.git/config). The secrets it finds carry their real
// value so the correlation engine can grep them back into source.

import { extractSecrets, SECRET_PATTERNS } from "./patterns.mjs";
import { fingerprint } from "./fingerprint.mjs";
import { extractOrigins } from "./origins.mjs";
import { checkDanglingCname, checkEmailRecords } from "./dns-checks.mjs";
import { discoverFromCtLogs } from "./ct-logs.mjs";
import { probeSupabase } from "./live-supabase.mjs";
import { safeFetch } from "./safe-fetch.mjs";

const UA = "xlogs/0.1 (+read-only security probe)";
const MAX_SCRIPTS = 25;          // cap bundles fetched
const MAX_BYTES = 3 * 1024 * 1024; // 3MB per asset
const FETCH_TIMEOUT_MS = 15000;

const SECURITY_HEADERS = [
  ["content-security-policy", "CSP not set — no defense-in-depth against injected scripts (XSS)."],
  ["strict-transport-security", "HSTS not set — connections can be downgraded to HTTP (MITM)."],
  ["x-content-type-options", "X-Content-Type-Options not set — MIME sniffing risk."],
  ["x-frame-options", "X-Frame-Options not set (and no CSP frame-ancestors) — clickjacking risk."],
  ["referrer-policy", "Referrer-Policy not set — full URLs (with tokens) may leak in Referer."],
];

async function fetchText(url, { headOk = false } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await safeFetch(url, { signal: ctrl.signal, headers: { "user-agent": UA } });
    const headers = {};
    for (const [k, v] of res.headers) headers[k.toLowerCase()] = v;
    let body = "";
    if (!headOk) {
      const reader = res.body?.getReader?.();
      if (reader) {
        let total = 0;
        const chunks = [];
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          chunks.push(value);
          if (total > MAX_BYTES) { try { await reader.cancel(); } catch {} break; }
        }
        body = Buffer.concat(chunks).toString("utf8");
      } else {
        body = await res.text();
      }
    }
    return { ok: res.ok, status: res.status, headers, body, finalUrl: res.url || url };
  } catch (e) {
    return { ok: false, status: 0, headers: {}, body: "", error: e?.message || String(e), finalUrl: url };
  } finally {
    clearTimeout(t);
  }
}

function sameOrigin(a, b) {
  try { return new URL(a).origin === new URL(b).origin; } catch { return false; }
}

// Pull <script src> URLs and inline <script> bodies out of an HTML document.
function extractScripts(html, baseUrl) {
  const srcs = [];
  const inline = [];
  const tagRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  for (const m of html.matchAll(tagRe)) {
    const attrs = m[1] || "";
    const srcM = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs);
    if (srcM) {
      try { srcs.push(new URL(srcM[1], baseUrl).href); } catch {}
    } else if (m[2] && m[2].trim()) {
      inline.push(m[2]);
    }
  }
  // also self-closing / module preloads
  const linkRe = /<link\b[^>]*\brel\s*=\s*["'](?:modulepreload|preload)["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
  for (const m of html.matchAll(linkRe)) {
    if (/\.m?js(\?|$)/i.test(m[1])) { try { srcs.push(new URL(m[1], baseUrl).href); } catch {} }
  }
  return { srcs: [...new Set(srcs)], inline };
}

export async function liveLayer(rawUrl, log = () => {}) {
  const url = /^https?:\/\//i.test(rawUrl) ? rawUrl : "https://" + rawUrl;
  const result = { url, reachable: false, secrets: [], missingHeaders: [], exposures: [], rls: [], fetched: [], notes: [] };
  // Coverage: what we actually probed, so a zero finding can prove we looked rather
  // than reading as "we did not check". Feeds the receipt + the clean verdict.
  const coverage = {
    headersChecked: SECURITY_HEADERS.length,
    headersPresent: 0,
    scriptsReferenced: 0,
    scriptsScanned: 0,
    keyFormats: SECRET_PATTERNS.length,
    mapsChecked: 0,
    pathsProbed: 0,
    supabase: { keyFound: false, tablesFound: 0, tablesProbed: 0 },
  };
  result.coverage = coverage;

  log(`fetching ${url}`);
  const root = await fetchText(url);
  if (!root.ok && root.status === 0) {
    result.notes.push(`could not reach ${url}: ${root.error || "no response"}`);
    return result;
  }
  result.reachable = true;
  result.finalUrl = root.finalUrl;
  result.fetched.push(root.finalUrl);

  // ---- security headers (checked on the root document response) --------------
  for (const [h, msg] of SECURITY_HEADERS) {
    if (h === "x-frame-options") {
      const csp = root.headers["content-security-policy"] || "";
      if (!root.headers[h] && !/frame-ancestors/i.test(csp)) result.missingHeaders.push({ header: "X-Frame-Options / frame-ancestors", note: msg });
      continue;
    }
    if (!root.headers[h]) result.missingHeaders.push({ header: h, note: msg });
  }
  coverage.headersPresent = coverage.headersChecked - result.missingHeaders.length;

  // ---- secrets in the root HTML + inline scripts -----------------------------
  const { srcs, inline } = extractScripts(root.body, root.finalUrl);
  const addSecrets = (secs, sourceUrl) => {
    for (const s of secs) result.secrets.push({ ...s, sourceUrl });
  };
  addSecrets(extractSecrets(root.body), root.finalUrl + " (HTML)");
  inline.forEach((code, i) => addSecrets(extractSecrets(code), `${root.finalUrl} (inline script #${i + 1})`));
  const textBlobs = [root.body, ...inline]; // accumulate all served code for the Supabase probe

  // ---- same-origin JS bundles -----------------------------------------------
  coverage.scriptsReferenced = srcs.length;
  const bundles = srcs.filter((s) => sameOrigin(s, url)).slice(0, MAX_SCRIPTS);
  if (srcs.length > bundles.length) result.notes.push(`scanned ${bundles.length} same-origin scripts (of ${srcs.length} referenced; cross-origin + overflow skipped)`);
  for (const b of bundles) {
    log(`  bundle ${b}`);
    const r = await fetchText(b);
    if (!r.ok) continue;
    coverage.scriptsScanned++;
    result.fetched.push(b);
    addSecrets(extractSecrets(r.body), b);
    textBlobs.push(r.body);
    // source map disclosure: //# sourceMappingURL or a sibling .map that resolves
    const mapM = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/.exec(r.body);
    const mapUrl = mapM ? (() => { try { return new URL(mapM[1], b).href; } catch { return null; } })() : (b + ".map");
    if (mapUrl && sameOrigin(mapUrl, url)) {
      coverage.mapsChecked++;
      // Fetch the body and confirm it is REALLY a source map (JSON with version +
      // mappings/sources) — a catch-all route that 200s everything must not false-positive.
      const mr = await fetchText(mapUrl);
      const looksLikeMap = mr.ok && /"version"\s*:/.test(mr.body) && /"(mappings|sources)"\s*:/.test(mr.body);
      if (looksLikeMap) result.exposures.push({ kind: "source-map", url: mapUrl, note: "Source map is public — your original source (and any secrets in it) is reconstructable." });
    }
  }

  // ---- classic exposed paths (read-only GET of your OWN origin) --------------
  // Every entry carries its OWN shape validator. A 200 is never enough on its own,
  // because plenty of single-page apps answer 200 for every path; without the shape
  // check this would be the single biggest false-positive source in the scanner.
  //
  // Deliberately NOT probed: /admin, /dashboard and friends. A 200 there almost always
  // means a login page, which is correct and safe, and we cannot tell an exposed admin
  // panel from a login form without interpreting the page. Guessing would manufacture
  // alarms, so the check is left out until it can be made evidence-based.
  const isEnvBody = (b) => /^[A-Z0-9_]+\s*=/m.test(b) && !/<html/i.test(b);
  const EXPOSED_PATHS = [
    ["/.env", isEnvBody, "Environment file served publicly: every secret in it is exposed."],
    ["/.env.local", isEnvBody, "Local environment file served publicly: every secret in it is exposed."],
    ["/.env.production", isEnvBody, "Production environment file served publicly: every secret in it is exposed."],
    ["/.git/config", (b) => /\[core\]/.test(b), ".git/ is served publicly: full source history is downloadable."],
    ["/.git/HEAD", (b) => /^ref:\s/.test(b), ".git/ is served publicly: full source history is downloadable."],
    // Editor sync config. When present it usually holds SFTP host + credentials.
    ["/.vscode/sftp.json", (b) => /"host"\s*:/.test(b) && /"(password|privateKeyPath)"\s*:/.test(b), "Editor upload config served publicly: it contains your server credentials."],
  ];
  const origin = new URL(url).origin;
  coverage.pathsProbed = EXPOSED_PATHS.length;
  // Probed in parallel so adding paths costs coverage, not scan time.
  const pathResults = await Promise.all(EXPOSED_PATHS.map(async ([path, valid, note]) => {
    const r = await fetchText(origin + path);
    return { path, note, hit: r.ok && r.status === 200 && valid(r.body || ""), body: r.body || "" };
  }));
  for (const p of pathResults) {
    if (!p.hit) continue;
    result.exposures.push({ kind: "exposed-path", url: origin + p.path, note: p.note });
    for (const s of extractSecrets(p.body)) result.secrets.push({ ...s, sourceUrl: origin + p.path });
  }

  // ---- platform fingerprint (XL-056) + backend surface map (INV-03) ----------
  // Both derive from text already in memory, so they cost no extra requests.
  const allText = textBlobs.join("\n");
  result.fingerprint = fingerprint(root.finalUrl, root.headers, allText);
  result.origins = extractOrigins(allText, root.finalUrl);

  // ---- DNS checks: dangling CNAME (XL-023) + email spoofing (XL-024) ---------
  // Public DNS reads only. Both are deliberately conservative; see lib/dns-checks.mjs.
  try {
    const hostname = new URL(root.finalUrl).hostname;
    log(`dns: checking ${hostname}`);
    // Run alongside the DNS lookups so the third-party certificate log adds no
    // wall-clock time of its own.
    const [cname, email, ct] = await Promise.all([
      checkDanglingCname(hostname, fetchText),
      checkEmailRecords(hostname),
      discoverFromCtLogs(hostname),
    ]);
    result.dns = { cname, email };
    result.ct = ct;
  } catch (e) {
    result.notes.push(`DNS checks skipped: ${e?.message || e}`);
    result.dns = { cname: { status: "inconclusive" }, email: { status: "inconclusive" } };
    result.ct = { status: "inconclusive", reason: "DNS and certificate-log checks could not run." };
  }

  // ---- Supabase RLS probe (read-only) — the flagship vibe-coder check ---------
  try {
    const supa = await probeSupabase(allText, log);
    result.rls = supa.findings || [];
    result.supabase = { detected: supa.detected, base: supa.base };
    coverage.supabase = { keyFound: !!supa.keyFound, tablesFound: supa.tablesFound || 0, tablesProbed: supa.tablesProbed || 0 };
    for (const n of supa.notes || []) result.notes.push(n);
    if (result.rls.length) log(`supabase: ${result.rls.length} table(s) readable anonymously`);
  } catch (e) {
    result.notes.push(`supabase probe skipped: ${e?.message || e}`);
  }

  return result;
}
