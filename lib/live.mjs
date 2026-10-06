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
import { scanStorage } from "./storage-scan.mjs";
import { discoverPages } from "./crawl.mjs";
import { fingerprint } from "./fingerprint.mjs";
import { extractOrigins } from "./origins.mjs";
import { extractSurface, analyseSpec, sriInventory } from "./surface.mjs";
import { extractSbom } from "./sbom.mjs";
import { checkScriptOrigins } from "./bad-cdns.mjs";
import { detectStack } from "./stack-detect.mjs";
import { extractSiteIdentity } from "./site-identity.mjs";
import { extractSiteDetails } from "./site-details.mjs";
import { pageWeight } from "./page-weight.mjs";
// ONE definition of same-site, shared with the third-party inventory. See lib/same-site.mjs:
// this used to live here while bad-cdns.mjs compared hostnames, and the two disagreed.
export { sameSite } from "./same-site.mjs";
import { sameSite } from "./same-site.mjs";
import { checkDanglingCname, checkEmailRecords } from "./dns-checks.mjs";
import { discoverFromCtLogs, isPlatform, apexOf } from "./ct-logs.mjs";
import { lookupDomain } from "./rdap.mjs";
import { compressionSummary } from "./compression.mjs";
import { probeSupabase } from "./live-supabase.mjs";
import { safeFetch, MAX_BODY_BYTES } from "./safe-fetch.mjs";
import { withSlot } from "./concurrency.mjs";
import { osvLookup } from "./ghscan/osv.mjs";

const UA = "xlogs/0.1 (+read-only security probe)";
export const MAX_SCRIPTS = 25;          // cap bundles fetched
const MAX_PAGES = 6;             // XL-227: additional same-origin pages crawled, sharing the outbound budget
const MAX_SOURCEMAP_PATHS = 400; // dependency paths kept for stack detection, from maps already read
// AMPLIFICATION CAP. Measured: one scan of a page with 20 scripts made 47 outbound
// requests (1 page + 20 bundles + 20 source-map probes + 6 exposed paths); the worst
// case with MAX_SCRIPTS is 1 + 25 + 25 + 6 = 57. That ratio is inherent to scanning
// (you cannot inspect a bundle without fetching it), but it must not grow silently as
// checks are added, and one unauthenticated inbound request should never be able to
// generate unbounded outbound work. Hitting this cap makes the scan INCOMPLETE rather
// than quietly partial, per the XLOGS-SEC-011 invariant.
export const MAX_OUTBOUND_PER_SCAN = 60;
const MAX_SECRETS_TOTAL = 250;   // findings listed per scan; see addSecrets
// NOT THE BINDING LIMIT. safeFetch buffers the body (MAX_BODY_BYTES, 10MB, marked incomplete past
// it) and hands it over as one chunk, so this read loop only stops early on a streamed body. The
// published per-asset limit is MAX_RESPONSE_MB in lib/capability-stats.mjs, guarded equal to safeFetch.
const MAX_BYTES = 10 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 15000;

const SECURITY_HEADERS = [
  ["content-security-policy", "CSP not set: no defense-in-depth against injected scripts (XSS)."],
  ["strict-transport-security", "HSTS not set: connections can be downgraded to HTTP (MITM)."],
  ["x-content-type-options", "X-Content-Type-Options not set: MIME sniffing risk."],
  ["x-frame-options", "X-Frame-Options not set (and no CSP frame-ancestors): clickjacking risk."],
  ["referrer-policy", "Referrer-Policy not set: full URLs (with tokens) may leak in Referer."],
];

// XL-250: A HEADER THAT IS PRESENT BUT DOES NOTHING COUNTS AS ABSENT, WITH THE REASON. Presence
// alone read HSTS max-age=0 as protection and a Report-Only CSP as a policy, and it missed a CSP set
// by <meta> tag, reporting "CSP not set" on a page that has one. Returns { ok, reason }.
export function headerEffect(h, headers, body = "") {
  const v = String(headers[h] || "").trim();
  if (h === "content-security-policy") {
    if (v) return { ok: true };
    if (/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*content=["'][^"']{4,}/i.test(String(body))) return { ok: true, via: "meta" };
    if (headers["content-security-policy-report-only"]) return { ok: false, reason: "only Content-Security-Policy-Report-Only is set, which reports violations but blocks nothing" };
    return { ok: false };
  }
  if (h === "strict-transport-security") {
    if (!v) return { ok: false };
    const age = Number((v.match(/max-age\s*=\s*"?(\d+)/i) || [])[1]);
    if (age === 0) return { ok: false, reason: "HSTS is set with max-age=0, which tells browsers to forget it" };
    return { ok: true };
  }
  if (h === "x-content-type-options") {
    if (!v) return { ok: false };
    return /^nosniff$/i.test(v) ? { ok: true } : { ok: false, reason: `X-Content-Type-Options is "${v.slice(0, 40)}", and only "nosniff" has an effect` };
  }
  if (h === "x-frame-options") {
    const ancestors = (String(headers["content-security-policy"] || "").match(/frame-ancestors\s+([^;]*)/i) || [])[1];
    if (ancestors !== undefined) {
      return /(^|\s)\*(\s|$)/.test(ancestors.trim()) ? { ok: false, reason: "frame-ancestors * lets any site frame the page" } : { ok: true };
    }
    if (!v) return { ok: false };
    return /^(deny|sameorigin)$/i.test(v) ? { ok: true } : { ok: false, reason: `X-Frame-Options is "${v.slice(0, 40)}", which browsers ignore (only DENY and SAMEORIGIN work)` };
  }
  if (h === "referrer-policy") {
    if (!v) return { ok: false };
    return /(^|,)\s*unsafe-url\s*$/i.test(v) ? { ok: false, reason: "Referrer-Policy is unsafe-url, which sends the full address, query string included, to every site" } : { ok: true };
  }
  return { ok: !!v };
}

// A served npm lockfile, recognised by SHAPE rather than by status code: SPA catch-alls answer 200
// with index.html for every path. Read off the first bytes only, so a lockfile truncated at our read
// cap is still recognised (and then reported as unparsed rather than silently skipped).
// The advisory lookup is the one call this module makes to a host other than the target, so tests
// replace it rather than reach the internet. Production never sets it.
let osvFetchForTest = null;
export function __setOsvFetchForTest(f) { osvFetchForTest = f; }

// WHERE A BUNDLE'S SOURCE MAP IS (XL-299). Returns { inline: jsonText } for a data: URI map,
// { url } otherwise. Precedence follows the browsers: the SourceMap (or legacy X-SourceMap)
// response header, then the LAST sourceMappingURL comment, because a bundle that inlines a library
// can carry that library's comment earlier in the file and only the trailing one is the bundle's
// own; then the sibling .map guess. An undecodable inline map returns { inline: "" }, which
// readSourceMap rejects, so it is counted as checked and never reported.
export function sourceMapLocation(body, headers = {}, bundleUrl) {
  const abs = (u) => { try { return new URL(u, bundleUrl).href; } catch { return null; } };
  const hdr = String(headers["sourcemap"] || headers["x-sourcemap"] || "").trim();
  const all = [...String(body || "").matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g)];
  const ref = hdr || (all.length ? all[all.length - 1][1] : "");
  if (/^data:/i.test(ref)) {
    const m = /^data:[^,]*?(;base64)?,(.*)$/is.exec(ref);
    let inline = "";
    try { inline = m ? (m[1] ? Buffer.from(m[2], "base64").toString("utf8") : decodeURIComponent(m[2])) : ""; } catch { inline = ""; }
    return { inline };
  }
  return { url: ref ? abs(ref) : abs(bundleUrl + ".map") };
}

export function isNpmLockfile(body, headers = {}) {
  if (/text\/html/i.test(String(headers["content-type"] || ""))) return false;
  const head = String(body || "").trimStart().slice(0, 4096);
  return head.startsWith("{") && /"lockfileVersion"\s*:\s*\d/.test(head) && /"(?:packages|dependencies|requires)"\s*:/.test(head);
}

async function fetchText(url, { headOk = false, clientKey = "anon", budget = null } = {}) {
  if (budget) {
    if (budget.used >= budget.max) {
      budget.exceeded = true;
      return { ok: false, status: 0, headers: {}, body: "", finalUrl: url, complete: false,
               bodyStatus: "fanout-cap", bodyReason: `This scan reached its limit of ${budget.max} outbound requests.` };
    }
    budget.used++;
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    // CONCURRENCY CEILINGS. Wrapping here, at the single outbound call site for the
    // whole live layer, is what makes the per-origin bound real: one scan fans out to
    // the page plus up to 25 bundles plus probes, so bounding "scans" would not bound
    // what the victim actually receives.
    const res = await withSlot(url, clientKey, () =>
      safeFetch(url, { signal: ctrl.signal, headers: { "user-agent": UA } }));
    const headers = {};
    for (const [k, v] of res.headers) headers[k.toLowerCase()] = v;
    // SET-COOKIE IS THE ONE HEADER THAT CANNOT SURVIVE AS A STRING. Iterating Headers joins
    // repeated fields with ", ", and a cookie's own Expires attribute contains a comma
    // ("expires=Mon, 16 Aug 2027"), so the joined value cannot be split back apart reliably - a
    // regex that tries will mangle real cookies silently rather than failing. getSetCookie()
    // returns the array they always were. Stored under a separate key so the header map keeps its
    // string-valued shape for every existing reader.
    try {
      const sc = res.headers.getSetCookie?.();
      if (Array.isArray(sc) && sc.length) headers["set-cookie-list"] = sc;
    } catch {}
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
    // Carry WHY the body ended. A truncated or undecodable response must never look
    // like a complete empty document, or the scanner reports "clean" on content it
    // never actually read.
    // HOW MANY BYTES THIS COST THE BROWSER, which we were already counting and discarding.
    //
    // `content-length` when the server sends one, because that is the true transfer size even
    // when we stopped reading at MAX_BYTES. Otherwise the bytes we actually read - and that is a
    // FLOOR, not a size, whenever the body was truncated. `bytesExact` carries which of the two it
    // is, so a page-weight total can say "at least" rather than quietly understating a huge bundle
    // as exactly the size of our own cap.
    const declared = Number(headers["content-length"]);
    const measured = Buffer.byteLength(body, "utf8");
    const exact = Number.isFinite(declared) && declared > 0;
    return { ok: res.ok, status: res.status, headers, body, finalUrl: res.url || url,
             // What the server actually negotiated, and what crossed the wire (XL-098). safe-fetch
             // strips the content-encoding header once it has decoded the body, so these two
             // properties are the only surviving record of it.
             encoding: res.contentEncoding || null,
             transferBytes: Number.isFinite(res.transferBytes) ? res.transferBytes : null,
             bytes: exact ? declared : measured,
             bytesExact: exact || res.bodyComplete !== false,
             complete: res.bodyComplete !== false, bodyStatus: res.bodyStatus || "ok", bodyReason: res.bodyReason || "" };
  } catch (e) {
    // A refused slot must read as INCOMPLETE, never as an empty successful fetch, or
    // back-pressure would quietly turn into a false "clean" (the XLOGS-SEC-011 invariant).
    const throttled = e?.code === "CONCURRENCY_TIMEOUT";
    return { ok: false, status: 0, headers: {}, body: "", error: e?.message || String(e), finalUrl: url,
             complete: false, bodyStatus: throttled ? "throttled" : "error", bodyReason: e?.message || String(e) };
  } finally {
    clearTimeout(t);
  }
}

function sameOrigin(a, b) {
  try { return new URL(a).origin === new URL(b).origin; } catch { return false; }
}

/**
 * SAME SITE, NOT SAME ORIGIN, for the app's own bundles.
 *
 * Production sites routinely serve their JavaScript from an asset subdomain: static.linear.app,
 * assets.example.com, cdn.example.com. Those are the app's OWN bundles on the app's OWN
 * infrastructure, and a same-ORIGIN test rejects every one of them. Measured on linear.app: 283
 * scripts referenced, 27 on static.linear.app, 0 scanned. The secrets check - the most important
 * one xlogs runs - silently did not run at all, and reported "none could be downloaded" having
 * requested nothing. Same failure as the apex-to-www redirect bug, different cause.
 *
 * THE BOUNDARY IS THE REGISTRABLE DOMAIN, AND THE PLATFORM LIST IS WHY THAT IS SAFE.
 * A naive "share the last two labels" rule would treat alice.github.io and bob.github.io as one
 * site, and they are two unrelated people. So a host under a known platform suffix is compared
 * whole: only the exact same hostname counts, never a sibling. Everything else compares apexes,
 * which is what a browser and a human both mean by "the same site".
 *
 * Genuinely third-party CDNs still fail this and are still skipped: cal.com's bundles live on
 * framerusercontent.com, which is somebody else's server, and we do not fetch it.
 */

// WHAT STACK-ONLY MODE DOES NOT DO, stated once, exported, and rendered wherever the mode runs.
//
// XL-244. The mode existed for a year inside the web app and was unreachable from the CLI we
// publish, so the tool strangers point at strangers had no gentle setting. Adding the flag was the
// easy half. The half that matters: a scan that quietly drops three checks and then prints a clean
// report is the zero-versus-never-looked failure in its purest form, and we had just written a
// ledger row refusing a rival's score for exactly that. So the list lives here, next to the gates
// it describes, and test/stack-only.test.mjs counts the `stackOnly` gates in this file and fails if
// the two ever disagree. A new gate without a line here is a silent omission; that is the point.
// Each entry's `id` is repeated as a `stack-only-skip: <id>` comment on every gate that
// implements it, because one check can need more than one gate (the private-file skip needs two
// expressions). The test compares the SET of tags in this file against the SET of ids here, so a
// new gate without a tag fails, and a tag with no entry fails. Counting gates alone would not
// have worked: the first version of that assertion read 4 gates against 3 checks and was right
// about the mismatch for the wrong reason.
export const STACK_ONLY_SKIPS = [
  { id: "private-files", name: "Private files served publicly",
    why: "the six paths that must never be public (.env and its variants, .git, editor credentials) and /package-lock.json are never requested" },
  { id: "database", name: "Database exposed to the public",
    why: "a Supabase connection is still detected from the code that ships, but its tables are never asked for rows" },
  { id: "other-pages", name: "Other pages on your site",
    why: "only the page you named is read; no sitemap is fetched and no links are followed" },
  { id: "api-spec", name: "Published API description",
    why: "an OpenAPI or Swagger file your code names is listed, but never downloaded" },
];

// A source map is JSON, version 3, with something in it to map. Two regexes on the body ("version"
// and "mappings"|"sources") matched an SPA shell carrying a video-player config, once per bundle,
// and an empty map ("mappings":"" with no sources). Neither reconstructs anything.
//
// XL-203: WHAT THE MAP CARRIES DECIDES WHAT THE FINDING MAY SAY. webpack's documented production
// setting `nosources-source-map` ships mappings and file names for error tracking and deliberately
// leaves the source text out. Nothing can be reconstructed from it; what it reveals is the
// project's file layout. The check used to print "your original source is reconstructable" for
// both shapes, which was untrue for one of them, so the classifier now reports whether any
// sourcesContent text is present and the engine grades and words the finding from that.
function readSourceMap(body) {
  if (!body || /<html/i.test(body)) return null;
  let j;
  try { j = JSON.parse(body); } catch { return null; }
  if (!j || typeof j !== "object" || Number(j.version) !== 3) return null;
  const textIn = (m) => Array.isArray(m?.sourcesContent) && m.sourcesContent.some((s) => typeof s === "string" && s.trim().length > 0);
  if (Array.isArray(j.sections) && j.sections.length) {
    // An index map: each section carries its own map. Source text is present if any section has it.
    const sources = j.sections.flatMap((s) => (Array.isArray(s?.map?.sources) ? s.map.sources : [])).filter((s) => typeof s === "string");
    const hasSourceText = j.sections.some((s) => textIn(s?.map));
    const head = hasSourceText ? j.sections.flatMap((s) => s?.map?.sourcesContent || []).filter((s) => typeof s === "string").join("\n").slice(0, 4000) : "";
    return { indexMap: true, sources, hasSourceText, file: typeof j.file === "string" ? j.file : "", sourceTextHead: head };
  }
  if (!(typeof j.mappings === "string" && j.mappings.length > 0 && Array.isArray(j.sources) && j.sources.length > 0)) return null;
  const sources = j.sources.filter((s) => typeof s === "string");
  const hasSourceText = textIn(j);
  const sourceTextHead = hasSourceText ? j.sourcesContent.filter((s) => typeof s === "string").join("\n").slice(0, 4000) : "";
  return { indexMap: false, sources, hasSourceText, file: typeof j.file === "string" ? j.file : "", sourceTextHead };
}
function isSourceMap(body) { return !!readSourceMap(body); }

// A SOURCE MAP LARGER THAN WE READ (2026-10-05). safeFetch stops a body at MAX_BODY_BYTES (10MB) and
// marks it incomplete; the maps that carry full source are exactly the ones that pass it, and
// JSON.parse failed on them, so the check read clear. This reads the truncated text by shape instead: the head must look like a v3 map, the
// sources array must close inside what we read, and source text counts only when a sourcesContent
// entry with real content is visible. Anything less returns null, so the bundle is reported as
// not fully checked rather than as clean.
export function readPartialSourceMap(body) {
  const t = String(body || "");
  const head = t.trimStart().slice(0, 4096);
  if (!head.startsWith("{") || /<html/i.test(head) || !/"version"\s*:\s*3\b/.test(head)) return null;
  const sm = /"sources"\s*:\s*(\[(?:[^\]"]|"(?:[^"\\]|\\.)*")*\])/.exec(t);
  if (!sm || !/"(?:mappings"\s*:\s*"|sourcesContent"\s*:\s*\[)/.test(t)) return null; // Rollup writes mappings LAST
  let sources;
  try { sources = JSON.parse(sm[1]).filter((s) => typeof s === "string"); } catch { return null; }
  if (!sources.length) return null;
  const hasSourceText = /"sourcesContent"\s*:\s*\[\s*(?:null\s*,\s*)*"(?:[^"\\]|\\.){20}/.test(t);
  return { indexMap: false, sources, hasSourceText, file: "", sourceTextHead: "", partial: true };
}

// XL-204: A LIBRARY'S OWN MAP IS NOT THE APP'S SOURCE. chart.umd.js and chart.umd.js.map copied out
// of the package's dist folder reconstruct Chart.js, which is on npm under MIT and readable by
// anyone already. None of the site's code is in it. Two shapes are recognised, both requiring the
// map itself to corroborate rather than trusting a file name:
//   1. every source path sits under node_modules/ (a bundler emitted a vendor chunk);
//   2. the bundle opens with an open-source licence banner naming a package and version, AND the
//      map's own file name or the bundle's name carries that package name.
// A concatenated bundle that starts with jQuery's banner and goes on to app code fails rule 2,
// because the map's file is main.js, not jquery; its app source still counts as exposed.
// Recognised maps become inventory (the shipped-library list), not a finding.
const LIBRARY_BANNER = /\/\*!?\s*\**\s*@?([A-Za-z][\w.-]{1,40}?)(?:\.js)?\s+v?(\d+\.\d+(?:\.\d+)?)[\s\S]{0,400}?\b(MIT|BSD|Apache|ISC|MPL|LGPL|Unlicense|WTFPL)\b/i;
function vendoredLibraryMap(bundleBody, map, bundleUrl) {
  const sources = map.sources || [];
  if (sources.length && sources.every((s) => /(^|\/)node_modules\//.test(s))) {
    const m = /node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(sources[0]);
    return { name: m ? m[1] : "a dependency", version: null, how: "every source path in the map is under node_modules/" };
  }
  const b = LIBRARY_BANNER.exec(String(bundleBody || "").slice(0, 600));
  if (!b) return null;
  const name = b[1];
  const version = b[2];
  const needle = name.toLowerCase();
  let bundleName = "";
  try { bundleName = new URL(bundleUrl).pathname.split("/").pop().toLowerCase(); } catch {}
  const fileNamesIt = (map.file || "").toLowerCase().includes(needle) || bundleName.includes(needle);
  if (!fileNamesIt) return null;
  return { name, version, how: `the bundle's licence banner names ${name} ${version} and the map belongs to a file of that name` };
}

// XL-206: A SERVED DOTFILE WITH NOTHING SECRET IN IT. A Vite app's public/.env of VITE_ variables
// is compiled into the bundle by design; the values are public and meant to be. Serving the file
// is a real hygiene problem (the folder holding configuration is public), and it is not an
// exposure of secrets, because there are none in it. The old note said "every secret in it is
// exposed" for every served .env. Now: any variable without a documented public prefix, or any
// key the secret extractor recognises, keeps CRITICAL; a file of public build variables only is
// HIGH with wording about the served file rather than about exposed secrets.
const PUBLIC_ENV_PREFIX = /^(VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|EXPO_PUBLIC_|GATSBY_|VUE_APP_|SVELTE_PUBLIC_|ASTRO_PUBLIC_)/;
function envExposure(body) {
  const keys = [];
  for (const line of String(body || "").split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=/.exec(line);
    if (m) keys.push(m[1]);
  }
  const nonPublic = keys.filter((k) => !PUBLIC_ENV_PREFIX.test(k));
  const secrets = extractSecrets(String(body || "")).length;
  return { keys, nonPublic, secrets, publicOnly: keys.length > 0 && nonPublic.length === 0 && secrets === 0 };
}

// Pull <script src> URLs and inline <script> bodies out of an HTML document.
function extractScripts(html, baseUrl) {
  const srcs = [];
  const inline = [];
  // LINEAR TOKENISER, not a regex. The previous `<script\b([^>]*)>([\s\S]*?)<\/script>` rescanned to
  // the end of the document for every unclosed <script>, so an attacker body of N unclosed starts
  // cost N x length: measured 240ms at 63KB and rising 4x per doubling, against a 3MB body cap.
  // indexOf walks forward only: each start looks for the next closer AFTER it and the walk stops at
  // the first start with no closer, so no byte is scanned more than a bounded number of times.
  const matches = [];
  const lower = html.toLowerCase();
  let pos = 0;
  while (pos < lower.length) {
    const open = lower.indexOf("<script", pos);
    if (open === -1) break;
    const tagEnd = lower.indexOf(">", open);
    if (tagEnd === -1) break;
    const nameEnd = open + 7; // "<script".length
    // \b after "script": the next char must not be a word char (rules out <scripts>, <scripting>).
    if (nameEnd < lower.length && /[a-z0-9_]/.test(lower[nameEnd])) { pos = nameEnd; continue; }
    const close = lower.indexOf("</script>", tagEnd + 1);
    if (close === -1) break;
    matches.push([null, html.slice(nameEnd, tagEnd), html.slice(tagEnd + 1, close)]);
    pos = close + 9; // "</script>".length
  }
  for (const m of matches) {
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

export async function liveLayer(rawUrl, log = () => {}, opts = {}) {
  // The per-client concurrency ceiling was always keyed "anon", so it was a global ceiling in
  // practice. Routes now pass the client address; nothing else about the slot changes.
  const clientKey = opts.clientKey || "anon";
  // STACK-ONLY MODE reads PUBLIC SIGNALS AND NOTHING ELSE.
  //
  // The tech-stack tool is pointed at other people's sites - "what are THEY running" - so it must
  // be gentler than the security scan, which is framed as auditing your OWN app. It skips the two
  // intrusive probes: the exposed-path checks that guess at /.env, /.git and /.vscode, and the
  // Supabase table enumeration. Those are legitimate when you are checking a site you own and
  // over-reaching when you are just curious what a stranger's site is built with.
  //
  // What remains is exactly what a browser loading the page already fetches: the homepage, the
  // scripts it references, and the public DNS/certificate records. Nothing here pokes at anything
  // a normal visit would not.
  const stackOnly = !!opts.stackOnly;
  const url = /^https?:\/\//i.test(rawUrl) ? rawUrl : "https://" + rawUrl;
  // `stackOnly` rides on the result so every downstream reader (the CLI report, the web panel,
  // a stored share) can state the mode instead of inferring it from a missing section. XL-244.
  const result = { url, reachable: false, stackOnly, secrets: [], missingHeaders: [], insecureCookies: [], insecureStorage: [], exposures: [], vendoredMaps: [], rls: [], fetched: [], notes: [] };
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
    // XL-290. requested=false is a stack-only scan; status is served | absent | error, so an
    // unanswered request can never read as "no lockfile".
    lockfile: { requested: false, status: null },
    supabase: { urlSeen: false, clientSignal: false, keyFound: false, keyKind: null, schemaRefused: false, schemaStatus: null, tablesFound: 0, tablesProbed: 0, tablesReadable: 0, tablesEmpty: 0, tablesRefused: 0, tablesErrored: 0 },
    // Completeness tracking. Any incomplete read downgrades the affected check to
    // inconclusive rather than letting it read as "clear".
    rootComplete: true,
    scriptsIncomplete: 0,
    incompleteReasons: [],
  };
  result.coverage = coverage;

  const budget = { used: 0, max: MAX_OUTBOUND_PER_SCAN, exceeded: false };
  coverage.outbound = budget;

  log(`fetching ${url}`);
  const root = await fetchText(url, { budget, clientKey });
  if (!root.ok && root.status === 0) {
    result.notes.push(`could not reach ${url}: ${root.error || "no response"}`);
    return result;
  }
  result.reachable = true;

  // A RESPONSE IS NOT THE APP. Only a total connection failure was treated as "could not
  // reach", so any non-2xx answer fell through here and the whole scan ran against whatever
  // body came back. When that body is a WAF challenge or a rate-limit page, every
  // source-derived check truthfully reports "nothing here" and the verdict came out CLEAN.
  //
  // Measured: a server returning 403 to every request scored verdict "clean" with ZERO
  // inconclusive checks. That is the same manufactured confidence scan-invariant.test.mjs
  // already forbids for a truncated body, arriving through a door nobody had shut. For a
  // security product a false all-clear is the worst possible output, because the reader acts
  // on it by doing nothing.
  //
  // We still record what we got, and DNS-derived checks are unaffected because they never
  // touched HTTP. What changes is that the checks which needed the app's own bytes can no
  // longer report a pass.
  result.rootStatus = root.status;
  // The protective headers the root response actually carried, name and value, so a
  // missing-header finding can be reproduced from the report (XL-174). ONLY the names in
  // SECURITY_HEADERS are kept: never Set-Cookie, never anything that could carry a session,
  // because this object is returned to the reader and a report must not become the place a
  // credential is copied from.
  result.rootHeaders = Object.fromEntries(
    SECURITY_HEADERS.map(([name]) => [name, root.headers ? root.headers[name] : undefined])
      .filter(([, v]) => typeof v === "string" && v.length > 0),
  );
  result.rootBlocked = !root.ok;
  if (result.rootBlocked) {
    result.notes.push(`The site answered ${root.status} rather than serving the page, so this scan never saw the application itself.`);
  }
  if (!root.complete) {
    coverage.rootComplete = false;
    coverage.incompleteReasons.push(`the page itself: ${root.bodyReason || root.bodyStatus}`);
    result.notes.push(`The page body could not be fully read (${root.bodyStatus}), so this scan is partial.`);
  }
  result.finalUrl = root.finalUrl;
  result.fetched.push(root.finalUrl);

  // ---- security headers (checked on the root document response) --------------
  for (const [h, msg] of SECURITY_HEADERS) {
    const eff = headerEffect(h, root.headers, root.body);
    if (eff.ok) continue;
    const header = h === "x-frame-options" ? "X-Frame-Options / frame-ancestors" : h;
    result.missingHeaders.push(eff.reason ? { header, note: eff.reason, inert: true, reason: eff.reason } : { header, note: msg });
  }
  coverage.headersPresent = coverage.headersChecked - result.missingHeaders.length;

  // ---- cookie flags (on the same root response; no extra request) -------------
  //
  // PURELY PASSIVE: this reads the Set-Cookie headers the homepage response already carried, via
  // the set-cookie-list captured above. It sends nothing and probes nothing, which is what lets a
  // cookie check exist at all under the read-only posture.
  //
  // SEVERITY IS EARNED, so the rules are deliberately narrow:
  //   - Missing `Secure` is flagged on any cookie, because the scan is HTTPS and a cookie set
  //     without Secure on an HTTPS response can later be sent over plain HTTP.
  //   - Missing `HttpOnly` is flagged ONLY when the cookie name looks like a session or auth
  //     token. A language-preference cookie without HttpOnly is not a finding, and flagging it
  //     would be exactly the broad-pattern false positive the doctrine forbids.
  //   - Missing `SameSite` rides along as a note on a cookie already flagged, never alone: its
  //     default (Lax) is a real mitigation, so absence by itself is not worth a reader's time.
  //
  // Coverage records how many cookies were seen, so "no cookie findings" on a response that set
  // none reads as "none to check" rather than as a pass.
  const setCookies = root.headers["set-cookie-list"] || [];
  coverage.cookiesSeen = setCookies.length;
  // NOT csrftoken, NOT xsrf. A CSRF token cookie is read by the page's own JavaScript and copied
  // into a request header (Django's csrftoken, Angular and Laravel's XSRF-TOKEN); that is the whole
  // mechanism. Telling an owner to set HttpOnly on it breaks every form on their site. It was in
  // this list until 2026-09-30, a live false positive found by comparing against benavlabs'
  // open-source rules, which exclude it for the same reason.
  const SESSIONISH = /^(sess|session|sid|ssid|token|auth|jwt|refresh|connect\.sid)/i;
  for (const raw of setCookies) {
    const [pair, ...attrs] = String(raw).split(";");
    const name = (pair.split("=")[0] || "").trim();
    if (!name) continue;
    const at = attrs.map((a) => a.trim().toLowerCase());
    const has = (flag) => at.some((a) => a === flag || a.startsWith(flag + "="));
    const missing = [];
    if (!has("secure")) missing.push("Secure");
    if (!has("httponly") && SESSIONISH.test(name)) missing.push("HttpOnly");
    if (missing.length && !has("samesite")) missing.push("SameSite");
    if (missing.length) result.insecureCookies.push({ name, missing });
  }

  // ---- secrets in the root HTML + inline scripts -----------------------------
  const { srcs, inline } = extractScripts(root.body, root.finalUrl);
  // XL-288: whether the homepage runs any script a CSP would govern (inline here; third-party
  // script hosts are counted below in result.scripts). Read by the header severity rule.
  result.rootInlineScripts = inline.length;
  result.rootScriptSrcs = srcs.length;
  // TOTAL cap across every blob. The per-blob cap in patterns.mjs bounds ONE document;
  // without a total, 25 bundles at 100 hits each still accumulates 2,500 findings into the
  // response, KV storage and the UI.
  //
  // Truncating here does NOT make the scan inconclusive, and that distinction matters. A
  // page carrying more than MAX_SECRETS_TOTAL live keys has already proven the finding
  // beyond any doubt; calling the result incomplete would UNDERSTATE it. What is incomplete
  // is the LIST, so that is exactly what we say, and the verdict stands.
  // XL-233: token-shaped writes to browser storage, from the same served JS the secret scan
  // reads. Deduped by key across the whole app; capped so a loop cannot flood the response.
  const seenStorage = new Set();
  const addStorage = (text, sourceUrl) => {
    for (const h of scanStorage(text)) {
      const id = `${h.api} ${h.key}`;
      if (seenStorage.has(id) || result.insecureStorage.length >= 50) continue;
      seenStorage.add(id);
      result.insecureStorage.push({ ...h, sourceUrl });
    }
  };
  const addSecrets = (secs, sourceUrl) => {
    for (const s of secs) {
      if (result.secrets.length >= MAX_SECRETS_TOTAL) { result.secretsTruncated = true; return; }
      result.secrets.push({ ...s, sourceUrl });
    }
  };
  addSecrets(extractSecrets(root.body), root.finalUrl + " (HTML)");
  addStorage(root.body, root.finalUrl + " (HTML)");
  inline.forEach((code, i) => addSecrets(extractSecrets(code), `${root.finalUrl} (inline script #${i + 1})`));
  const textBlobs = [root.body, ...inline]; // accumulate all served code for the Supabase probe

  // ---- MULTI-PAGE CRAWL (XL-227) --------------------------------------------------------------
  // Follow the owner's own linked and sitemap-declared pages so every check runs per route, not
  // just on the homepage. Same-origin only (lib/crawl.mjs enforces it), and it shares the one
  // outbound budget, so a heavy site spends its budget and reports incomplete rather than
  // fanning out without bound. Skipped in stack-only mode, which stays a single gentle read.
  result.pages = [];
  result.pageHeaderGaps = [];
  // ONE DEFINITION OF "PROTECTED" for the homepage and every crawled page (2026-10-05). This used
  // its own presence test, so a route sending HSTS max-age=0 or a report-only CSP passed as
  // protected here after XL-250 had stopped the homepage from counting the same headers.
  const headerOn = (h, hdrs, body) => headerEffect(h, hdrs, body).ok;
  if (!stackOnly) { // stack-only-skip: other-pages
    let sitemapXml = "";
    try {
      const sm = await fetchText(new URL(root.finalUrl).origin + "/sitemap.xml", { budget, clientKey });
      if (sm.ok && /<urlset|<sitemapindex/i.test(sm.body || "")) sitemapXml = sm.body;
    } catch {}
    const pageUrls = discoverPages(root.body, root.finalUrl, sitemapXml, { max: MAX_PAGES });
    coverage.pagesDiscovered = pageUrls.length;
    for (const pu of pageUrls) {
      if (budget.used >= budget.max) { result.notes.push(`page crawl stopped at the outbound budget after ${result.pages.length} of ${pageUrls.length} pages`); break; }
      const pr = await fetchText(pu, { budget, clientKey });
      const rec = { url: pu, status: pr.status, reachable: !!pr.ok };
      if (pr.ok && pr.complete !== false) {
        addSecrets(extractSecrets(pr.body), pu);
        addStorage(pr.body, pu);
        textBlobs.push(pr.body);
        const ps = extractScripts(pr.body, pr.finalUrl);
        for (const ssrc of ps.srcs) srcs.push(ssrc);
        for (const code of ps.inline) { addSecrets(extractSecrets(code), pu + " (inline)"); addStorage(code, pu); }
        // Headers the ROOT sets but this page does not: a protection applied to only some routes
        // protects only those routes, which is a real per-page finding the homepage cannot show.
        const gaps = [];
        for (const [h] of SECURITY_HEADERS) {
          if (headerOn(h, root.headers, root.body) && !headerOn(h, pr.headers, pr.body)) gaps.push(h);
        }
        rec.missingHeaders = gaps;
        if (gaps.length) result.pageHeaderGaps.push({ url: pu, missing: gaps });
      }
      result.pages.push(rec);
    }
    coverage.pagesCrawled = result.pages.filter((p) => p.reachable).length;
  }

  // ---- same-origin JS bundles -----------------------------------------------
  //
  // SAME-ORIGIN AS THE DOCUMENT WE ACTUALLY FETCHED, not as the URL that was typed.
  //
  // This compared against `url`, the pre-redirect input. Every site that redirects apex to www
  // (or www to apex) therefore had EVERY one of its bundles classified as cross-origin and
  // skipped, so the secrets check - the most important one we run - silently never ran. It
  // reported "references N scripts, but none could be downloaded", which was not true: nothing
  // was ever requested.
  //
  // Found on clovion.ai: 13 scripts referenced, 0 scanned, 7 outbound requests used out of 60.
  // The bundles fetch perfectly well; the filter rejected them before anything was tried. The
  // rest of this function already resolves against root.finalUrl (extractScripts, fingerprint,
  // extractOrigins, checkScriptOrigins) - these two comparisons were the odd ones out.
  //
  // This is what "same origin" means for a subresource: the origin of the document that
  // referenced it. Using the typed URL was simply the wrong base.
  // Deduped: the crawl pushes each page's scripts into srcs, and pages share chunks, so the same
  // bundle is referenced many times. Count and fetch each once.
  {
    const uniq = [...new Set(srcs)];
    srcs.length = 0;
    for (const u of uniq) srcs.push(u);
  }
  coverage.scriptsReferenced = srcs.length;
  // Bounded: a big app can have thousands of dependency paths, and the detector only needs enough
  // to match a package name.
  const sourcemapPaths = new Set();
  // What each script cost, collected as we go. Third-party scripts are NOT fetched - that is the
  // whole point of the same-site filter below, and fetching a stranger's CDN to weigh it would
  // turn a read-only scanner into a traffic generator. They are counted and named instead, which
  // is an honest and separately useful number.
  const weights = [];
  const bundles = srcs.filter((s) => sameSite(s, root.finalUrl)).slice(0, MAX_SCRIPTS);
  if (srcs.length > bundles.length) result.notes.push(`scanned ${bundles.length} same-origin scripts (of ${srcs.length} referenced; cross-origin + overflow skipped)`);
  for (const b of bundles) {
    log(`  bundle ${b}`);
    const r = await fetchText(b, { budget, clientKey });
    if (!r.ok) {
      // A BUNDLE WE COULD NOT FETCH IS INCOMPLETE COVERAGE, NOT A NON-EVENT.
      //
      // This was a bare `continue`: the failure was dropped without incrementing anything or
      // recording why. So a throttled slot, a 403 or a timeout left scriptsScanned and
      // scriptsIncomplete both at zero, which reads identically to "there were no bundles" - and
      // that is the branch that produced the misleading "none could be downloaded" with an empty
      // reason list. Same rule as the !r.complete case directly below: a script we did not read
      // must never be silently absent from the coverage figures.
      coverage.scriptsIncomplete++;
      coverage.incompleteReasons.push(`${b}: ${r.bodyReason || r.bodyStatus || `HTTP ${r.status}`}`);
      continue;
    }
    if (!r.complete) {
      // We fetched it but could not read all of it. Counting this as "scanned" would
      // claim coverage we do not have; a live key could sit in the part we never saw.
      coverage.scriptsIncomplete++;
      coverage.incompleteReasons.push(`${b}: ${r.bodyReason || r.bodyStatus}`);
      continue;
    }
    coverage.scriptsScanned++;
    result.fetched.push(b);
    // Page weight, from a fetch already paid for. Deterministic and first-party: this is what the
    // deployment served us, not an estimate and not a third party's opinion of it.
    // `encoding` rides along for XL-098: the compression the server actually negotiated for this
    // response, read from a header we already have. No extra request, and it is a measurement of
    // what was served rather than an opinion about what should have been.
    weights.push({ url: b, bytes: r.bytes || 0, exact: r.bytesExact !== false, firstParty: true,
                   encoding: r.encoding || null, transferBytes: r.transferBytes });
    addSecrets(extractSecrets(r.body), b);
    addStorage(r.body, b);
    textBlobs.push(r.body);
    // source map disclosure (XL-299): the SourceMap response header, else the LAST
    // sourceMappingURL comment, else a sibling .map. An inline data: map is decoded from the
    // bundle we already hold, with no request.
    const loc = sourceMapLocation(r.body, r.headers, b);
    let mapUrl = null, mapBody = null, mapTruncated = false;
    if (loc.inline !== undefined) {
      coverage.mapsChecked++;
      mapUrl = b + "#inline-source-map";
      mapBody = loc.inline;
    } else if (loc.url && sameOrigin(loc.url, root.finalUrl)) {
      // Same base as the bundle filter above, and for the same reason: a source map sits beside
      // the bundle that names it, on the document's origin, not on whatever host was typed.
      coverage.mapsChecked++;
      mapUrl = loc.url;
      // Fetch the body and confirm it is REALLY a source map (JSON with version +
      // mappings/sources) — a catch-all route that 200s everything must not false-positive.
      const mr = await fetchText(mapUrl, { budget, clientKey });
      mapBody = mr.ok ? mr.body : null;
      mapTruncated = mr.ok && mr.complete === false;
      // No answer is not "no map". Recorded so the receipt row reads inconclusive, never clear.
      if (mr.status === 0 || (mapTruncated && !readPartialSourceMap(mr.body))) {
        (coverage.mapsUnanswered ||= []).push({ url: mapUrl, reason: mr.status === 0 ? (mr.bodyReason || mr.error || "no response") : "larger than we read, and its start does not show a complete source list" });
      }
    }
    if (mapBody !== null) {
      const map = readSourceMap(mapBody) || (mapTruncated ? readPartialSourceMap(mapBody) : null);
      if (map) {
        const vendored = vendoredLibraryMap(r.body, map, b);
        if (vendored) {
          // XL-204: inventory, not a finding. The receipt still counts the bundle as checked.
          coverage.mapsVendored = (coverage.mapsVendored || 0) + 1;
          result.vendoredMaps.push({ url: mapUrl, bundle: b, name: vendored.name, version: vendored.version, how: vendored.how });
        } else {
          result.exposures.push({
            kind: "source-map",
            url: mapUrl,
            hasSourceText: map.hasSourceText,
            sourceCount: map.sources.length,
            partial: !!map.partial,
            note: (map.partial ? `Source map is larger than the ${Math.round(MAX_BODY_BYTES / 1048576)}MB we read; this is confirmed from that first part. ` : "") + (map.hasSourceText
              ? "Source map is public and carries your source text: your original source (and any secrets in it) is reconstructable."
              : `Source map is public but carries no source text (a nosources map), so nothing can be reconstructed from it. What it does reveal is your project's file layout: ${map.sources.length} file name${map.sources.length === 1 ? "" : "s"}.`),
          });
        }
        // DEPENDENCY PATHS ONLY, for stack detection. A source map's `sources[]` is a literal
        // file listing of the project, and it was being fetched, tested for two keys, and
        // discarded - the richest stack evidence a scan ever holds, already paid for.
        //
        // node_modules/ ONLY, deliberately. The application's own file names are the author's
        // private structure; reading them to say "you use React" would be rummaging through
        // something we have no business publishing. A dependency path names a public package.
        for (const m of String(mapBody).matchAll(/"((?:[^"\\]|\\.)*node_modules\/[^"]{0,120})"/g)) {
          if (sourcemapPaths.size >= MAX_SOURCEMAP_PATHS) break;
          sourcemapPaths.add(m[1]);
        }
        if (/"webpack:\/\//.test(mapBody)) sourcemapPaths.add("webpack://");
      }
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
    // `[core]` at a line start and NOT an HTML document. The bare `/\[core\]/` matched a landing page
    // that showed a git config sample in a <pre>, reached through a 302 from /.git/config.
    ["/.git/config", (b) => /^\s*\[core\]/m.test(b) && !/<html/i.test(b), ".git/ is served publicly: full source history is downloadable."],
    ["/.git/HEAD", (b) => /^ref:\s/.test(b), ".git/ is served publicly: full source history is downloadable."],
    // Editor sync config. When present it usually holds SFTP host + credentials.
    // Same HTML guard as /.env. Without it a Next.js shell served by a catch-all (its __NEXT_DATA__
    // carries "host" and a login form's "password") read as an editor upload config.
    ["/.vscode/sftp.json", (b) => !/<html/i.test(b) && /"host"\s*:/.test(b) && /"(password|privateKeyPath)"\s*:/.test(b), "Editor upload config served publicly: it contains your server credentials."],
  ];
  const origin = new URL(url).origin;
  coverage.pathsProbed = stackOnly ? 0 : EXPOSED_PATHS.length; // stack-only-skip: private-files
  // Probed in parallel so adding paths costs coverage, not scan time. Skipped entirely in
  // stack-only mode: guessing at a stranger's /.env is exactly the over-reach the tech-stack
  // tool exists to avoid.
  const pathResults = stackOnly ? [] : await Promise.all(EXPOSED_PATHS.map(async ([path, valid, note]) => { // stack-only-skip: private-files
    const r = await fetchText(origin + path, { budget, clientKey });
    const hit = r.ok && r.status === 200 && valid(r.body || "");
    // NO ANSWER IS NOT "NOT SERVED". A request that got no response (status 0: dropped, timed out,
    // throttled, or over the request budget), or a 200 whose body we did not finish reading, says
    // nothing about the file. Until 2026-09-30 both read as clear.
    const unanswered = !hit && (r.status === 0 || (r.status === 200 && r.complete === false));
    return { path, note, hit, unanswered, reason: unanswered ? (r.bodyReason || r.error || "no response") : null, body: r.body || "" };
  }));
  coverage.pathsUnanswered = pathResults.filter((p) => p.unanswered).map((p) => ({ path: p.path, reason: p.reason }));
  // XL-290: a served npm lockfile. Not one of the six never-public paths (a lockfile holds no
  // secret), so it is graded as a low disclosure; its value is that its EXACT pins are the one case
  // where the web scan may name a published advisory, because a lockfile states versions rather
  // than us guessing them from a banner. One request, same stack-only gate as the private files.
  if (!stackOnly) { // stack-only-skip: private-files
    const lr = await fetchText(origin + "/package-lock.json", { budget, clientKey });
    coverage.lockfile = { requested: true, status: lr.status === 0 ? "error" : "absent", reason: lr.status === 0 ? (lr.bodyReason || lr.error || "no response") : null };
    if (lr.ok && lr.status === 200 && isNpmLockfile(lr.body || "", lr.headers)) {
      // A lockfile we could not parse (truncated at our read cap, or the v1 format with no
      // "packages" map) is still a served lockfile, but its advisories were NOT checked. That is
      // said in the finding; it is never read as "no advisories".
      coverage.lockfile.status = "served";
      let adv = { findings: [], checked: 0, totalPackages: 0, parsed: null, error: null };
      try { adv = await osvLookup([{ path: "package-lock.json", content: lr.body }], osvFetchForTest ? { fetchImpl: osvFetchForTest } : undefined); } catch (e) { adv.error = String(e?.message || e); }
      result.exposures.push({ kind: "lockfile", url: origin + "/package-lock.json",
        advisories: (adv.findings || []).slice(0, 10).map((f) => ({ severity: f.severity, dev: !!f.dev, location: f.location, evidence: f.evidence })),
        advisoryCount: (adv.findings || []).length, advisoriesChecked: adv.checked || 0, totalPackages: adv.totalPackages || 0,
        advisoryLookup: !adv.parsed ? "unparsed" : adv.error ? "partial" : "complete",
        advisoryError: adv.error || null, truncated: lr.complete === false });
    }
  }
  for (const p of pathResults) {
    if (!p.hit) continue;
    if (p.path.startsWith("/.env")) {
      // XL-206: grade the served dotfile by what is in it, and say only what is true of it.
      const env = envExposure(p.body);
      const named = env.nonPublic.slice(0, 6).join(", ");
      const head = p.note.split(":")[0];
      result.exposures.push({
        kind: "exposed-path",
        url: origin + p.path,
        publicOnly: env.publicOnly,
        envKeys: env.keys.length,
        nonPublicKeys: env.nonPublic.slice(0, 12),
        note: env.publicOnly
          ? `${head}. Every one of its ${env.keys.length} variable${env.keys.length === 1 ? "" : "s"} carries a public build prefix (VITE_, NEXT_PUBLIC_ and the like), so nothing secret is in this file. The folder that holds your configuration is public, and the next file in it may not be as harmless.`
          : `${head}: ${env.nonPublic.length} of its ${env.keys.length} variable${env.keys.length === 1 ? "" : "s"} ha${env.nonPublic.length === 1 ? "s" : "ve"} no public prefix (${named}${env.nonPublic.length > 6 ? ", ..." : ""})${env.secrets ? ` and ${env.secrets} recognised secret key format${env.secrets === 1 ? "" : "s"} appear${env.secrets === 1 ? "s" : ""} in it` : ""}, so every secret in it is exposed.`,
      });
    } else {
      result.exposures.push({ kind: "exposed-path", url: origin + p.path, note: p.note });
    }
    addSecrets(extractSecrets(p.body), origin + p.path); // same cap as every other source
  }

  // ---- platform fingerprint (XL-056) + backend surface map (INV-03) ----------
  // Both derive from text already in memory, so they cost no extra requests.
  const allText = textBlobs.join("\n");
  result.fingerprint = fingerprint(root.finalUrl, root.headers, allText);
  result.origins = extractOrigins(allText, root.finalUrl);
  // SURFACE MAP (XL-256 and siblings, INV-33): the app's OWN endpoints named in that same text.
  // Inventory, never called. No request.
  result.surface = extractSurface(allText, root.finalUrl);
  // XL-305: read ONE published API description the code names, same site only, never guessed.
  // One counted request; its operations are read, never called. Skipped in stack-only mode: a
  // browser loading the page does not download the spec.
  if (result.surface.specs.length) {
    const specPath = result.surface.specs[0];
    if (stackOnly) { // stack-only-skip: api-spec
      result.surface.spec = { path: specPath, status: "skipped-stack-only" };
    } else {
      const sr = await fetchText(new URL(specPath, root.finalUrl).href, { budget, clientKey });
      result.surface.spec = !sr.ok
        ? { path: specPath, status: sr.bodyStatus === "fanout-cap" ? "budget" : "unreadable", httpStatus: sr.status || null }
        : { path: specPath, ...analyseSpec(sr.body) };
    }
  }
  // Live SBOM (XL-045): libraries identifiable in what shipped. Inventory, not a finding.
  result.sbom = extractSbom(srcs, textBlobs);
  // XL-204: a public library's own source map is inventory. It joins the shipped-library list
  // with its provenance stated, so a reader can see why it is not a finding.
  for (const v of result.vendoredMaps) {
    const name = String(v.name || "").toLowerCase();
    if (!name || result.sbom.libraries.some((l) => l.name === name)) continue;
    result.sbom.libraries.push({ name, version: v.version || "unknown", source: "source-map" });
  }
  // XL-005: third-party script origins (inventory) + documented-bad CDN check (finding).
  result.scripts = checkScriptOrigins(srcs, root.finalUrl);
  // XL-320: integrity hashes on version-pinned CDN assets in the homepage HTML. Inventory.
  result.scripts.sri = sriInventory(root.body);
  // Stack detection is deferred until after the DNS block below, because the CNAME target and the
  // SPF/MX records are two of its strongest signals and they resolve down there.

  // ---- DNS checks: dangling CNAME (XL-023) + email spoofing (XL-024) ---------
  // Public DNS reads only. Both are deliberately conservative; see lib/dns-checks.mjs.
  try {
    const hostname = new URL(root.finalUrl).hostname;
    log(`dns: checking ${hostname}`);
    // Run alongside the DNS lookups so the third-party certificate log adds no
    // wall-clock time of its own.
    // The domain registration lookup (XL-096) rides along with the DNS and certificate calls
    // for the same reason they ride together: one more parallel request adds no wall-clock time.
    const [cname, email, ct, rdap] = await Promise.all([
      checkDanglingCname(hostname, fetchText),
      checkEmailRecords(hostname),
      discoverFromCtLogs(hostname),
      lookupDomain(hostname),
    ]);
    result.dns = { cname, email };
    result.ct = ct;
    result.rdap = rdap;
  } catch (e) {
    result.notes.push(`DNS checks skipped: ${e?.message || e}`);
    result.dns = { cname: { status: "inconclusive" }, email: { status: "inconclusive" } };
    result.ct = { status: "inconclusive", reason: "DNS and certificate-log checks could not run." };
    result.rdap = { status: "inconclusive", reason: "DNS and registry lookups could not run." };
  }

  // ---- WHAT THIS SITE IS BUILT WITH ------------------------------------------
  // Every input below was already fetched for some other reason: the root headers were read for
  // five security headers and then dropped, the script URLs were used for host counting, the
  // source-map dependency paths were tested for two JSON keys, the CNAME was resolved for the
  // takeover check, and the TXT/MX records were reduced to two booleans. Zero extra requests -
  // which is what makes this affordable at all, with roughly three of sixty left in the budget.
  try {
    result.techStack = detectStack({
      headers: root.headers,
      html: root.body,
      scriptUrls: srcs,
      bundleText: allText,
      sourcemapPaths: [...sourcemapPaths],
      cname: result.dns?.cname?.cname || "",
      txt: result.dns?.email?.txtRecords || [],
      mx: result.dns?.email?.mxHosts || [],
    });
  } catch (e) {
    // Inventory must never be able to break a scan.
    result.techStack = { items: [], categories: [] };
    result.notes.push(`stack detection skipped: ${e?.message || e}`);
  }

  // PAGE WEIGHT, from fetches already paid for. Measured, first-party and reproducible, which is
  // what separates it from a Lighthouse score and is why it is the only performance signal allowed
  // to raise an alert in Watch. Third-party scripts are counted and named here, never downloaded.
  //
  // Placed AFTER stack detection on purpose: it correlates weight with the technologies that carry
  // it, and detectStack does not run until the DNS block above has resolved. Computed earlier, the
  // correlation would silently have been empty on every scan - the feature would have "worked".
  // COMPRESSION, MEASURED (XL-098). Every first-party response this scan already fetched, and
  // whether the server compressed it. Summarised by lib/compression.mjs, which is pure so the
  // partial cases can be tested directly. Inventory: no severity, no verdict effect.
  try {
    result.compression = compressionSummary([
      { url: root.finalUrl, encoding: root.encoding || null, bytes: root.bytes || 0, transferBytes: root.transferBytes },
      ...weights.map((w) => ({ url: w.url, encoding: w.encoding || null, bytes: w.bytes || 0, transferBytes: w.transferBytes })),
    ]);
  } catch (e) {
    result.compression = { status: "inconclusive", reason: e?.message || String(e) };
  }


  result.weight = pageWeight({
    weights,
    thirdParty: result.scripts?.thirdParty || [],
    htmlBytes: root.bytes || 0,
    coverage,
    technologies: result.techStack?.items || [],
  });

  // WHAT THE PAGE PUBLISHES ABOUT ITS OWNER. Reads HTML already in memory; no extra request.
  try {
    result.identity = extractSiteIdentity(root.body);
    result.details = extractSiteDetails({ html: root.body, finalUrl: root.finalUrl, requestedUrl: url, scriptUrls: srcs });
  } catch (e) {
    result.identity = { identifiers: [], org: null };
  }

  // ---- Supabase RLS probe (read-only) — the flagship vibe-coder check ---------
  // Skipped in stack-only mode: asking a stranger's database for rows to see if RLS is off is a
  // security test of their site, not a reading of what they built with. Detecting that Supabase
  // is PRESENT still happens above, from the code - it is the table enumeration that is dropped.
  if (stackOnly) { // stack-only-skip: database
    result.rls = [];
  } else {
    try {
      const supa = await probeSupabase(allText, log, { budget });
      result.rls = supa.findings || [];
      result.supabase = { detected: supa.detected, base: supa.base };
      coverage.supabase = {
        urlSeen: !!supa.urlSeen, clientSignal: !!supa.clientSignal,
        keyFound: !!supa.keyFound, keyKind: supa.keyKind || null,
        schemaRefused: !!supa.schemaRefused, schemaStatus: supa.schemaStatus ?? null,
        tablesFound: supa.tablesFound || 0, tablesProbed: supa.tablesProbed || 0,
        tablesReadable: supa.tablesReadable || 0, tablesEmpty: supa.tablesEmpty || 0,
        tablesRefused: supa.tablesRefused || 0, tablesErrored: supa.tablesErrored || 0,
        budgetStopped: !!supa.budgetStopped,
      };
      for (const n of supa.notes || []) result.notes.push(n);
      if (result.rls.length) log(`supabase: ${result.rls.length} table(s) readable anonymously`);
    } catch (e) {
      // A PROBE THAT CRASHED DID NOT LOOK. Left alone, coverage keeps its default keyFound:false and
      // the receipt says "No Supabase connection was visible", turning our own failure into a
      // statement about the app. Mark it so the receipt reports inconclusive instead.
      coverage.supabase = { ...coverage.supabase, probeError: String(e?.message || e) };
      result.notes.push(`supabase probe skipped: ${e?.message || e}`);
    }
  }

  // Say it out loud. A silently shortened list reads as "that is all of them", which for
  // a secret-exposure finding is the difference between "you leaked 250 keys" and
  // "you leaked at least 250 keys, and we stopped counting".
  if (result.secretsTruncated) {
    result.notes.push(`More than ${MAX_SECRETS_TOTAL} exposed secrets were found; the list is truncated. The verdict is unaffected: this is already a confirmed exposure.`);
  }

  return result;
}
