// SURFACE MAP (XL-256, XL-257, XL-258, XL-314, INV-33): the app's own attack surface, read from
// code it already serves, and never called.
//
// The third-party origin map (lib/origins.mjs, INV-03) answers "which outside services does this
// app talk to". This answers the next question: which of the app's OWN endpoints does its code
// name: API routes, form actions, GraphQL and tRPC endpoints, WebSockets, webhook receivers, and
// published API descriptions. Every rival that discovers surface then probes it; the line xlogs
// holds (doctrine rule 1) is that discovery is observation and calling is not. So every entry here
// is labelled "referenced, not called", and nothing in this file makes a request.
//
// PRECISION RULES, each earned by a false positive the obvious regex would produce:
//   - Only prefixes that name an application API (/api/, /trpc/, /graphql, /webhook). A bare
//     /v1/ matched every SDK in a bundle.
//   - Library-internal paths are excluded. supabase-js ships "/rest/v1", "/auth/v1",
//     "/storage/v1"; they are relative to the SUPABASE host, not to the app, and listing them as
//     the app's routes would be wrong twice. Same for Next.js internals and Sentry's envelope path.
//   - A prefix alone is not a route: "/api/" followed by nothing is how SDKs build URLs at runtime.
//   - Assets (.js, .css, images, fonts) are not endpoints.
//   - tRPC procedures are only read when a tRPC client is actually present, because the call
//     shape (`x.y.useQuery(`) is also ordinary react-query code.
//
// Deterministic and capped: the same bundle always yields the same map, sorted.

import { sameSite } from "./same-site.mjs";

const MAX_ROUTES = 60;
const MAX_ITEMS = 20;

const APP_PREFIX = /^\/(?:api|trpc|graphql|webhooks?)(?:\/|$)/i;
const LIBRARY_PATH = /^\/(?:rest\/v1|auth\/v1|storage\/v1|functions\/v1|realtime\/v1|graphql\/v1|_next\/|__nextjs|_vercel\/|api\/\d+\/(?:envelope|store)\/|api\/embed\/)/i;
const ASSET = /\.(?:m?js|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|json\.gz)(?:$|\?)/i;
const SPEC = /(?:openapi|swagger)(?:[.-][\w.-]*)?\.(?:json|ya?ml)$|\/api-docs(?:\/?|\.json)$|\/swagger\/v\d+\/swagger\.json$/i;

function normalisePath(p) {
  let s = String(p).split(/[?#]/)[0];
  s = s.replace(/\$\{[^}]{0,60}\}/g, ":param").replace(/\/{2,}/g, "/");
  if (s.length > 1) s = s.replace(/\/$/, "");
  return s;
}

function isAppRoute(path) {
  if (/^\/graphql$/i.test(path)) return true; // a GraphQL endpoint IS the bare path
  if (!APP_PREFIX.test(path) || LIBRARY_PATH.test(path) || ASSET.test(path)) return false;
  if (path.length > 120) return false;
  return !/^\/(?:api|trpc|webhooks?)\/?$/i.test(path); // a bare prefix is how SDKs build URLs, not a route
}

/**
 * @param {string} text  every blob the live layer already fetched (HTML, inline scripts, bundles)
 * @param {string} selfUrl the scanned page's final URL
 */
export function extractSurface(text, selfUrl) {
  const src = String(text || "");
  const routes = new Map(); // path -> { path, methods:Set, how:Set }
  const addRoute = (raw, how, method) => {
    const path = normalisePath(raw);
    if (!isAppRoute(path)) return;
    const r = routes.get(path) || { path, methods: new Set(), how: new Set() };
    r.how.add(how);
    if (method) r.methods.add(method.toUpperCase());
    routes.set(path, r);
  };
  const external = (u) => { try { return !sameSite(u, selfUrl); } catch { return true; } };

  // 1. fetch / axios / ky / $fetch calls with a literal first argument.
  for (const m of src.matchAll(/\b(?:fetch|\$fetch|ky|axios(?:\.(get|post|put|patch|delete))?)\(\s*[`"'](\/[^`"'\s]{1,160})[`"']/g)) {
    addRoute(m[2], "fetch", m[1]);
  }
  // 2. Any string literal that is an application API path.
  for (const m of src.matchAll(/[`"'](\/(?:api|trpc|graphql|webhooks?)(?:\/[^`"'\s]{0,140})?)[`"']/gi)) addRoute(m[1], "code");
  // 3. Absolute same-site URLs to an API path.
  for (const m of src.matchAll(/[`"'](https?:\/\/[^`"'\s/]+)(\/(?:api|trpc|graphql|webhooks?)[^`"'\s]{0,140})[`"']/gi)) {
    if (!external(m[1])) addRoute(m[2], "code");
  }
  // 4. HTML form actions (a POST form is an endpoint the page itself declares).
  for (const m of src.matchAll(/<form\b([^>]{0,400})>/gi)) {
    const attrs = m[1];
    const action = (attrs.match(/\baction=["'](\/[^"'\s]{1,160})["']/i) || [])[1];
    if (!action) continue;
    const method = (attrs.match(/\bmethod=["']?(get|post)/i) || [])[1] || "GET";
    const path = normalisePath(action);
    if (ASSET.test(path) || LIBRARY_PATH.test(path)) continue;
    const r = routes.get(path) || { path, methods: new Set(), how: new Set() };
    r.how.add("form"); r.methods.add(method.toUpperCase());
    routes.set(path, r);
  }

  // GraphQL endpoints: same-site paths from above, plus absolute URLs anywhere (a hosted backend).
  const graphql = new Map();
  for (const r of routes.values()) if (/\/graphql(?:\/|$)/i.test(r.path)) graphql.set(r.path, { endpoint: r.path, external: false });
  for (const m of src.matchAll(/[`"'](https?:\/\/[^`"'\s]+\/(?:v\d+\/)?graphql)(?:\/)?[`"']/gi)) {
    const u = m[1];
    if (/\.supabase\.co\/graphql\/v1$/i.test(u)) continue; // Supabase's own pg_graphql endpoint
    if (!graphql.has(u)) graphql.set(u, { endpoint: u, external: external(u) });
  }

  // tRPC: only when a tRPC client is present.
  let trpc = null;
  if (/\/(?:api\/)?trpc\b|httpBatchLink|createTRPC(?:Proxy|React|Next)?|@trpc\//.test(src)) {
    const procs = new Map();
    for (const m of src.matchAll(/\.((?:[a-z][A-Za-z0-9]*\.){1,3})(useQuery|useSuspenseQuery|useInfiniteQuery|useMutation|query|mutate)\(/g)) {
      const name = m[1].slice(0, -1);
      if (/^(?:current|prototype|default|exports|window|document|console)\b/.test(name)) continue;
      const kind = /mutat/i.test(m[2]) ? "mutation" : "query";
      procs.set(name, { procedure: name, kind });
    }
    const base = [...routes.keys()].find((p) => /\/trpc(?:\/|$)/i.test(p)) || (src.match(/[`"'](\/(?:api\/)?trpc)[`"']/) || [])[1] || null;
    trpc = { base, procedures: [...procs.values()].sort((a, b) => a.procedure.localeCompare(b.procedure)).slice(0, MAX_ROUTES) };
  }

  // WebSockets.
  const websockets = new Set();
  for (const m of src.matchAll(/[`"'](wss?:\/\/[^`"'\s]{3,200})[`"']/g)) {
    if (/localhost|127\.0\.0\.1|\.supabase\.co\/realtime|\$\{/.test(m[1])) continue;
    websockets.add(m[1].split(/[?#]/)[0]);
  }

  // Published API descriptions named by the code (never guessed).
  const specs = new Set();
  for (const m of src.matchAll(/[`"']((?:https?:\/\/[^`"'\s/]+)?\/[^`"'\s]{0,120}?)[`"']/g)) {
    const s = m[1];
    if (!SPEC.test(s.split(/[?#]/)[0])) continue;
    if (/^https?:/i.test(s) && external(s)) continue;
    specs.add(/^https?:/i.test(s) ? new URL(s).pathname : normalisePath(s));
  }

  const routeList = [...routes.values()]
    .map((r) => ({ path: r.path, methods: [...r.methods].sort(), how: [...r.how].sort() }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const webhooks = routeList.filter((r) => /webhook/i.test(r.path)).map((r) => ({ path: r.path }));

  return {
    routes: routeList.slice(0, MAX_ROUTES),
    routesTruncated: Math.max(0, routeList.length - MAX_ROUTES),
    graphql: [...graphql.values()].slice(0, MAX_ITEMS),
    trpc,
    websockets: [...websockets].sort().slice(0, MAX_ITEMS),
    webhooks: webhooks.slice(0, MAX_ITEMS),
    specs: [...specs].sort().slice(0, MAX_ITEMS),
    note: "Referenced in the code your site serves. Not called: xlogs never sends a request to these.",
  };
}

/**
 * XL-305: read a published API description the app's own code names, and report what IT declares.
 * Observation, not probing: the document is published, we fetch it once, and we never call an
 * operation it lists. The claim is always the spec's own ("this description declares no
 * authentication for these operations"), never ours ("these are open"): a public endpoint can be
 * public on purpose, so this is inventory with no severity.
 *
 * Body-shape validated like the private-file checks: an HTML catch-all page answering 200 for
 * /openapi.json is "not an API description", not an empty one.
 */
const HTTP_METHODS = ["get", "put", "post", "delete", "patch", "options", "head", "trace"];
export function analyseSpec(bodyText) {
  let doc;
  try { doc = JSON.parse(String(bodyText || "")); } catch {
    return { status: "not-a-spec", reason: /^\s*(openapi|swagger)\s*:/m.test(String(bodyText || "")) ? "a YAML description, which this check does not parse yet" : "the response was not a JSON API description" };
  }
  const version = doc && (doc.openapi || doc.swagger);
  if (!version || !doc.paths || typeof doc.paths !== "object") return { status: "not-a-spec", reason: "the response was JSON but not an OpenAPI or Swagger description" };
  const globalSec = Array.isArray(doc.security) ? doc.security : null;
  const schemes = Object.keys((doc.components && doc.components.securitySchemes) || doc.securityDefinitions || {}).sort();
  const ops = [];
  for (const [path, item] of Object.entries(doc.paths)) {
    if (!item || typeof item !== "object") continue;
    for (const m of HTTP_METHODS) {
      const op = item[m];
      if (!op || typeof op !== "object") continue;
      const sec = Array.isArray(op.security) ? op.security : globalSec;
      // No requirement stated, an empty list, or an explicit {} alternative all mean "callable
      // without credentials" in OpenAPI's own semantics.
      const open = !sec || sec.length === 0 || sec.some((req) => req && typeof req === "object" && Object.keys(req).length === 0);
      ops.push({ method: m.toUpperCase(), path, declaresAuth: !open });
    }
  }
  ops.sort((a, b) => (a.path === b.path ? a.method.localeCompare(b.method) : a.path.localeCompare(b.path)));
  const withoutAuth = ops.filter((o) => !o.declaresAuth).map(({ method, path }) => ({ method, path }));
  return {
    status: "read",
    format: doc.openapi ? `OpenAPI ${doc.openapi}` : `Swagger ${doc.swagger}`,
    operations: ops.length,
    schemes,
    withoutAuth: withoutAuth.slice(0, MAX_ROUTES),
    withoutAuthCount: withoutAuth.length,
  };
}

/**
 * XL-320: Subresource Integrity on VERSION-PINNED CDN scripts and stylesheets. Inventory, no
 * severity, never blocks a clean verdict.
 *
 * The precision rule that makes this worth showing: only a URL pinned to an exact version can
 * carry a stable hash. A moving loader (js.stripe.com/v3, a Google tag, an @latest tag) changes
 * under the same URL by design, so an integrity hash would break it; flagging those would teach
 * people to ignore the line. So: jsDelivr, unpkg and cdnjs URLs with an exact x.y.z version only.
 */
const PINNED_CDN = /^https:\/\/(?:cdn\.jsdelivr\.net\/(?:npm|gh)\/[^/]+@\d+\.\d+\.\d+|unpkg\.com\/(?:@[^/]+\/)?[^/@]+@\d+\.\d+\.\d+|cdnjs\.cloudflare\.com\/ajax\/libs\/[^/]+\/\d+\.\d+\.\d+)\//i;
export function sriInventory(html) {
  const pinned = [];
  for (const m of String(html || "").matchAll(/<(script|link)\b([^>]{0,600})>/gi)) {
    const attrs = m[2];
    const isStyle = m[1].toLowerCase() === "link";
    if (isStyle && !/\brel=["']?stylesheet/i.test(attrs)) continue;
    const url = (attrs.match(isStyle ? /\bhref=["']([^"']+)["']/i : /\bsrc=["']([^"']+)["']/i) || [])[1];
    if (!url || !PINNED_CDN.test(url)) continue;
    pinned.push({ url, kind: isStyle ? "stylesheet" : "script", hasIntegrity: /\bintegrity=["']sha(?:256|384|512)-/i.test(attrs) });
  }
  const missing = pinned.filter((p) => !p.hasIntegrity).map(({ url, kind }) => ({ url, kind }));
  return { pinned: pinned.length, missing: missing.slice(0, MAX_ITEMS) };
}

/** The total number of distinct surface entries, for a one-line summary. */
export function surfaceCount(s) {
  if (!s) return 0;
  return (s.routes || []).length + (s.graphql || []).length + ((s.trpc && s.trpc.procedures) || []).length + (s.websockets || []).length + (s.specs || []).length;
}
