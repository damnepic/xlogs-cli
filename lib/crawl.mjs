// SAME-ORIGIN PAGE DISCOVERY for the multi-page scan (XL-227).
//
// AppMettle's one real advantage was reading more than the homepage. This finds the owner's own
// other pages so the security checks run on each route, not just the root: a header set on only
// some routes, a secret in a bundle only one page loads, a token written to storage on the
// dashboard but not the landing page.
//
// STRICTLY THE OWNER'S OWN PAGES. Every URL returned is same-origin with the page we actually
// fetched. The scanner is framed as auditing your own app, and following a link to a third-party
// site would turn a read-only self-audit into traffic against someone else. Cross-origin links,
// assets, and non-navigational schemes are all dropped here rather than filtered later.
//
// PURE and BOUNDED. Given the HTML, the base URL and an optional sitemap body, it returns an
// ordered, deduplicated, capped list. The caller owns the request budget; this only decides which
// URLs are worth spending it on.

// Extensions that are assets, not pages. A scan of styles.css is not a page inspection.
const ASSET_EXT = /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|pdf|zip|gz|mp4|webm|mp3|wav|json|xml|txt|rss|atom|wasm|csv)(\?|#|$)/i;
// Schemes and shapes that are not a page to GET.
const NON_PAGE = /^(mailto:|tel:|javascript:|data:|blob:|sms:|#)/i;

function normalize(u) {
  try {
    const url = new URL(u);
    url.hash = "";
    url.search = ""; // a query string is usually the same page in a different state, not a new page
    // Trailing-slash-insensitive key: "/about" and "/about/" are one page.
    let path = url.pathname.replace(/\/+$/, "");
    if (path === "") path = "/";
    url.pathname = path;
    return url;
  } catch {
    return null;
  }
}

function anchorsFrom(html) {
  const out = [];
  const re = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
  for (const m of html.matchAll(re)) out.push(m[1].trim());
  return out;
}

function locsFrom(sitemapXml) {
  const out = [];
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  for (const m of sitemapXml.matchAll(re)) out.push(m[1].trim());
  return out;
}

/**
 * @param {string} html         the fetched root page HTML
 * @param {string} baseUrl      the URL that HTML was actually served from (post-redirect)
 * @param {string} sitemapXml   the body of /sitemap.xml, or "" if none
 * @param {{max?: number}} opts
 * @returns {string[]} absolute, same-origin, deduped page URLs, excluding the root, capped at max
 */
export function discoverPages(html, baseUrl, sitemapXml = "", opts = {}) {
  const max = Number.isInteger(opts.max) ? opts.max : 6;
  const base = normalize(baseUrl);
  if (!base) return [];
  const origin = base.origin;
  const rootKey = base.href;

  // Sitemap first (an owner's declared routes are the best signal of what matters), then anchors in
  // document order. A Set preserves first-seen order and dedupes across both sources.
  const seen = new Set();
  const ordered = [];
  const add = (raw) => {
    if (!raw || NON_PAGE.test(raw)) return;
    let abs;
    try { abs = new URL(raw, base.href); } catch { return; }
    if (abs.origin !== origin) return;              // owner's own pages only
    if (ASSET_EXT.test(abs.pathname)) return;       // not an asset
    const norm = normalize(abs.href);
    if (!norm) return;
    const key = norm.href;
    if (key === rootKey) return;                    // the root is already scanned
    if (seen.has(key)) return;
    seen.add(key);
    ordered.push(key);
  };

  for (const loc of locsFrom(sitemapXml || "")) add(loc);
  for (const href of anchorsFrom(html || "")) add(href);

  return ordered.slice(0, max);
}
