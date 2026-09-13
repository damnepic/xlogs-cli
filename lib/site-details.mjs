// HOW THIS SITE IS CONFIGURED, from the page the scan already fetched.
//
// The discovery, social and application configuration a site publishes about itself. All of it is
// in the HTML we already hold, so this costs no request, and all of it is something the site put
// there deliberately for a crawler to read.
//
// DELIBERATELY NOT DUPLICATED HERE: HTTPS, HSTS and CSP. Those are security findings and they live
// in the receipt with their evidence and their fix. Repeating them as neutral configuration facts
// would give the same condition two different weights on one page, and the softer one would be the
// one people believe.
//
// Everything is reported as PRESENT or ABSENT with what we looked for, never as a score. "No
// canonical" is a fact about the page; whether it matters depends on the site, and inventing a
// grade would be manufacturing a judgement out of an observation.

const attr = (tag, name) => {
  const m = new RegExp(`${name}\\s*=\\s*["']([^"']*)["']`, "i").exec(tag);
  return m ? m[1].trim() : null;
};

function metaContent(html, key, which = "name") {
  const re = new RegExp(`<meta[^>]+${which}\\s*=\\s*["']${key}["'][^>]*>`, "i");
  const m = re.exec(html);
  return m ? attr(m[0], "content") : null;
}

function linkHref(html, rel) {
  const re = new RegExp(`<link[^>]+rel\\s*=\\s*["'][^"']*\\b${rel}\\b[^"']*["'][^>]*>`, "i");
  const m = re.exec(html);
  return m ? attr(m[0], "href") : null;
}

// The five entities that survive into every title and description. Left encoded, a compared title
// reads "SEC Filings &amp; Insider Trading" in a report a person is meant to read, and two sites
// that differ only in how they escaped an ampersand would compare as different.
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", "#39": "'", nbsp: " " };
const decode = (s) => String(s).replace(/&(amp|lt|gt|quot|apos|#39|nbsp);/g, (_, e) => ENTITIES[e]);

const trim = (s, n = 180) =>
  (s == null ? null : decode(String(s)).replace(/\s+/g, " ").trim().slice(0, n) || null);

/**
 * @param {object} input
 * @param {string} input.html root HTML already fetched
 * @param {string} input.finalUrl the URL actually analysed, after redirects
 * @param {string} input.requestedUrl what the visitor typed
 * @param {string[]} input.scriptUrls script URLs referenced by the page
 */
export function extractSiteDetails({ html = "", finalUrl = "", requestedUrl = "", scriptUrls = [] } = {}) {
  const h = String(html);

  // ---- discovery -----------------------------------------------------------------------------
  const titleM = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(h);
  const langM = /<html[^>]*\slang\s*=\s*["']([^"']+)["']/i.exec(h);
  const hreflangs = [...h.matchAll(/<link[^>]+rel\s*=\s*["']alternate["'][^>]*>/gi)]
    .map((m) => attr(m[0], "hreflang"))
    .filter(Boolean);

  const discovery = {
    title: trim(titleM ? titleM[1].replace(/<[^>]+>/g, "") : null),
    description: trim(metaContent(h, "description")),
    canonical: trim(linkHref(h, "canonical"), 300),
    robots: trim(metaContent(h, "robots")),
    language: trim(langM ? langM[1] : null, 20),
    // A feed the page declares. Not fetched: its presence is the fact.
    feed: trim(
      linkHref(h, "alternate") && /rss|atom/i.test(h.match(/<link[^>]+rel\s*=\s*["'][^"']*alternate[^"']*["'][^>]*>/i)?.[0] || "")
        ? linkHref(h, "alternate") : null, 300),
    hreflang: [...new Set(hreflangs)].slice(0, 12),
  };

  // ---- how it presents itself when shared -----------------------------------------------------
  const social = {
    ogTitle: trim(metaContent(h, "og:title", "property")),
    ogDescription: trim(metaContent(h, "og:description", "property")),
    ogImage: trim(metaContent(h, "og:image", "property"), 300),
    ogType: trim(metaContent(h, "og:type", "property"), 40),
    twitterCard: trim(metaContent(h, "twitter:card"), 40) || trim(metaContent(h, "twitter:card", "property"), 40),
  };

  // ---- application capability -----------------------------------------------------------------
  // A manifest link and a registered service worker are what separate a page from an installable
  // app, and both are declared in the markup.
  const application = {
    manifest: !!linkHref(h, "manifest"),
    serviceWorker: /serviceWorker\s*\.\s*register\s*\(/.test(h),
    themeColor: trim(metaContent(h, "theme-color"), 40),
    favicon: !!(linkHref(h, "icon") || linkHref(h, "shortcut icon") || linkHref(h, "apple-touch-icon")),
    viewport: !!metaContent(h, "viewport"),
    structuredData: [...new Set(
      [...h.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)]
        .flatMap((m) => {
          try {
            const p = JSON.parse(m[1].trim());
            const nodes = [].concat(p["@graph"] || p);
            return nodes.map((n) => (Array.isArray(n?.["@type"]) ? n["@type"][0] : n?.["@type"])).filter(Boolean);
          } catch { return []; }
        })
    )].slice(0, 10),
  };

  // ---- architecture, from this request ---------------------------------------------------------
  // THE REDIRECT IS EVIDENCE FROM THIS LOOKUP, not a history. BuiltWith ships a redirect tab built
  // from years of crawling; this is simply "you typed X and we analysed Y", which is a fact about
  // the request we just made and is worth showing because it explains what everything else
  // describes.
  let redirected = null;
  try {
    if (requestedUrl && finalUrl && new URL(requestedUrl).href !== new URL(finalUrl).href) {
      redirected = { from: new URL(requestedUrl).href, to: new URL(finalUrl).href };
    }
  } catch { /* an unparseable pair is not worth a claim */ }

  let firstParty = 0, thirdParty = 0;
  try {
    const site = new URL(finalUrl).hostname.toLowerCase();
    for (const u of scriptUrls) {
      try { (new URL(u).hostname.toLowerCase() === site ? firstParty++ : thirdParty++); } catch {}
    }
  } catch { /* leave the counts at zero rather than guess */ }

  const architecture = {
    redirected,
    scripts: { total: scriptUrls.length, firstParty, thirdParty },
    iframes: (h.match(/<iframe\b/gi) || []).length,
  };

  return { discovery, social, application, architecture };
}
