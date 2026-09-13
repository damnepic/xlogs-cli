// XL-005: third-party script origins, checked against a small curated list of script
// CDNs that are PUBLICLY DOCUMENTED as compromised or operator-hostile.
//
// Scoping decision, stated plainly: xlogs does not run a threat-intelligence feed and
// will not pretend to. This list contains only incidents with public, citable
// documentation that are stable facts (a domain that served a supply-chain attack does
// not un-serve it). Every entry names its source. An unrecognised third-party host is
// NEVER flagged from this list; it appears only as neutral inventory. That keeps the
// check high-confidence and the false-positive rate at zero by construction.
//
// The polyfill.io cluster: in June 2024 the polyfill.io domain (bought by Funnull in
// Feb 2024) began injecting malicious redirects into the polyfill script it served to
// ~100k+ sites. Sansec documented the attack and the sibling CDNs run by the same
// operator. Sources: sansec.io/research/polyfill-supply-chain-attack, plus wide
// coverage (Cloudflare, Google Ads blocking affected sites).

export const BAD_CDNS = [
  { host: "polyfill.io", reason: "Served a documented supply-chain attack (June 2024): the CDN injected malicious redirects into the polyfill script.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "cdn.polyfill.io", reason: "Same domain as polyfill.io; the attack was served from this hostname.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "bootcdn.net", reason: "Documented by Sansec as run by the same operator as polyfill.io and observed serving malicious payloads.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "bootcss.com", reason: "Documented in the same Sansec research as the polyfill.io operator's CDN cluster.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "staticfile.net", reason: "Documented in the same Sansec research as the polyfill.io operator's CDN cluster.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "staticfile.org", reason: "Documented in the same Sansec research as the polyfill.io operator's CDN cluster.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "unionadjs.com", reason: "Payload domain observed in the polyfill.io attack chain.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "xhsbpza.com", reason: "Payload domain observed in the polyfill.io attack chain.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "union.macoms.la", reason: "Payload domain observed in the polyfill.io attack chain.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
  { host: "newcrbpc.com", reason: "Payload domain observed in the polyfill.io attack chain.", source: "sansec.io/research/polyfill-supply-chain-attack", date: "2024-06" },
];

import { sameSite } from "./same-site.mjs";

const BAD_BY_HOST = new Map(BAD_CDNS.map((e) => [e.host, e]));

function hostOf(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch { return null; }
}

// Match the host or any subdomain of a listed host (cdn.polyfill.io endsWith polyfill.io).
export function badCdnFor(host) {
  if (!host) return null;
  if (BAD_BY_HOST.has(host)) return BAD_BY_HOST.get(host);
  for (const [bad, entry] of BAD_BY_HOST) {
    if (host.endsWith("." + bad)) return entry;
  }
  return null;
}

/**
 * Inventory third-party script hosts and flag any that are on the documented-bad list.
 * @param {string[]} srcs all <script src> URLs found in the HTML
 * @param {string} pageUrl the page being scanned (to exclude same-origin)
 * @returns {{ thirdParty: Array<{host:string, count:number}>, bad: Array<{host:string, url:string, reason:string, source:string, date:string}> }}
 */
export function checkScriptOrigins(srcs = [], pageUrl = "") {
  // SAME-SITE, NOT SAME-HOSTNAME. Comparing hostnames counted static.linear.app as a third party
  // on linear.app - a site's own asset subdomain listed as an external dependency, while the
  // bundle scanner three files away treated the identical URL as first-party. One definition now.
  const counts = new Map();
  const bad = [];
  const badSeen = new Set();

  for (const src of srcs) {
    const h = hostOf(src);
    if (!h || sameSite(src, pageUrl)) continue;
    counts.set(h, (counts.get(h) || 0) + 1);
    const entry = badCdnFor(h);
    if (entry && !badSeen.has(h)) {
      badSeen.add(h);
      bad.push({ host: h, url: src, reason: entry.reason, source: entry.source, date: entry.date });
    }
  }

  const thirdParty = [...counts.entries()]
    .map(([host, count]) => ({ host, count }))
    .sort((a, b) => b.count - a.count);
  return { thirdParty, bad };
}
