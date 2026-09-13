// WHAT YOUR PAGE PUBLISHES ABOUT WHO OWNS IT.
//
// This is BuiltWith's "Relationship" and "Meta" tabs, inverted, and the inversion is the whole
// point.
//
// BuiltWith takes a tracking identifier off your page - a Google Analytics UA-, an AdSense
// ca-pub-, a Tag Manager GTM- - and searches its corpus for every OTHER site carrying the same
// one, producing a map of everything one person owns. That is a real capability and it is
// reconnaissance: it is sold to marketers, and it works just as well for someone building a
// target list. We logged it REJECTED (XL-085) and that stands. Building it would require a global
// crawl we refuse to run, and would make a security scanner into an ownership-mapping tool.
//
// THE SAME FACT, POINTED THE OTHER WAY, IS A DEFENSIVE FINDING. The identifiers are in your HTML,
// in plain sight, and most people who ship them have no idea they are a durable cross-site
// fingerprint. So instead of "here is everyone else who shares this ID", we say:
//
//   "Your page publishes these identifiers. They are the same on every property that uses this
//    account, so anyone can pivot from this site to your others. That may be exactly what you
//    want, or it may connect a personal project to your employer."
//
// No corpus. No pivot performed. No third party named. It tells the owner what they are exposing
// and lets them decide, which is the difference between a security tool and a recon tool.
//
// ZERO ADDITIONAL REQUESTS: every pattern below reads HTML the scan already fetched.

// Identifiers that are STABLE ACROSS A WHOLE ACCOUNT rather than per-site. That property is what
// makes them a pivot: a per-page nonce reveals nothing, an AdSense publisher ID reveals a
// portfolio. Only account-level identifiers are listed, deliberately.
const LINKABLE = [
  [/\bUA-\d{4,10}-\d{1,4}\b/g, "Google Analytics (legacy)",
    "One Analytics property. The same UA- id appears on every site in that property."],
  [/\bG-[A-Z0-9]{8,12}\b/g, "Google Analytics 4",
    "One GA4 measurement id, shared by every site reporting into it."],
  [/\bGTM-[A-Z0-9]{4,10}\b/g, "Google Tag Manager",
    "One container id. Anyone can request the container and read which tags you load."],
  [/\bca-pub-\d{10,20}\b/gi, "Google AdSense",
    "One AdSense publisher id, identical across every site on that account. The strongest ownership link of the set."],
  [/\bpub-\d{10,20}\b/g, "Google AdSense (publisher)",
    "An AdSense publisher id, identical across every site on that account."],
];

// Identity the site states about ITSELF, in structured data it published for search engines to
// read. This is not scraped contact data and it is not enrichment: it is the organisation's own
// schema.org block, which exists to be read.
//
// Deliberately NOT collected: named individuals, email addresses, phone numbers. BuiltWith's Meta
// tab ships "Publicly Listed Contacts" and a "Find People on LinkedIn" link, which is the
// lead-generation product we rejected (XL-075). An organisation describing itself is fair game;
// a list of humans to contact is not.
function jsonLdBlocks(html) {
  const out = [];
  for (const m of String(html).matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const parsed = JSON.parse(m[1].trim());
      out.push(...(Array.isArray(parsed) ? parsed : [parsed]));
    } catch { /* a malformed block is the site's problem, not a reason to fail the scan */ }
  }
  return out;
}

function typeOf(node) {
  const t = node?.["@type"];
  return Array.isArray(t) ? t.join(",") : String(t || "");
}

/**
 * @param {string} html the root HTML the scan already fetched
 * @returns {{identifiers: Array, org: object|null}}
 */
export function extractSiteIdentity(html = "") {
  const seen = new Map();
  for (const [re, label, note] of LINKABLE) {
    for (const m of String(html).matchAll(re)) {
      const value = m[0];
      // ONE IDENTIFIER, ONE ROW. These patterns nest: "pub-123" matches inside "ca-pub-123", so a
      // single AdSense id was being reported twice under two labels, which reads as two separate
      // exposures. The longer, more specific form is listed first and wins; anything that is a
      // substring of something already seen is the same identifier and is dropped.
      if (seen.has(value)) continue;
      if ([...seen.keys()].some((k) => k.includes(value))) continue;
      seen.set(value, { value, label, note });
      if (seen.size >= 12) break;
    }
  }

  // The organisation's own description of itself, if it published one.
  let org = null;
  for (const node of jsonLdBlocks(html)) {
    const graph = node["@graph"] ? (Array.isArray(node["@graph"]) ? node["@graph"] : [node["@graph"]]) : [node];
    for (const n of graph) {
      if (!/Organization|Corporation|LocalBusiness|NewsMediaOrganization/i.test(typeOf(n))) continue;
      const sameAs = [].concat(n.sameAs || []).filter((s) => typeof s === "string").slice(0, 8);
      org = {
        name: typeof n.name === "string" ? n.name.slice(0, 120) : null,
        // The country only. A full street address is the site's to publish and not ours to
        // re-key into a profile, and a coarse location is enough to say "this is stated publicly".
        country: n.address?.addressCountry
          ? String(n.address.addressCountry).slice(0, 60)
          : null,
        profiles: sameAs,
      };
      if (org.name || org.profiles.length) break;
      org = null;
    }
    if (org) break;
  }

  return { identifiers: [...seen.values()], org };
}
