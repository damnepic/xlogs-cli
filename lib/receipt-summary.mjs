// PROOF OF INSPECTION.
//
// xlogs has two kinds of proof and only ever showed one of them well:
//
//   PROOF OF PRESENCE    "here is the exposed secret we found"
//   PROOF OF INSPECTION  "we looked for exposed secrets across the HTML, inline scripts,
//                        same-origin bundles and exposed files, and did not find one"
//
// The four checks that differentiate this product - Supabase RLS, exposed config files,
// exposed secrets, public source maps - are SILENT WHEN THEY PASS. That is what makes them
// good, and it is also why a healthy site sees only the two commodity findings (missing
// headers, SPF/DMARC) and concludes the scanner is shallow. Measured on two real sites:
// each returned clean with exactly one finding, and it was one of those two.
//
// So the absence has to be shown, and shown in the same register as a finding. The whole
// risk in doing that is overclaiming, because absence of evidence is easy to phrase as
// evidence of absence:
//
//   NEVER  "Your site has no exposed secrets."        (a claim about the site)
//   ALWAYS "No exposed secrets in the 3 scripts we read." (a claim about what we inspected)
//
//   NEVER  "Your source code is protected."
//   ALWAYS "No public source map on the 2 bundles we checked."
//
// Every clear-state line below therefore carries its own SCOPE - a count, or the set that
// was examined. That is not stylistic. A bounded claim is one we can defend; an unbounded
// one is the manufactured certainty this product refuses everywhere else.
//
// A note on "n/a": inapplicable must never read as a pass. "No Supabase in this app" is not
// "your database is secure", so those lines say what was absent, not what was safe.

/**
 * A short, result-phrased, SCOPE-BOUNDED line for one receipt entry.
 * @param {{id: string, status: string}} item
 * @param {object} coverage live.coverage
 * @param {object} live the live-layer result
 * @returns {string}
 */
export function summarize(item, coverage = {}, live = {}) {
  const c = coverage;
  const s = c.supabase || {};
  const n = (v, one, many) => `${v} ${v === 1 ? one : many}`;

  switch (item.id) {
    case "database":
      if (item.status === "found") return `${n((live.rls || []).length, "table", "tables")} readable by a logged-out stranger`;
      if (item.status === "clear") return `No public read access on the ${n(s.tablesProbed || 0, "table", "tables")} we asked for data`;
      if (item.status === "n/a") return "No Supabase connection visible in this app's code, so there was no database to test";
      return "Could not test the tables. This is not a pass";

    case "secrets":
      if (item.status === "found") return "A live key was found in what your app serves";
      if (item.status === "clear")
        return `No secrets in the ${n(c.scriptsScanned || 0, "script", "scripts")} we read, against ${n(c.keyFormats || 0, "key format", "key formats")}`;
      if (item.status === "n/a") return "This page loads no same-origin JavaScript, so there was no bundle to search";
      return "Some scripts could not be read, so a key could be hiding in the part we never saw. This is not a pass";

    case "headers":
      if (item.status === "found") return `${n((c.headersChecked || 0) - (c.headersPresent || 0), "header", "headers")} missing of ${c.headersChecked} checked`;
      return `All ${c.headersChecked} headers we check were set`;

    case "browserstorage":
      if (item.status === "found") return "A token-shaped key is written to browser storage";
      if (item.status === "clear") return `No token written to browser storage in the ${n(c.scriptsScanned || 0, "script", "scripts")} we read`;
      if (item.status === "inconclusive") return "Your scripts could not be read, so this was not checked. This is not a pass";
      return "This page loads no same-origin JavaScript, so there was nothing to read";

    case "sourcemaps":
      if (item.status === "found") return "A public source map was downloaded and confirmed real";
      if (item.status === "clear") return `No public source map on the ${n(c.mapsChecked || 0, "bundle", "bundles")} we checked`;
      return "No bundle referenced a source map, so there was nothing to expose";

    case "privatefiles":
      if (item.status === "found") return "A private file was served publicly and its contents confirmed";
      return `None of the ${n(c.pathsProbed || 0, "private path", "private paths")} we requested returned that file`;

    case "thirdparty": {
      const sc = live.scripts || { thirdParty: [] };
      if (item.status === "found") return "A script loads from a publicly documented compromised CDN";
      if (!sc.thirdParty.length) return "This page loads no third-party scripts, so there was nothing to compare";
      return `None of the ${n(sc.thirdParty.length, "third-party domain", "third-party domains")} matched a documented compromised CDN`;
    }

    case "dns": {
      const d = (live.dns || {}).cname || {};
      if (item.status === "found") return "A CNAME points at a service that no longer claims it";
      if (item.status === "inconclusive") return "Your DNS could not be read, so this was not tested. This is not a pass";
      return d.cname ? "Your CNAME still resolves to a live service" : "No CNAME on this hostname, so nothing could be left dangling";
    }

    case "ctlogs": {
      // Inventory, never a verdict: a certificate proves a name was ISSUED, not that a
      // host is live or misconfigured. Saying "no other addresses" would be a claim about
      // the internet, not about what we read.
      const ct = live.ct || {};
      if (ct.status === "found") return `${n(ct.total || 0, "other name", "other names")} listed in public certificate logs, for you to review`;
      if (ct.status === "inconclusive") return "The public certificate log could not be reached, so this was not checked";
      if (ct.status === "n/a") return "Certificate logs were not applicable here";
      return "No other names listed in public certificate logs";
    }

    case "email": {
      if (item.status === "found") return "Missing SPF or DMARC, so mail can be forged as your domain";
      if (item.status === "inconclusive") return "Your DNS could not be read, so this was not tested";
      if (item.status === "n/a") return "Not applicable to this hostname";
      return "SPF and DMARC are both published";
    }

    default:
      return "";
  }
}

// Phrases that turn a bounded observation into a claim about the whole application. Used by
// the test, and listed here so the rule lives next to the copy it governs rather than in a
// test file nobody reads while writing new lines.
export const FORBIDDEN_ABSOLUTES = [
  /\byour (site|app|code|source) is (safe|secure|protected|clean)\b/i,
  /\bno .* (anywhere|at all)\b/i,
  /\bfully (secure|protected)\b/i,
  /\bnothing is exposed\b/i,
  /\bguaranteed\b/i,
];
