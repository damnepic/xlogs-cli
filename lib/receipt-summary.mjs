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
      // An empty answer is empty OR protected; "no public read access" claimed the second.
      if (item.status === "clear") return `None of the ${n(s.tablesProbed || 0, "table", "tables")} we asked returned rows (empty or protected)`;
      // A skipped check is not an absent database: stack-only never asks (XL-244), and this line
      // said "No Supabase connection visible" for it until 2026-09-30.
      if (item.status === "n/a" && live.stackOnly) return "Not checked: a stack-only scan never asks a database for rows";
      if (item.status === "n/a" && s.urlSeen) return "A Supabase address is in the code, but no database client or key was served with it";
      if (item.status === "n/a") return "No Supabase connection visible in this app's code, so there was no database to test";
      if (s.probeError) return "Our database check failed to run. This is not a pass";
      if (!s.keyFound && s.urlSeen) return "A Supabase client ships with a key we did not recognise, so no table was tested. This is not a pass";
      if (s.schemaRefused && !s.tablesProbed) return "Supabase would not list the tables to a public key, so none was tested. This is not a pass";
      return "Could not test every table. This is not a pass";

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
      if (item.status === "inconclusive") return `${n((c.mapsUnanswered || []).length, "source map request", "source map requests")} could not be read, so ${(c.mapsUnanswered || []).length === 1 ? "that bundle was" : "those bundles were"} not checked. This is not a pass`;
      return "No bundle referenced a source map, so there was nothing to expose";

    case "privatefiles":
      if (item.status === "found") return "A private file was served publicly and its contents confirmed";
      if (item.status === "inconclusive") return `${n((c.pathsUnanswered || []).length, "private path", "private paths")} got no answer, so ${(c.pathsUnanswered || []).length === 1 ? "it was" : "they were"} not checked. This is not a pass`;
      return `None of the ${n(c.pathsProbed || 0, "private path", "private paths")} we requested returned that file`;

    case "lockfile":
      if (item.status === "found") return "Your npm lockfile is downloadable from the live site";
      if (item.status === "inconclusive") return "The lockfile request got no answer, so this was not checked. This is not a pass";
      if (item.status === "n/a") return "Not requested on this scan";
      return "We requested /package-lock.json and it was not served";

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
      if (item.status === "found") return (live.dns?.email?.missing || []).length ? "Missing SPF or DMARC, so mail can be forged as your domain" : "DMARC is published as p=none, so it reports forged mail but does not stop it";
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
