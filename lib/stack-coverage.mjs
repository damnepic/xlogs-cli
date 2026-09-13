// STACK AWARENESS: say what we detected, and which of it we actually check.
//
// The app profile already identifies the stack - builder, host, and up to ten backend
// categories. The receipt already says what each check did. Nothing connected them, so a
// user could not see WHY a particular check ran, which is most of what makes an inspection
// feel like an inspection rather than a checklist.
//
// THE CONSTRAINT THAT SHAPES THIS FILE.
//
// The obvious version of this feature is "we detected Vercel, so we checked for Vercel
// deployment mistakes". That would be a lie. xlogs detects TEN backend categories and has a
// specific check for exactly ONE of them (Supabase). Writing stack-aware copy on top of
// coverage we do not have would recreate, in a new place, precisely the promise gap the
// homepage and copy audits were built to close.
//
// So this reports three states, and the third is the interesting one:
//
//   CHECKED       we detected it AND we have a check aimed at it
//   OBSERVED      we detected it; it informs other checks but has no dedicated check
//   NOT PRESENT   we did not detect it, so nothing about it was tested
//
// Saying "detected, not yet checked" out loud is uncomfortable and correct. It is the same
// rule as the receipt: absence of a finding must never be presented as coverage. It also
// happens to be the honest roadmap - the gap between what we can already SEE and what we can
// TEST is the detector backlog, derived from real detection rather than guesswork.

/**
 * Backend categories the origin scanner can name, mapped to the check that covers them.
 * `check` is a receipt id, or null when nothing specifically tests it yet.
 *
 * Keep this HONEST. A mapping here is a claim that the named check actually examines that
 * technology, not merely that a scan happened while the technology was present.
 */
export const BACKEND_COVERAGE = [
  { match: /Supabase/i, label: "Supabase", check: "database",
    note: "We asked its tables for data as a logged-out stranger." },
  { match: /Firebase/i, label: "Firebase", check: null,
    note: "Detected. xlogs has no Firebase-specific check yet, so nothing about its rules was tested." },
  { match: /Stripe/i, label: "Stripe", check: null,
    note: "Detected. Its key format is one of the ones we search bundles for." },
  // CLERK WAS BEING SILENTLY DROPPED. fingerprint.mjs detects it by name, and the only entry it
  // could have matched was /Authentication/i, a CATEGORY label from origins.mjs that never
  // reaches this function. A detected technology produced no row at all: not checked, not
  // observed, absent. Named explicitly now, along with the other things the detector sees.
  { match: /^Clerk$/i, label: "Clerk", check: null,
    note: "Detected. xlogs does not test authentication behaviour, by design: that would mean attacking your app." },
  // THE FRAMEWORK ROW IS THE ONE MOST PEOPLE WILL READ, because almost every app has one. It maps
  // to a check that genuinely applies to it: the bundles a framework ships are what the secrets
  // scan reads.
  { match: /^(Next\.js|Nuxt|Astro|SvelteKit|Remix|Gatsby|Create React App|Vue|Angular|Svelte|React)$/i,
    label: "Your framework's bundles", check: "secrets",
    note: "We read the JavaScript it ships to the browser, looking for keys that should never leave your server." },
  { match: /^(WordPress|Drupal|Joomla|Ghost|Shopify|Webflow|Wix|Squarespace|Framer)$/i,
    label: "Your platform", check: null,
    note: "Detected. xlogs has no platform-specific check for it yet, so only the general checks ran." },
  { match: /^(Vercel|Netlify|Cloudflare|Cloudflare Pages|Render|Fly\.io|Railway|Heroku|GitHub Pages|AWS ELB|Google Cloud)$/i,
    label: "Your host", check: null,
    note: "Detected. Hosting is inventory here: xlogs tests what your deployment serves, not your provider's configuration." },
  { match: /^Prisma$/i, label: "Prisma", check: null,
    note: "Detected in a public source map. xlogs does not reach your database through it; only what shipped to the browser was read." },
  { match: /AI provider/i, label: "AI provider", check: null,
    note: "Detected. Provider key formats are among the ones we search bundles for." },
  { match: /AWS/i, label: "AWS", check: null,
    note: "Detected. xlogs has no bucket or IAM check yet; only the AWS key format is searched for." },
  { match: /Google API/i, label: "Google API", check: null,
    note: "Detected. The Google key format is among the ones we search bundles for." },
  { match: /Authentication/i, label: "Auth provider", check: null,
    note: "Detected. xlogs does not test authentication behaviour, by design: that would mean attacking your app." },
  { match: /Analytics/i, label: "Analytics", check: null,
    note: "Detected. Inventory only." },
  { match: /Error tracking/i, label: "Error tracking", check: null,
    note: "Detected. Inventory only." },
  { match: /Email/i, label: "Email service", check: null,
    note: "Detected. Separate from the SPF/DMARC check, which tests your domain rather than this service." },
];

/**
 * @param {object} result a scan result
 * @returns {{detected: Array, checked: number, observed: number}}
 */
export function stackCoverage(result = {}) {
  const fp = result.fingerprint || {};

  // ONE CANONICAL PIPELINE, not two detector universes.
  //
  // This read `fingerprint.backends` alone, which can only ever hold four values (Supabase,
  // Firebase, Stripe, Clerk). Seven of the ten entries below match CATEGORY labels produced by
  // origins.mjs, and origins was never passed in - so those seven were unreachable, and Clerk
  // matched nothing because its name is not the word "Authentication". The result: a coverage map
  // that could only ever light up three technologies, on a scanner that now detects dozens.
  //
  // The detector's output is the primary source now. The other two are folded in rather than
  // replaced, because they find things it does not: fingerprint knows the AI builder, and origins
  // categorises hostnames referenced in code that never appear as a header or an asset path.
  const backends = [
    ...(result.techStack?.items || []).flatMap((i) => [i.name, i.category]),
    ...(fp.backends || []).map((b) => (typeof b === "string" ? b : b.label || b.kind || "")),
    ...(result.origins || []).map((o) => (typeof o === "string" ? o : o.category || o.label || "")),
  ].filter(Boolean);

  const receipt = result.receipt || [];
  const ranById = new Map(receipt.map((r) => [r.id, r]));

  const detected = [];
  const seen = new Set();
  for (const entry of BACKEND_COVERAGE) {
    if (!backends.some((b) => entry.match.test(b))) continue;
    // Several detections can map to one row (Next.js and React both mean "your framework's
    // bundles"). Printing that row twice would read as two separate pieces of coverage.
    if (seen.has(entry.label)) continue;
    seen.add(entry.label);
    const row = entry.check ? ranById.get(entry.check) : null;
    // A mapped check only counts as CHECKED if it actually produced a result. A check that
    // was inapplicable or could not complete has not covered anything, and saying otherwise
    // would be the same overclaim in a smaller box.
    const reallyRan = row && (row.status === "clear" || row.status === "found");
    detected.push({
      label: entry.label,
      state: reallyRan ? "checked" : "observed",
      note: reallyRan ? entry.note : (entry.check ? "Detected, but that check could not complete on this scan." : entry.note),
    });
  }

  return {
    detected,
    checked: detected.filter((d) => d.state === "checked").length,
    observed: detected.filter((d) => d.state === "observed").length,
  };
}

/**
 * Why a given check ran, or did not, in terms of what was observed. This is the sentence
 * that turns a checklist into an inspection: not "we checked source maps" but "your app
 * ships 14 bundles, so we looked at each for a public source map".
 */
export function whyChecked(id, coverage = {}, live = {}) {
  const c = coverage;
  const s = c.supabase || {};
  const fp = live.fingerprint || {};
  const sc = live.scripts || { thirdParty: [] };

  switch (id) {
    case "database":
      return s.keyFound
        ? "Your code contains a Supabase connection, so we tested it."
        : "No Supabase connection appears in your code, so there was nothing to test.";
    case "secrets":
      return c.scriptsReferenced
        ? `Your page loads ${c.scriptsReferenced} script${c.scriptsReferenced === 1 ? "" : "s"}, so each one we could read was searched.`
        : "This page loads no same-origin JavaScript.";
    case "headers":
      return "Every site gets this one: it reads the response your homepage already sends.";
    case "browserstorage":
      return c.scriptsReferenced
        ? `Your page loads ${c.scriptsReferenced} script${c.scriptsReferenced === 1 ? "" : "s"}, so each one we could read was searched for a token written to browser storage.`
        : "This page loads no same-origin JavaScript, so there was nothing to read for storage writes.";
    case "sourcemaps":
      return c.mapsChecked > 0
        ? "Your bundles reference source maps, so we followed each one."
        : "No bundle referenced a source map.";
    case "privatefiles":
      return "Every site gets this one: the same six paths are requested regardless of stack.";
    case "thirdparty":
      return sc.thirdParty.length
        ? `Your page loads scripts from ${sc.thirdParty.length} third-party domain${sc.thirdParty.length === 1 ? "" : "s"}.`
        : "Your page loads no third-party scripts.";
    case "dns":
      return "Runs on the hostname you gave us.";
    case "ctlogs":
      return "Public certificate logs are keyed by your domain.";
    case "email":
      return "SPF and DMARC are properties of your domain, not of your app.";
    default:
      return fp.builder ? `Applies to apps built with ${fp.builder.label}.` : "";
  }
}
