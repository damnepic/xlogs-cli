// WHY XLOGS RAN THE CHECKS IT RAN.
//
// The machine-readable join between what a scan OBSERVED and what it CHECKED. One graph, consumed
// by the scan result, /tech-stack, Watch diffs and eventually MCP, so the answer to "why did you
// run this check" is the same everywhere and is data rather than a sentence assembled in a
// component.
//
// THE TARGET IS 100% CLASSIFIED, NOT 100% CONNECTED. This is the rule that keeps the graph honest.
// The old table produced a row only for technologies it happened to map, so six detections yielded
// three rows and the other three vanished - which reads as "we had nothing to say" when the truth
// was "nobody classified this yet". Every detection now falls into one of three buckets, and the
// default is the honest one.
//
// Coverage percentage must NEVER become a target. The failure mode is obvious once named: someone
// looks at "62% connected" and goes hunting for checks to attach to font providers. A technology
// with no legitimate security relationship is correctly classified as observed-only, and that is a
// finished answer, not a gap.
//
//   changes-checks   Observing it made a check RUN that otherwise would not have. The strongest
//                    claim, and the rarest: the check must be genuinely conditional on the
//                    detection, not merely related to it.
//   context          The check runs regardless, but knowing this technology changes how the
//                    result should be READ. Never changes severity - it explains, it does not
//                    grade.
//   observed-only    No legitimate relationship to any check xlogs performs. A complete answer.
//
// Every entry carries `reason` (the causal claim, in the reader's terms) and `basis` (what class
// of evidence establishes the relationship), so a row can always answer "says who".

export const RELATION = {
  CHANGES: "changes-checks",
  CONTEXT: "context",
  OBSERVED: "observed-only",
};

// ---- THE GRAPH ---------------------------------------------------------------------------------
//
// Order matters: the first match wins, so specific names precede category fallbacks.
export const STACK_RELATIONS = [
  // --- changes-checks: the check is genuinely conditional on the detection ----------------------
  //
  // Only ONE entry qualifies today, and inflating this bucket is precisely the temptation the
  // classified-not-connected rule exists to resist. The Supabase table probe literally does not
  // execute unless a Supabase connection is found in the served code, so observing it changed what
  // ran. Nothing else in the scanner is conditional in that way yet.
  {
    match: /^Supabase$/i, label: "Supabase", relation: RELATION.CHANGES, check: "database",
    reason: "Finding a Supabase connection is what makes the database check run at all. Without it there is no database for us to ask anything of.",
    basis: "A Supabase URL or key in the served code",
  },

  // --- context: the check runs anyway, but this changes how to read it --------------------------
  {
    match: /^(Next\.js|Nuxt|Astro|SvelteKit|Remix|Gatsby|Create React App|Angular|Vue|Svelte|React)$/i,
    label: "Your framework", relation: RELATION.CONTEXT, check: "secrets",
    reason: "Frameworks inline environment variables marked public into the browser bundle at build time. That is where an accidentally-exposed key usually ends up, and it is what the bundle scan reads.",
    // THE SHORT FORM, used when the check produced no result. A full explanatory paragraph
    // followed by "not tested" makes the card read as theory rather than evidence: the reasoning
    // outweighs a payload that is not there. When the check DID run, the long form earns its
    // space because it explains a real result.
    brief: "Frameworks can place build-time values into browser-delivered code.",
    basis: "A framework marker in the headers, markup or asset paths",
  },
  {
    match: /^(Next\.js|Nuxt|Astro|SvelteKit|Remix|Gatsby|Vite|webpack|Turbopack)$/i,
    label: "Your build tool", relation: RELATION.CONTEXT, check: "sourcemaps",
    reason: "Build tools can emit source maps beside each bundle. Whether they are published is a deployment setting, which is why we follow every map a bundle names.",
    brief: "Build tools can emit source maps beside each bundle.",
    basis: "A build-tool marker in the served code or asset paths",
  },
  {
    match: /^(Vercel|Netlify|Cloudflare Pages|Render|Fly\.io|Railway|Heroku|GitHub Pages)$/i,
    label: "Your host", relation: RELATION.CONTEXT, check: "headers",
    reason: "Hosting platforms set some security headers for you and leave others to your config. Knowing the host is how you tell 'the platform did not set this' from 'your app removed it'.",
    brief: "Hosting platforms set some security headers and leave others to your config.",
    basis: "A platform-specific response header",
  },
  {
    match: /^(Cloudflare|Amazon CloudFront|Fastly)$/i,
    label: "Your CDN", relation: RELATION.CONTEXT, check: "headers",
    reason: "A CDN terminates the connection and rewrites response headers, so what we read describes the edge rather than your origin. Anything server-side may be invisible to us for that reason alone.",
    brief: "A CDN rewrites response headers, so what we read describes the edge, not your origin.",
    basis: "An edge response header",
  },
  {
    match: /^(WordPress|Drupal|Joomla|Ghost)$/i,
    label: "Your CMS", relation: RELATION.CONTEXT, check: "privatefiles",
    reason: "Self-hosted CMS installs commonly leave config and backup files reachable under the web root, which is the class of file the private-file check requests.",
    brief: "Self-hosted CMS installs commonly leave config files reachable under the web root.",
    basis: "A CMS marker in the markup or asset paths",
  },
  {
    match: /^(Stripe|PayPal|Square|Paddle)$/i,
    label: "Your payment provider", relation: RELATION.CONTEXT, check: "secrets",
    reason: "Payment providers issue a publishable key meant for the browser and a secret key that must never leave your server. Both are among the formats the bundle scan searches, so it can tell them apart.",
    brief: "Payment providers issue both a browser-safe key and a server-only secret key.",
    basis: "The provider's own script host",
  },
  {
    match: /^(Firebase|Prisma|PlanetScale|MongoDB|Neon)$/i,
    label: "Your backend", relation: RELATION.CONTEXT, check: "secrets",
    reason: "Backend SDKs ship a client config to the browser. Which parts of it are safe to publish differs by provider, and the bundle scan looks for the parts that are not.",
    brief: "Backend SDKs ship a client config to the browser.",
    basis: "An SDK marker in the served code",
  },

  // --- observed-only: a complete answer, not a gap ----------------------------------------------
  {
    match: /^(analytics|marketing|seo|support|ui|library|tooling|ai)$/i,
    label: null, relation: RELATION.OBSERVED, check: null,
    reason: "xlogs performs no check aimed at this class of service. It is listed because it is part of what your page loads, not because anything about it was tested.",
    basis: "Category of the detection",
  },
  {
    match: /^(email|privacy|monitoring|cdn|hosting|server|language|build|css|platform|cms|auth|payments|backend|framework|security)$/i,
    label: null, relation: RELATION.OBSERVED, check: null,
    reason: "Detected, but xlogs has no check aimed specifically at it. Only the general checks ran.",
    basis: "Category of the detection",
  },
];

/**
 * Classify ONE detection. Never returns null: an unrecognised technology is classified as
 * observed-only, which is what makes "100% classified" achievable rather than aspirational.
 *
 * @param {{name:string, category:string}} item a detection from lib/stack-detect.mjs
 * @param {Map<string,object>} receiptById the scan's receipt rows, keyed by check id
 */
export function classify(item, receiptById = new Map()) {
  const entry =
    STACK_RELATIONS.find((e) => e.match.test(item.name)) ||
    STACK_RELATIONS.find((e) => e.match.test(item.category)) ||
    null;

  const relation = entry ? entry.relation : RELATION.OBSERVED;
  const checkId = entry?.check || null;
  const row = checkId ? receiptById.get(checkId) : null;

  // A mapped check only counts as having produced a result if it actually ran. A check that was
  // inapplicable or could not complete has covered nothing, and saying otherwise would be the same
  // overclaim the receipt exists to prevent.
  const ran = !!(row && (row.status === "clear" || row.status === "found"));

  return {
    technology: item.name,
    category: item.category,
    confidence: item.confidence,
    relation,
    checkId,
    reason: entry
      ? entry.reason
      : "xlogs has no check aimed at this, so nothing about it was tested. It is listed because it is part of what your page loads.",
    // The short form of `reason`, for the case where the check produced no result. Falls back to
    // the long form so a missing `brief` degrades to something correct rather than to nothing.
    brief: entry?.brief || entry?.reason || null,
    basis: entry?.basis || "Detected in what the page served",
    // The fourth step of the chain, and the only one that can carry a verdict. It comes from the
    // CHECK, never from the detection: observing Supabase says nothing about whether a table is
    // readable, and only the probe that asked can answer that.
    outcome: ran ? row.status : null,
    outcomeDetail: ran ? row.detail || row.summary || "" : "",
    ranLabel: row?.label || null,
  };
}

/**
 * Collapse classified rows into one link per check: which technologies pointed at it, why, and
 * what it turned up.
 *
 * Rows that name no check are NOT folded in here. They are complete answers in their own right and
 * belong in the observed-only list, where the reader can see how much of their stack xlogs
 * deliberately says nothing about. Hiding that list would make the chain look like full coverage.
 */
export function groupByCheck(rows = []) {
  const out = new Map();
  for (const r of rows) {
    if (!r.checkId) continue;
    if (!out.has(r.checkId)) {
      out.set(r.checkId, {
        checkId: r.checkId,
        // The strongest relation among the technologies pointing here. If any one of them made
        // the check RUN, that is the true story of this link, and describing it as mere context
        // would understate what happened.
        relation: r.relation,
        technologies: [],
        reasons: [],
        briefs: [],
        outcome: r.outcome,
        outcomeDetail: r.outcomeDetail,
        ranLabel: r.ranLabel,
      });
    }
    const g = out.get(r.checkId);
    g.technologies.push(r.technology);
    if (!g.reasons.includes(r.reason)) g.reasons.push(r.reason);
    if (r.brief && !g.briefs.includes(r.brief)) g.briefs.push(r.brief);
    if (r.relation === RELATION.CHANGES) g.relation = RELATION.CHANGES;
    // An outcome is a property of the check, so every row pointing at it agrees. Taking the first
    // non-null keeps a row whose lookup missed from blanking one that found the result.
    if (g.outcome == null && r.outcome != null) {
      g.outcome = r.outcome; g.outcomeDetail = r.outcomeDetail; g.ranLabel = r.ranLabel;
    }
  }
  return [...out.values()];
}

/**
 * The whole graph for one scan: every detection classified, nothing dropped.
 *
 * Returns counts alongside the rows so a caller can say "5 observed, 1 changed what we checked"
 * without recomputing, and so the honest denominator is always available.
 */
export function relateStack(techStack = {}, receipt = [], evidence = {}) {
  const byId = new Map((receipt || []).map((r) => [r.id, r]));

  // DETECTIONS THE STACK DETECTOR CANNOT SEE.
  //
  // This layer read `techStack.items` alone, and that quietly killed the one genuinely causal
  // relationship in the whole graph. The stack detector has exactly ONE Supabase signal - a
  // `node_modules/@supabase/` path inside a PUBLISHED SOURCE MAP - so it only fires on the small
  // minority of deployments that ship maps. The database check does not use that signal at all:
  // it runs off a Supabase connection read out of the bundle itself, which is both far more
  // common and much stronger evidence.
  //
  // So a site could have its database probed, get a real result, and still show no causal card,
  // because the graph was reading a weaker detector than the check was. The tests did not catch
  // it: they hand classify() a Supabase item directly, which is precisely the shape production
  // never produced. Exported, unit-tested, unreachable.
  //
  // The fix is to feed the graph the evidence the SCAN already holds rather than only what the
  // detector happened to name. If we found a Supabase connection, we detected Supabase - by a
  // better signal than the one that missed it.
  // KEYFOUND, NOT DETECTED. These are two different questions and the names do not say so.
  // In lib/live-supabase.mjs, `keyFound` means a Supabase key and base URL are present in the
  // served code - that is the DETECTION, and it is what makes the database check run. `detected`
  // is only set later, after the Supabase API actually answers an enumeration request, so it
  // means REACHABLE.
  //
  // A real scan of a Lovable-built app showed the two disagreeing inside one result: the receipt
  // said "Found a Supabase connection, but its table list could not be read" while
  // `result.supabase.detected` was false. Keying off the wrong one meant the causal card vanished
  // on exactly the sites where the check had the most to say.
  const items = [...(techStack.items || [])];
  if (evidence.supabase?.keyFound && !items.some((i) => /^supabase$/i.test(i.name))) {
    items.push({ name: "Supabase", category: "backend", confidence: "conclusive" });
  }

  const rows = items.map((i) => classify(i, byId));
  return {
    rows,
    // THE CHAIN, one link per CHECK rather than one per technology.
    //
    // Grouping here rather than in a component, because the alternative is every surface - the
    // scan page, /tech-stack, a CSV export, MCP - inventing its own and drifting apart.
    //
    // It is also the difference between a readable answer and a stutter. A Next.js app detects
    // Next.js, React, Turbopack and webpack, which classify into two checks; ungrouped that is
    // four cards saying the same two things, and the repetition reads as four separate pieces of
    // coverage when there are two.
    byCheck: groupByCheck(rows),
    total: rows.length,
    changed: rows.filter((r) => r.relation === RELATION.CHANGES).length,
    context: rows.filter((r) => r.relation === RELATION.CONTEXT).length,
    observedOnly: rows.filter((r) => r.relation === RELATION.OBSERVED).length,
    // Every row carries a relation, by construction. Asserted in the tests rather than assumed,
    // because "classified" is the property the whole design rests on.
    classified: rows.length,
  };
}
