// Framework-agnostic scan engine. This is the ONE entry point every surface calls
// (web API, CLI, future GitHub check / Watch) so detection logic is never duplicated.
// It runs the deterministic live layer and returns findings already enriched from the
// shared knowledge object, in a plain-JSON shape a UI or report can render directly.
//
// URL-only (the web MVP scope): the live layer is pure Node (fetch), no bash, no repo,
// no source upload — so this runs fine in a serverless function.

import { liveLayer } from "./live.mjs";
import { acquireOriginLease } from "./origin-lease.mjs";
import { coalesce } from "./concurrency.mjs";
import { summarize } from "./receipt-summary.mjs";
import { whyChecked, stackCoverage } from "./stack-coverage.mjs";
import { relateStack } from "./stack-relations.mjs";
import { mask } from "./patterns.mjs";
import { vulnForCategory, taxonomyFor } from "./knowledge/vulns.mjs";
import { fixForAgent, FIX_AGENTS } from "./knowledge/index.mjs";
import { baselineNote } from "./builder-baselines.mjs";

// A Supabase ANON key is meant to be public (the frontend ships it) — do NOT flag it as
// an exposed secret. A SERVICE_ROLE key is the dangerous one. Decode and tell them apart.
function jwtClaims(tok) {
  try {
    return JSON.parse(Buffer.from(tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) || {};
  } catch { return {}; }
}
function jwtRole(tok) { return jwtClaims(tok).role || null; }

// No mutable module state lives in this file. A shared counter made a findings id depend
// on how many OTHER scans had run in the same process, so the same site scanned twice
// produced different ids. Nothing depended on them for identity (mutes key off
// category|location, repo stats use stable check ids), so it was not a contamination bug
// between concurrent scans - but it did contradict the deterministic claim on the
// homepage. Ids are now derived from the finding, in stampIds() below.
// XL-020: CONFIRMED means xlogs directly observed the exposure (rows came back, a real
// file was served, a source-map validated, a key decoded). POTENTIAL means a missing
// protection or an unexploited risk we did not prove (a header is absent, a takeover is
// possible but we did not claim the name). Never mark something CONFIRMED we did not see.
const CONFIDENCE_BY_CATEGORY = {
  "supabase-rls": "confirmed",
  "exposed-path": "confirmed",
  "source-map": "confirmed",
  "exposed-secret": "confirmed",
  "compromised-cdn": "confirmed",
  "missing-sri": "potential",
  "subdomain-takeover": "potential",
  "email-spoofing": "potential",
  "missing-header": "potential",
  "exposed-lockfile": "confirmed",
};

function enrich(category, { severity, location, technical, confidence, extra = {} } = {}) {
  const v = vulnForCategory(category);
  const fixes = {};
  if (v) for (const a of FIX_AGENTS) fixes[a] = fixForAgent(v, a, location);
  const tax = v ? taxonomyFor(v.id) : { cwe: null, cweName: null, owasp: null };
  return {
    vulnId: v?.id || null,
    category,
    cwe: tax.cwe,
    cweName: tax.cweName,
    owasp: tax.owasp,
    severity: severity || v?.severity || "medium",
    confidence: confidence || CONFIDENCE_BY_CATEGORY[category] || "confirmed",
    title: v?.title || category,
    plain: v?.plain || "",
    whyAi: v?.whyAi || "",
    // human-first "what we observed" + a technical line for the expandable section
    observed: technical || (v ? (v.evidence || "").replaceAll("{location}", location || "") : ""),
    location: location || "",
    requiredState: v?.requiredState || "",
    fixSteps: (v?.fixSteps || []).map((s) => s.replaceAll("{location}", location || "the spot shown")),
    verify: v?.verify || "",
    fixes,
    ...extra,
  };
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ---- coverage receipt (XL-031) ---------------------------------------------
// Every check reports what it actually did, so "no findings" can never be confused
// with "we did not look". Status is one of:
//   clear        - the check ran and found nothing wrong
//   found        - the check ran and found something (a finding exists for it)
//   inconclusive - the check could not complete (XL-034)
//   n/a          - the check did not apply to this app
export function buildReceipt(live, findings) {
  // Every row gets a bounded, result-phrased summary. Stamped in ONE place at the end
  // rather than written inline nine times, so a new check cannot ship without one and the
  // scope-bounding rule cannot drift line by line. See lib/receipt-summary.mjs.
  return stampSummaries(buildReceiptRows(live, findings), live);
}

function stampSummaries(rows, live) {
  for (const row of rows) {
    row.summary = summarize(row, live.coverage || {}, live);
    // WHY this check ran, in terms of what was observed. This is what turns a checklist
    // into an inspection: not "we checked source maps" but "your bundles reference source
    // maps, so we followed each one".
    row.because = whyChecked(row.id, live.coverage || {}, live);
  }
  return rows;
}

function buildReceiptRows(live, findings) {
  const c = live.coverage || {};
  const has = (cat) => findings.some((f) => f.category === cat);
  const s = c.supabase || {};
  const r = [];

  // STACK-ONLY: A CHECK THAT DID NOT RUN IS NOT A PASS (XL-244).
  //
  // Found by building the CLI flag and reading the receipt it produced: in stack-only mode the
  // private-file row reported `clear` with the detail "Requested 0 paths", and the database row
  // claimed no Supabase connection was visible even when the code plainly shipped one, because
  // the coverage counter that sentence reads is only written on the branch the mode skips. Both
  // are the zero-versus-never-looked failure, in the surface whose entire job is to prevent it,
  // and both have been live on /tech-stack since stack-only mode existed. A skipped check is
  // `n/a` with the reason, which is the same rule the receipt already applies everywhere else.
  const skipped = !!live.stackOnly;

  // 1. Database
  if (skipped) {
    r.push({ id: "database", label: "Database exposed to the public", status: "n/a",
      detail: "Not checked: this was a stack-only scan, which never asks a database for rows. A connection may well be present; we did not test it." });
  } else if (s.probeError) {
    // The probe crashed. That is our failure, not a fact about the app.
    r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
      detail: "Our database check failed to run on this scan, so we cannot say whether a Supabase connection is present or open. This is not a pass." });
  } else if (!s.keyFound && s.urlSeen && s.clientSignal) {
    // A database client ships, but its key is in no format we recognise. Before 2026-09-30 this
    // read "No Supabase connection was visible", which was false for every app on Supabase's
    // sb_publishable_ keys and produced a CLEAN verdict over an open table in the fixture.
    r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
      detail: "Your code talks to a Supabase database, but we did not recognise a public key for it, so we could not test any table. This is not a pass." });
  } else if (!s.keyFound && s.urlSeen) {
    r.push({ id: "database", label: "Database exposed to the public", status: "n/a",
      detail: "A Supabase address appears in your code, but no database client or public key was served with it, so there was no database a stranger could query with what we saw." });
  } else if (!s.keyFound) {
    r.push({ id: "database", label: "Database exposed to the public", status: "n/a",
      detail: "No Supabase connection was visible in this app's code, so there was no database for us to test anonymously." });
  } else if (s.tablesProbed > 0) {
    const readable = (live.rls || []).length;
    const found = Math.max(s.tablesFound || 0, s.tablesProbed);
    const unasked = found - s.tablesProbed;
    const asked = `Asked ${s.tablesProbed}${unasked > 0 ? ` of ${found}` : ""} table${s.tablesProbed === 1 ? "" : "s"} for data as a logged-out stranger.`;
    const tail = unasked > 0
      ? ` The other ${unasked} were not asked (${s.budgetStopped ? "the scan reached its request limit" : `we stop at ${s.tablesProbed}`}).`
      : "";
    if (readable) {
      r.push({ id: "database", label: "Database exposed to the public", status: "found",
        detail: `${asked} ${readable} returned real rows.${tail}` });
    } else if (s.tablesErrored > 0) {
      // A read that failed (not a 401/403 refusal) did not check that table.
      r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
        detail: `${asked} None returned rows, but ${s.tablesErrored} could not be read at all, so those were not checked.${tail} This is not a pass.` });
    } else if (unasked > 0) {
      // A capped probe that found nothing has not checked the tables it never asked about.
      r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
        detail: `${asked} None of those returned rows.${tail} This is not a pass for them.` });
    } else {
      // An empty answer means empty OR protected. It is not proof that a policy exists.
      r.push({ id: "database", label: "Database exposed to the public", status: "clear",
        detail: `${asked} None returned any rows: each is empty or protected, and from outside we cannot tell which. That is not proof a policy exists.` });
    }
  } else if (s.budgetStopped) {
    // XL-310: the probe now shares the scan's request budget, so a heavy site can spend it first.
    r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
      detail: "Found a Supabase connection, but this scan reached its request limit before the database could be asked. This is not a pass." });
  } else if (s.schemaRefused) {
    r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
      detail: "Found a Supabase connection, but Supabase no longer lets a public key list a project's tables (since April 2026), so we could not learn which tables to test. A table can still be readable; this is not a pass." });
  } else {
    r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
      detail: "Found a Supabase connection, but its table list could not be read, so we could not test the tables. This is not a pass." });
  }

  // 2. Secret keys
  // AGAINST THE APP'S OWN SCRIPTS (2026-10-06). The denominator used to count third-party scripts
  // too, which are never fetched by design, so a page whose only script was a third-party tag (the
  // Lovable tagger, an analytics snippet) read "none could be downloaded" and turned the whole verdict
  // incomplete over code that is not the app's. Results stored before scriptsFirstParty existed fall
  // back to the old count, so they keep their original meaning.
  const own = Number.isFinite(c.scriptsFirstParty) ? c.scriptsFirstParty : c.scriptsReferenced;
  const third = Math.max(0, (c.scriptsReferenced || 0) - own);
  const thirdNote = third ? ` ${third} third-party script${third === 1 ? " is" : "s are"} listed, not read: ${third === 1 ? "it is" : "they are"} someone else's code.` : "";
  // THE INVARIANT: a script we fetched but could not fully read must NOT count as
  // scanned. A truncated or undecodable bundle can hide a live key in the part we never
  // saw, so this reports INCONCLUSIVE rather than "clear", which in turn stops the
  // verdict from claiming the app is clean.
  if (c.scriptsIncomplete > 0) {
    r.push({ id: "secrets", label: "Secret keys shipped to the browser", status: "inconclusive",
      detail: `${c.scriptsIncomplete} of your scripts could not be fully read (${(c.incompleteReasons || [])[0] || "truncated or undecodable response"}), so we cannot say whether a key is exposed in them. This is not a pass.` });
  } else if (c.scriptsScanned > 0) {
    r.push({ id: "secrets", label: "Secret keys shipped to the browser", status: has("exposed-secret") ? "found" : "clear",
      detail: `Read ${c.scriptsScanned} of ${own} same-origin script${own === 1 ? "" : "s"} your app loads, checking each against ${c.keyFormats} key formats.${thirdNote}` });
  } else {
    r.push({ id: "secrets", label: "Secret keys shipped to the browser", status: own ? "inconclusive" : "n/a",
      detail: own
        ? `Your app references ${own} same-origin script${own === 1 ? "" : "s"}, but none could be downloaded, so they were not checked. This is not a pass.`
        : `This page loads no same-origin JavaScript, so there was no bundle to search.${thirdNote}` });
  }

  // 3. Headers. Headers themselves arrive before the body, so an unreadable BODY does
  // not invalidate them; but if the page could not be read at all, the source-derived
  // checks below it are affected and the scan is flagged partial.
  r.push({ id: "headers", label: "Protective security headers", status: has("missing-header") ? "found" : "clear",
    detail: `Checked ${c.headersChecked} headers on your homepage response. ${c.headersPresent} of ${c.headersChecked} were set.` });

  // 3b. Auth tokens in browser storage (XL-233). A check that reads the served JS, so it is
  // body-derived and goes inconclusive if the app was never seen.
  r.push({ id: "browserstorage", label: "Auth tokens in browser storage", status: has("insecure-storage") ? "found" : (c.scriptsScanned > 0 || own === 0 ? "clear" : "inconclusive"),
    detail: has("insecure-storage")
      ? `A token-shaped key is written to browser storage, where any script on the page can read it.`
      : c.scriptsScanned > 0
        ? `Read ${c.scriptsScanned} of ${own} same-origin script${own === 1 ? "" : "s"} for tokens written to localStorage or sessionStorage. Documented auth-library session stores are not counted.`
        : own === 0
          ? "This page loads no same-origin JavaScript, so there was nothing to read for storage writes."
          : "Your scripts could not be read, so this was not checked. This is not a pass." });

  // 4. Source maps
  const smGaps = c.mapsUnanswered || [];
  r.push({ id: "sourcemaps", label: "Original source code downloadable", status: has("source-map") ? "found" : smGaps.length ? "inconclusive" : (c.mapsChecked > 0 ? "clear" : "n/a"),
    detail: smGaps.length && !has("source-map")
      ? `Checked ${c.mapsChecked} bundle${c.mapsChecked === 1 ? "" : "s"} for a public source map, but ${smGaps.length} could not be read (${smGaps.map((g) => `${g.url}: ${g.reason}`).join("; ")}). Those were not checked. This is not a pass.`
      : c.mapsChecked > 0
      ? `Checked ${c.mapsChecked} bundle${c.mapsChecked === 1 ? "" : "s"} for a public source map.${c.mapsVendored ? ` ${c.mapsVendored} of the maps found belong${c.mapsVendored === 1 ? "s" : ""} to a public open-source library, not to your code, and ${c.mapsVendored === 1 ? "is" : "are"} listed as inventory rather than as a finding.` : ""}`
      : "No bundles referenced a source map, so there was nothing to expose." });

  // 5. Private files
  const pfGaps = c.pathsUnanswered || [];
  r.push({ id: "privatefiles", label: "Private files served publicly", status: skipped ? "n/a" : (has("exposed-path") ? "found" : pfGaps.length ? "inconclusive" : "clear"),
    detail: skipped
      ? "Not checked: this was a stack-only scan, which never requests the private-file paths. Nothing here says they are safe."
      : `Requested ${c.pathsProbed} paths that must never be public (.env and its variants, .git, editor credentials). We require the response to actually look like that file, not just return 200, before flagging.` +
        (pfGaps.length ? ` ${pfGaps.length} of them got no complete answer (${pfGaps.map((g) => `${g.path}: ${g.reason}`).join("; ")}), so ${pfGaps.length === 1 ? "that path was" : "those paths were"} not checked. This is not a pass.` : "") });

  // 5a. A served npm lockfile (XL-290). One request, full mode only. An unanswered request is a
  // gap, never "no lockfile".
  const lk = c.lockfile || {};
  r.push({ id: "lockfile", label: "Dependency list served publicly", status: skipped ? "n/a" : has("exposed-lockfile") ? "found" : lk.status === "error" ? "inconclusive" : lk.requested ? "clear" : "n/a",
    detail: skipped
      ? "Not checked: this was a stack-only scan, which never requests /package-lock.json."
      : has("exposed-lockfile")
        ? "Your npm lockfile is downloadable, so anyone can read your exact dependency versions. Where the file allowed it, each pinned package was checked against the public OSV advisory database."
        : lk.status === "error"
          ? `The request for /package-lock.json got no answer (${lk.reason || "no response"}), so this was not checked. This is not a pass.`
          : lk.requested
            ? "Requested /package-lock.json. It was not served (we require the response to actually be a lockfile, not just return 200)."
            : "Not checked on this scan." });

  // 5b. Third-party scripts vs documented-compromised CDNs (XL-005)
  const sc = live.scripts || { thirdParty: [], bad: [] };
  r.push({ id: "thirdparty", label: "Scripts from compromised CDNs", status: has("compromised-cdn") ? "found" : "clear",
    detail: sc.thirdParty.length
      ? `Your page loads scripts from ${sc.thirdParty.length} third-party domain${sc.thirdParty.length === 1 ? "" : "s"}. Each was compared against a curated list of publicly documented compromised CDNs. Unknown domains are listed, never flagged.${sc.sri && sc.sri.missing.length ? ` ${sc.sri.missing.length} of ${sc.sri.pinned} version-pinned CDN file${sc.sri.pinned === 1 ? "" : "s"} load without an integrity hash, so a changed file would run unnoticed: ${sc.sri.missing.map((x) => x.url).join(", ")}.` : ""}`
      : "This page loads no third-party scripts, so there was nothing to compare." });

  // 6. Dangling DNS / subdomain takeover
  const dnsc = (live.dns || {}).cname || {};
  r.push({ id: "dns", label: "DNS pointing at something you lost", status: dnsc.status === "found" ? "found" : dnsc.status === "inconclusive" ? "inconclusive" : "clear",
    detail: dnsc.status === "found"
      ? dnsc.evidence
      : dnsc.status === "inconclusive"
        ? "Your DNS could not be read, so this was not tested."
        : dnsc.cname
          ? `Followed your CNAME to ${dnsc.cname} and confirmed it still resolves to a live service. A CNAME to a hosting provider is normal and is not reported as a problem.`
          : "No CNAME record on this hostname, so there is nothing that could be left dangling." });

  // 7. Other addresses on the domain, from public certificate logs. This is INVENTORY:
  // a certificate proves a name was issued, not that a host is live or misconfigured,
  // so it never becomes a finding and never carries a severity.
  const ct = live.ct || {};
  r.push({ id: "ctlogs", label: "Other addresses on your domain", status: ct.status === "found" ? "clear" : ct.status === "n/a" ? "n/a" : ct.status === "inconclusive" ? "inconclusive" : "clear",
    detail: ct.status === "found"
      ? `Public certificate logs list ${ct.total} other name${ct.total === 1 ? "" : "s"} on ${ct.apex}. These are addresses that exist, not problems: we did not test them. Worth a look if any is a staging or admin site you forgot was public.`
      : ct.status === "n/a"
        ? ct.reason
        : ct.status === "inconclusive"
          ? ct.reason || "The public certificate log could not be reached, so this was not checked."
          : `Public certificate logs list no other names on ${ct.apex || "your domain"}.` });

  // 8. Email spoofing protection
  const dnse = (live.dns || {}).email || {};
  r.push({ id: "email", label: "Email spoofing protection", status: dnse.status === "found" ? "found" : dnse.status === "n/a" ? "n/a" : dnse.status === "inconclusive" ? "inconclusive" : "clear",
    detail: dnse.status === "n/a"
      ? dnse.reason
      : dnse.status === "inconclusive"
        ? (dnse.reason || "Your DNS could not be read, so this was not tested.")
        : dnse.status === "found"
          ? `Checked ${dnse.apex} for SPF and DMARC. ${(dnse.missing || []).length ? `Missing: ${dnse.missing.join(", ")}.` : "Both are published, but DMARC is set to p=none, so it only reports and does not stop forged mail."}${(dnse.unanswered || []).length ? ` The ${dnse.unanswered.join(" and ")} lookup did not answer, so that one was not checked.` : ""}`
          : `Checked ${dnse.apex} for SPF and DMARC. Both are published.` });

  // BLOCKED AT THE DOOR: every row that needed the app's own bytes becomes inconclusive.
  //
  // Applied as a post-pass rather than threaded through each branch above, so the rule is in
  // ONE place and reads as one sentence: if we never saw the app, we cannot pass any check
  // that depends on having seen it. The verdict is computed from inconclusive rows further
  // down, so marking them here is what stops "clean" without inventing a second code path.
  //
  // DNS, certificate-log and email rows are deliberately NOT touched: they resolve records
  // and never asked the site for anything, so a block says nothing about them.
  if (live.rootBlocked) {
    const BODY_DERIVED = new Set(["database", "secrets", "browserstorage", "headers", "sourcemaps", "privatefiles", "lockfile", "thirdparty"]);
    for (const row of r) {
      if (!BODY_DERIVED.has(row.id)) continue;
      row.status = "inconclusive";
      row.detail = `The site answered ${live.rootStatus} instead of serving the page, so this check never reached your app. This is not a pass.`;
    }
  }

  return r;
}

// ---- the verdict (INV-04) ---------------------------------------------------
// A clean scan should be a first-class, evidence-backed answer, not an empty list.
// Only "critical" and "high" block a clean verdict; anything milder is reported as a
// named residual with the reason it is not urgent.
// Checks whose incompleteness CANNOT hide a vulnerability. The certificate-log lookup
// is inventory: it lists other names on a domain, carries no severity and never becomes
// a finding. Letting a third party's rate limit (Cert Spotter answers 403 under load)
// downgrade an otherwise clean verdict is the mirror image of a false clean: it cries
// wolf, and a verdict that is noisy for reasons outside the app teaches people to
// ignore it. Such rows still appear in the receipt, honestly marked inconclusive; they
// just do not block "clean".
const INVENTORY_ONLY = new Set(["ctlogs"]);

export function buildVerdict(findings, receipt) {
  const urgent = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const minor = findings.filter((f) => f.severity !== "critical" && f.severity !== "high");
  // Only SECURITY-relevant gaps block a clean verdict.
  const inconclusive = receipt.filter((x) => x.status === "inconclusive" && !INVENTORY_ONLY.has(x.id));

  if (urgent.length) {
    return {
      level: "issues",
      headline: urgent.length === 1 ? "One serious issue to fix" : `${urgent.length} serious issues to fix`,
      summary: "Fix these before anything else. Each one is something a stranger could act on right now.",
      residuals: [],
      inconclusive: inconclusive.map((x) => x.label),
    };
  }

  // Nothing urgent. Say so plainly, and stand behind it with the receipt.
  const residuals = minor.slice(0, 3).map((f) => ({
    title: f.title,
    why: f.severity === "medium"
      ? "Worth doing, but nobody can take your data with this alone."
      : "Minor hardening. Safe to leave for now.",
  }));
  // When the gap is the DATABASE, lead with the gap. It is the check this audience needs most, and
  // since hosted Supabase stopped listing tables to public keys (April 2026) it is the common gap,
  // so "Nothing serious found" would open most Supabase results with reassurance about the one
  // thing we could not test.
  const dbGap = inconclusive.some((x) => x.id === "database");
  const headline = dbGap
    ? (inconclusive.length === 1 ? "Your database could not be tested" : `Your database and ${inconclusive.length - 1} other check${inconclusive.length === 2 ? "" : "s"} could not be tested`)
    : inconclusive.length === 1 ? "Nothing serious found, with one gap"
      : inconclusive.length > 1 ? `Nothing serious found, with ${inconclusive.length} gaps` : "Nothing serious found";
  const summary = inconclusive.length
    ? `We could not complete ${inconclusive.length === 1 ? "one check" : `${inconclusive.length} checks`}, so this is not a clean bill of health. Everything we could test held up.`
    : minor.length
      ? "No one can read your data or use your keys. What is left is hardening, not exposure."
      : "Every check we ran came back clean. Nothing we test for is exposed on this app right now.";

  return { level: inconclusive.length ? "incomplete" : "clean", headline, summary, residuals, inconclusive: inconclusive.map((x) => x.label) };
}

// Build the enriched finding list from a live-layer result. Exported so the CLI can
// produce the SAME findings (and therefore the same severities and SARIF) as the web
// scanner, instead of maintaining a second severity mapping that could drift.
// XL-030: infer a leaked key's blast radius from explicit live/test markers in its value.
// Conservative on purpose: an unmarked key returns mode "unknown" and keeps its default
// severity, so we never downgrade a real key just because we could not classify it.
function assetCriticality(value) {
  const v = String(value || "");
  // A webhook signing secret carries no live/test marker, so it is graded for what it DOES rather
  // than labelled "LIVE": whoever holds it can forge events the server trusts.
  if (/^whsec_/.test(v)) {
    return { mode: "signing-secret", severity: "critical", note: "This is a webhook signing secret: anyone holding it can forge events your server treats as genuine." };
  }
  if (/(^|[_-])live([_-]|$)|sk_live|rk_live|pk_live/i.test(v)) {
    return { mode: "live", severity: "critical", note: "This looks like a LIVE key, so the impact is immediate." };
  }
  if (/(^|[_-])test([_-]|$)|sk_test|rk_test|pk_test/i.test(v)) {
    return { mode: "test", severity: "medium", note: "This looks like a TEST key: lower impact than a live key, but it still should not be public." };
  }
  return { mode: "unknown", severity: null };
}

// WHICH PATTERN HITS ARE PUBLIC BY DESIGN, and so never a finding. Exported because it is ONE
// judgement: until 2026-09-30 it lived only inside buildFindings, and the dev CLI (scan.mjs) read
// raw pattern hits, so its report printed a public Supabase anon key as a HIGH "rotate this"
// secret that the web scanner correctly ignores (XL-251, measured on two real sites). Returns the
// reason as a string, or null when the hit is a real secret candidate.
export function publicByDesign(s) {
  const v = String((s && s.value) || "");
  // GOOGLE BROWSER API KEYS ARE PUBLIC BY DESIGN, the same way a Supabase anon key is.
  // Firebase ships `apiKey: "AIza..."` in the client on purpose; Google documents it as safe
  // to embed, because access is controlled by Security Rules and per-key restrictions rather
  // than by hiding the string. Reporting it as an exposed secret fired HIGH on essentially
  // every Firebase app. We cannot tell from a bundle whether the key carries referrer or API
  // restrictions, and the doctrine is explicit that an uncertain finding is not shown.
  if (/^AIza[0-9A-Za-z_-]{35}$/.test(v)) return "google-browser-key";
  if (/^eyJ[A-Za-z0-9_-]+\.eyJ/.test(v)) {
    const claims = jwtClaims(v);
    if (claims.role !== "service_role") return "non-service-jwt"; // anon / session / other JWTs are not leaks
    // The key `supabase start` prints on every developer machine: issuer "supabase-demo", signed
    // with the CLI's published default secret. It is in thousands of READMEs and opens nothing on
    // a hosted project, so a docs page quoting it is not a leak.
    if (claims.iss === "supabase-demo") return "supabase-demo-key";
  }
  return null;
}

// XL-200: the vocabulary that makes a readable table a data exposure rather than reference data.
// Matched per underscore-separated part, so `name` alone (a countries table) does not count while
// `full_name`, `first_name` and `username` do. Kept to personal, credential, ownership and money
// words on purpose: `title`, `body` or `price_cents` describe content, not a person.
export const PERSONAL_COLUMN = /(^|_)(e_?mail|phone|mobile|tel|fax|address|street|city|zip|postcode|postal|dob|birth\w*|age|gender|ssn|passport|national_?id|tax_?id|password|passwd|pwd|hash|salt|token|secret|api_?key|access_?key|private|stripe_?(customer|id)|customer_?id|payment|card|iban|bank|account_?(number|no|id)|user_?id|owner_?id|profile_?id|author_?id|member_?id|ip_?address|first_?name|last_?name|full_?name|surname|given_?name|family_?name|username|display_?name|nickname|avatar|photo|session|cookie|device|balance|salary|income|medical|diagnosis|health)(_|$)/i;

export function buildFindings(live) {
  const findings = [];

  // 1. Supabase RLS — the flagship finding
  //
  // XL-200: GRADED BY WHAT THE COLUMNS ARE. Reading rows as a stranger cannot tell "row level
  // security is off" from "a deliberate read-for-everyone policy on reference data"; a countries
  // table and a profiles table look identical from outside. What differs is the columns. A table
  // with a personal-looking column (email, phone, address, date of birth, a token, a password, a
  // payment customer id, an owner id) is a data exposure and stays CRITICAL. A table with none of
  // those is HIGH, worded as the question it is: readable by anyone, fine if that is meant. The
  // finding is still CONFIRMED either way, because rows came back; confidence is not what changed.
  for (const r of live.rls || []) {
    const columns = r.columns || [];
    const personal = columns.filter((c) => PERSONAL_COLUMN.test(String(c)));
    const cols = columns.join(", ") || "(unknown)";
    const approx = r.count !== undefined ? ` Approx ${r.count} rows.` : "";
    findings.push(enrich("supabase-rls", {
      severity: personal.length ? "critical" : "high",
      location: r.table,
      technical: personal.length
        ? `The table "${r.table}" returned rows to an anonymous request. Exposed columns: ${cols}.${approx} ${personal.join(", ")} look${personal.length === 1 ? "s" : ""} personal, so this is treated as a data exposure. Xlogs never stores the row contents.`
        : `The table "${r.table}" returned rows to an anonymous request. Columns: ${cols}.${approx} None of them looks personal, so this may be reference data with a deliberate public read policy; if so, that is fine. If you did not mean this table to be readable by everyone, row level security is not protecting it. Xlogs never stores the row contents.`,
      extra: {
        table: r.table, columns, count: r.count, endpoint: r.endpoint,
        personalColumns: personal, gradedBy: "columns",
        // The knowledge entry's plain text talks about customer emails and private records. For a
        // table with none of those columns that sentence would be untrue, so the finding carries
        // its own.
        ...(personal.length ? {} : {
          title: "Anyone can read this table; confirm that is deliberate",
          plain: "This table can be read by anyone without logging in. Its columns do not look like personal data, so it may be reference data you meant to be public, and that is fine. If you did not mean it to be public, it needs a row level security policy like your other tables.",
        }),
      },
    }));
  }

  // 2. Exposed files (.env/.git) + source maps
  for (const e of live.exposures || []) {
    if (e.kind === "lockfile") {
      // XL-290. The lockfile itself is a low disclosure. It rises to medium only when OSV rates an
      // advisory high on a package that ships to users (not a dev dependency): the version is
      // stated by the file, the rating by the advisory's own database, and neither is ours.
      const advs = e.advisories || [];
      const shippedHigh = advs.filter((a) => a.severity === "high" && !a.dev);
      const lookup = e.advisoryLookup === "unparsed"
        ? ` Its advisories were NOT checked: ${e.truncated ? "the file is larger than we read" : "it is in the old lockfile format, which does not list exact versions per package"}. This is not a pass.`
        : e.advisoryLookup === "partial"
          ? ` The advisory lookup did not finish (${e.advisoryError}), so ${e.advisoriesChecked} of ${e.totalPackages} packages were checked. This is not a pass for the rest.`
          : ` All ${e.advisoriesChecked} pinned packages were checked against OSV.`;
      const advText = e.advisoryCount
        ? ` ${e.advisoryCount} package${e.advisoryCount === 1 ? " matches" : "s match"} a published advisory: ${advs.slice(0, 5).map((a) => a.location.replace(/^.* : /, "") + (a.dev ? " (dev only)" : "")).join(", ")}${e.advisoryCount > 5 ? ` and ${e.advisoryCount - 5} more` : ""}.`
        : e.advisoryLookup === "complete" ? " None matches a published advisory." : "";
      findings.push(enrich("exposed-lockfile", {
        severity: shippedHigh.length ? "medium" : "low",
        location: e.url,
        technical: `Your site serves its npm lockfile at ${e.url}, which lists every package and exact version the app was built with.${lookup}${advText}`,
        extra: { advisories: advs, advisoryCount: e.advisoryCount || 0, advisoryLookup: e.advisoryLookup },
      }));
      continue;
    }
    const cat = e.kind === "source-map" ? "source-map" : "exposed-path";
    let severity = cat === "exposed-path" ? "critical" : "high";
    const extra = {};
    if (cat === "exposed-path" && e.publicOnly) {
      // XL-206: a served dotfile of public build variables. Real, and not an exposure of secrets.
      severity = "high";
      extra.title = "A configuration file is being served publicly";
      extra.plain = "A .env file is downloadable from your live site. This one holds only public build variables, the kind your bundle already ships, so no secret is in it. The problem is the folder: if this file is served, the next file put beside it is served too.";
      extra.publicOnly = true;
      extra.envKeys = e.envKeys;
    } else if (cat === "exposed-path" && e.nonPublicKeys) {
      extra.nonPublicKeys = e.nonPublicKeys;
    }
    if (cat === "source-map") {
      extra.hasSourceText = !!e.hasSourceText;
      if (!e.hasSourceText) {
        // XL-203: mappings and names only. The file layout leaked; the source did not.
        severity = "medium";
        extra.title = "Your project's file layout is downloadable";
        extra.plain = "Your app serves a source map that carries no source text (webpack calls this a nosources map). Nothing can be reconstructed from it. What it does hand a reader is the list of your project's file names, which shows how the app is organised.";
      }
    }
    findings.push(enrich(cat, { severity, location: e.url, technical: e.note, extra }));
  }

  // 3. Secrets in the served bundles. JWTs need care: apps legitimately ship anon /
  //    session tokens to the browser, so a bare JWT is NOT a leak. Only a Supabase
  //    service_role JWT (full DB access) is. Non-JWT provider keys are flagged as-is.
  for (const s of live.secrets || []) {
    if (publicByDesign(s)) continue; // one judgement, shared with the dev CLI (see publicByDesign)
    const isJwt = /^eyJ[A-Za-z0-9_-]+\.eyJ/.test(s.value);
    if (isJwt) {
      findings.push(enrich("exposed-secret", {
        severity: "critical",
        location: s.sourceUrl,
        technical: `A Supabase service_role key (${mask(s.value)}) is in your client code at ${s.sourceUrl}. This is a full-access key and must never reach the browser: anyone can use it to read and write your entire database.`,
        extra: { secretName: "Supabase service_role key" },
      }));
      continue;
    }
    // XL-030: weight severity by what the key actually is. A LIVE payment/API key is an
    // immediate critical; a TEST key is real exposure but far lower impact. We only shift
    // on explicit live/test markers in the value, never on a loose guess.
    const asset = assetCriticality(s.value);
    findings.push(enrich("exposed-secret", {
      severity: asset.severity || s.severity || "high",
      location: s.sourceUrl,
      technical: `${s.name} (${mask(s.value)}) found at ${s.sourceUrl}. Anyone loading your app can read it.${asset.note ? " " + asset.note : ""}`,
      extra: { secretName: s.name, keyMode: asset.mode },
    }));
  }

  // 3a2. Documented-compromised CDN scripts (XL-005). Only publicly documented hosts
  //      are ever flagged (see lib/bad-cdns.mjs); unknown hosts stay inventory.
  for (const b of (live.scripts?.bad || [])) {
    findings.push(enrich("compromised-cdn", {
      severity: "high",
      location: b.host,
      technical: `Your page loads a script from ${b.url}. ${b.reason} Documented: ${b.source} (${b.date}).`,
      extra: { badHost: b.host, source: b.source },
    }));
  }

  // 3a3. Version-pinned CDN files with no integrity hash (XL-320). Low, so it can never block a
  //      clean verdict. Only pinned URLs are counted (lib/surface.mjs sriInventory): a moving loader
  //      cannot carry a stable hash, and flagging it would teach people to ignore the check.
  const sri = live.scripts?.sri;
  if (sri && (sri.missing || []).length) {
    findings.push(enrich("missing-sri", {
      severity: "low",
      location: sri.missing.map((x) => x.url).join(", "),
      technical: `${sri.missing.length} of the ${sri.pinned} version-pinned CDN file${sri.pinned === 1 ? "" : "s"} your page loads ${sri.missing.length === 1 ? "has" : "have"} no integrity attribute: ${sri.missing.map((x) => `${x.url} (${x.kind})`).join(", ")}. If the CDN ever served a changed file, the browser would run it.`,
      extra: { sriMissing: sri.missing },
    }));
  }

  // 3b. DNS: dangling CNAME / subdomain takeover, and email spoofing protection.
  const dns = live.dns || {};
  if (dns.cname?.status === "found") {
    findings.push(enrich("subdomain-takeover", {
      severity: "high",
      location: live.url,
      technical: dns.cname.evidence,
      extra: { cnameTarget: dns.cname.cname, provider: dns.cname.provider || undefined },
    }));
  }
  if (dns.email?.status === "found" && (dns.email.missing || []).length) {
    findings.push(enrich("email-spoofing", {
      // Spoofing protection is real but not an active data exposure. It stays medium,
      // and drops to low when the domain does not even receive mail.
      // Only a CONFIRMED "no MX" lowers it: receivesMail is null when the MX lookup failed.
      severity: dns.email.receivesMail === false ? "low" : "medium",
      location: dns.email.missing.join(" and "),
      technical: `${dns.email.apex} publishes no ${dns.email.missing.join(" and ")} record${dns.email.missing.length > 1 ? "s" : ""}.${dns.email.receivesMail ? " This domain also receives mail (it has MX records)." : " This domain does not appear to receive mail, so the risk is spoofing only."}`,
      extra: { apex: dns.email.apex, missing: dns.email.missing },
    }));
  } else if (dns.email?.status === "found" && (dns.email.weak || []).length) {
    // XL-250: SPF and DMARC both exist, but DMARC says p=none. Present and inert, so it is reported,
    // and low: the domain did set up DMARC and is one word away from enforcing it.
    findings.push(enrich("email-spoofing", {
      severity: "low",
      location: "DMARC p=none",
      technical: `${dns.email.apex} publishes DMARC with p=none, which tells receiving servers to deliver mail that fails the check and only report it. The record is there; it does not stop a forged message. Moving to p=quarantine, then p=reject once your own mail passes, is what makes it enforce.`,
      extra: { apex: dns.email.apex, missing: [], weak: dns.email.weak, title: "Your DMARC record does not enforce anything" },
    }));
  }

  // 4a. Cookie flags (one grouped finding, like the headers). Passive: read off the same root
  //     response, no extra request. The category maps to the broken-auth knowledge entry, which
  //     until this check existed was documentation with no live check behind it.
  if ((live.insecureCookies || []).length) {
    const parts = live.insecureCookies.map((c) => `${c.name} (missing ${c.missing.join(", ")})`);
    findings.push(enrich("insecure-cookie", {
      severity: "medium",
      location: live.insecureCookies.map((c) => c.name).join(", "),
      technical: `Cookies set by your homepage response are missing protective flags: ${parts.join("; ")}. Secure keeps a cookie off plain HTTP, HttpOnly keeps it away from page scripts, SameSite limits cross-site sends.`,
      extra: { cookies: live.insecureCookies },
    }));
  }

  // 3c. Auth tokens in browser storage (XL-233). LOW and POTENTIAL: we see the write in the
  // served code, not the runtime value, and documented library session stores are already
  // excluded in the detector. One finding per (storage, key), each naming where it was seen.
  for (const s of live.insecureStorage || []) {
    findings.push(enrich("insecure-storage", {
      severity: "low",
      confidence: "potential",
      location: s.sourceUrl,
      technical: `Your code writes "${s.key}" to ${s.api} at ${s.sourceUrl}. Any script on the page can read ${s.api}, so a token kept there is exposed to cross-site scripting and persists after the tab closes. If this is your auth library's own session store it may be its default; if you set it yourself, move it to an httpOnly cookie.`,
      extra: { storageKey: s.key, storageApi: s.api },
    }));
  }

  // 4. Missing security headers (one grouped finding), now union-aware across crawled pages
  // (XL-227). Root gaps drive it as before; when the root is clean but a sub-page is missing a
  // header the root sets, the finding still fires and names the routes. Single-page scans have no
  // pageHeaderGaps, so their behaviour is unchanged.
  const rootMissing = (live.missingHeaders || []).map((h) => h.header);
  const pageGaps = live.pageHeaderGaps || [];
  const pagePath = (u) => { try { return new URL(u).pathname; } catch { return u; } };
  if (rootMissing.length || pageGaps.length) {
    const gapNote = pageGaps.length
      ? ` Other pages are missing headers the homepage sets: ${pageGaps.map((g) => `${pagePath(g.url)} (${g.missing.join(", ")})`).join("; ")}.`
      : "";
    const location = rootMissing.length
      ? rootMissing.join(", ")
      : [...new Set(pageGaps.flatMap((g) => g.missing))].join(", ");
    // XL-250: a header that is present but inert is named with its reason, not as "absent".
    const inert = (live.missingHeaders || []).filter((h) => h.inert);
    const inertNote = inert.length ? ` Present but with no effect: ${inert.map((h) => h.reason).join("; ")}.` : "";
    const technical = rootMissing.length
      ? `These protective headers were absent or ineffective on your homepage response: ${rootMissing.join(", ")}.${inertNote}${gapNote}`
      : `Your homepage sets the protective headers, but other pages do not.${gapNote} A header set on only some routes protects only those routes.`;
    // XL-288: SEVERITY FOLLOWS WHAT THE HEADER WOULD PROTECT. A Content-Security-Policy governs
    // scripts. When CSP is the ONLY gap and the homepage runs no inline script and loads no script
    // from another site, there is nothing for it to govern, so the gap is low. Every other case
    // keeps medium: this rule can only lower one narrow case, it never raises anything.
    const onlyCsp = rootMissing.length === 1 && rootMissing[0] === "content-security-policy" && !pageGaps.length;
    // Both counts must have been MEASURED: an absent count is "never looked", not zero, and must not
    // lower anything (the first draft read undefined as 0; its own control test caught it).
    const measured = typeof live.rootInlineScripts === "number" && !!(live.scripts && Array.isArray(live.scripts.thirdParty));
    const noScriptSurface = measured && live.rootInlineScripts === 0 && live.scripts.thirdParty.length === 0;
    const severity = onlyCsp && noScriptSurface ? "low" : "medium";
    findings.push(enrich("missing-header", { severity, location, technical }));
  }

  findings.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  return stampIds(findings);
}

// DETERMINISTIC, and unique within one scan.
//
// The id is derived from what the finding IS (its category and where it was seen), so the
// same site scanned twice, in any process, in any order, yields the same ids. Collisions
// are possible - two exposed secrets can share a location - so identical bases are
// numbered by their order WITHIN this scan. That keeps them unique without reintroducing
// state that outlives the scan.
function stampIds(findings) {
  const used = new Map();
  for (const f of findings) {
    const base = [f.category, f.location || ""].join(":").replace(/[^a-zA-Z0-9:_.-]+/g, "-").slice(0, 80);
    const n = (used.get(base) || 0) + 1;
    used.set(base, n);
    f.id = n === 1 ? base : base + "#" + n;
  }
  return findings;
  return findings;
}

/**
 * Public entry point. Holds a GLOBAL per-origin lease for the duration of the scan, so the
 * ceiling applies across every serverless instance rather than within one process.
 *
 * Wrapped here rather than at each route because all six callers (scan, v1/scan, share,
 * badge, showcase, watch cron) funnel through this function. A ceiling that any one entry
 * point can skip is not a ceiling.
 *
 * A refused scan THROWS rather than returning a partial result. That is deliberate and
 * follows the core invariant: back-pressure must never be presentable as a completed scan,
 * because a scan that did no work would otherwise report nothing found.
 */
export async function scanUrl(url, opts = {}) {
  // SINGLE FLIGHT, outermost. If 100 callers ask for the same URL at once, that should be
  // ONE scan and 100 shared answers, not 100 scan trees aimed at one site. It sits outside
  // the lease so those callers also consume ONE lease rather than queueing against each
  // other and being told the origin is busy by their own duplicates.
  //
  // This control existed and was unit-tested for a while without ever being called from
  // production code, which is its own lesson: a passing test on an unwired function proves
  // the function works, not that the system has the property.
  //
  // Sharing a result is sound here because a scan is read-only and has no per-caller state.
  //
  // The mode is part of the key. A stack-only scan skips the exposed-path and Supabase probes, so
  // it is a DIFFERENT result from a full scan of the same URL - coalescing them under one key
  // would hand a stack lookup the security findings it deliberately did not run, or vice versa.
  return coalesce(`scan:${opts.stackOnly ? "stack" : "full"}:${url}`, () => leasedScan(url, opts));
}

async function leasedScan(url, opts) {
  const lease = await acquireOriginLease(url);
  if (!lease.held) {
    const e = new Error("This site is already being scanned as often as we allow at once. Please try again in a moment.");
    e.code = "ORIGIN_BUSY";
    e.status = 429;
    throw e;
  }
  try {
    return await runScan(url, opts);
  } finally {
    await lease.release(); // released on every path, including a thrown scan
  }
}

async function runScan(url, { log = () => {}, stackOnly = false, clientKey } = {}) {
  // Measured, not estimated (doctrine 6). We report the real elapsed time of THIS scan
  // rather than a published average we have no stored history to compute.
  const startedAt = Date.now();
  // clientKey rides through so the per-client concurrency slot is keyed by the caller, not "anon".
  const live = await liveLayer(url, log, { stackOnly, clientKey });
  const findings = buildFindings(live);
  // INV-31: where the scan fingerprinted the builder and we hold a dated scan of that builder's
  // untouched starter, say whether the starter has the same finding. Only from a completed check.
  const builderId = live.fingerprint?.builder?.id;
  if (builderId) for (const f of findings) { const note = baselineNote(f.category, builderId); if (note) f.builderBaseline = note; }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (counts[f.severity] !== undefined) counts[f.severity]++;

  const receipt = buildReceipt(live, findings);
  const verdict = buildVerdict(findings, receipt);

  return {
    url: live.url,
    reachable: live.reachable,
    supabase: live.supabase || { detected: false },
    // What built it / where it runs (XL-056) and the backend surface it reaches (INV-03).
    // Both are inventory, not findings: they carry no severity and raise no alarm.
    fingerprint: live.fingerprint || { builder: null, host: null, backends: [], signals: [] },
    origins: live.origins || [],
    // INV-33: the app's own endpoints named in its code, plus what a published API description
    // declares. Inventory, never called, no severity.
    surface: live.surface || null,
    ct: live.ct || { status: "inconclusive" },
    // Domain registration facts (XL-096) and per-response compression (XL-098). Both INVENTORY:
    // no severity, no verdict effect, measured from calls this scan already made.
    rdap: live.rdap || { status: "inconclusive" },
    compression: live.compression || { status: "inconclusive" },
    // Live SBOM (XL-045): libraries identified in the shipped bundles. Inventory.
    sbom: live.sbom || { libraries: [], note: "" },
    // XL-005: third-party script hosts (inventory) + documented-bad hits (findings above).
    scripts: live.scripts || { thirdParty: [], bad: [] },
    // What the site is built with, each item carrying the evidence that produced it. INVENTORY:
    // never scored, never a severity, never able to change a verdict. Knowing a site runs Next.js
    // is not a problem with the site.
    techStack: live.techStack || { items: [], categories: [] },
    // What the page states about who owns it, and which account-level identifiers it publishes.
    // Inventory, and framed as an exposure the owner controls rather than a pivot we performed.
    identity: live.identity || { identifiers: [], org: null },
    // How the site is configured, from the page we already fetched. Reported present/absent with
    // what we looked for, never scored: whether a missing canonical matters depends on the site.
    details: live.details || null,
    // The root response's protective headers (SECURITY_HEADERS names only, never cookies), so a
    // missing-header finding can show what the response carried and be reproduced (XL-174).
    rootHeaders: live.rootHeaders || null,
    // The other same-origin pages the scan inspected (XL-227). Inventory: proof of how deep the
    // scan reached, so the reader can see it was not root-only.
    pages: live.pages || [],
    // The mode travels with the result so every surface that renders it (the CLI, the web panel,
    // a stored share, an MCP reply) can state which checks did not run instead of inferring it
    // from a missing section. XL-244.
    stackOnly: !!live.stackOnly,
    // PAGE WEIGHT: what the deployment ships, measured from responses this scan already fetched.
    // Deliberately NOT a score and deliberately not mixed with any Lighthouse figure - this half is
    // reproducible, which is what lets it carry a regression claim in Watch. See lib/page-weight.mjs.
    weight: live.weight || null,
    durationMs: Date.now() - startedAt,
    findings,
    counts,
    receipt,
    verdict,
    // Which of the stack we DETECTED is actually covered by a check, and which is only
    // observed. The third state is the point: xlogs names ten backend categories and has a
    // specific check for one of them, and saying so is the same rule as the receipt -
    // absence of a finding must never be presented as coverage.
    // techStack and origins are passed now. Without them stackCoverage could only ever see
    // fingerprint.backends (four possible values), so the map that tells a user WHICH of their
    // technologies we actually checked was reporting on a fraction of what we detect.
    stack: stackCoverage({ fingerprint: live.fingerprint, receipt, techStack: live.techStack, origins: live.origins }),
    // THE JOIN, one row per detection, nothing dropped.
    //
    // `stack` above answers "how many recognised services did we see, and did their check run",
    // and it can only speak about technologies that appear in its own table - which is why six
    // detections on catnames.com produced three rows and the other three disappeared without
    // trace. This answers a different and more useful question, for EVERY detection: because we
    // observed X, what did xlogs do differently, and what did that turn up.
    //
    // The default classification is observed-only, so the denominator is always the full
    // detection list. 100% classified is achievable; 100% connected is not, and must never be a
    // target - a font provider with no security relationship is a finished answer.
    // `live.supabase` is passed because the stack detector cannot see what the bundle scan found -
    // see the note in relateStack(). Without it the one causal relationship in the graph is
    // unreachable in production while passing every test.
    stackRelations: relateStack(live.techStack, receipt, { supabase: live.coverage?.supabase }),
    notes: live.notes || [],
    scannedAt: undefined, // stamped by the caller (kept deterministic here)
  };
}
