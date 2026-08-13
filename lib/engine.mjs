// Framework-agnostic scan engine. This is the ONE entry point every surface calls
// (web API, CLI, future GitHub check / Watch) so detection logic is never duplicated.
// It runs the deterministic live layer and returns findings already enriched from the
// shared knowledge object, in a plain-JSON shape a UI or report can render directly.
//
// URL-only (the web MVP scope): the live layer is pure Node (fetch), no bash, no repo,
// no source upload — so this runs fine in a serverless function.

import { liveLayer } from "./live.mjs";
import { mask } from "./patterns.mjs";
import { vulnForCategory, taxonomyFor } from "./knowledge/vulns.mjs";
import { fixForAgent } from "./knowledge/index.mjs";

const AGENTS = ["default", "lovable", "cursor", "claude-code", "manual"];

// A Supabase ANON key is meant to be public (the frontend ships it) — do NOT flag it as
// an exposed secret. A SERVICE_ROLE key is the dangerous one. Decode and tell them apart.
function jwtRole(tok) {
  try {
    const p = JSON.parse(Buffer.from(tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return p.role || null;
  } catch { return null; }
}

let _id = 0;
function enrich(category, { severity, location, technical, extra = {} } = {}) {
  const v = vulnForCategory(category);
  const fixes = {};
  if (v) for (const a of AGENTS) fixes[a] = fixForAgent(v, a, location);
  const tax = v ? taxonomyFor(v.id) : { cwe: null, cweName: null, owasp: null };
  return {
    id: `f${++_id}`,
    vulnId: v?.id || null,
    category,
    cwe: tax.cwe,
    cweName: tax.cweName,
    owasp: tax.owasp,
    severity: severity || v?.severity || "medium",
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
function buildReceipt(live, findings) {
  const c = live.coverage || {};
  const has = (cat) => findings.some((f) => f.category === cat);
  const s = c.supabase || {};
  const r = [];

  // 1. Database
  if (!s.keyFound) {
    r.push({ id: "database", label: "Database exposed to the public", status: "n/a",
      detail: "No Supabase connection was visible in this app's code, so there was no database for us to test anonymously." });
  } else if (s.tablesProbed > 0) {
    const readable = (live.rls || []).length;
    r.push({ id: "database", label: "Database exposed to the public", status: readable ? "found" : "clear",
      detail: readable
        ? `Asked ${s.tablesProbed} table${s.tablesProbed === 1 ? "" : "s"} for data as a logged-out stranger. ${readable} returned real rows.`
        : `Asked ${s.tablesProbed} table${s.tablesProbed === 1 ? "" : "s"} for data as a logged-out stranger. None returned any rows.` });
  } else {
    r.push({ id: "database", label: "Database exposed to the public", status: "inconclusive",
      detail: "Found a Supabase connection, but its table list could not be read, so we could not test the tables. This is not a pass." });
  }

  // 2. Secret keys
  if (c.scriptsScanned > 0) {
    r.push({ id: "secrets", label: "Secret keys shipped to the browser", status: has("exposed-secret") ? "found" : "clear",
      detail: `Read ${c.scriptsScanned} of ${c.scriptsReferenced} script${c.scriptsReferenced === 1 ? "" : "s"} your app loads, checking each against ${c.keyFormats} key formats.` });
  } else {
    r.push({ id: "secrets", label: "Secret keys shipped to the browser", status: c.scriptsReferenced ? "inconclusive" : "n/a",
      detail: c.scriptsReferenced
        ? `Your app references ${c.scriptsReferenced} script${c.scriptsReferenced === 1 ? "" : "s"}, but none could be downloaded, so they were not checked.`
        : "This page loads no same-origin JavaScript, so there was no bundle to search." });
  }

  // 3. Headers
  r.push({ id: "headers", label: "Protective security headers", status: has("missing-header") ? "found" : "clear",
    detail: `Checked ${c.headersChecked} headers on your homepage response. ${c.headersPresent} of ${c.headersChecked} were set.` });

  // 4. Source maps
  r.push({ id: "sourcemaps", label: "Original source code downloadable", status: has("source-map") ? "found" : (c.mapsChecked > 0 ? "clear" : "n/a"),
    detail: c.mapsChecked > 0
      ? `Checked ${c.mapsChecked} bundle${c.mapsChecked === 1 ? "" : "s"} for a public source map.`
      : "No bundles referenced a source map, so there was nothing to expose." });

  // 5. Private files
  r.push({ id: "privatefiles", label: "Private files served publicly", status: has("exposed-path") ? "found" : "clear",
    detail: `Requested ${c.pathsProbed} paths that must never be public (.env and its variants, .git, editor credentials). We require the response to actually look like that file, not just return 200, before flagging.` });

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
        ? "Your DNS could not be read, so this was not tested."
        : dnse.status === "found"
          ? `Checked ${dnse.apex} for SPF and DMARC. Missing: ${(dnse.missing || []).join(", ")}.`
          : `Checked ${dnse.apex} for SPF and DMARC. Both are published.` });

  return r;
}

// ---- the verdict (INV-04) ---------------------------------------------------
// A clean scan should be a first-class, evidence-backed answer, not an empty list.
// Only "critical" and "high" block a clean verdict; anything milder is reported as a
// named residual with the reason it is not urgent.
function buildVerdict(findings, receipt) {
  const urgent = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const minor = findings.filter((f) => f.severity !== "critical" && f.severity !== "high");
  const inconclusive = receipt.filter((x) => x.status === "inconclusive");

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
  const headline = inconclusive.length ? "Nothing serious found, with one gap" : "Nothing serious found";
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
export function buildFindings(live) {
  const findings = [];

  // 1. Supabase RLS — the flagship finding
  for (const r of live.rls || []) {
    findings.push(enrich("supabase-rls", {
      severity: "critical",
      location: r.table,
      technical: `The table "${r.table}" returned rows to an anonymous request. Exposed columns: ${(r.columns || []).join(", ") || "(unknown)"}.${r.count !== undefined ? ` Approx ${r.count} rows.` : ""} Xlogs never stores the row contents.`,
      extra: { table: r.table, columns: r.columns || [], count: r.count, endpoint: r.endpoint },
    }));
  }

  // 2. Exposed files (.env/.git) + source maps
  for (const e of live.exposures || []) {
    const cat = e.kind === "source-map" ? "source-map" : "exposed-path";
    findings.push(enrich(cat, { severity: cat === "exposed-path" ? "critical" : "high", location: e.url, technical: e.note }));
  }

  // 3. Secrets in the served bundles. JWTs need care: apps legitimately ship anon /
  //    session tokens to the browser, so a bare JWT is NOT a leak. Only a Supabase
  //    service_role JWT (full DB access) is. Non-JWT provider keys are flagged as-is.
  for (const s of live.secrets || []) {
    const isJwt = /^eyJ[A-Za-z0-9_-]+\.eyJ/.test(s.value);
    if (isJwt) {
      if (jwtRole(s.value) !== "service_role") continue; // anon / session / other JWTs are not leaks
      findings.push(enrich("exposed-secret", {
        severity: "critical",
        location: s.sourceUrl,
        technical: `A Supabase service_role key (${mask(s.value)}) is in your client code at ${s.sourceUrl}. This is a full-access key and must never reach the browser — anyone can use it to read and write your entire database.`,
        extra: { secretName: "Supabase service_role key" },
      }));
      continue;
    }
    findings.push(enrich("exposed-secret", {
      severity: s.severity || "high",
      location: s.sourceUrl,
      technical: `${s.name} (${mask(s.value)}) found at ${s.sourceUrl}. Anyone loading your app can read it.`,
      extra: { secretName: s.name },
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
      severity: dns.email.receivesMail ? "medium" : "low",
      location: dns.email.missing.join(" and "),
      technical: `${dns.email.apex} publishes no ${dns.email.missing.join(" and ")} record${dns.email.missing.length > 1 ? "s" : ""}.${dns.email.receivesMail ? " This domain also receives mail (it has MX records)." : " This domain does not appear to receive mail, so the risk is spoofing only."}`,
      extra: { apex: dns.email.apex, missing: dns.email.missing },
    }));
  }

  // 4. Missing security headers (one grouped finding)
  if ((live.missingHeaders || []).length) {
    const list = live.missingHeaders.map((h) => h.header).join(", ");
    findings.push(enrich("missing-header", { severity: "medium", location: list, technical: `These protective headers were absent on your homepage response: ${list}.` }));
  }

  findings.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  return findings;
}

export async function scanUrl(url, { log = () => {} } = {}) {
  // Measured, not estimated (doctrine 6). We report the real elapsed time of THIS scan
  // rather than a published average we have no stored history to compute.
  const startedAt = Date.now();
  const live = await liveLayer(url, log);
  const findings = buildFindings(live);

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
    ct: live.ct || { status: "inconclusive" },
    durationMs: Date.now() - startedAt,
    findings,
    counts,
    receipt,
    verdict,
    notes: live.notes || [],
    scannedAt: undefined, // stamped by the caller (kept deterministic here)
  };
}
