// KNOWN-VULNERABILITY LOOKUP for the repo scanner, against OSV.dev.
//
// WHY THIS IS PERMITTED when INV-08 rejected "version-aware risk". That rejection was about the
// LIVE scan: a version guessed from a response banner maps to CVEs wrongly more often than rightly
// (backporting, config-dependence, CDN masking), which makes it a false-positive machine. A
// lockfile is the opposite epistemics. package-lock.json states the EXACT bytes npm will install,
// declared by the repository itself. Querying a public advisory database with an exact declared
// version is measurement; mapping a banner to one is speculation. Same wedge, honest form.
//
// SCOPE, stated narrowly because narrow is what keeps it true:
//   - npm lockfiles only (package-lock.json v2/v3), because the version there is exact. yarn.lock
//     and pnpm-lock.yaml are not parsed yet, and when one is present but unparsed the result SAYS
//     so rather than reading as "no known vulnerabilities".
//   - OSV.dev only: free, public, no key, and it aggregates GHSA + npm advisories. One fixed
//     extra host, which keeps ghscan's no-arbitrary-URL posture intact (github.com + api.osv.dev).
//   - Advisories change over time, so the same repo can honestly return different results on
//     different days. That is the same property our DNS and certificate checks already have; the
//     scan is stamped with scannedAt and the finding names the database.
//
// SEVERITY IS EARNED. A dependency with a known advisory is a REVIEW-shaped fact ("worth
// explaining before you trust this repo"), not proof the repo is malicious, so nothing here ever
// emits CRITICAL - the REJECT verdict stays reserved for active-compromise signals. Advisories
// whose own severity is high or critical surface as HIGH; the rest as NOTE.
//
// BOUNDED ABSENCE THROUGHOUT. Every cap (package count, detail fetches, the wall-clock deadline)
// is reported in the result, and a lookup that could not run returns { checked: 0, error } - the
// caller surfaces that as a check error, never as a clean pass.

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns/";

// Caps. MAX_PACKAGES bounds the query cost on monorepos; MAX_DETAILS bounds the per-vuln severity
// fetches; the deadline is ONE wall-clock budget for the whole lookup, fixed before the first
// connect - an idle timeout is not a deadline.
const MAX_PACKAGES = 1500;
const BATCH_SIZE = 500;
const MAX_DETAILS = 20;
const DEADLINE_MS = 12000;

/**
 * Exact {name, version} pairs from package-lock.json v2/v3.
 * Returns { pkgs, lockfilesSeen, parsed } - lockfilesSeen lists every lockfile present, so the
 * caller can say "a yarn.lock exists and was not checked" instead of implying it was.
 */
export function parseNpmLock(files) {
  const lockNames = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"];
  const seen = files
    .filter((f) => lockNames.some((n) => f.path === n || f.path.endsWith("/" + n)))
    .map((f) => f.path);
  const lock = files.find((f) => f.path === "package-lock.json" || f.path.endsWith("/package-lock.json"));
  if (!lock) return { pkgs: [], lockfilesSeen: seen, parsed: null };
  let json;
  try { json = JSON.parse(lock.content); } catch { return { pkgs: [], lockfilesSeen: seen, parsed: null }; }
  const packages = json.packages;
  if (!packages || typeof packages !== "object") return { pkgs: [], lockfilesSeen: seen, parsed: null };

  const out = new Map();
  for (const [path, meta] of Object.entries(packages)) {
    // The "" key is the root project itself, not a dependency.
    if (!path || !meta || !meta.version) continue;
    // node_modules/@scope/name or node_modules/name, possibly nested. The NAME is everything
    // after the last node_modules/ segment.
    const i = path.lastIndexOf("node_modules/");
    if (i === -1) continue;
    const name = path.slice(i + "node_modules/".length);
    if (!name || meta.link) continue;
    // DIRECT means the project itself lists it; TRANSITIVE means a dependency pulled it in. The
    // lockfile path says which: one "node_modules/" segment is direct, nested segments are not.
    // A transitive advisory is fixed by upgrading the parent, not by editing package.json, and
    // the remediation wording has to say so or the reader edits the wrong file.
    const direct = path.split("node_modules/").length === 2;
    out.set(`${name}@${meta.version}`, { name, version: meta.version, dev: !!meta.dev, direct });
  }
  return { pkgs: [...out.values()], lockfilesSeen: seen, parsed: lock.path };
}

async function post(url, body, signal, fetchImpl) {
  const res = await fetchImpl(url, {
    method: "POST",
    signal,
    headers: { "content-type": "application/json", "user-agent": "xlogs/0.1 (+read-only repo audit)" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`osv ${res.status}`);
  return res.json();
}

function sevRank(v) {
  // OSV severity comes as CVSS vectors and/or ecosystem-specific labels. We look for the
  // database_specific severity GHSA publishes, then fall back to a CVSS score threshold.
  const label = (v?.database_specific?.severity || "").toUpperCase();
  if (label === "CRITICAL" || label === "HIGH") return "HIGH";
  if (label === "MODERATE" || label === "MEDIUM" || label === "LOW") return "NOTE";
  const cvss = (v?.severity || []).find((s) => /^CVSS/.test(s.type || ""));
  if (cvss?.score) {
    const m = String(cvss.score).match(/\/?(?:AV|A:)?.*?([0-9]+\.[0-9]).*$/);
    // A CVSS *vector* has no plain score; treat unscored as NOTE rather than guessing upward.
    if (m && Number(m[1]) >= 7) return "HIGH";
  }
  return "NOTE";
}

/**
 * The lookup. Returns:
 *   { findings, checked, totalPackages, capped, lockfilesSeen, parsed, unresolved, error }
 * findings are shaped like ghscan findings ({ id, severity, title, location, evidence }) so the
 * route can merge them with runChecks output. Never throws.
 */
/**
 * The fix versions an advisory states for one package, as it states them. OSV records carry
 * affected[] entries per package with SEMVER ranges whose events include { fixed }. We read
 * those for the matching npm package name only, so a record covering several packages never
 * attributes another package's fix to this one. Nothing is computed from version arithmetic.
 */
export function fixedVersionsFor(name, records) {
  const out = new Set();
  for (const rec of records) {
    for (const a of rec?.affected || []) {
      if (a?.package?.ecosystem !== "npm" || a?.package?.name !== name) continue;
      for (const r of a.ranges || []) for (const ev of r.events || []) if (ev?.fixed) out.add(String(ev.fixed));
    }
  }
  return [...out].sort().slice(0, 3);
}

export async function osvLookup(files, { fetchImpl = fetch } = {}) {
  const { pkgs, lockfilesSeen, parsed } = parseNpmLock(files);
  const base = {
    checked: 0,
    totalPackages: pkgs.length,
    capped: pkgs.length > MAX_PACKAGES,
    lockfilesSeen,
    parsed,
    unresolved: 0,
    findings: [],
    error: null,
  };
  if (!parsed) {
    // No parseable npm lockfile. NOT an error and NOT a pass: the caller states which lockfiles
    // were seen but unread, so absence stays bounded.
    return base;
  }
  const target = pkgs.slice(0, MAX_PACKAGES);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DEADLINE_MS);
  try {
    // Batch queries. OSV echoes results in request order.
    const hits = new Map(); // "name@version" -> [vuln ids]
    for (let i = 0; i < target.length; i += BATCH_SIZE) {
      const chunk = target.slice(i, i + BATCH_SIZE);
      const res = await post(OSV_BATCH, {
        queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version })),
      }, ctrl.signal, fetchImpl);
      // A 200 WE CANNOT READ IS NOT "NO ADVISORIES" (2026-09-30). OSV echoes one result per query;
      // if the shape changes, `(res.results || [])` would yield zero hits while `checked` still
      // counted the packages, reporting "N checked, none vulnerable" from a response we never
      // understood. Refuse it, so the lookup is reported partial like any other failure.
      if (!Array.isArray(res && res.results) || res.results.length !== chunk.length) {
        throw new Error(`unexpected response shape (${Array.isArray(res && res.results) ? res.results.length : "no"} results for ${chunk.length} queries)`);
      }
      res.results.forEach((r, j) => {
        const ids = (r.vulns || []).map((v) => v.id);
        if (ids.length) hits.set(`${chunk[j].name}@${chunk[j].version}`, ids);
      });
      base.checked += chunk.length;
    }

    if (hits.size === 0) return base;

    // Severity needs the vuln records. Fetch details for a capped set of UNIQUE ids; anything
    // past the cap is still reported, with its severity marked unverified rather than invented.
    const uniqueIds = [...new Set([...hits.values()].flat())];
    const details = new Map();
    for (const id of uniqueIds.slice(0, MAX_DETAILS)) {
      try { details.set(id, await (await fetchImpl(OSV_VULN + id, { signal: ctrl.signal })).json()); }
      catch { /* one missing detail record must not kill the lookup; it reads as unverified */ }
    }
    base.unresolved = Math.max(0, uniqueIds.length - details.size);

    for (const [pkg, ids] of hits) {
      const sevs = ids.map((id) => details.has(id) ? sevRank(details.get(id)) : null);
      const knownHigh = sevs.includes("HIGH");
      const allKnown = sevs.every((s) => s !== null);
      const summary = ids.slice(0, 4).join(", ") + (ids.length > 4 ? ` and ${ids.length - 4} more` : "");
      // Shaped like engine.mjs finding(), so every downstream surface treats these the same.
      const meta = target.find((p) => `${p.name}@${p.version}` === pkg);
      const fixedIn = fixedVersionsFor(meta?.name, ids.map((id) => details.get(id)).filter(Boolean));
      base.findings.push({
        id: "known-vuln",
        severity: knownHigh ? "high" : "low",
        dev: !!meta?.dev,
        title: "A pinned dependency has a published security advisory",
        location: parsed + " : " + pkg,
        evidence: `${pkg}${meta?.direct === false ? " (a transitive dependency: something you depend on pulled it in, so the fix is upgrading that parent)" : meta?.direct ? " (a direct dependency)" : ""}${meta?.dev ? " (development only: it runs at install and build time, it does not ship to your users)" : ""} matches ${ids.length} published advisor${ids.length === 1 ? "y" : "ies"} in OSV (${summary}).` +
          (fixedIn.length ? ` Fixed in ${fixedIn.join(", ")} according to the advisory.` : "") +
          (knownHigh ? " At least one is rated high or critical by its own database." :
           allKnown ? " None of them is rated high by its own database." :
           " Severity could not be confirmed for every advisory, so this is listed rather than rated upward."),
      });
    }
    // Deterministic order: highs first, then alphabetical, so the same repo renders the same way.
    base.findings.sort((a, b) => (a.severity === b.severity ? a.location.localeCompare(b.location) : a.severity === "high" ? -1 : 1));
    return base;
  } catch (e) {
    base.error = e?.name === "AbortError" ? "osv: did not finish inside the deadline" : `osv: ${e?.message || e}`;
    // Findings gathered before the failure still stand - they were measured. The error rides
    // along so the caller reports the lookup as partial rather than complete.
    return base;
  } finally {
    clearTimeout(timer);
  }
}
