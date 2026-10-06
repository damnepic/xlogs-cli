// ONE CONSOLIDATED FIX PASTE (XL-183). Every finding already carries a per-agent fix; this joins
// them into a single deterministic document ordered by severity, then location, then title, so a
// reader can hand their coding agent the whole scan in one paste instead of one finding at a time.
//
// Determinism is the point, not a nicety: the same report must produce byte-identical text on
// every render, or two people pasting "the fix" into two agents would be giving them different
// instructions. The sort key is fixed and total; nothing depends on the order findings arrived in.
//
// No severity is invented and no finding is dropped silently. A finding without a fix for the
// chosen agent falls back to its default fix; a finding with no fix at all is listed by title with
// a note saying so, because a paste that quietly omits a finding is the kind of absence that reads
// as "nothing to do".

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function fixSortKey(f) {
  return [RANK[String(f.severity || "").toLowerCase()] ?? 9, String(f.location || ""), String(f.title || "")];
}

function cmp(a, b) {
  const ka = fixSortKey(a), kb = fixSortKey(b);
  for (let i = 0; i < ka.length; i++) {
    if (ka[i] < kb[i]) return -1;
    if (ka[i] > kb[i]) return 1;
  }
  return 0;
}

/**
 * @param {Array} findings  the scan's findings (any order)
 * @param {string} agent    "claude-code" | "lovable" | "cursor" | "codex" | "manual"
 * @param {string} url      the scanned URL, named in the header so the paste is self-describing
 * @returns {string}        "" when there is nothing to fix
 */
export function consolidatedFix(findings, agent = "claude-code", url = "") {
  const list = [...(findings || [])].filter((f) => f && f.severity !== "info").sort(cmp);
  if (!list.length) return "";
  const L = [];
  L.push(`# Fixes for ${url || "this app"}, ${list.length} finding${list.length === 1 ? "" : "s"}, ordered by severity`);
  L.push("");
  L.push("Work top to bottom. Each section is one finding: what was observed, then the fix, then how to verify it.");
  L.push("");
  list.forEach((f, i) => {
    const sev = String(f.severity || "").toUpperCase();
    L.push(`## ${i + 1}. [${sev}] ${f.title || f.category}${f.location ? ` at ${f.location}` : ""}`);
    L.push("");
    if (f.observed) { L.push(`Observed: ${f.observed}`); L.push(""); }
    const text = f.fixes?.[agent] || f.fixes?.default || "";
    if (text) L.push(text.trim());
    else L.push("(No paste-ready fix is available for this finding. Read the evidence above and apply the change by hand.)");
    if (f.verify) { L.push(""); L.push(`Verify: ${f.verify}`); }
    L.push("");
  });
  return L.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}
