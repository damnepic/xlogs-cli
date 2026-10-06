// WHAT THIS SCAN COULD NOT CHECK (XL-185): three lists, no score.
//
// A clean result is a statement about the checks that ran, and it only stays honest if the things
// the scanner cannot see are listed beside it. Three kinds of absence, kept apart because they
// mean different things:
//   structural    what xlogs never checks, on any site, by design (server-side auth logic, RLS
//                 policy correctness, business logic, git history). A fixed list, the same for
//                 every scan, so it cannot be tuned to make a result look fuller.
//   notApplicable checks that did not apply to THIS site (no Supabase, no CNAME), from the receipt.
//   incomplete    checks that tried and could not finish, from the receipt. Never a pass.
//
// The UI lets a reader tick items as "I checked this myself". The ticks live in the reader's
// browser only, and nothing is computed from them: there is no completeness percentage, because
// a percentage over a list this scanner cannot verify would be a manufactured number.

export const NOT_CHECKABLE = [
  { id: "rls-policy", label: "Whether your Row Level Security policies are CORRECT", why: "xlogs asks each table for rows as a stranger. A table that returns nothing may have a good policy or a wrong one that happens to hide these rows; only reading the policy says which." },
  { id: "server-auth", label: "Server-side authorisation logic", why: "Whether a logged-in user can reach another user's records is decided in code xlogs never runs. A read-only scan cannot log in, and must not." },
  { id: "business-logic", label: "Business-logic flaws", why: "Price manipulation, step-skipping, replay: these are about what your app should do, which no pattern can know." },
  { id: "git-history", label: "Secrets deleted from the current code but alive in git history", why: "The web scan reads what is served now. A repository scan reads the current tree. Neither reads old commits." },
  { id: "private-repos", label: "Anything in a private repository", why: "The repository scanner reads public tarballs only." },
  { id: "runtime-deps", label: "Dependency vulnerabilities from a live response", why: "A version guessed from a header maps to advisories wrongly more often than rightly, so the web scan refuses to. The repository scan checks exact pins in package-lock.json instead." },
  { id: "authenticated-surface", label: "Pages behind a login", why: "Every request is anonymous. What your app shows to a signed-in user is outside the scan by construction." },
];

/**
 * @param {Array} receipt  the scan's receipt rows ({ id, label, status, detail })
 */
export function notChecked(receipt = []) {
  const rows = Array.isArray(receipt) ? receipt : [];
  return {
    structural: NOT_CHECKABLE,
    notApplicable: rows.filter((r) => r.status === "n/a").map((r) => ({ id: r.id, label: r.label, detail: r.detail })),
    incomplete: rows.filter((r) => r.status === "inconclusive").map((r) => ({ id: r.id, label: r.label, detail: r.detail })),
  };
}

export const TICK_STORAGE_PREFIX = "xlogs:notchecked:";
