// The deploy-gate decision, shared by the dev CLI (scan.mjs) and the published npm CLI so the two
// cannot drift. Pure: findings and verdict in, exit code and messages out. No I/O.
//
// Exit codes: 0 passed, 1 a finding at or above the threshold, 4 could not verify.
//
// A GATE MUST NOT PASS BY NOT LOOKING (2026-09-30). Hosted Supabase stopped listing tables to
// public keys in April 2026, so the database check is inconclusive on most Supabase apps, and
// both CLIs used to print "gate passed" over a database they never tested. An inconclusive
// security check now blocks the gate unless the caller accepts the gap explicitly, and even then
// every gap is named. A finding always wins over a gap: a readable table fails regardless.

export const GATE_ORDER = ["critical", "high", "medium", "low"];

export function gateDecision({ findings = [], verdict = {} } = {}, failOn, { allowInconclusive = false } = {}) {
  const idx = GATE_ORDER.indexOf(failOn);
  if (idx < 0) throw new Error(`failOn must be one of ${GATE_ORDER.join(" | ")}`);
  const allowed = new Set(GATE_ORDER.slice(0, idx + 1));
  const failures = findings.filter((f) => allowed.has(f.severity));
  if (failures.length) {
    return {
      code: 1, status: "failed", failures, gaps: [],
      lines: [`GATE FAILED: ${failures.length} finding(s) at or above ${failOn}`,
        ...failures.map((f) => `  [${f.severity}] ${f.title}${f.location ? " at " + f.location : ""}`)],
    };
  }
  const gaps = Array.isArray(verdict.inconclusive) ? verdict.inconclusive : [];
  if (gaps.length && !allowInconclusive) {
    return {
      code: 4, status: "inconclusive", failures: [], gaps,
      lines: [`GATE INCONCLUSIVE: nothing at or above ${failOn}, but ${gaps.length} check(s) could not run:`,
        ...gaps.map((g) => `  [not checked] ${g}`),
        "  This is not a pass. Re-run with --allow-inconclusive to accept these gaps explicitly."],
    };
  }
  return {
    code: 0, status: gaps.length ? "passed-with-gaps" : "passed", failures: [], gaps,
    lines: [gaps.length
      ? `gate passed WITH ${gaps.length} check(s) not run (--allow-inconclusive): ${gaps.join("; ")}`
      : `gate passed: no findings at or above ${failOn}`],
  };
}
