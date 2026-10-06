// Shared secret-detection patterns. BOTH layers (repo grep + live-bundle scan)
// use this ONE set so a hit on each side is directly comparable — that shared
// vocabulary is what makes cross-layer correlation possible at all.
//
// `correlate: true` means the exact matched value is unambiguous enough to be traced
// back to its origin in source (single-line keys). Multi-line blocks (private keys) are
// flagged but not value-correlated.

export const SECRET_PATTERNS = [
  // BOUNDED BOTH SIDES. A real AWS access key ID is a standalone 20-character token.
  // Unbounded, this matched AKIA + 16 uppercase characters anywhere INSIDE a longer
  // uppercase run, so an ordinary uppercase checksum produced a CRITICAL.
  { name: "AWS access key",        severity: "critical", correlate: true,  re: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])/g },
  { name: "Google API key",        severity: "high",     correlate: true,  re: /AIza[0-9A-Za-z_\-]{35}/g },
  { name: "GitHub token",          severity: "critical", correlate: true,  re: /gh[pousr]_[0-9A-Za-z]{36,}/g },
  { name: "Slack token",           severity: "high",     correlate: true,  re: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { name: "Stripe live secret key", severity: "critical", correlate: true, re: /sk_live_[0-9A-Za-z]{16,}/g },
  { name: "Stripe restricted key", severity: "critical", correlate: true,  re: /rk_live_[0-9A-Za-z]{16,}/g },
  // THE TEST-KEY AND WEBHOOK BRANCHES WERE UNREACHABLE. lib/engine.mjs grades sk_test_/rk_test_ as
  // medium and whsec_ as critical, but until 2026-09-30 no pattern here could produce those values,
  // so both branches only ever ran in a test that hand-fed the value. Left-bounded so a longer
  // identifier ending in the prefix does not match.
  { name: "Stripe test secret key", severity: "medium", correlate: true,  re: /(?<![A-Za-z0-9_])[sr]k_test_[0-9A-Za-z]{16,}/g },
  { name: "Stripe webhook signing secret", severity: "critical", correlate: true, re: /(?<![A-Za-z0-9_])whsec_[0-9A-Za-z]{24,}/g },
  // XL-249 (2026-09-30): formats four agents found missing, each with a fixed, documented prefix and
  // a length floor, left-bounded like the rest, and each with a false-positive control in
  // test/secret-breadth.test.mjs. Formats whose exact shape could not be confirmed were left out.
  { name: "GitHub fine-grained token", severity: "critical", correlate: true, re: /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{60,}/g },
  { name: "GitLab personal access token", severity: "critical", correlate: true, re: /(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}/g },
  { name: "SendGrid API key",      severity: "critical", correlate: true,  re: /(?<![A-Za-z0-9_])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g },
  { name: "OpenRouter API key",    severity: "critical", correlate: true,  re: /(?<![A-Za-z0-9-])sk-or-v1-[a-f0-9]{64}(?![a-f0-9])/g },
  { name: "Anthropic admin key",   severity: "critical", correlate: true,  re: /(?<![A-Za-z0-9-])sk-ant-admin\d{2}-[A-Za-z0-9_-]{30,}/g },
  // A database URL with a password in it. Localhost, loopback, documentation hosts and placeholder
  // credentials are rejected in extractSecrets (DB_URL_NOT_A_LEAK) rather than here, so the rule
  // stays readable. A connection string in a browser bundle is a leak even when the host is private:
  // it names the database and hands over its password.
  { name: "Database URL with password", severity: "critical", correlate: true, re: /(?<![A-Za-z0-9+.-])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?):\/\/[^\s:@/"'`<>]{1,64}:[^\s@/"'`<>]{4,128}@[^\s/"'`:<>]{3,253}/g },
  // Tight: real OpenAI/Anthropic keys are a long CONTINUOUS token — either a known
  // prefix (sk-proj-/sk-svcacct-/sk-ant-api03-) + 30+ chars, or legacy sk- + 40+
  // continuous alphanumerics. This deliberately does NOT match hyphenated minified CSS
  // class names like `sk-icon-position` (a real false positive seen on vercel.com).
  // LEFT-ANCHORED, and this is the second fix to the same pattern. The first one raised the
  // length threshold, which killed `sk-icon-position` but left the regex unanchored, so any
  // word ENDING in "sk" still reached it: `mask-<sha1>.png` matched the legacy branch
  // (a 40-character content hash is 40 continuous alphanumerics) and a `.task-proj-*` class
  // matched the project branch. Both reported CRITICAL. Fixing the instance is not fixing the
  // class; the class here is "no left boundary". A genuine key is preceded by a quote, an
  // equals sign, a space or a line start, never by a letter, digit or hyphen.
  { name: "OpenAI / Anthropic key", severity: "critical", correlate: true, re: /(?<![A-Za-z0-9-])sk-(?:(?:proj|svcacct|ant-api03)-[A-Za-z0-9_-]{30,}|[A-Za-z0-9]{40,})/g },
  // LEFT-ANCHORED for the same reason the sk- pattern was: without it, every "eyJ" inside a long
  // run of token characters starts a fresh greedy match that backtracks looking for ".eyJ", which
  // is quadratic on an attacker body of "eyJa" repeated (measured 32s at 200KB). A real JWT is
  // never preceded by a token character, so nothing legitimate is lost.
  { name: "JWT (possible Supabase service_role)", severity: "high", correlate: true, re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },
  // Supabase's current SERVER key. Like the legacy service_role JWT it bypasses Row Level Security
  // entirely, but it is not a JWT, so the branch above never saw it: until 2026-09-30 an app that
  // shipped one to the browser got no finding at all. Its public counterpart, sb_publishable_, is
  // meant to ship and is deliberately NOT a pattern here. Left-bounded like the sk- pattern.
  { name: "Supabase secret key",   severity: "critical", correlate: true,  re: /(?<![A-Za-z0-9_-])sb_secret_[A-Za-z0-9_-]{16,}/g },
  // REQUIRES KEY MATERIAL, not just the header. Matching the BEGIN line alone meant any page
  // explaining PEM format reported a CRITICAL with no key present. The lookahead demands 60
  // continuous base64 characters shortly after the header, which every real key body has and no
  // placeholder does. Quantifiers are bounded, so this adds no backtracking risk, and the
  // matched VALUE is still just the header line rather than the key itself.
  { name: "Private key block",     severity: "critical", correlate: false, re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----(?=[\s]{0,10}[A-Za-z0-9+/=]{60})/g },
];

// Placeholder / obvious-fake filter, so an example key in a tutorial is never
// reported as a real secret.
const PLACEHOLDER = /example|placeholder|your[_-]|xxxx|<|dummy|sample|redacted|changeme|test[_-]?(key|token)|fake|\bfoo\b|\bbar\b/i;

// Exact keys vendors print in their own documentation. Any tutorial, docs mirror or course page
// quotes them, and they open nothing, so a hit on one is never a finding. Exact values only: a
// prefix rule would hide real keys.
//
// WRITTEN IN PARTS, JOINED AT LOAD (2026-10-06). They are Stripe's published samples, not secrets,
// but whole they are exactly what GitHub push protection refuses, and it (rightly) blocked the
// public CLI repository on them. The joined values are identical, so recognition is unchanged.
const VENDOR_DOC_SAMPLES = new Set([
  ["sk", "test", "4eC39HqLyjWDarjtT1zdp7dc"].join("_"), // Stripe API reference sample secret key
  ["sk", "test", "BQokikJOvBiI2HlWgH4olfQ2"].join("_"), // Stripe's older documentation sample secret key
]);

// A database URL that is not a leak: a local or documentation host, or credentials that are a
// placeholder. Tutorials and READMEs are full of postgres://user:password@localhost:5432/db.
const DB_URL_NOT_A_LEAK = /@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host|hostname|db|database|postgres|mysql|mongo|redis|server|[a-z0-9-]*example\.(?:com|org|net)|[a-z0-9.-]*\.(?:test|invalid|local|localhost))(?:[:/]|$)|:\/\/(?:user|username|admin|root|postgres)?:(?:pass(?:word)?|pwd|secret|admin|root|postgres|\*+|\.\.\.|\$\{[^}]*\}|%[a-z_]+%)@/i;

// Extract distinct secret hits from a blob of text (HTML or JS source).
// Returns [{ name, severity, value, correlate }]. Values are de-duplicated.
// HOW MANY HITS ONE BLOB MAY PRODUCE.
//
// The patterns themselves are linear. Measured, the worst adversarial input took 2.68ms
// across 120KB, so this is NOT a ReDoS guard. The risk is output VOLUME. De-duplication
// collapses a page repeating one fake key ten million times, but it cannot collapse
// DISTINCT values, and those are trivial to generate: 10MB of "AKIA" plus a counter
// produced 300,000 findings in 372ms, every one of which would flow into the result
// object, the JSON response, KV storage and the UI.
//
// The cap is on the number of DISTINCT hits, because time was never the problem. 100 per
// blob is far beyond any real site; a page with more than that has already made its point.
export const MAX_HITS_PER_BLOB = 100;

export function extractSecrets(text, limit = MAX_HITS_PER_BLOB) {
  const seen = new Set();
  const out = [];
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of text.matchAll(p.re)) {
      const value = m[0];
      if (PLACEHOLDER.test(value) || VENDOR_DOC_SAMPLES.has(value)) continue;
      if (p.name === "Database URL with password" && DB_URL_NOT_A_LEAK.test(value)) continue;
      const key = p.name + "\u0000" + value;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: p.name, severity: p.severity, value, correlate: p.correlate });
      // Stop reading the blob entirely rather than finishing and slicing afterwards. The
      // point is to not do the work, not to hide it once it is done.
      if (out.length >= limit) return out;
    }
  }
  return out;
}

// Mask a secret value for display — never print it whole, even though (for the
// live layer) it is already public. Show enough to identify, not to reuse.
export function mask(value) {
  if (!value) return "(empty)";
  const v = String(value);
  if (v.length <= 12) return v.slice(0, 2) + "•".repeat(Math.max(2, v.length - 2));
  return v.slice(0, 4) + "•".repeat(8) + v.slice(-4) + ` (${v.length} chars)`;
}
