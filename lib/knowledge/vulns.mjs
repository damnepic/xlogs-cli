// The shared knowledge object (product doctrine: product and content must not fork).
//
// CANONICAL security truth, defined ONCE per vulnerability:
//   title (the problem) · plain (what it means) · whyAi · evidence · check ·
//   requiredState (the end state that must be true after fixing) · fixSteps
//   (agent-agnostic steps to reach it) · verify (how we confirm) · platforms · slug
//
// The security truth does NOT fragment by coding tool. Agent-specific phrasing
// ("Fix with Lovable / Cursor / Claude Code / manually") is PRESENTATION, produced
// by the adapter in ./index.mjs from requiredState + fixSteps. This same object
// powers both a scanner finding AND an SEO page. One source of truth.

// Derived straight from the patterns (the same derivation lib/capability-stats.mjs uses), because
// this file ships in the OSS package and capability-stats does not.
import { SECRET_PATTERNS } from "../patterns.mjs";
const KEY_FORMATS = SECRET_PATTERNS.length;
export const VULNS = {
  "supabase-rls": {
    id: "supabase-rls",
    slug: "supabase-rls",
    // ASSERTIVE, because this finding is CONFIRMED, and the evidence line two fields below
    // says exactly why: "An anonymous (logged-out) request to your Supabase API RETURNED ROWS
    // from {location}."
    //
    // It read "Your database MAY BE publicly readable" - a hedge on something xlogs directly
    // observed. That is the mirror of the email-spoofing overclaim and it is the more
    // damaging of the two: this is the flagship CRITICAL finding, and hedging it makes the
    // loudest alarm the scanner can raise sound like a guess. Understating a confirmed
    // exposure is as dishonest as overstating a potential one.
    //
    // Scoped to the table rather than "your database", because the check flags per table and
    // the location line names which one.
    title: "Anyone can read this database table",
    severity: "critical",
    plain:
      "Your database tables can be read by anyone, not just logged-in users. Someone could open your app's data (customer emails, orders, private records) without ever creating an account.",
    whyAi:
      "Supabase only protects a table once you turn on Row Level Security (RLS) and write access rules for it. AI tools frequently build a working app without doing that, so the tables are wide open by default.",
    evidence:
      "An anonymous (logged-out) request to your Supabase API returned rows from {location}. xlogs shows the table and its columns as proof, and never stores the row contents.",
    check:
      "xlogs finds your public Supabase URL and anon key in your app (the same ones your frontend uses), asks the database as an anonymous user which tables it can read, and flags any that return real rows. Read-only: it never writes or deletes.",
    requiredState:
      "Row Level Security is enabled on every table, with policies so a table only returns rows to users allowed to see them; no table returns private data to an anonymous request.",
    fixSteps: [
      "Enable Row Level Security (RLS) on every table, especially {location}",
      "Add a policy per table so only authenticated users can read/write their own rows (keep intentionally-public tables public on purpose)",
      "Re-check that an anonymous request no longer returns private rows",
    ],
    verify:
      "After you deploy the policies, xlogs repeats the same anonymous read test and confirms the table no longer returns data without a login.",
    platforms: ["lovable", "bolt", "base44", "supabase", "v0", "replit"],
  },

  "exposed-secret": {
    id: "exposed-secret",
    slug: "exposed-api-keys",
    title: "A secret key is exposed",
    severity: "critical",
    plain:
      "A password-like key that is supposed to stay private is sitting in your app where other people can find it. Anyone who copies it can act as you: run up bills, read your data, or send email in your name.",
    whyAi:
      "AI coding tools often paste an API key straight into a file to make something work, instead of hiding it in a private environment variable. It runs fine, so nothing warns you.",
    evidence:
      "The key was found at {location}. If it also appears in your live site's JavaScript, anyone visiting your app can read it from their browser.",
    check:
      // Honest count, DERIVED from lib/patterns.mjs (it was typed as 9 and went stale when the
      // list grew to 12 on 2026-09-30). Inflated check counts are what we criticise rivals for.
      `xlogs scans your live JavaScript against ${KEY_FORMATS} key formats covering Stripe (live, test and webhook secrets), OpenAI, Anthropic, AWS, Google, GitHub, Slack, private key blocks, and Supabase server keys (service_role and sb_secret_).`,
    requiredState:
      "The key is stored only in a server-side secret / environment variable, never in code or the client bundle, and the exposed value has been rotated (regenerated) because the old one is public.",
    fixSteps: [
      "Move the key's value into a server-only environment variable",
      "Remove the literal value from the code and any client-side bundle ({location})",
      "Make sure the .env file is in .gitignore",
      "Rotate (regenerate) the key at the provider, and assume the old one is compromised",
    ],
    verify:
      "After you deploy the fix, xlogs re-scans your live app and your files and confirms the key is no longer present.",
    platforms: ["lovable", "bolt", "replit", "cursor", "v0", "base44", "supabase"],
  },

  "missing-security-headers": {
    id: "missing-security-headers",
    slug: "missing-security-headers",
    title: "Missing safety headers",
    severity: "medium",
    plain:
      "Your site is missing a few standard safety settings that browsers use to block common attacks (like injecting scripts or embedding your site inside a fake one).",
    whyAi:
      "These are set once in your server or host config. AI tools focus on features and usually skip them, because the app looks and works the same without them.",
    evidence: "These protective headers were absent on your homepage response: {location}.",
    check: "xlogs reads your live site's response headers and lists the protective ones that are missing.",
    requiredState:
      "The response includes Content-Security-Policy, Strict-Transport-Security, X-Frame-Options (or a CSP frame-ancestors), X-Content-Type-Options, and Referrer-Policy, with safe values.",
    fixSteps: [
      "Add the missing headers ({location}) in your framework or host config",
      "Use strict-but-safe defaults",
      "Redeploy and confirm they appear",
    ],
    verify: "After you deploy, xlogs re-reads your headers and confirms the missing ones are now present.",
    platforms: ["lovable", "bolt", "replit", "cursor", "v0", "vercel", "netlify"],
  },

  "source-map-exposure": {
    id: "source-map-exposure",
    slug: "source-map-exposure",
    title: "Your original source code is downloadable",
    severity: "high",
    plain:
      "Your app is publicly serving 'source maps': files that let anyone reconstruct your original, unminified code (and any secrets or logic inside it) straight from the browser.",
    whyAi: "Build tools generate source maps to help debugging, and AI-generated setups often ship them to production by accident.",
    evidence: "A public source map was found at {location}.",
    check: "xlogs checks whether your live JavaScript bundles expose their .map files.",
    requiredState: "Production no longer serves .map source-map files publicly.",
    fixSteps: [
      "Turn off source-map generation for production builds (or stop the host serving .map files). This affects {location}",
      "Redeploy",
    ],
    verify: "After you redeploy, xlogs re-checks and confirms the .map files are no longer public.",
    platforms: ["lovable", "bolt", "replit", "cursor", "v0", "vercel", "netlify"],
  },

  "exposed-source": {
    id: "exposed-source",
    slug: "exposed-source-files",
    title: "Private files are being served publicly",
    severity: "critical",
    plain:
      "A file that should never be public, like your .env (which holds secrets) or your .git folder (your whole code history), is downloadable from your live site.",
    whyAi: "A misconfigured host or a bad deploy can expose these. AI setups sometimes deploy the whole project folder, including files that should be ignored.",
    evidence: "This file responded publicly: {location}.",
    check: "xlogs makes a read-only request for a small set of files that must never be public (.env, .git/config).",
    requiredState:
      "Private files (.env, .git) are not downloadable from the live site, and any secret that was in an exposed .env has been rotated.",
    fixSteps: [
      "Stop the host from serving {location} (fix the host config and .gitignore, and keep it out of the deploy output)",
      "Rotate any secret that was in an exposed .env",
    ],
    verify: "After the fix, xlogs re-requests the file and confirms it is no longer public.",
    platforms: ["lovable", "bolt", "replit", "cursor", "v0"],
  },

  "sql-injection": {
    id: "sql-injection",
    slug: "sql-injection",
    title: "Your database queries can be tampered with",
    severity: "high",
    plain:
      "Your app builds database commands by gluing in whatever a user types. A malicious user can type something crafted to read, change, or delete data they should not be able to.",
    whyAi: "AI tools often assemble queries by string concatenation because it is the most direct way to make a feature work, instead of using safe parameterized queries.",
    evidence: "User input reaches a database query unsafely at {location}.",
    check: "xlogs scans your source for database queries built from concatenated or interpolated input.",
    requiredState:
      "Database queries use parameterized / bound values; no query is built by concatenating or interpolating user input.",
    fixSteps: [
      "Rewrite the query at {location} to use parameterized (bound) values or your ORM's safe query builder",
      "Check the rest of the file for the same pattern",
    ],
    verify: "Re-scan after the fix; xlogs confirms the query no longer interpolates user input.",
    platforms: ["cursor", "claude-code", "replit", "bolt"],
  },

  xss: {
    id: "xss",
    slug: "xss",
    title: "Your app can be tricked into running attacker scripts",
    severity: "high",
    plain:
      "Your app puts user-provided content straight onto the page as HTML. An attacker can slip in a script that runs in your visitors' browsers and steals their session or data.",
    whyAi: "AI tools reach for the quickest way to render content (like innerHTML or dangerouslySetInnerHTML) without sanitizing it first.",
    evidence: "Unsanitized dynamic content is written to the page at {location}.",
    check: "xlogs scans your source for HTML sinks (dangerouslySetInnerHTML, innerHTML, document.write) fed dynamic input.",
    requiredState: "User-provided content is rendered as text, or sanitized with a vetted library before being inserted as HTML.",
    fixSteps: [
      "At {location}, render the content as text where possible",
      "Where HTML is genuinely needed, sanitize the input with a vetted library (e.g. DOMPurify) before inserting it",
    ],
    verify: "Re-scan after the fix; xlogs confirms the unsafe HTML sink is gone.",
    platforms: ["cursor", "claude-code", "v0", "bolt", "lovable"],
  },

  "subdomain-takeover": {
    id: "subdomain-takeover",
    slug: "subdomain-takeover",
    title: "Someone else could take over your subdomain",
    severity: "high",
    plain:
      "One of your DNS records points at a service that is no longer there. Anyone who claims that spot can put their own content on your address, and to a visitor it will look like your site.",
    whyAi:
      "It usually happens after a change of plan: you deploy a preview or move a site to another host, delete the old project, and forget the DNS record still pointing at it. The record keeps working right up until someone else claims the empty spot.",
    evidence: "The DNS for {location} points at a target that is unclaimed or no longer resolves.",
    check:
      "xlogs reads your public DNS. A CNAME pointing at a hosting provider is completely normal and is not reported. It is only flagged when the target does not resolve at all, or the provider itself answers that nothing is claimed there.",
    requiredState:
      "Every DNS record either points at a service you still control, or is removed.",
    fixSteps: [
      "In your DNS settings, find the record for {location}",
      "If you still want that address, re-claim it at the provider it points to so it is yours again",
      "If you no longer use it, delete the DNS record entirely",
    ],
    verify: "After you update DNS, xlogs re-checks the record and confirms it no longer points at an unclaimed target.",
    platforms: ["vercel", "netlify", "lovable", "replit", "bolt"],
  },

  "compromised-cdn": {
    id: "compromised-cdn",
    slug: "compromised-cdn-script",
    title: "Your site loads a script from a compromised CDN",
    severity: "high",
    plain:
      "Your page pulls JavaScript from a domain that has been publicly documented serving malicious code to the sites that use it. That script runs with full access to your page: it can read what your users type and send them anywhere.",
    whyAi:
      "These CDN links come from copy-pasted snippets and old tutorials, and AI tools trained on that same material reproduce them. The link worked for years, then the domain changed hands, and nothing on your side changed to warn you.",
    evidence: "Your page loads a script from {location}, which is publicly documented as compromised.",
    check:
      "xlogs lists every third-party domain your page loads scripts from and compares them against a short list of domains with publicly documented supply-chain attacks, each with a citable source. Unknown domains are never flagged, only listed, so this check cannot false-positive on an ordinary CDN.",
    requiredState:
      "No script on the page loads from a domain with a documented compromise.",
    fixSteps: [
      "Find the <script> tag that loads from {location} and remove it",
      "If you still need what it provided, self-host the file or load it from a maintained CDN, and check whether you need it at all (most polyfills are unnecessary in modern browsers)",
      "Add a Content-Security-Policy script-src directive so only domains you chose can run scripts on your page",
    ],
    verify: "Re-scan after removing the tag. The finding clears when no script loads from a documented-compromised domain.",
    platforms: ["lovable", "bolt", "v0", "replit", "cursor"],
  },

  "missing-subresource-integrity": {
    id: "missing-subresource-integrity",
    slug: "missing-subresource-integrity",
    title: "A pinned CDN file loads without an integrity hash",
    severity: "low",
    plain:
      "Your page loads a fixed version of a library from a public CDN without an integrity attribute. The browser runs whatever that URL returns. With the hash in place, it refuses a file that changed.",
    whyAi: "Snippets copied from a library's README usually include the CDN URL but not the integrity hash, and AI tools reproduce the snippet as they saw it.",
    evidence: "These pinned CDN files load without an integrity attribute: {location}.",
    check:
      "xlogs reads the script and stylesheet tags in the HTML your homepage already served. It only counts files whose URL names an exact version on jsDelivr, unpkg or cdnjs, because only those can carry a stable hash. Loaders that change on purpose (a payment SDK, an analytics tag, @latest) are never listed.",
    requiredState:
      "Every version-pinned file loaded from a public CDN carries an integrity attribute (and crossorigin=\"anonymous\").",
    fixSteps: [
      "For each file listed at {location}, copy the SRI hash the CDN publishes for that exact version (jsDelivr and cdnjs show it beside the file)",
      "Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" to the tag",
      "Or self-host the file, so no third party can change it",
    ],
    verify: "Re-scan after deploying. The finding clears when every pinned CDN file carries an integrity attribute.",
    platforms: ["lovable", "bolt", "v0", "replit", "cursor"],
  },

  "email-spoofing": {
    id: "email-spoofing",
    slug: "email-spoofing",
    // HEDGED, because this finding is classified POTENTIAL.
    //
    // It read "Anyone can send email that looks like it is from you" - a flat assertion of
    // capability sitting directly above a POTENTIAL badge, above evidence that said "this
    // domain does not appear to receive mail, so the risk is spoofing only". The confidence
    // label exists precisely to separate what we OBSERVED from what is merely possible, and
    // the headline was overriding it.
    //
    // The house pattern was already correct next door: subdomain-takeover, also potential,
    // reads "Someone else COULD take over your subdomain". This now matches it.
    title: "Someone could send email that looks like it is from you",
    severity: "medium",
    plain:
      "Your domain is missing the records that tell the world which servers may send email as you. Without them, someone could send a convincing email from your address, and your real messages are also more likely to land in spam.",
    whyAi:
      "These are DNS settings, not app code, so no build tool sets them up. If you wired an email service into your app, it likely told you to add them and it is easy to skip that step once the emails start sending.",
    evidence: "Your domain is missing: {location}.",
    check:
      "xlogs reads your domain's public DNS for an SPF record and a DMARC record. It skips this entirely on platform subdomains, because those records belong to the platform and you cannot change them.",
    requiredState:
      "The domain publishes an SPF record listing who may send for it, and a DMARC record telling receivers what to do with mail that fails.",
    fixSteps: [
      "Add the {location} record(s) at your DNS provider",
      "If you send email through a service, use the exact SPF value it gives you",
      "Start DMARC at p=none to observe, then tighten to quarantine or reject once your legitimate mail passes",
    ],
    verify: "After DNS updates, xlogs re-reads the records and confirms they are published.",
    platforms: ["vercel", "netlify", "resend", "supabase"],
  },

  "insecure-token-storage": {
    id: "insecure-token-storage",
    slug: "insecure-token-storage",
    title: "An auth token is kept in browser storage",
    severity: "low",
    plain:
      "Your app writes what looks like a login token to localStorage or sessionStorage. Anything there can be read by any script on the page, including one injected through a bug or a third-party dependency, and it stays after the tab closes.",
    whyAi: "AI tools reach for localStorage because it is the simplest thing that works; the safer place, an httpOnly cookie the browser will not let scripts read, takes a little more setup.",
    evidence: "A token-shaped key is written to browser storage at {location}.",
    check: "xlogs reads the JavaScript your app already served and looks for a write to localStorage or sessionStorage under a credential-shaped key. It never runs the code and never reads the stored value. Documented auth-library session stores are excluded, because those are the library default rather than your choice.",
    requiredState:
      "Session and access tokens are kept in an httpOnly, Secure cookie the browser will not expose to JavaScript, not in localStorage or sessionStorage.",
    fixSteps: [
      "At {location}, stop writing the token to localStorage or sessionStorage",
      "Have your server set it as an httpOnly, Secure, SameSite cookie instead",
      "Read it server-side from the cookie rather than from client JavaScript",
    ],
    verify: "After you deploy, xlogs re-reads your served JavaScript and confirms the token is no longer written to browser storage.",
    platforms: ["lovable", "bolt", "replit", "cursor", "v0", "base44", "polsia"],
  },

  "dependency-lockfile-exposure": {
    id: "dependency-lockfile-exposure",
    slug: "dependency-lockfile-exposure",
    title: "Your dependency list is downloadable",
    severity: "low",
    plain:
      "Your site serves package-lock.json, the file that lists every package your app was built with and its exact version. It holds no secret, but it tells anyone which known vulnerabilities to try, without guessing.",
    whyAi: "AI builders often deploy the whole project folder, or a static host publishes the repository root, so files meant for the build step end up on the public site.",
    evidence: "The lockfile is served at {location}.",
    check: "xlogs requests /package-lock.json once (never on a stack-only scan) and requires the response to actually be an npm lockfile, not just a 200. When it is, the exact versions it states are looked up in the public OSV advisory database. This check sends nothing else to your site.",
    requiredState:
      "Build files such as package.json and package-lock.json are not in the folder your host publishes.",
    fixSteps: [
      "Stop publishing the project root: serve only your build output folder (dist, build, out or .next)",
      "Remove {location} from the deployed files and redeploy",
      "Upgrade any package the scan named with an advisory, starting with those that ship to users",
    ],
    verify: "After you redeploy, xlogs requests /package-lock.json again and confirms it is no longer served.",
    platforms: ["replit", "bolt", "lovable", "cursor", "v0"],
  },

  "broken-auth": {
    id: "broken-auth",
    slug: "broken-authentication",
    title: "Your login or access checks may be weak",
    severity: "high",
    plain:
      "Something about how your app checks who is logged in (or what they are allowed to do) looks unsafe: for example, an API route with no login check, or a token that is not properly verified.",
    whyAi: "Getting auth exactly right is fiddly, and AI tools often produce something that logs a user in but skips the guard rails that keep other users out.",
    evidence: "An authentication / authorization weakness was found at {location}.",
    check: "On a live scan, xlogs reads the cookies your homepage response sets and flags session cookies missing Secure or HttpOnly - passively, from the response a normal visit already receives. With source access (the CLI), it also looks for missing auth checks on mutating routes and unverified tokens (JWT alg:none).",
    requiredState:
      "Protected routes verify the user is authenticated AND authorized before acting; tokens are verified with a pinned algorithm; session cookies use httpOnly, secure, and sameSite.",
    fixSteps: [
      "At {location}, add a check that the user is logged in AND allowed to perform the action before it does anything",
      "Verify any token's signature and pin the allowed algorithm (never accept 'none')",
      "Set httpOnly, secure, and sameSite on session cookies",
    ],
    verify: "After the fix, xlogs re-checks that the weakness is resolved.",
    platforms: ["lovable", "bolt", "replit", "cursor", "v0", "claude-code"],
  },
};

// CWE + OWASP Top 10 (2021) identifiers, kept in their own map so the security truth
// above stays readable. These are labels for people who want them (and for SARIF /
// GitHub code scanning); they are NOT a compliance product and we never imply one.
//
// A null cwe is deliberate and honest: subdomain takeover has no well-fitting CWE, and
// forcing a wrong identifier to fill the field would be worse than leaving it empty.
export const TAXONOMY = {
  "supabase-rls": { cwe: "CWE-284", cweName: "Improper Access Control", owasp: "A01:2021 Broken Access Control" },
  "exposed-secret": { cwe: "CWE-798", cweName: "Use of Hard-coded Credentials", owasp: "A07:2021 Identification and Authentication Failures" },
  "missing-security-headers": { cwe: "CWE-693", cweName: "Protection Mechanism Failure", owasp: "A05:2021 Security Misconfiguration" },
  "source-map-exposure": { cwe: "CWE-540", cweName: "Inclusion of Sensitive Information in Source Code", owasp: "A05:2021 Security Misconfiguration" },
  "exposed-source": { cwe: "CWE-538", cweName: "Sensitive Information in an Externally-Accessible File", owasp: "A05:2021 Security Misconfiguration" },
  "subdomain-takeover": { cwe: null, cweName: null, owasp: "A05:2021 Security Misconfiguration" },
  "compromised-cdn": { cwe: "CWE-829", cweName: "Inclusion of Functionality from Untrusted Control Sphere", owasp: "A08:2021 Software and Data Integrity Failures" },
  "email-spoofing": { cwe: "CWE-290", cweName: "Authentication Bypass by Spoofing", owasp: "A05:2021 Security Misconfiguration" },
  "sql-injection": { cwe: "CWE-89", cweName: "SQL Injection", owasp: "A03:2021 Injection" },
  xss: { cwe: "CWE-79", cweName: "Cross-site Scripting", owasp: "A03:2021 Injection" },
  "broken-auth": { cwe: "CWE-287", cweName: "Improper Authentication", owasp: "A07:2021 Identification and Authentication Failures" },
  "dependency-lockfile-exposure": { cwe: "CWE-538", cweName: "Sensitive Information in an Externally-Accessible File", owasp: "A06:2021 Vulnerable and Outdated Components" },
  "missing-subresource-integrity": { cwe: "CWE-353", cweName: "Missing Support for Integrity Check", owasp: "A08:2021 Software and Data Integrity Failures" },
  "insecure-token-storage": { cwe: "CWE-922", cweName: "Insecure Storage of Sensitive Information", owasp: "A04:2021 Insecure Design" },
};

export function taxonomyFor(id) {
  return TAXONOMY[id] || { cwe: null, cweName: null, owasp: null };
}

// Map a scanner finding category/kind to a knowledge entry id.
export const CATEGORY_MAP = {
  "committed-secret": "exposed-secret",
  "client-exposed-secret": "exposed-secret",
  "exposed-secret": "exposed-secret",
  "sql-injection": "sql-injection",
  xss: "xss",
  "source-map": "source-map-exposure",
  "exposed-path": "exposed-source",
  "missing-header": "missing-security-headers",
  "jwt-alg-none": "broken-auth",
  "nextjs-unauth-route": "broken-auth",
  "insecure-cookie": "broken-auth",
  "csrf-disabled": "broken-auth",
  "supabase-rls": "supabase-rls",
  "subdomain-takeover": "subdomain-takeover",
  "compromised-cdn": "compromised-cdn",
  "email-spoofing": "email-spoofing",
  "insecure-storage": "insecure-token-storage",
  "exposed-lockfile": "dependency-lockfile-exposure",
  "missing-sri": "missing-subresource-integrity",
};

export function vulnForCategory(category) {
  if (!category) return null;
  const id = CATEGORY_MAP[category];
  return id ? VULNS[id] : null;
}

export function vulnBySlug(slug) {
  return Object.values(VULNS).find((v) => v.slug === slug) || null;
}
