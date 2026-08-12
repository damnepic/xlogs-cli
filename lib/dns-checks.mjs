// DNS checks: dangling CNAME / subdomain takeover (XL-023) and email spoofing
// protection (XL-024). Both are public DNS reads, no writes, no exploitation.
//
// SEVERITY MUST BE EARNED. Subdomain-takeover checks are notorious for false positives,
// so this module is deliberately conservative:
//
//  - A CNAME pointing at a hosting provider is NORMAL, not a finding. Every Vercel and
//    Netlify site has one. We only flag when there is real evidence the target is
//    unclaimed: either the CNAME target does not resolve at all (dangling), or the
//    provider serves its own documented "nothing is here" fingerprint.
//  - Email records are only checked on a domain the user plausibly CONTROLS. Reporting
//    a missing SPF record on someone-else's-platform.app is noise the user cannot act
//    on, so platform subdomains are reported as not-applicable with the reason.

import dns from "node:dns/promises";

const DNS_TIMEOUT_MS = 5000;

// Hosting platforms whose subdomains are NOT the user's to configure. An app at
// my-thing.vercel.app cannot set SPF for vercel.app, so email checks do not apply.
const PLATFORM_SUFFIXES = [
  "vercel.app", "netlify.app", "lovable.app", "lovableproject.com", "bolt.host",
  "replit.app", "replit.dev", "repl.co", "base44.app", "v0.dev", "v0.app",
  "pages.dev", "workers.dev", "github.io", "herokuapp.com", "onrender.com",
  "fly.dev", "web.app", "firebaseapp.com", "surge.sh", "glitch.me", "streamlit.app",
];

// Documented "this subdomain is not claimed" fingerprints. We require BOTH that the
// CNAME points at the provider AND that the response carries the fingerprint, so a
// normal, healthy site on the same provider is never flagged.
const TAKEOVER_SIGNATURES = [
  { provider: "GitHub Pages", cname: /\.github\.io$/i, body: /There isn't a GitHub Pages site here/i },
  { provider: "Heroku", cname: /\.herokudns\.com$|\.herokuapp\.com$/i, body: /No such app/i },
  { provider: "Amazon S3", cname: /\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$/i, body: /NoSuchBucket/i },
  { provider: "Shopify", cname: /\.myshopify\.com$/i, body: /Sorry, this shop is currently unavailable/i },
  { provider: "Fastly", cname: /\.fastly(lb)?\.net$/i, body: /Fastly error: unknown domain/i },
  { provider: "Surge.sh", cname: /\.surge\.sh$/i, body: /project not found/i },
  { provider: "Bitbucket", cname: /\.bitbucket\.io$/i, body: /Repository not found/i },
  { provider: "Ghost", cname: /\.ghost\.io$/i, body: /Domain error/i },
  { provider: "Webflow", cname: /\.proxy-ssl\.webflow\.com$|\.webflow\.io$/i, body: /The page you are looking for doesn't exist or has been moved/i },
];

function withTimeout(p, ms) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("dns timeout")), ms))]);
}
async function tryDns(fn) {
  try { return await withTimeout(fn(), DNS_TIMEOUT_MS); } catch { return null; }
}

function isPlatformSubdomain(hostname) {
  const h = hostname.toLowerCase();
  return PLATFORM_SUFFIXES.find((s) => h === s || h.endsWith("." + s)) || null;
}

// An IP literal or a dotless host (localhost, an internal name) has no domain to own,
// so neither DNS check is meaningful. Saying "not applicable" is the honest answer;
// running the check anyway would invent a finding nobody can act on.
function isNotADomain(hostname) {
  const h = (hostname || "").toLowerCase();
  if (!h || !h.includes(".")) return true;                  // localhost, internal names
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;        // IPv4 literal
  if (h.includes(":") || h.startsWith("[")) return true;     // IPv6 literal
  return false;
}

// Best-effort registrable domain. Without a public-suffix list this is an approximation,
// so we only use it to decide WHERE to look for email records, never to make a claim.
function apexOf(hostname) {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const twoLevel = /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/i;
  const last3 = parts.slice(-3).join(".");
  if (twoLevel.test(parts.slice(-2).join("."))) return last3;
  return parts.slice(-2).join(".");
}

/**
 * Dangling CNAME / subdomain takeover.
 * @param {string} hostname
 * @param {(url:string)=>Promise<{ok:boolean,status:number,body:string}>} fetchText
 *        the live layer's own fetcher, so this stays inside the SSRF-guarded path.
 */
export async function checkDanglingCname(hostname, fetchText) {
  const out = { status: "clear", cname: null, provider: null, evidence: null };
  if (isNotADomain(hostname)) { out.status = "n/a"; out.reason = "This target is an IP address or a local name, so it has no DNS record to dangle."; return out; }
  const chain = await tryDns(() => dns.resolveCname(hostname));
  if (!chain || !chain.length) return out; // no CNAME at all: nothing to dangle
  const target = chain[0];
  out.cname = target;

  // Does the CNAME target resolve? If it does not, the record points at nothing.
  const addrs = await tryDns(() => dns.resolve4(target).catch(() => dns.resolve6(target)));
  if (!addrs || !addrs.length) {
    out.status = "found";
    out.evidence = `Your DNS points ${hostname} at ${target}, but ${target} does not resolve to any address. The name is claimable by whoever registers it next.`;
    return out;
  }

  // It resolves. Only flag if the provider itself says the subdomain is unclaimed.
  const sig = TAKEOVER_SIGNATURES.find((s) => s.cname.test(target));
  if (!sig) return out; // normal CNAME to a provider we do not have a signature for: NOT a finding
  const res = await fetchText(`https://${hostname}/`).catch(() => null);
  if (res && res.body && sig.body.test(res.body)) {
    out.status = "found";
    out.provider = sig.provider;
    out.evidence = `${hostname} points at ${sig.provider} (${target}), and ${sig.provider} responds that no site is claimed there. Someone else can claim that name and serve content on your domain.`;
  }
  return out;
}

/**
 * Email spoofing protection (SPF / DMARC), checked only where the user can act.
 */
export async function checkEmailRecords(hostname) {
  if (isNotADomain(hostname)) {
    return { status: "n/a", reason: "This target is an IP address or a local name, so it has no domain to publish email records for.", missing: [] };
  }
  const platform = isPlatformSubdomain(hostname);
  if (platform) {
    return { status: "n/a", reason: `${hostname} is a ${platform} subdomain, so its email records belong to ${platform}, not to you.`, missing: [] };
  }
  const apex = apexOf(hostname);
  const [txt, dmarc, mx] = await Promise.all([
    tryDns(() => dns.resolveTxt(apex)),
    tryDns(() => dns.resolveTxt(`_dmarc.${apex}`)),
    tryDns(() => dns.resolveMx(apex)),
  ]);
  const flat = (recs) => (recs || []).map((r) => (Array.isArray(r) ? r.join("") : String(r)));
  const hasSpf = flat(txt).some((v) => /^v=spf1/i.test(v.trim()));
  const hasDmarc = flat(dmarc).some((v) => /^v=DMARC1/i.test(v.trim()));

  const missing = [];
  if (!hasSpf) missing.push("SPF");
  if (!hasDmarc) missing.push("DMARC");

  return {
    status: missing.length ? "found" : "clear",
    apex,
    hasSpf,
    hasDmarc,
    receivesMail: !!(mx && mx.length),
    missing,
    // DKIM is deliberately NOT checked: its record lives at a selector name only the
    // domain owner knows (e.g. resend._domainkey), so we cannot test it without
    // guessing, and a guess that comes back empty would be a false alarm.
  };
}
