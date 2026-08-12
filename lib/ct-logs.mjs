// Certificate Transparency discovery (XL-022) — surface other addresses on your domain
// that you may have forgotten are public: an old staging deploy, a preview branch, an
// admin subdomain nobody remembers.
//
// Every certificate issued for a public domain is logged publicly. We read that log.
// It is public data about the user's own domain, no scanning of the hosts involved.
//
// HONESTY CONSTRAINTS (these are why the feature is inventory, not a finding):
//  - A certificate log proves a certificate was ISSUED, not that a host is live, nor
//    that it is misconfigured. We do not probe the hosts, and we say so.
//  - Nothing here is a vulnerability, so it carries no severity and raises no alarm.
//  - Skipped on platform subdomains: querying the log for "vercel.app" would return a
//    vast list belonging to other people and tell the user nothing about their own app.

// Source: Cert Spotter (sslmate). Chosen over crt.sh after measuring both: crt.sh
// returned HTTP 502 on repeated attempts while Cert Spotter answered in ~0.35s. The
// timeout is deliberately tight, because a slow third party must never be allowed to
// dominate a scan that promises results in seconds. On timeout we report inconclusive.
const CT_ENDPOINT = "https://api.certspotter.com/v1/issuances";
const CT_TIMEOUT_MS = 4000;
const MAX_NAMES = 12;

// Same platform list as the DNS checks: an app at my-thing.vercel.app does not own
// vercel.app, so its certificate log is neither theirs nor useful.
const PLATFORM_SUFFIXES = [
  "vercel.app", "netlify.app", "lovable.app", "lovableproject.com", "bolt.host",
  "replit.app", "replit.dev", "repl.co", "base44.app", "v0.dev", "v0.app",
  "pages.dev", "workers.dev", "github.io", "herokuapp.com", "onrender.com",
  "fly.dev", "web.app", "firebaseapp.com", "surge.sh", "glitch.me", "streamlit.app",
];

function isPlatform(hostname) {
  const h = hostname.toLowerCase();
  return PLATFORM_SUFFIXES.find((s) => h === s || h.endsWith("." + s)) || null;
}

function apexOf(hostname) {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const twoLevel = /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/i;
  if (twoLevel.test(parts.slice(-2).join("."))) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

// Names that are noise rather than "a thing you forgot": the apex itself, wildcards,
// and the host we are already scanning.
function isInteresting(name, apex, scanned) {
  const n = name.toLowerCase().trim();
  if (!n || n.startsWith("*")) return false;
  if (n === apex || n === scanned) return false;
  if (n === "www." + apex) return false; // www is not a forgotten deploy
  if (!n.endsWith("." + apex)) return false;
  return true;
}

/**
 * @param {string} hostname the scanned hostname
 * @returns {{status:string, apex?:string, names?:string[], truncated?:number, reason?:string}}
 */
export async function discoverFromCtLogs(hostname) {
  const platform = isPlatform(hostname);
  if (platform) {
    return { status: "n/a", reason: `${hostname} is a ${platform} subdomain, so its certificate log belongs to ${platform} and would not tell you about your own app.` };
  }
  if (!hostname.includes(".") || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return { status: "n/a", reason: "This target is an IP address or a local name, so it has no certificate log." };
  }

  const apex = apexOf(hostname);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), CT_TIMEOUT_MS);
  try {
    const url = `${CT_ENDPOINT}?domain=${encodeURIComponent(apex)}&include_subdomains=true&expand=dns_names`;
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "user-agent": "xlogs/0.1 (+read-only security probe)", accept: "application/json" },
    });
    if (!res.ok) return { status: "inconclusive", apex, reason: `The public certificate log did not answer (HTTP ${res.status}), so this was not checked.` };
    const rows = await res.json();
    if (!Array.isArray(rows)) return { status: "inconclusive", apex, reason: "The public certificate log returned an unexpected response." };

    const set = new Set();
    for (const r of rows) {
      for (const raw of r?.dns_names || []) {
        const n = String(raw).toLowerCase().trim();
        if (isInteresting(n, apex, hostname)) set.add(n);
      }
    }
    const all = [...set].sort();
    return {
      status: all.length ? "found" : "clear",
      apex,
      names: all.slice(0, MAX_NAMES),
      truncated: Math.max(0, all.length - MAX_NAMES),
      total: all.length,
    };
  } catch (e) {
    // A timeout or network failure is INCONCLUSIVE, never a silent pass.
    return { status: "inconclusive", apex, reason: "The public certificate log did not respond in time, so this was not checked." };
  } finally {
    clearTimeout(t);
  }
}
