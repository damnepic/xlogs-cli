// Backend Surface Map (INV-03) — from the ONE pasted URL, enumerate every backend
// origin the deployed app actually contacts, from code the app already serves.
//
// This is enterprise attack-surface management inverted: instead of paying a crawler to
// enumerate a company's assets from outside, we read one app's own shipped bundle and
// report the surface it reaches for. Free, instant, anonymous, and nothing stored.
//
// Strictly read-only and derived from text already in memory (the bundles the secrets
// check downloaded), so it costs no extra fetches to build the inventory.

// Hosts that are analytics/CDN/font furniture rather than "backends this app talks to".
// Kept explicit so the map stays about YOUR surface, not the whole internet.
import { isDocExampleHost } from "./doc-examples.mjs";

const FURNITURE = [
  /^fonts\.(googleapis|gstatic)\.com$/i,
  /^www\.w3\.org$/i,
  /^schema\.org$/i,
  /^(www\.)?gravatar\.com$/i,
  /\.(png|jpg|jpeg|svg|gif|webp|ico|css|woff2?)$/i,
];

// Recognisable categories, so a non-engineer can read the map.
const CATEGORY = [
  [/\.supabase\.co$/i, "Database (Supabase)"],
  [/firebaseio\.com$|firebaseapp\.com$/i, "Database (Firebase)"],
  [/\.stripe\.com$/i, "Payments (Stripe)"],
  [/\.openai\.com$|\.anthropic\.com$/i, "AI provider"],
  [/\.googleapis\.com$/i, "Google API"],
  [/\.amazonaws\.com$/i, "AWS"],
  [/posthog|mixpanel|segment|amplitude|plausible|google-analytics|googletagmanager/i, "Analytics"],
  [/sentry\.io$|bugsnag/i, "Error tracking"],
  [/clerk|auth0\.com$|okta\.com$/i, "Authentication"],
  [/resend\.com$|sendgrid|postmark|mailgun/i, "Email"],
];

function categorise(hostname) {
  for (const [re, label] of CATEGORY) if (re.test(hostname)) return label;
  // An api.* / *-api host is a service even if we do not recognise the vendor.
  if (/^api\./i.test(hostname) || /(^|\.)api[.-]/i.test(hostname)) return "API endpoint";
  return null; // not recognised as a service — see the honesty note in extractOrigins
}

/**
 * Extract distinct third-party origins referenced by the app's own served code.
 * @param {string} text     concatenated HTML + JS the scanner already fetched
 * @param {string} selfUrl  the scanned URL, so we exclude the app's own origin
 * @param {number} max      cap, so a huge bundle cannot produce an unreadable list
 */
export function extractOrigins(text, selfUrl, max = 20) {
  let selfHost = "";
  try { selfHost = new URL(selfUrl).hostname.toLowerCase(); } catch {}

  const counts = new Map();
  for (const m of String(text || "").matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi)) {
    const host = m[1].toLowerCase();
    if (!host || host === selfHost) continue;
    // same registrable-ish suffix (api.myapp.com when scanning myapp.com) is still "ours"
    if (selfHost && (host.endsWith("." + selfHost) || selfHost.endsWith("." + host))) continue;
    if (FURNITURE.some((re) => re.test(host))) continue;
    if (isDocExampleHost(host)) continue; // a documentation example, not this app's backend (2026-10-06)
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) continue; // bare IPs are usually placeholders
    counts.set(host, (counts.get(host) || 0) + 1);
  }

  // HONESTY CONSTRAINT: we read code, we do not execute it, so we cannot prove the app
  // actually calls a hostname it mentions. A documentation link (nextjs.org, react.dev)
  // is not a backend. Reporting those as "services your app talks to" would be exactly
  // the kind of padded inventory we criticise rivals for. So we report only origins we
  // can categorise as a real service, and the UI still says "references", not "calls".
  return [...counts.entries()]
    .map(([host, refs]) => ({ host, refs, category: categorise(host) }))
    .filter((o) => o.category !== null)
    .sort((a, b) => b.refs - a.refs)
    .slice(0, max);
}
