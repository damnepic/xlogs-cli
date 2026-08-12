// Platform fingerprint (XL-056) — which AI builder shipped this app, and where it is
// hosted, inferred ONLY from signals the app already serves publicly.
//
// Doctrine notes:
//  - Every detection records the SIGNAL that produced it, so a claim is never an
//    unexplained guess. If we cannot say why, we do not say it.
//  - Builder and host are separate questions. "Hosted on Vercel" is not "built with v0".
//  - Unknown is a first-class answer. We never guess a builder to fill the field.
//
// This also unblocks INV-01 (per-generator defect index): the fingerprint is the
// dimension that aggregate finding counts would be grouped by.

// Builder signatures. `host` matches the deployed hostname; `mark` matches anything in
// the served HTML/JS. Keep these NARROW: a false builder attribution is a wrong claim.
const BUILDERS = [
  {
    id: "lovable",
    label: "Lovable",
    host: [/\.lovable\.app$/i, /\.lovableproject\.com$/i],
    // Lovable injects the GPT Engineer tagger script into generated apps.
    mark: [/cdn\.gpteng\.co/i, /gptengineer\.js/i, /lovable-tagger/i],
  },
  {
    id: "bolt",
    label: "Bolt",
    host: [/\.bolt\.host$/i, /\.bolt\.new$/i],
    mark: [/bolt\.new\//i],
  },
  {
    id: "replit",
    label: "Replit",
    host: [/\.replit\.app$/i, /\.replit\.dev$/i, /\.repl\.co$/i],
    mark: [/replit-dev-banner/i, /__replco/i],
  },
  {
    id: "base44",
    label: "Base44",
    host: [/\.base44\.app$/i],
    mark: [/base44\.app\//i],
  },
  {
    id: "v0",
    label: "v0",
    host: [/\.v0\.dev$/i, /\.v0\.app$/i],
    mark: [/v0\.dev\//i],
  },
];

// Hosts are a separate, usually higher-confidence signal (response headers).
const HOSTS = [
  { id: "vercel", label: "Vercel", header: "x-vercel-id" },
  { id: "netlify", label: "Netlify", header: "x-nf-request-id" },
  { id: "cloudflare", label: "Cloudflare", header: "cf-ray" },
  { id: "fly", label: "Fly.io", header: "fly-request-id" },
  { id: "render", label: "Render", header: "x-render-origin-server" },
];

// Backends worth naming when the app clearly talks to them.
const BACKENDS = [
  { id: "supabase", label: "Supabase", mark: [/[a-z0-9-]+\.supabase\.co/i] },
  { id: "firebase", label: "Firebase", mark: [/firebaseio\.com/i, /firebaseapp\.com/i, /firebase\.googleapis\.com/i] },
  { id: "stripe", label: "Stripe", mark: [/js\.stripe\.com/i] },
  { id: "clerk", label: "Clerk", mark: [/clerk\.[a-z.]+\/npm/i, /clerk\.accounts\.dev/i] },
];

function hostnameOf(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

/**
 * @param {string} url        the final scanned URL
 * @param {object} headers    response headers of the root document (lowercased keys)
 * @param {string} text       concatenated served HTML + JS
 * @returns {{builder, host, backends, signals}}
 */
export function fingerprint(url, headers = {}, text = "") {
  const hostname = hostnameOf(url);
  const signals = [];

  let builder = null;
  for (const b of BUILDERS) {
    const hostHit = (b.host || []).find((re) => re.test(hostname));
    if (hostHit) {
      builder = { id: b.id, label: b.label, confidence: "high" };
      signals.push(`hostname matches ${b.label} (${hostname})`);
      break;
    }
  }
  if (!builder) {
    for (const b of BUILDERS) {
      const markHit = (b.mark || []).find((re) => re.test(text));
      if (markHit) {
        // A build marker in shipped code is good evidence, but an app can be moved to a
        // custom domain, so we report it as medium rather than high.
        builder = { id: b.id, label: b.label, confidence: "medium" };
        signals.push(`${b.label} build marker found in the served code`);
        break;
      }
    }
  }

  let host = null;
  for (const h of HOSTS) {
    if (headers[h.header]) {
      host = { id: h.id, label: h.label, confidence: "high" };
      signals.push(`${h.label} response header (${h.header})`);
      break;
    }
  }

  const backends = [];
  for (const s of BACKENDS) {
    if ((s.mark || []).some((re) => re.test(text))) {
      backends.push({ id: s.id, label: s.label });
      signals.push(`${s.label} referenced in the served code`);
    }
  }

  return { builder, host, backends, signals };
}
