// DOMAIN REGISTRATION FACTS (XL-096): how old the domain is, who it is registered through,
// when the registration expires, and whether transfer locks are set.
//
// WHY THIS IS INVENTORY AND NOT A FINDING. None of it is a vulnerability. A domain registered
// last week is not insecure; a domain expiring next month is not a breach. What these facts do is
// answer questions a reader of a security report actually has ("is this the real company's domain
// or a lookalike registered on Tuesday?", "is the thing my whole login flow depends on about to
// lapse?"), and they are MEASURED rather than estimated, which is the only kind of number this
// product ships. They carry no severity and cannot move a verdict.
//
// SOURCE. RDAP, the registries' own successor to WHOIS: a public, keyless, structured JSON
// protocol. We query rdap.org, which redirects to the authoritative registry for the TLD, so the
// answer comes from the registry rather than from a reseller's cache. One request per scan,
// alongside the DNS lookups, with a tight timeout for the same reason the certificate log has
// one: a slow third party must never dominate a scan that promises results in seconds.
//
// WHAT WE DELIBERATELY DO NOT READ. Registrant name, email, address, phone. They are redacted for
// most domains anyway, and collecting the ones that are not would make this a people-search
// feature. We read dates, the registrar's organisation name, and the status flags. Nothing about
// a person.

const RDAP_ENDPOINT = "https://rdap.org/domain/";
// MEASURED, not guessed. rdap.org answers with a redirect to the authoritative registry, so every
// lookup is two round trips. Warm, four domains measured on 2026-09-04 took 0.21s, 0.26s, 0.32s and
// 0.50s; cold, one took 3.0s and a 4s budget cut it off, which turned a working check into a
// permanent "inconclusive" for that domain. 6s clears the cold path with room and still bounds a
// slow third party, which is what the budget is for. This runs in parallel with the DNS and
// certificate lookups, so it only costs wall-clock time when it is the slowest of the three.
const RDAP_TIMEOUT_MS = 6000;

// Same platform list as the DNS and certificate checks, and for the same reason: the registration
// of vercel.app belongs to Vercel. Reporting Vercel's domain age on a user's app would be a fact
// about somebody else, presented as if it were about them.
const PLATFORM_SUFFIXES = [
  "vercel.app", "netlify.app", "lovable.app", "lovableproject.com", "bolt.host",
  "replit.app", "replit.dev", "repl.co", "base44.app", "v0.dev", "v0.app",
  "pages.dev", "workers.dev", "github.io", "herokuapp.com", "onrender.com",
  "fly.dev", "web.app", "firebaseapp.com", "surge.sh", "glitch.me", "streamlit.app",
];

function platformOf(hostname) {
  const h = String(hostname || "").toLowerCase();
  return PLATFORM_SUFFIXES.find((s) => h === s || h.endsWith("." + s)) || null;
}

export function apexOf(hostname) {
  const parts = String(hostname || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const twoLevel = /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/i;
  if (twoLevel.test(parts.slice(-2).join("."))) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

// The registrar is the entity carrying the "registrar" role. Its display name lives in a vCard
// array, which is a nested array format: ["vcard", [["fn", {}, "text", "Example Registrar, LLC"], ...]].
// We read the fn (formatted name) field and nothing else.
export function registrarName(entities) {
  const list = Array.isArray(entities) ? entities : [];
  const reg = list.find((e) => Array.isArray(e?.roles) && e.roles.includes("registrar"));
  if (!reg) return null;
  const card = reg.vcardArray?.[1];
  if (!Array.isArray(card)) return typeof reg.handle === "string" ? reg.handle : null;
  const fn = card.find((f) => Array.isArray(f) && f[0] === "fn");
  const name = fn && typeof fn[3] === "string" ? fn[3].trim() : "";
  return name || (typeof reg.handle === "string" ? reg.handle : null);
}

export function eventDate(events, action) {
  const list = Array.isArray(events) ? events : [];
  const hit = list.find((e) => String(e?.eventAction || "").toLowerCase() === action);
  if (!hit || typeof hit.eventDate !== "string") return null;
  const t = Date.parse(hit.eventDate);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

export function daysBetween(fromIso, toIso) {
  const a = Date.parse(fromIso), b = Date.parse(toIso);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.floor((b - a) / 86400000);
}

// Status flags, kept only where they say something an owner can act on. The registry vocabulary is
// long and mostly internal; these four are the ones that answer "can this domain be taken from me
// quietly?".
const LOCK_LABELS = {
  "client transfer prohibited": "transfer locked",
  "server transfer prohibited": "transfer locked at the registry",
  "client delete prohibited": "delete locked",
  "server delete prohibited": "delete locked at the registry",
  "client update prohibited": "update locked",
  "server update prohibited": "update locked at the registry",
  "pending delete": "PENDING DELETE",
  "redemption period": "in redemption (expired, recoverable)",
  "client hold": "on hold, may not resolve",
  "server hold": "on hold at the registry, may not resolve",
};

export function locksFrom(status) {
  const list = Array.isArray(status) ? status : [];
  const out = [];
  for (const s of list) {
    const label = LOCK_LABELS[String(s || "").toLowerCase()];
    if (label && !out.includes(label)) out.push(label);
  }
  return out;
}

/**
 * @param {string} hostname the scanned hostname
 * @param {{fetchImpl?: Function, now?: number}} [opts]
 * @returns {Promise<object>} { status: "found"|"n/a"|"inconclusive", ... }
 */
export async function lookupDomain(hostname, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const now = opts.now || Date.now();

  const platform = platformOf(hostname);
  if (platform) {
    return { status: "n/a", reason: `${hostname} is a ${platform} subdomain, so its registration belongs to ${platform} rather than to you.` };
  }
  if (!String(hostname || "").includes(".") || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return { status: "n/a", reason: "This target is an IP address or a local name, so it has no domain registration." };
  }

  const apex = apexOf(hostname);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), RDAP_TIMEOUT_MS);
  try {
    const res = await fetchImpl(RDAP_ENDPOINT + encodeURIComponent(apex), {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "user-agent": "xlogs/0.1 (+read-only security probe)", accept: "application/rdap+json, application/json" },
    });
    // 404 is a real answer, not a failure: the registry says there is no such registration.
    if (res.status === 404) {
      return { status: "n/a", apex, reason: `The registry has no registration record for ${apex}.` };
    }
    if (!res.ok) {
      return { status: "inconclusive", apex, reason: `The domain registry did not answer (HTTP ${res.status}), so this was not read.` };
    }
    const j = await res.json();
    if (!j || typeof j !== "object") {
      return { status: "inconclusive", apex, reason: "The domain registry returned an unexpected response." };
    }

    const registeredAt = eventDate(j.events, "registration");
    const expiresAt = eventDate(j.events, "expiration");
    const updatedAt = eventDate(j.events, "last changed");
    const nowIso = new Date(now).toISOString();

    return {
      status: "found",
      apex,
      registrar: registrarName(j.entities),
      registeredAt,
      expiresAt,
      updatedAt,
      // Age and time-to-expiry are DERIVED here rather than in the UI, so every surface that shows
      // them shows the same number computed the same way.
      ageDays: registeredAt ? daysBetween(registeredAt, nowIso) : null,
      daysToExpiry: expiresAt ? daysBetween(nowIso, expiresAt) : null,
      locks: locksFrom(j.status),
      nameservers: Array.isArray(j.nameservers)
        ? j.nameservers.map((n) => String(n?.ldhName || "").toLowerCase()).filter(Boolean).slice(0, 8)
        : [],
      dnssec: typeof j.secureDNS?.delegationSigned === "boolean" ? j.secureDNS.delegationSigned : null,
    };
  } catch {
    return { status: "inconclusive", apex, reason: "The domain registry did not respond in time, so this was not read." };
  } finally {
    clearTimeout(t);
  }
}
