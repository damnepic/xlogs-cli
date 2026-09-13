// Outbound concurrency control.
//
// THE PROPERTY THIS EXISTS FOR:
//   No number of independent xlogs users can cause outbound concurrency toward a single
//   target to exceed that target's configured ceiling.
//
// Per-IP rate limiting does not give you this. The dangerous scenario is not one abusive
// client sending 1,000 scans; it is 1,000 *different* clients all scanning the same
// victim origin. Source diversity is the attacker's tool, so the target needs a budget
// of its own that is independent of who asked.
//
// It also matters that the unit is the FAN-OUT, not the request. One scan fetches the
// page, then up to 25 same-origin bundles, source maps, exposed-path probes and the
// Supabase API. So "10 concurrent scans" can mean hundreds of victim-facing sockets
// unless the limit sits on the outbound connection itself.
//
// Four independent controls, each protecting a different party:
//   GLOBAL      protects xlogs' own infrastructure from total overload
//   PER-ORIGIN  protects the scanned site from us
//   PER-CLIENT  protects xlogs from one abusive caller
//   SINGLE-FLIGHT  collapses identical concurrent work so N callers asking for the same
//                  scan produce ONE outbound scan, not N
//
// These are in-process. That is a real limitation on serverless and it is stated rather
// than papered over: each instance enforces its own ceiling, so the effective global
// limit is (instances x GLOBAL). The per-origin ceiling still bounds a single instance's
// fan-out, and the KV rate limiter remains the cross-instance control. A truly global
// ceiling needs a shared semaphore; see the note at the bottom.

export const LIMITS = {
  GLOBAL: 24,        // outbound requests in flight from this instance, all targets
  PER_ORIGIN: 4,     // outbound requests in flight toward ONE origin, all callers
  PER_CLIENT: 8,     // outbound requests in flight on behalf of one client
  QUEUE_WAIT_MS: 15000, // how long a request waits for a slot before giving up
};

// A tiny FIFO semaphore. Deliberately not a library: this must be readable, because a
// subtle bug here silently removes a security control.
class Semaphore {
  constructor(max) { this.max = max; this.active = 0; this.waiters = []; }
  async acquire(timeoutMs) {
    if (this.active < this.max) { this.active++; return true; }
    return new Promise((resolve) => {
      const waiter = { resolve, timer: null };
      waiter.timer = setTimeout(() => {
        const i = this.waiters.indexOf(waiter);
        if (i !== -1) this.waiters.splice(i, 1);
        resolve(false); // timed out waiting for a slot
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }
  release() {
    const next = this.waiters.shift();
    if (next) { clearTimeout(next.timer); next.resolve(true); return; } // hand the slot over
    this.active = Math.max(0, this.active - 1);
  }
  get inFlight() { return this.active; }
  get queued() { return this.waiters.length; }
}

const global_ = new Semaphore(LIMITS.GLOBAL);
const perOrigin = new Map(); // originKey -> Semaphore
const perClient = new Map(); // clientKey -> Semaphore

function semFor(map, key, max) {
  let s = map.get(key);
  if (!s) { s = new Semaphore(max); map.set(key, s); }
  return s;
}

/**
 * THE TARGET IDENTITY MODEL.
 *
 * The per-origin ceiling is only meaningful if an attacker cannot dodge it by varying
 * the spelling of the URL. Two requests are "the same target" when they reach the same
 * service, so the key is scheme + host + port, with the host lowercased, a trailing
 * root dot removed, IPv6 brackets normalised, and default ports folded in.
 *
 * Deliberately NOT folded together: http vs https (genuinely different services), and
 * different ports (also different services). Those are separate budgets on purpose,
 * which is the same distinction the badge cache-key fix made.
 *
 * Known limitation, stated: two DIFFERENT hostnames resolving to one IP get separate
 * budgets. Keying on the resolved IP would close that, but it would also collapse every
 * site behind a shared CDN address into one budget and throttle unrelated victims
 * together. Hostname is the honest unit for a scanner; the global ceiling is the
 * backstop for the IP-level case.
 */
export function originKeyOf(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return "invalid"; }
  let host = u.hostname.toLowerCase();
  if (host.endsWith(".") && host.length > 1) host = host.slice(0, -1); // trailing root dot
  host = host.replace(/^\[|\]$/g, "");                                  // IPv6 brackets
  const scheme = u.protocol.replace(":", "");
  const port = u.port || (scheme === "https" ? "443" : "80");           // fold default ports
  return `${scheme}://${host}:${port}`;
}

/**
 * Run `fn` while holding a slot in all three ceilings. Acquires in a fixed order
 * (global, origin, client) so concurrent callers cannot deadlock each other, and
 * releases in every path including throws.
 *
 * @returns {Promise<any>} whatever fn returns
 * @throws {Error} with .code = "CONCURRENCY_TIMEOUT" if a slot never came free
 */
export async function withSlot(target, clientKey, fn) {
  const oKey = originKeyOf(target);
  const cKey = clientKey || "anon";
  const oSem = semFor(perOrigin, oKey, LIMITS.PER_ORIGIN);
  const cSem = semFor(perClient, cKey, LIMITS.PER_CLIENT);

  const held = [];
  const fail = (which) => {
    for (const s of held) s.release();
    const e = new Error(`Too many scans in flight (${which}). Please retry shortly.`);
    e.code = "CONCURRENCY_TIMEOUT";
    e.which = which;
    throw e;
  };

  if (!(await global_.acquire(LIMITS.QUEUE_WAIT_MS))) fail("global");
  held.push(global_);
  if (!(await oSem.acquire(LIMITS.QUEUE_WAIT_MS))) fail("origin");
  held.push(oSem);
  if (!(await cSem.acquire(LIMITS.QUEUE_WAIT_MS))) fail("client");
  held.push(cSem);

  try {
    return await fn();
  } finally {
    for (const s of held) s.release();
    if (oSem.inFlight === 0 && oSem.queued === 0) perOrigin.delete(oKey); // bound map growth
    if (cSem.inFlight === 0 && cSem.queued === 0) perClient.delete(cKey);
  }
}

// ---- SINGLE FLIGHT --------------------------------------------------------
// 100 people asking for a scan of the same URL at the same moment should produce ONE
// outbound scan and 100 shared answers, not 100 scan trees aimed at one victim. This is
// the control that most directly stops xlogs being used to concentrate traffic.
const inFlightScans = new Map(); // key -> Promise

export function coalesce(key, fn) {
  const existing = inFlightScans.get(key);
  if (existing) return existing;
  const p = (async () => fn())().finally(() => inFlightScans.delete(key));
  inFlightScans.set(key, p);
  return p;
}

/** Introspection for tests and diagnostics. Never used for control flow. */
export function stats() {
  return {
    globalInFlight: global_.inFlight,
    globalQueued: global_.queued,
    origins: [...perOrigin.entries()].map(([k, s]) => ({ origin: k, inFlight: s.inFlight, queued: s.queued })),
    clients: [...perClient.entries()].map(([k, s]) => ({ client: k, inFlight: s.inFlight, queued: s.queued })),
    coalescing: inFlightScans.size,
  };
}

// Test-only: reset all state between cases.
export function __resetForTests() {
  global_.active = 0; global_.waiters.length = 0;
  perOrigin.clear(); perClient.clear(); inFlightScans.clear();
}

// SCOPE, and where the rest of the answer lives. These semaphores are per process: on
// Vercel each concurrent instance holds its own, so on their own they bound fan-out
// WITHIN one scan and nothing more.
//
// The cross-instance half is lib/origin-lease.mjs, which holds a distributed lease in KV
// allowing MAX_SCANS_PER_ORIGIN concurrent scans of one origin across every instance. The
// two compose, and the resulting global claim is exact:
//
//   outbound concurrency toward one victim <= MAX_SCANS_PER_ORIGIN x PER_ORIGIN = 2 x 4 = 8
//
// for any number of clients, instances or regions. Eight, not four, and not "unbounded".
// The lease fails open, so if KV is unreachable this file's per-instance ceiling is what
// remains in force.
