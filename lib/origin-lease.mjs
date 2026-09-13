// A per-origin ceiling that is GLOBAL, not per instance.
//
// lib/concurrency.mjs bounds outbound fan-out inside one process. On Vercel that leaves a
// real gap, and it was recorded rather than hidden: with N concurrent serverless instances
// the true ceiling is (N x PER_ORIGIN). A victim does not care how many of our processes
// were involved, so "bounded per instance" is not the property worth claiming.
//
// This closes it with a distributed lease held in the KV store every instance already
// shares.
//
// WHY LEASES ARE TAKEN PER SCAN, NOT PER REQUEST
//
// The obvious design puts the distributed check on every outbound request, matching the
// in-process semaphore. Measured against the real pipeline, one scan makes 47 outbound
// requests, so that would add ~94 KV round-trips per scan. That cost is not paid by the
// attacker, it is paid by every ordinary user, and doctrine here is that the free scan
// stays genuinely usable.
//
// So the two controls are layered by what each is good at:
//   in-process semaphore -> bounds FAN-OUT within one scan            (free, exact)
//   distributed lease    -> bounds SCANS of one origin across instances (2 round-trips)
//
// Global outbound concurrency toward one victim is therefore bounded by
// MAX_SCANS_PER_ORIGIN x LIMITS.PER_ORIGIN = 2 x 4 = 8, for any number of clients,
// instances or regions. Eight, stated exactly, not "four" and not "unbounded".
//
// FAILS OPEN, deliberately. If KV is unreachable the scan proceeds under the in-process
// ceiling alone, degrading to exactly today's behaviour rather than taking the product
// down. This is a courtesy-to-third-parties control, not a security boundary; the SSRF
// guards are the boundary and they never fail open.

import { randomUUID } from "node:crypto";
import { originKeyOf } from "./concurrency.mjs";

export const MAX_SCANS_PER_ORIGIN = 2;

// How long a lease survives without being released. Any instance that crashes, is frozen
// mid-scan or is reaped by the platform would otherwise hold a slot forever; the TTL is
// what makes a leaked slot self-healing. Set above the scan timeout so a slow-but-alive
// scan is never evicted while it is still working.
export const LEASE_TTL_MS = 90_000;

const KV_URL = process.env.KV_REST_API_URL || "";
const KV_TOKEN = process.env.KV_REST_API_TOKEN || "";

// LEASE IDENTITY. Every holder must be a DISTINCT member of the sorted set, or ZADD
// overwrites an existing entry instead of adding one and the ceiling silently disappears.
//
// The first version used `${pid}-${Date.now()}-${counter++}`. The counter is module state,
// so it restarts at 0 in every instance: ten instances booting in the same millisecond
// produced ten IDENTICAL member names, the set held one entry, and everyone ranked 0. The
// distributed test caught it before it shipped. Cross-instance uniqueness cannot be built
// out of per-instance state, so it comes from the CSPRNG.
const leaseId = () => randomUUID();

/** Default transport: one HTTP round-trip for a whole command pipeline. */
async function upstashPipeline(commands) {
  const res = await fetch(KV_URL.replace(/\/$/, "") + "/pipeline", {
    method: "POST",
    headers: { authorization: `Bearer ${KV_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(commands),
  });
  if (!res.ok) throw new Error(`kv ${res.status}`);
  return res.json();
}

// Injectable so the property can be tested deterministically against an in-memory Redis,
// rather than only being asserted in prose. See test/origin-lease.test.mjs.
let transport = null;
export function __setTransport(fn) { transport = fn; }
export function leaseEnabled() { return Boolean(transport || (KV_URL && KV_TOKEN)); }

function send(commands) {
  return (transport || upstashPipeline)(commands);
}

/**
 * THE ACQUIRE SCRIPT. Purge expired leases, count what is left, and take a slot only if
 * there is room, all inside ONE server-side execution.
 *
 * WHY A SCRIPT AND NOT A PIPELINE OF PRIMITIVES.
 *
 * The first version avoided a script with the classic "write first, then ask your rank"
 * trick: ZADD yourself, then ZRANK, and hold a slot if rank < max. That is genuinely
 * race-free only when scores are unique and monotonic. Ours are millisecond timestamps,
 * and under load many acquisitions land in the SAME millisecond. Redis then breaks ties
 * lexicographically by member, and the members are random UUIDs, so a LATER arrival can
 * rank below an earlier one that already returned held. Measured in the distributed test:
 * four callers to a ceiling of two, three of them believed they held a slot.
 *
 * A pipeline cannot fix this, because no command in a pipeline can branch on the result of
 * an earlier one. Check-then-act needs to happen where the data is. Hence EVAL: it is
 * atomic by definition, it does not depend on tie-break order at all, and it is still a
 * single round-trip.
 */
const ACQUIRE = [
  "local key = KEYS[1]",
  "redis.call('ZREMRANGEBYSCORE', key, 0, ARGV[1])",   // expired leases are freed first
  "redis.call('PEXPIRE', key, ARGV[5])",                // idle origins leave nothing behind
  "if redis.call('ZCARD', key) < tonumber(ARGV[2]) then",
  "  redis.call('ZADD', key, ARGV[3], ARGV[4])",
  "  return 1",
  "end",
  "return 0",
].join("\n");

/**
 * Acquire a global slot for `target`.
 *
 * @returns {Promise<{held: boolean, release: () => Promise<void>, reason?: string}>}
 *          held=false means the origin is at its global ceiling; the caller should refuse
 *          rather than proceed, so back-pressure is never mistaken for a completed scan.
 */
export async function acquireOriginLease(target, max = MAX_SCANS_PER_ORIGIN) {
  if (!leaseEnabled()) return { held: true, release: async () => {}, reason: "disabled" };

  const key = `xlogs:lease:${originKeyOf(target)}`;
  const now = Date.now();
  const id = leaseId();

  try {
    const out = await send([
      ["EVAL", ACQUIRE, "1", key,
        String(now - LEASE_TTL_MS),   // ARGV[1] purge threshold
        String(max),                  // ARGV[2] ceiling
        String(now),                  // ARGV[3] our score
        id,                           // ARGV[4] our member
        String(LEASE_TTL_MS * 2)],    // ARGV[5] key TTL
    ]);
    // STRICTLY, not coerced. `Number(null)` is 0, so a store returning nulls would have
    // read as "refused" and blocked every scan on the very failure this is meant to
    // survive. Only an explicit 1 or 0 is an answer; anything else is a malfunction.
    const raw = out?.[0]?.result;
    const granted = raw === 1 || raw === "1" ? 1 : raw === 0 || raw === "0" ? 0 : null;
    if (granted === null) return { held: true, release: async () => {}, reason: "bad-reply" }; // fail open
    if (granted === 0) return { held: false, release: async () => {}, reason: "origin-busy" };

    return { held: true, release: async () => { try { await send([["ZREM", key, id]]); } catch {} } };
  } catch {
    return { held: true, release: async () => {}, reason: "kv-unavailable" }; // fail open
  }
}
