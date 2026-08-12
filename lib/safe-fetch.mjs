// SSRF-hardened fetch for a public URL scanner. The input-URL check in ssrf.mjs is
// necessary but NOT sufficient: a public hostname can RESOLVE to a private IP, or a
// public URL can REDIRECT to an internal one (cloud metadata at 169.254.169.254, a
// router at 192.168.x, etc). So every fetch here:
//   1) resolves the host and refuses if any resolved IP is private/loopback/link-local
//   2) follows redirects MANUALLY, re-validating each hop the same way
// This is used for every outbound request the scan makes (root page, JS bundles,
// exposed-path probes, and the Supabase API derived from the app's bundle).

import dns from "node:dns/promises";
import net from "node:net";

function ip4Private(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true; // malformed -> block
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
  if (a === 192 && b === 168) return true; // 192.168/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a >= 224) return true; // multicast + reserved
  return false;
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return ip4Private(ip);
  if (net.isIPv6(ip)) {
    const low = ip.toLowerCase();
    if (low === "::1" || low === "::") return true;
    if (low.startsWith("fe80") || low.startsWith("fc") || low.startsWith("fd")) return true;
    const m = /::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(low); // IPv4-mapped
    if (m) return ip4Private(m[1]);
    return false;
  }
  return true; // not an IP literal -> block (defensive)
}

// Test-only escape hatch so the suite can scan a loopback mock server. Read at call
// time. Defaults OFF; NEVER set XLOGS_ALLOW_PRIVATE in production — it disables the
// SSRF guard's private-IP block.
const allowPrivate = () => process.env.XLOGS_ALLOW_PRIVATE === "1";

export async function assertPublicHost(hostname) {
  const h = (hostname || "").replace(/^\[|\]$/g, "");
  let ips;
  if (net.isIP(h)) ips = [h];
  else {
    try { ips = (await dns.lookup(h, { all: true })).map((r) => r.address); }
    catch { throw new Error("Could not resolve that host."); }
  }
  if (!ips.length) throw new Error("That host did not resolve.");
  if (!allowPrivate()) for (const ip of ips) if (isPrivateIp(ip)) throw new Error("Refusing to scan a private or internal address.");
  return ips;
}

// fetch with per-hop SSRF validation. Throws if any hop targets a private address.
export async function safeFetch(urlStr, opts = {}) {
  let current = urlStr;
  for (let hop = 0; hop < 6; hop++) {
    const u = new URL(current);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http and https can be scanned.");
    await assertPublicHost(u.hostname);
    const res = await fetch(current, { ...opts, redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return res;
      current = new URL(loc, current).toString(); // validate the next hop on the next loop
      continue;
    }
    return res;
  }
  throw new Error("Too many redirects.");
}
