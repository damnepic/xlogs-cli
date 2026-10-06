// SSRF-hardened fetch for a public URL scanner.
//
// THREE layers, because each one alone is insufficient:
//   1) ssrf.mjs rejects obviously-private literals and non-http(s) protocols.
//   2) assertPublicHost resolves the hostname and refuses if ANY returned A/AAAA
//      record is private, loopback, link-local or metadata.
//   3) THE SOCKET IS PINNED to an address we validated in step 2.
//
// Layer 3 is the one that closes DNS rebinding, and it is why this file no longer uses
// global fetch(). The previous implementation did:
//
//     await assertPublicHost(u.hostname);   // our lookup: public -> passes
//     await fetch(current, ...);            // undici's OWN lookup: could be 127.0.0.1
//
// Two independent resolutions means the IP we validated is not guaranteed to be the IP
// we connect to. An attacker who controls DNS for their own domain answers "public" to
// the first lookup and "127.0.0.1" to the second (a short TTL is enough), and the
// scanner connects to loopback with validation already satisfied. That is a real
// time-of-check/time-of-use bug, not a theoretical one.
//
// The fix: resolve once, validate every returned address, then hand node:http(s) a
// custom `lookup` that can ONLY return one of those validated addresses. The socket
// therefore connects to a checked IP by construction. TLS still uses the real hostname
// for SNI and certificate validation, so pinning does not weaken HTTPS.
//
// node:http(s) is used rather than undici's Agent because xlogs ships zero runtime
// dependencies and undici is not importable as a built-in.

import dns from "node:dns/promises";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import { Readable } from "node:stream";

// Response limits. Every one of these exists because the response is attacker
// controlled: the site being scanned chooses its own size, encoding and pacing.
//
// MAX_COMPRESSED is what we accept off the wire. MAX_BODY is what we accept AFTER
// decompression, and it is the one that stops a compression bomb: a few hundred KB of
// gzip can expand to hundreds of MB, so bounding the download alone is not enough.
// The decompressor is told the limit directly so it aborts mid-stream rather than
// after the memory is already committed.
export const MAX_COMPRESSED_BYTES = 8 * 1024 * 1024;  // 8MB off the wire
export const MAX_BODY_BYTES = 10 * 1024 * 1024;       // 10MB after decompression
const BODY_TIMEOUT_MS = 20000;                        // reading the body cannot hang forever

// TIME IS ALSO ATTACKER CONTROLLED. The scanned site chooses the PACING of its response,
// not only its size, and slow-response exhaustion costs the attacker nothing: a server that
// accepts the connection and then dribbles bytes ties up a real outbound slot indefinitely.
// With GLOBAL = 24 slots, 24 parked sockets deny service to every other user on no
// bandwidth at all.
//
// THE KEY DISTINCTION: an idle timeout is NOT a deadline. A server sending one byte every
// (idle - 1) seconds resets an idle timer forever and is never disconnected. Only wall
// clock terminates a trickle, so REQUEST_DEADLINE_MS bounds the WHOLE call including
// connect, TLS, headers, body and every redirect hop. Measured before this existed: a
// silent server held safeFetch open past 120 seconds, until the test runner was killed.
//
// The socket idle timeout below is defence in depth that frees dead connections sooner. It
// is not the guarantee; the deadline is.
export const REQUEST_DEADLINE_MS = 25000;
const SOCKET_IDLE_MS = 10000;

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

// IPv6 TO ITS 16 BYTES, so an embedded IPv4 can be judged as the IPv4 it is.
//
// THE BYPASS THIS CLOSES, reproduced 2026-09-02 against a loopback listener: safeFetch of
// http://[::ffff:127.0.0.1]:PORT/ returned 200 from 127.0.0.1 with XLOGS_ALLOW_PRIVATE unset.
// The old guard matched the DOTTED mapped form "::ffff:1.2.3.4" with a regex, but the URL parser
// serialises that literal to the HEX form "::ffff:7f00:1" before the guard ever sees it, so the
// regex never matched and the address fell through to "return false". The same hole reached
// loopback via a 30x redirect from an attacker's domain, which is the shape that matters for a
// scanner that follows redirects on behalf of anyone.
//
// The fix is structural rather than another regex: parse to bytes, then classify every known
// IPv4-embedding layout by the bytes it embeds. Mapped (::ffff:a.b.c.d), SIIT (::ffff:0:a.b.c.d),
// compat (::a.b.c.d), NAT64 (64:ff9b::a.b.c.d) and 6to4 (2002:AABB:CCDD::) all carry an IPv4 that
// decides whether the destination is private. Anything that fails to parse is refused, because a
// literal we cannot read is not one we should connect to.
function ipv6Bytes(ip) {
  let s = String(ip).toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  // A trailing dotted quad becomes two hex groups.
  const dq = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (dq) {
    const [a, b, c, d] = dq.slice(1).map(Number);
    if ([a, b, c, d].some((n) => n > 255)) return null;
    s = s.slice(0, dq.index) + ((a << 8) | b).toString(16) + ":" + ((c << 8) | d).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16);
    out.push(n >> 8, n & 0xff);
  }
  return out;
}

function embeddedIpv4(bytes) {
  const dotted = (o) => `${bytes[o]}.${bytes[o + 1]}.${bytes[o + 2]}.${bytes[o + 3]}`;
  const zero = (from, to) => bytes.slice(from, to).every((b) => b === 0);
  // ::ffff:a.b.c.d (mapped) and ::ffff:0:a.b.c.d (SIIT)
  if (zero(0, 10) && bytes[10] === 0xff && bytes[11] === 0xff) return dotted(12);
  if (zero(0, 8) && bytes[8] === 0xff && bytes[9] === 0xff && zero(10, 12)) return dotted(12);
  // ::a.b.c.d (deprecated compat)
  if (zero(0, 12)) return dotted(12);
  // 64:ff9b::/96 (NAT64 well-known prefix)
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zero(4, 12)) return dotted(12);
  // 2002:AABB:CCDD::/16 (6to4): the IPv4 is bytes 2..5
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return dotted(2);
  return null;
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return ip4Private(ip);
  if (net.isIPv6(ip)) {
    const bytes = ipv6Bytes(ip);
    if (!bytes) return true; // unparseable literal: refuse
    // Unspecified and loopback.
    if (bytes.every((b) => b === 0)) return true;
    if (bytes.slice(0, 15).every((b) => b === 0) && bytes[15] === 1) return true;
    // Link-local fe80::/10 and unique-local fc00::/7.
    if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
    if ((bytes[0] & 0xfe) === 0xfc) return true;
    // Any layout that embeds an IPv4 is judged as that IPv4.
    const v4 = embeddedIpv4(bytes);
    if (v4) return ip4Private(v4);
    return false;
  }
  return true; // not an IP literal -> block (defensive)
}

// Test-only escape hatch so the suite can scan a loopback mock server. Read at call
// time. Defaults OFF; NEVER set XLOGS_ALLOW_PRIVATE in production.
const allowPrivate = () => process.env.XLOGS_ALLOW_PRIVATE === "1";

/** Resolve a hostname and refuse unless EVERY returned address is public. */
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

const MAX_REDIRECTS = 6;

/**
 * One request to an already-validated destination, with the socket pinned.
 * @param {URL} u
 * @param {string[]} validatedIps addresses returned by assertPublicHost for u.hostname
 */
function requestPinned(u, validatedIps, opts, deadlineAt) {
  return new Promise((resolve, reject) => {
    const isHttps = u.protocol === "https:";
    const lib = isHttps ? https : http;

    // THE PIN. node:net calls this instead of the system resolver, so the connection
    // can only go to an address we already checked. A rebinding answer never reaches
    // the socket because the socket never asks DNS again.
    const pinnedLookup = (hostname, options, cb) => {
      const ip = validatedIps.find((a) => (options?.family === 6 ? net.isIPv6(a) : options?.family === 4 ? net.isIPv4(a) : true));
      if (!ip) return cb(new Error("No validated address available for this host."));
      // Defence in depth: re-check immediately before handing the address over.
      if (!allowPrivate() && isPrivateIp(ip)) return cb(new Error("Refusing to connect to a private address."));
      const family = net.isIPv6(ip) ? 6 : 4;
      // Node calls lookup with { all: true } on newer versions and then expects an
      // array; returning the 3-arg form there fails with ERR_INVALID_IP_ADDRESS.
      if (options?.all) return cb(null, [{ address: ip, family }]);
      cb(null, ip, family);
    };

    const req = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,          // used for Host header, SNI and cert validation
        port: u.port || (isHttps ? 443 : 80),
        path: u.pathname + u.search,
        method: opts.method || "GET",
        // fetch() sent this automatically. Without it we download uncompressed bodies,
        // and any server that compresses anyway would hand us bytes we cannot read.
        headers: { "accept-encoding": "gzip, deflate, br", ...(opts.headers || {}) },
        lookup: pinnedLookup,
        servername: net.isIP(u.hostname) ? undefined : u.hostname, // keep TLS honest
        // NO SHARED AGENT, for two reasons that both matter here.
        //
        // Resources: Node 19+ enables keepAlive on the global agent, so a completed request
        // hands its socket back to a pool and holds it open. For a scanner that connects to
        // arbitrary attacker-chosen hosts, that means lingering file descriptors to servers
        // picked by the attacker. A one-off agent closes the connection when the response
        // ends. (Timed-out requests were already torn down correctly; req.destroy() does
        // destroy the socket. That was verified directly rather than assumed, after a test
        // fixture with a paused server socket made it look otherwise.)
        //
        // Pinning: a pooled socket is reused WITHOUT calling lookup, so a connection we
        // believe is pinned would not have been pinned by this request. The destination is
        // the same validated address today, but "the check ran" and "the check ran for this
        // request" should not be allowed to drift apart in the one place that closes
        // rebinding.
        agent: false,
      },
      (res) => {
        // Record what we actually connected to, so tests can assert the pin held.
        const connectedTo = res.socket?.remoteAddress || null;
        resolve({ res, connectedTo });
      }
    );

    req.on("error", reject);

    // THE DEADLINE, applied to the connect-and-headers phase. Without it a server that
    // accepts the socket and says nothing holds this promise open forever, because header
    // parsing never begins and the body timeout further down never gets a chance to run.
    const left = Math.max(0, deadlineAt - Date.now());
    const deadline = setTimeout(() => {
      req.destroy(new Error("The server took too long to send a response."));
    }, left);
    const clear = () => clearTimeout(deadline);
    req.on("response", clear);
    req.on("error", clear);
    req.on("close", clear);

    // Idle timeout as well, so an abandoned connection is released early rather than held
    // for the full deadline. Defence in depth: it does nothing against a trickle.
    req.setTimeout(SOCKET_IDLE_MS, () => {
      req.destroy(new Error("The connection went idle."));
    });

    if (opts.signal) {
      if (opts.signal.aborted) { clear(); req.destroy(new Error("Aborted")); return; }
      opts.signal.addEventListener("abort", () => req.destroy(new Error("Aborted")), { once: true });
    }
    req.end();
  });
}

/**
 * Read a response body with HARD bounds on both the compressed and decompressed sizes,
 * decompressing as we go.
 *
 * Why this exists: global fetch() (undici) transparently decompressed gzip/deflate/br,
 * so replacing it with node:http silently broke content reading. A gzipped page would
 * be scanned as compressed bytes and every finding missed, which for a security scanner
 * means confidently reporting "clean" on a vulnerable site. That is the functional half.
 *
 * The security half: undici's transparent decompression had NO size limit, so this path
 * was always bomb-vulnerable. Restoring decompression without a bound would restore the
 * hole, so the limit is enforced INSIDE the decompressor (maxOutputLength) and again on
 * the accumulated buffer. Both the socket and the decompressor are destroyed the moment
 * either cap is crossed, rather than after the memory is committed.
 *
 * @returns {Promise<Buffer>} the decoded body, truncated at MAX_BODY_BYTES
 */
function readBodyBounded(nodeRes, deadlineAt) {
  return new Promise((resolve) => {
    // Encoding handling FAILS CLOSED. A single known token is decoded; anything else
    // (a stacked "gzip, br", an unknown token, an empty-but-present header) is reported
    // as unreadable rather than passed through as if it were text.
    //
    // This matters because the identity fall-through was a silent wrong answer: with
    // "gzip, br" we handed 66 bytes of compressed garbage to the scanner, which found
    // no secrets in it and called the site clean.
    const rawEnc = String(nodeRes.headers["content-encoding"] || "").toLowerCase().trim();
    const SUPPORTED = { gzip: 1, "x-gzip": 1, deflate: 1, br: 1, identity: 1, "": 1 };
    const unsupported = !(rawEnc in SUPPORTED);

    const make = rawEnc === "gzip" || rawEnc === "x-gzip" ? () => zlib.createGunzip({ maxOutputLength: MAX_BODY_BYTES })
      : rawEnc === "deflate" ? () => zlib.createInflate({ maxOutputLength: MAX_BODY_BYTES })
      : rawEnc === "br" ? () => zlib.createBrotliDecompress({ maxOutputLength: MAX_BODY_BYTES })
      : null;

    if (unsupported) {
      try { nodeRes.destroy(); } catch {}
      return resolve({ buf: Buffer.alloc(0), status: "unsupported-encoding", reason: `Content-Encoding "${rawEnc}" is not one we decode.`, encoding: rawEnc || null, transferBytes: 0 });
    }

    const chunks = [];
    let decoded = 0;
    let raw = 0;
    let done = false;
    let sawEnd = false;      // the response stream ended normally
    let sinkEnded = false;   // the decompressor flushed cleanly

    // finish(status) records WHY the read stopped. "ok" is only reachable when the
    // transport ended AND (if compressed) the decompressor flushed without error.
    const finish = (status, reason) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { nodeRes.destroy(); } catch {}
      // `encoding` and `raw` ride out with the body (XL-098). The header is deleted further down
      // because the buffer is decoded, so this is the only place the negotiated encoding and the
      // number of bytes that actually crossed the wire survive.
      resolve({ buf: Buffer.concat(chunks), status, reason: reason || "", encoding: rawEnc || null, transferBytes: raw });
    };
    // Whichever is sooner: the body budget, or what is left of the WHOLE-CALL deadline.
    // Taking only the body budget would let slow headers plus a slow body add up past the
    // deadline, which is exactly the arithmetic a slow-response attack relies on.
    const budget = Math.max(0, Math.min(BODY_TIMEOUT_MS, deadlineAt - Date.now()));
    const timer = setTimeout(() => finish("timeout", "The response body did not finish in time."), budget);

    const sink = make ? make() : null;
    if (sink) {
      sink.on("data", (c) => {
        decoded += c.length;
        if (decoded > MAX_BODY_BYTES) { try { sink.destroy(); } catch {} return finish("oversized", "The decompressed response exceeded the size limit."); }
        chunks.push(c);
      });
      // A bomb trips maxOutputLength here; a TRUNCATED or corrupt stream also errors
      // here. Both are reported, never silently treated as a complete read.
      sink.on("error", (e) => finish(
        e?.code === "ERR_BUFFER_TOO_LARGE" ? "oversized" : "decode-error",
        e?.code === "ERR_BUFFER_TOO_LARGE" ? "The decompressed response exceeded the size limit." : "The compressed response was truncated or corrupt."
      ));
      sink.on("end", () => { sinkEnded = true; finish(sawEnd ? "ok" : "truncated", sawEnd ? "" : "The connection closed before the response finished."); });
    }

    nodeRes.on("data", (c) => {
      raw += c.length;
      if (raw > MAX_COMPRESSED_BYTES) {
        if (sink) { try { sink.destroy(); } catch {} }
        return finish("oversized", "The response exceeded the download size limit.");
      }
      if (sink) { if (!sink.write(c)) nodeRes.pause(), sink.once("drain", () => nodeRes.resume()); }
      else {
        decoded += c.length;
        if (decoded > MAX_BODY_BYTES) return finish("oversized", "The response exceeded the size limit.");
        chunks.push(c);
      }
    });
    nodeRes.on("end", () => { sawEnd = true; if (sink) sink.end(); else finish("ok"); });
    // A socket that dies mid-body is a partial read, not a complete one.
    nodeRes.on("error", (e) => finish("truncated", `The connection failed while reading the response (${e?.code || "error"}).`));
    nodeRes.on("aborted", () => finish("truncated", "The connection was aborted before the response finished."));
  });
}

/**
 * fetch-compatible response. Callers use .ok, .status, .headers, .body.getReader(),
 * .text() and .url, so those are what we provide.
 */
function toResponse(nodeRes, finalUrl, connectedTo, body) {
  const headers = new Headers();
  for (const [k, v] of Object.entries(nodeRes.headers)) {
    if (Array.isArray(v)) v.forEach((one) => headers.append(k, one));
    else if (v !== undefined) headers.set(k, v);
  }
  // The body is already decoded, so drop the encoding header: leaving it would tell a
  // consumer to decode bytes that are no longer encoded.
  headers.delete("content-encoding");
  // ...but the fact that it WAS encoded is not lost, because that is a measurement of what the
  // deployment served (XL-098). It goes on the response as its own property, where nothing can
  // mistake it for a live instruction to decode.
  headers.delete("content-length");
  const out = new Response(body.buf, { status: nodeRes.statusCode, headers });
  Object.defineProperty(out, "url", { value: finalUrl });
  // Surfaced for the SSRF regression test: the address the socket actually used.
  Object.defineProperty(out, "connectedTo", { value: connectedTo });
  // THE INVARIANT CARRIER. "ok" only when the body was fully received and cleanly
  // decoded. Callers must treat anything else as "we did not see all of this", never
  // as an empty-but-complete document.
  Object.defineProperty(out, "bodyStatus", { value: body.status });
  Object.defineProperty(out, "bodyReason", { value: body.reason });
  // The encoding the server negotiated, and the bytes that actually crossed the wire before
  // decoding. Both measured, both otherwise unrecoverable once the header is dropped above.
  Object.defineProperty(out, "contentEncoding", { value: body.encoding || null });
  Object.defineProperty(out, "transferBytes", { value: Number.isFinite(body.transferBytes) ? body.transferBytes : null });
  Object.defineProperty(out, "bodyComplete", { value: body.status === "ok" });
  return out;
}

/**
 * Fetch with per-hop SSRF validation AND socket pinning. Redirects are followed
 * manually so every hop is validated and pinned independently: a redirect can change
 * host, scheme and port, so re-validating only the first URL would be pointless.
 */
export async function safeFetch(urlStr, opts = {}) {
  // READ-ONLY IS ENFORCED HERE, not by convention (XL-269, 2026-09-30). This is the only fetcher
  // that talks to a scanned site, and until now it passed any method through, so doctrine rule 1
  // held only because every caller happened to send GET. A future check that sends a POST, PUT,
  // PATCH or DELETE to a target now fails before a socket opens, with a message naming the rule.
  // A request body is refused for the same reason: GET and HEAD carry none.
  const method = String(opts.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    throw new Error(`safeFetch refuses ${method}: xlogs only reads (GET and HEAD). Doctrine rule 1.`);
  }
  if (opts.body !== undefined && opts.body !== null) {
    throw new Error("safeFetch refuses a request body: xlogs only reads (GET and HEAD). Doctrine rule 1.");
  }
  // ONE deadline for the whole call, fixed before the first connect. Per-hop deadlines
  // would let a redirect chain multiply the bound (five hops at 25s each is 125s), and the
  // redirect target is chosen by the same attacker who controls the pacing.
  const deadlineAt = Date.now() + REQUEST_DEADLINE_MS;
  let current = urlStr;
  for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
    const u = new URL(current);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http and https can be scanned.");

    // Validate THIS hop, then pin the socket to what we validated.
    const validatedIps = await assertPublicHost(u.hostname);
    const { res, connectedTo } = await requestPinned(u, validatedIps, opts, deadlineAt);

    if (res.statusCode >= 300 && res.statusCode < 400) {
      const loc = res.headers.location;
      if (!loc) return toResponse(res, current, connectedTo, await readBodyBounded(res, deadlineAt));
      res.resume(); // drain the redirect body so the socket can be reused/closed
      current = new URL(loc, current).toString(); // next loop validates + pins again
      continue;
    }
    // Bounded read + decode happens BEFORE the caller sees anything, so no caller can
    // forget the limit.
    const body = await readBodyBounded(res, deadlineAt);
    return toResponse(res, current, connectedTo, body);
  }
  throw new Error("Too many redirects.");
}
