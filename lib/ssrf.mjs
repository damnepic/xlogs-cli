// Guard for a hosted scanner that fetches user-submitted URLs. We only ever want to
// scan public web apps, never our own internal network or cloud metadata. This blocks
// obvious private / loopback / link-local targets and non-http(s) schemes.
//
// Note: this is a pragmatic MVP guard, not DNS-rebinding-proof. A hardened version would
// resolve the host and re-check the resolved IP at fetch time. Flagged as a TODO.

const PRIVATE_HOST = [
  /^localhost$/i,
  /\.local$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./, // link-local + cloud metadata (169.254.169.254)
  /^0\./,
  /^::1$/,
  /^\[?::1\]?$/,
  /^fe80:/i,
  /^fc00:/i,
  /^fd[0-9a-f]{2}:/i,
];
// 172.16.0.0 - 172.31.255.255
function is172Private(host) {
  const m = /^172\.(\d{1,3})\./.exec(host);
  return m && Number(m[1]) >= 16 && Number(m[1]) <= 31;
}

export function normalizeAndValidate(input) {
  let raw = String(input || "").trim();
  if (!raw) return { ok: false, reason: "Enter your app's URL." };
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  let u;
  try { u = new URL(raw); } catch { return { ok: false, reason: "That does not look like a valid URL." }; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, reason: "Only http and https URLs can be scanned." };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (!host.includes(".") && !host.includes(":")) return { ok: false, reason: "Enter a full domain, like myapp.com." };
  if (PRIVATE_HOST.some((re) => re.test(host)) || is172Private(host)) {
    return { ok: false, reason: "For safety, xlogs only scans public web addresses (not local or private ones)." };
  }
  return { ok: true, url: u.toString() };
}
