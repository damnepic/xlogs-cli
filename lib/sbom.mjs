// Live SBOM (XL-045): enumerate third-party JS libraries actually shipped to the browser.
//
// This is INVENTORY, not a finding. It carries no severity. It is also, by nature,
// INCOMPLETE: modern bundlers strip library names and versions, so a library can be in
// the bundle with no identifiable marker. We therefore only report what we can identify
// with HIGH confidence, from two reliable signals, and we say plainly that the list is
// not exhaustive. Guessing a version we cannot see would be exactly the kind of
// manufactured claim the doctrine forbids.
//
// Signal 1: a script URL that names the package and version (CDN-hosted).
// Signal 2: a library's own version banner/marker inside a fetched bundle.

// name@version inside a known package CDN path. Handles scoped names (@scope/name).
const CDN_RE = new RegExp(
  "(?:cdn\\.jsdelivr\\.net/npm/|unpkg\\.com/|cdnjs\\.cloudflare\\.com/ajax/libs/|esm\\.sh/|ga\\.jspm\\.io/npm:|skypack\\.dev/)" +
  "((?:@[\\w.-]+/)?[\\w.-]+)@(\\d+\\.\\d+\\.\\d+[\\w.-]*)",
  "gi"
);

// Curated, high-confidence banner/version markers. Each regex captures the version from
// that library's OWN self-identifying string, so a match is not a guess. Kept small and
// specific on purpose; an unrecognised library is simply not listed rather than mislabelled.
const SIGNATURES = [
  { name: "jquery", re: /jQuery\s+(?:JavaScript\s+Library\s+)?v?(\d+\.\d+\.\d+)/i },
  { name: "vue", re: /Vue\.js\s+v(\d+\.\d+\.\d+)/i },
  { name: "bootstrap", re: /Bootstrap\s+v(\d+\.\d+\.\d+)/i },
  { name: "lodash", re: /lodash[\s\S]{0,40}?VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/i },
  { name: "moment", re: /\/\/!\s*moment\.js[\s\S]{0,4000}?version\s*[:=]\s*['"](\d+\.\d+\.\d+)['"]/i },
  { name: "gsap", re: /GSAP\s+(\d+\.\d+\.\d+)/i },
  { name: "swiper", re: /Swiper\s+(\d+\.\d+\.\d+)/i },
  { name: "axios", re: /axios[\s\S]{0,40}?VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/i },
  { name: "alpinejs", re: /Alpine[\s\S]{0,40}?version\s*=\s*['"](\d+\.\d+\.\d+)['"]/i },
  { name: "d3", re: /d3[\s\S]{0,20}?version\s*=\s*['"](\d+\.\d+\.\d+)['"]/i },
];

/**
 * @param {string[]} srcs all <script src> URLs seen in the HTML (any origin)
 * @param {string[]} blobs fetched bundle bodies
 * @returns {{ libraries: Array<{name:string, version:string, source:string}>, note:string }}
 */
export function extractSbom(srcs = [], blobs = []) {
  const seen = new Map(); // name -> { name, version, source }

  for (const url of srcs) {
    let m;
    CDN_RE.lastIndex = 0;
    while ((m = CDN_RE.exec(url))) {
      const name = m[1].toLowerCase();
      if (!seen.has(name)) seen.set(name, { name, version: m[2], source: "cdn" });
    }
  }

  for (const body of blobs) {
    if (!body) continue;
    // Only look at the head of each bundle, where banners and version constants live, to
    // stay fast and avoid deep-scan false positives.
    const head = body.slice(0, 4000);
    for (const sig of SIGNATURES) {
      if (seen.has(sig.name)) continue;
      const m = sig.re.exec(head);
      if (m) seen.set(sig.name, { name: sig.name, version: m[1], source: "banner" });
    }
  }

  const libraries = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
  return {
    libraries,
    note: "Identified from what your app shipped. Bundlers strip most names, so this is not a complete dependency list.",
  };
}
