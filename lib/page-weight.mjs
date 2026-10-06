// WHAT THIS DEPLOYMENT SHIPS TO A BROWSER, measured rather than scored.
//
// The deterministic half of performance, and deliberately the half that is OURS. Every number here
// comes from a response this scan already fetched: the bytes the server sent, the scripts the page
// referenced, the third-party hosts it pulls from. No Lighthouse, no API key, no second opinion,
// and the same deployment measured twice gives the same answer - which matters, because three
// places in xlogs' own copy promise exactly that.
//
// THE SPLIT THAT KEEPS THAT PROMISE INTACT:
//
//   MEASURED (here)   page weight, JavaScript bytes, first-party vs third-party split, which
//                     vendors cost what, how many scripts block. Reproducible. Can alert.
//   REPORTED (PSI)    Lighthouse score, LCP, INP, CLS. Google's lab, varying ±5 points run to run
//                     for reasons that have nothing to do with the site. Never alerts on its own.
//
// Mixing those two into one "site score" would produce a number that is neither reproducible nor
// explicable, and would quietly make "the same app always produces the same result" false.
//
// WHAT THIS DELIBERATELY DOES NOT DO is grade. There is no 0-100, no red/amber/green, and no
// "performance: poor". A 2 MB bundle is a fact; whether it is a problem depends on the app, the
// audience and the connection, and none of those are visible from here. It reports weight and what
// is carrying it, and lets the size speak.

// Third-party script hosts cost a browser a connection, a download and main-thread time, but we do
// NOT fetch them: weighing a stranger's CDN would make a read-only scanner into a traffic
// generator, and the same-site filter that keeps the secrets scan honest applies here too. So
// third parties are COUNTED AND NAMED, never sized, and the copy has to say so - an unmeasured
// vendor silently omitted from a total is the same class of error as an unread bundle called clean.

const KB = 1024;

export function formatBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return "0 KB";
  if (n < KB) return `${n} B`;
  if (n < KB * KB) return `${Math.round(n / KB)} KB`;
  return `${(n / (KB * KB)).toFixed(n < KB * KB * 10 ? 1 : 0)} MB`;
}

/**
 * @param {object} input
 * @param {Array<{url:string, bytes:number, exact:boolean}>} input.weights first-party scripts read
 * @param {string[]} input.thirdParty third-party script hosts referenced
 * @param {number} input.htmlBytes size of the root document
 * @param {object} input.coverage the scan's coverage counters
 * @param {Array<{name:string, category:string}>} input.technologies detected stack
 */
export function pageWeight({ weights = [], thirdParty = [], htmlBytes = 0, coverage = {}, technologies = [] } = {}) {
  const scripts = weights.filter((w) => w.bytes > 0);
  const jsBytes = scripts.reduce((n, w) => n + w.bytes, 0);
  // "At least", whenever any single script's size is a floor rather than a measurement, or whenever
  // scripts were referenced that we never read. Both understate, and an understated total presented
  // as exact is the failure mode that matters here.
  const anyFloor = scripts.some((w) => !w.exact);
  // The app's OWN scripts we tried and could not read (2026-10-06). Third-party scripts are never
  // downloaded by design, so they are not "could not read"; they make the total a floor, and are
  // named once below as third-party hosts. Results without scriptsFirstParty keep the old count.
  const own = Number.isFinite(coverage.scriptsFirstParty) ? coverage.scriptsFirstParty : (coverage.scriptsReferenced || 0);
  const unread = Math.max(0, own - (coverage.scriptsScanned || 0));
  const bounded = anyFloor || unread > 0 || thirdParty.length > 0;

  const heaviest = [...scripts].sort((a, b) => b.bytes - a.bytes).slice(0, 5)
    .map((w) => ({ url: w.url, bytes: w.bytes, exact: w.exact, label: fileOf(w.url) }));

  // Which detected technologies are the ones that actually ship weight to a browser. This is the
  // correlation that makes the number actionable rather than merely alarming: "1.8 MB" is a fact,
  // "1.8 MB, and you load four analytics vendors" is a lead.
  const WEIGHTY = /^(analytics|marketing|support|ai|monitoring)$/i;
  const passengers = technologies
    .filter((t) => WEIGHTY.test(t.category || ""))
    .map((t) => t.name);

  return {
    // Everything below is MEASURED. A consumer can say so without qualifying it.
    htmlBytes,
    jsBytes,
    totalBytes: htmlBytes + jsBytes,
    // Whether the totals are exact or a lower bound, and why. Never rounded away.
    bounded,
    boundedReason: bounded
      ? [
          unread > 0 ? `${unread} of its own script${unread === 1 ? "" : "s"} could not be read` : null,
          thirdParty.length ? `scripts from ${thirdParty.length} third-party host${thirdParty.length === 1 ? "" : "s"} are not downloaded` : null,
          anyFloor ? "at least one response was larger than we read" : null,
        ].filter(Boolean).join(", ")
      : "",
    scriptsRead: scripts.length,
    scriptsReferenced: coverage.scriptsReferenced || 0,
    // The denominator for "N of M scripts read": the app's own scripts, the only ones ever fetched.
    scriptsFirstParty: own,
    heaviest,
    // NAMED, NOT SIZED, and the distinction is stated wherever this is shown.
    //
    // Normalised to STRINGS. checkScriptOrigins returns Array<{host, count}>, and passing those
    // through meant a component rendering a host got an object: React error #31, the result never
    // painted, and the page reloaded itself. The server was returning 200 and every test passed -
    // only looking at it found this. A library boundary should not hand its caller a shape that
    // depends on which producer filled it.
    thirdParty: {
      count: thirdParty.length,
      hosts: thirdParty.slice(0, 12).map((t) => (typeof t === "string" ? t : t?.host || String(t))),
    },
    passengers,
  };
}

function fileOf(u) {
  try { const p = new URL(u).pathname; return p.split("/").filter(Boolean).pop() || p; }
  catch { return u; }
}

/**
 * One sentence, in the reader's terms, with no grade in it.
 */
export function weightSummary(w, domain = "This page") {
  if (!w || (!w.jsBytes && !w.htmlBytes)) return "";
  const parts = [`${domain} ships ${w.bounded ? "at least " : ""}${formatBytes(w.totalBytes)}`];
  const unread = (Number.isFinite(w.scriptsFirstParty) ? w.scriptsFirstParty : w.scriptsReferenced) - w.scriptsRead;
  if (w.jsBytes) {
    parts.push(`${formatBytes(w.jsBytes)} of it JavaScript across ${w.scriptsRead} file${w.scriptsRead === 1 ? "" : "s"}`);
    if (unread > 0) parts.push(`with ${unread} more script${unread === 1 ? "" : "s"} we could not read`);
  } else if (w.scriptsReferenced > 0) {
    // MEASURED ZERO IS NOT SHIPPED ZERO. Reading "cal.com ships at least 2.2 MB" with no mention
    // of JavaScript, when 29 of its scripts sit on a CDN we deliberately do not download, tells the
    // reader this site ships no JavaScript. It ships plenty; we weighed none of it, and the
    // sentence has to say which of those two it means.
    parts.push(`none of its ${w.scriptsReferenced} script${w.scriptsReferenced === 1 ? "" : "s"} could be weighed, so the JavaScript is not counted here`);
  }
  if (w.thirdParty.count) {
    parts.push(`plus scripts from ${w.thirdParty.count} third-party host${w.thirdParty.count === 1 ? "" : "s"} we did not download`);
  }
  return parts.join(", ") + ".";
}

// ---- REGRESSION, and the reason this belongs in Watch ------------------------------------------
//
// Byte counts are the one performance signal that can honestly alert. A Lighthouse score moves ±5
// points between two identical runs, so diffing it would reproduce the certificate-log flake with
// ten times the volume and destroy the invariant Watch is built on: if xlogs interrupts you,
// something got worse. Bytes do not drift. If a deployment shipped 480 KB last week and 1.1 MB
// today, that is a fact about the deployment, not about the weather in Google's datacentre.
//
// A floor is still applied, because a hashed filename or a chunk split can move a total by a few
// KB without anything meaningful changing, and an alert that fires on noise is an alert nobody
// reads. Both conditions must hold: a relative jump AND an absolute one.
export const WEIGHT_ALERT_RATIO = 1.25;      // 25% heavier
export const WEIGHT_ALERT_ABSOLUTE = 150 * KB;

export function weightRegression(before, after) {
  const a = before?.jsBytes || 0, b = after?.jsBytes || 0;
  if (!a || !b) return null;
  // A BOUNDED TOTAL CANNOT SUPPORT A REGRESSION CLAIM. If either side was a lower bound, the
  // difference between them is not a measurement, and "your site got 30% heavier" would be a guess
  // presented as a fact. Same rule as bounded absence in the diff: report that we could not
  // compare, never a confident number built on an incomplete read.
  if (before.bounded || after.bounded) {
    return { kind: "unconfirmed", from: a, to: b,
      reason: "One of the two page-weight totals was a lower bound, so the change cannot be measured." };
  }
  const delta = b - a;
  if (delta <= 0) return delta < 0 ? { kind: "lighter", from: a, to: b, delta } : null;
  const heavier = b / a >= WEIGHT_ALERT_RATIO && delta >= WEIGHT_ALERT_ABSOLUTE;
  return { kind: heavier ? "heavier" : "drift", from: a, to: b, delta };
}
