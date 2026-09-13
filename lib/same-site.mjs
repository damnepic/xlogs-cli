// IS THIS RESOURCE THE SITE'S OWN, OR SOMEBODY ELSE'S? One answer, for every subsystem.
//
// This lived inside lib/live.mjs while lib/bad-cdns.mjs answered the same question a different
// way - hostname equality - and the two disagreed by construction. Measured on linear.app:
// static.linear.app is SAME-SITE to the bundle scanner, which is why its 27 scripts get read at
// all, and THIRD-PARTY to the inventory, which listed it as an external dependency. Neither file
// was wrong on its own. They were wrong at the boundary, which is the shape of bug no single-file
// test can see.
//
// It inflated third-party counts for any site serving assets from its own subdomain, which is
// most production apps and nearly all of the ones this scanner is pointed at. And the two answers
// feed different products: the secrets check, the page-weight total, the technology inventory, the
// diff's bounded absence. Four surfaces cannot be allowed to hold two definitions.
//
// REGISTRABLE DOMAIN, NOT HOSTNAME. static.linear.app and linear.app are the same site by any
// reasonable reading: the same party controls both and the assets are the app's own.
//
// EXCEPT ON A SHARED PLATFORM, where the suffix is the whole point. alice.github.io and
// bob.github.io share a registrable domain and are strangers, so a naive apex comparison would
// hand one user's scanner another user's bundles.

import { isPlatform, apexOf } from "./ct-logs.mjs";

/**
 * @param {string} a a resource URL
 * @param {string} b the document URL it was referenced from
 */
export function sameSite(a, b) {
  try {
    const ha = new URL(a).hostname.toLowerCase();
    const hb = new URL(b).hostname.toLowerCase();
    if (ha === hb) return true;
    // On a shared platform host, siblings are strangers. Exact match only.
    if (isPlatform(ha) || isPlatform(hb)) return false;
    return apexOf(ha) === apexOf(hb);
  } catch { return false; }
}

/** The inverse, named so a caller reads as what it means rather than as a negation. */
export const isThirdParty = (a, b) => !sameSite(a, b);
