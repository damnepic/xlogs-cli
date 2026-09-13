// WHAT THIS SITE IS BUILT WITH, from evidence already in hand.
//
// ZERO ADDITIONAL REQUESTS. Every signal below comes from something a scan already fetched and
// then threw away: the root response headers, the shape of the bundle URLs, the HTML the secrets
// pass already read, the CNAME target the takeover check already resolved, the SPF record the
// email check already reduced to a boolean. The scan's outbound budget is 60 with roughly three
// requests of headroom, so a detector that needed its own fetches could not ship. This one adds
// none.
//
// THREE RULES, and they are the whole design.
//
// 1. EVERY CLAIM CARRIES ITS EVIDENCE. Each detection records the exact string that produced it -
//    the header line, the path prefix, the marker. The scanner's standing rule is that we read
//    code, we do not execute it, so we can only ever say what we SAW. A stack chip with no
//    evidence behind it is the same overclaim as a finding headline that outruns its receipt.
//
// 2. CONFIDENCE IS EARNED, NOT ASSUMED. A vendor response header is near-conclusive. A path
//    convention is strong. A string appearing somewhere in a bundle is weak, because bundles
//    inline their dependencies' names constantly - "react" appears in code that does not use
//    React. Weak signals are reported as weak, and never on their own promote a technology.
//
// 3. NOTHING HERE IS A FINDING. This is inventory, like the certificate-log names and the
//    third-party script hosts: it is never scored, never severity-carrying, and never blocks a
//    clean verdict. Knowing a site runs Next.js is not a problem with the site.
//
// CLEAN ROOM. The signal patterns here are written from first principles and public vendor
// documentation - the header a platform documents itself as sending, the asset path a framework
// documents itself as emitting. No fingerprint database was copied from any existing detector;
// Wappalyzer's dataset in particular is not under a licence we could adopt.

// Confidence ladder. Ordered, so a stronger signal for the same technology wins.
const RANK = { conclusive: 3, strong: 2, weak: 1 };

// ---- HEADER SIGNALS -------------------------------------------------------------------------
// A response header the platform sets itself. The strongest class available without executing
// anything: the origin is telling us what it is.
const HEADER_SIGNALS = [
  // [header, test, technology, category, confidence]
  ["x-vercel-id", null, "Vercel", "hosting", "conclusive"],
  ["x-vercel-cache", null, "Vercel", "hosting", "conclusive"],
  ["x-nf-request-id", null, "Netlify", "hosting", "conclusive"],
  ["cf-ray", null, "Cloudflare", "cdn", "conclusive"],
  ["x-render-origin-server", null, "Render", "hosting", "conclusive"],
  ["fly-request-id", null, "Fly.io", "hosting", "conclusive"],
  ["x-amz-cf-id", null, "Amazon CloudFront", "cdn", "conclusive"],
  ["x-served-by", /cache-/i, "Fastly", "cdn", "strong"],
  ["x-github-request-id", null, "GitHub Pages", "hosting", "conclusive"],
  ["x-shopify-stage", null, "Shopify", "platform", "conclusive"],
  ["x-drupal-cache", null, "Drupal", "cms", "conclusive"],
  // Servers and runtimes that name themselves.
  ["server", /^cloudflare/i, "Cloudflare", "cdn", "conclusive"],
  ["server", /^vercel/i, "Vercel", "hosting", "conclusive"],
  ["server", /^nginx/i, "nginx", "server", "strong"],
  ["server", /^apache/i, "Apache", "server", "strong"],
  ["server", /^caddy/i, "Caddy", "server", "strong"],
  ["server", /^gunicorn/i, "Gunicorn", "server", "strong"],
  ["server", /^cowboy/i, "Cowboy", "server", "strong"],
  ["server", /^awselb/i, "AWS ELB", "hosting", "strong"],
  ["server", /GSE|Google Frontend/i, "Google Cloud", "hosting", "strong"],
  ["server", /^Microsoft-IIS/i, "IIS", "server", "strong"],
  // x-powered-by is the classic self-report. Often stripped, never wrong when present.
  ["x-powered-by", /next\.js/i, "Next.js", "framework", "conclusive"],
  ["x-powered-by", /express/i, "Express", "framework", "conclusive"],
  ["x-powered-by", /php/i, "PHP", "language", "conclusive"],
  ["x-powered-by", /asp\.net/i, "ASP.NET", "framework", "conclusive"],
  ["x-powered-by", /shopify/i, "Shopify", "platform", "conclusive"],
  ["x-powered-by", /wp\s*engine/i, "WP Engine", "hosting", "conclusive"],
  // The App Router's cache key. Nothing else emits these Vary values.
  ["vary", /\brsc\b|next-router-state-tree/i, "Next.js", "framework", "conclusive"],
  ["x-nextjs-prerender", null, "Next.js", "framework", "conclusive"],
  ["x-generator", /drupal/i, "Drupal", "cms", "conclusive"],
  ["x-generator", /wordpress/i, "WordPress", "cms", "conclusive"],
];

// ---- COOKIE SIGNALS -------------------------------------------------------------------------
// A cookie NAME the platform sets. We read names only, never values - a value could be a session
// token, and this feature has no business holding one.
const COOKIE_SIGNALS = [
  [/^__cf_bm|^__cflb|^cf_clearance/i, "Cloudflare", "cdn", "strong"],
  [/^_shopify_|^shopify_/i, "Shopify", "platform", "conclusive"],
  [/^PHPSESSID$/i, "PHP", "language", "strong"],
  [/^laravel_session$/i, "Laravel", "framework", "conclusive"],
  // DELIBERATELY NOT HERE: `XSRF-TOKEN`. Laravel does set it, and so does every Angular app and
  // several other frameworks - it is a convention, not a fingerprint. Nor `*_session`, which
  // would match most of the PHP web. This detector has no concept of a signal that STRENGTHENS
  // without ESTABLISHING: every entry in these tables creates a detection at its stated
  // confidence. Until that concept exists, a shared convention cannot be listed at all, because
  // listing it would mean asserting Laravel on evidence that does not support it.
  [/^ASP\.NET_SessionId$/i, "ASP.NET", "framework", "conclusive"],
  [/^JSESSIONID$/i, "Java", "language", "strong"],
  [/^wordpress_|^wp-settings/i, "WordPress", "cms", "conclusive"],
  [/^django|^csrftoken$/i, "Django", "framework", "strong"],
  [/^_session_id$/i, "Rails", "framework", "weak"],
  [/^ph_.*_posthog$/i, "PostHog", "analytics", "strong"],
  [/^__stripe_/i, "Stripe", "payments", "strong"],
  [/^_ga$|^_gid$/i, "Google Analytics", "analytics", "strong"],
  [/^ajs_/i, "Segment", "analytics", "strong"],
  [/^intercom-/i, "Intercom", "support", "strong"],
];

// ---- ASSET PATH SIGNALS ---------------------------------------------------------------------
// The directory a build tool emits into. Strong because it is structural: you get this path
// because the tool produced it, not because someone wrote a string.
const PATH_SIGNALS = [
  [/\/_next\/static\//, "Next.js", "framework", "conclusive"],
  [/\/_nuxt\//, "Nuxt", "framework", "conclusive"],
  [/\/_astro\//, "Astro", "framework", "conclusive"],
  [/\/\.svelte-kit\/|\/_app\/immutable\//, "SvelteKit", "framework", "conclusive"],
  [/\/wp-content\/|\/wp-includes\//, "WordPress", "cms", "conclusive"],
  [/\/cdn\.shopify\.com\//, "Shopify", "platform", "conclusive"],
  [/\/_vercel\/insights/, "Vercel Analytics", "analytics", "strong"],
  [/\/static\/js\/main\.[a-f0-9]+\.chunk\.js/, "Create React App", "framework", "strong"],
  [/\/assets\/index-[A-Za-z0-9_-]{8}\.js/, "Vite", "build", "strong"],
  [/\/build\/_shared\/|\/build\/root-/, "Remix", "framework", "strong"],
  [/\/_expo\//, "Expo", "framework", "strong"],
  [/\/livewire\//, "Laravel Livewire", "framework", "strong"],
  // LIVEWIRE IMPLIES LARAVEL, and the detector was naming only the component library. Livewire
  // ships for Laravel and nothing else, so observing it is conclusive evidence of the framework
  // underneath. A Livewire site previously reported "Laravel Livewire" and never "Laravel",
  // which is how a user came to report Laravel as undetected on a site running it.
  [/\/livewire\//, "Laravel", "framework", "conclusive"],
  // Laravel's own first-party admin panel and its route-exposure package. Both are Laravel-only,
  // so the asset path is as specific as a framework marker gets.
  [/\/nova-api\/|\/nova\/(app|styles)/, "Laravel Nova", "tooling", "conclusive"],
  [/\/nova-api\/|\/nova\/(app|styles)/, "Laravel", "framework", "conclusive"],
  [/\/js\/filament\/|\/filament\/app\./, "Filament", "tooling", "strong"],
  [/\/js\/filament\/|\/filament\/app\./, "Laravel", "framework", "strong"],
];

// ---- HTML MARKER SIGNALS ---------------------------------------------------------------------
// Markup a framework emits into the document it renders.
const HTML_SIGNALS = [
  // __NEXT_DATA__ IS A PAGES ROUTER SIGNAL, NOT A NEXT.JS SIGNAL. An App Router site emits none
  // of it and no buildId - it streams an RSC payload into `self.__next_f` instead. Keying only on
  // __NEXT_DATA__ reports "not Next.js" on every modern Next.js site, which is the same
  // generational trap as data-reactroot, removed in React 18.
  [/self\.__next_f/, "Next.js", "framework", "conclusive"],
  [/<script[^>]+id="__NEXT_DATA__"/i, "Next.js", "framework", "conclusive"],
  [/<div[^>]+id="__next"/i, "Next.js", "framework", "strong"],
  [/<div[^>]+id="__nuxt"/i, "Nuxt", "framework", "strong"],
  [/\sdata-reactroot\b/i, "React", "framework", "strong"],
  [/\sng-version="/i, "Angular", "framework", "conclusive"],
  // LARAVEL, from markup rather than from a cookie. `laravel_session` is the strongest signal we
  // have but the cookie NAME IS CONFIGURABLE - it defaults to `{app}_session` - so a large share
  // of real Laravel apps never emit the literal string. These do not depend on that.
  //
  // Livewire attributes are emitted into the DOM by the component runtime and exist only in
  // Livewire, which exists only for Laravel.
  [/\swire:(snapshot|effects|id)=/i, "Laravel Livewire", "framework", "conclusive"],
  [/\swire:(snapshot|effects|id)=/i, "Laravel", "framework", "conclusive"],
  // Ziggy publishes Laravel's route table to JavaScript. Laravel-only package.
  [/Ziggy\s*=\s*\{|tightenco\/ziggy/i, "Laravel", "framework", "strong"],
  [/<[^>]+\sdata-svelte-h=/i, "Svelte", "framework", "strong"],
  [/<astro-island\b/i, "Astro", "framework", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="WordPress/i, "WordPress", "cms", "conclusive"],
  // Astro and Ghost publish generator tags AND versions. Without a detection here their version
  // signal had nothing to attach to, and was silently discarded.
  [/<meta[^>]+name=["']generator["'][^>]+content=["']Astro/i, "Astro", "framework", "conclusive"],
  [/<meta[^>]+name=["']generator["'][^>]+content=["']Ghost/i, "Ghost", "cms", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Hugo/i, "Hugo", "framework", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Jekyll/i, "Jekyll", "framework", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Gatsby/i, "Gatsby", "framework", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Docusaurus/i, "Docusaurus", "framework", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Webflow/i, "Webflow", "platform", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Framer/i, "Framer", "platform", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Wix/i, "Wix", "platform", "conclusive"],
  [/<meta[^>]+name="generator"[^>]+content="Squarespace/i, "Squarespace", "platform", "conclusive"],
  // Tailwind's atomic classes are distinctive as a CLUSTER, never as one class. Requiring three
  // co-occurring utilities keeps a stray "flex" from claiming a whole framework.
  [/class="[^"]*\bflex\b[^"]*"[\s\S]{0,4000}class="[^"]*\b(items-center|justify-between)\b[^"]*"[\s\S]{0,4000}class="[^"]*\b(px-\d|py-\d|text-(sm|lg|xl))\b[^"]*"/,
    "Tailwind CSS", "css", "weak"],
];

// ---- THIRD-PARTY SERVICE SIGNALS ---------------------------------------------------------------
//
// BREADTH, from script hosts the page already declares. A service loaded from its own vendor
// domain is naming itself: `js.stripe.com` is not a guess about Stripe.
//
// Deliberately a curated list rather than a race to tens of thousands of fingerprints. A thousand
// detections that each carry evidence is a better product than fifty thousand guesses, and every
// entry here is a vendor-documented host.
const HOST_SIGNALS = [
  // VENDOR-CONTROLLED HOSTS ONLY. A host is an observed dependency; it becomes a NAMED technology
  // only through an explicit mapping like these, where the hostname itself uniquely identifies the
  // product. Shared infrastructure - cloudfront.net, amazonaws.com, googleusercontent.com, a
  // customer's own cdn.* subdomain - is deliberately absent and must stay absent: mapping those
  // would invent a technology out of a hosting choice. test/stack-detect.test.mjs asserts it.
  //
  // These were the conspicuous gap. The table already knew Fathom, Bunny Fonts and Osano while
  // missing the single most common third-party stack on the web, so a site loading Tag Manager,
  // AdSense and Cloudflare Insights reported none of the three - from evidence the scan had
  // already fetched and was carrying in its own response.
  [/www\.googletagmanager\.com/i, "Google Tag Manager", "analytics"],
  [/www\.google-analytics\.com|ssl\.google-analytics\.com/i, "Google Analytics", "analytics"],
  [/static\.cloudflareinsights\.com/i, "Cloudflare Web Analytics", "analytics"],
  [/vitals\.vercel-insights\.com|va\.vercel-scripts\.com/i, "Vercel Analytics", "analytics"],
  [/cdn\.matomo\.cloud|matomo\.php/i, "Matomo", "analytics"],
  [/analytics\.umami\.is|umami\.js/i, "Umami", "analytics"],
  [/cdn\.heapanalytics\.com/i, "Heap", "analytics"],
  [/cdn\.mouseflow\.com/i, "Mouseflow", "analytics"],
  // Advertising. The publisher id is separately visible in the markup, so reporting the network
  // from its own script host contradicts nothing and explains where that id came from.
  [/pagead2\.googlesyndication\.com|adsbygoogle/i, "Google AdSense", "marketing"],
  [/www\.googleadservices\.com|googleads\.g\.doubleclick\.net/i, "Google Ads", "marketing"],
  [/s\.amazon-adsystem\.com/i, "Amazon Ads", "marketing"],
  [/static\.ads-twitter\.com/i, "X Ads", "marketing"],
  [/cdn\.taboola\.com/i, "Taboola", "marketing"],
  [/ct\.pinterest\.com|s\.pinimg\.com\/ct/i, "Pinterest Tag", "marketing"],
  // Maps and video, both of which ship a lot of code and are near-universally recognisable.
  [/maps\.googleapis\.com|maps\.gstatic\.com/i, "Google Maps", "ui"],
  [/api\.mapbox\.com|api\.tiles\.mapbox\.com/i, "Mapbox", "ui"],
  [/player\.vimeo\.com|vimeocdn\.com/i, "Vimeo", "ui"],
  [/fast\.wistia\.(net|com)/i, "Wistia", "ui"],
  [/(cdn|stream)\.mux\.com/i, "Mux", "ui"],
  [/cdn\.loom\.com/i, "Loom", "ui"],
  // Search.
  [/[a-z0-9-]+\.algolia(net|\.net)\.com|cdn\.jsdelivr\.net\/npm\/algoliasearch/i, "Algolia", "tooling"],
  [/cdn\.typesense\.org/i, "Typesense", "tooling"],
  // Experimentation and feature flags.
  [/cdn\.optimizely\.com/i, "Optimizely", "tooling"],
  [/clientstream\.launchdarkly\.com|app\.launchdarkly\.com/i, "LaunchDarkly", "tooling"],
  [/cdn\.growthbook\.io/i, "GrowthBook", "tooling"],
  [/api\.statsig\.com|featureassets\.org/i, "Statsig", "tooling"],
  [/cdn\.splitstatic\.io|sdk\.split\.io/i, "Split", "tooling"],
  // Scheduling and embeds people recognise on sight.
  [/assets\.calendly\.com/i, "Calendly", "tooling"],
  [/js\.hsforms\.net\/forms/i, "HubSpot Forms", "marketing"],
  [/embed\.typeform\.com/i, "Typeform", "tooling"],
  [/tally\.so\/widgets/i, "Tally", "tooling"],
  // Consent and privacy, which most detectors miss and which matters to the audience.
  [/cookiebot\.com|consent\.cookiebot/i, "Cookiebot", "privacy"],
  [/cdn\.cookielaw\.org|onetrust\.com/i, "OneTrust", "privacy"],
  [/app\.termly\.io/i, "Termly", "privacy"],
  [/cookieyes\.com/i, "CookieYes", "privacy"],
  [/usercentrics\.eu/i, "Usercentrics", "privacy"],
  [/klaro|osano\.com/i, "Osano", "privacy"],
  // Error monitoring.
  [/browser\.sentry-cdn\.com|@sentry\/|sentry\.io/i, "Sentry", "monitoring"],
  [/bugsnag\.com/i, "Bugsnag", "monitoring"],
  [/rollbar\.com/i, "Rollbar", "monitoring"],
  [/datadoghq|datadog-browser/i, "Datadog", "monitoring"],
  [/newrelic\.com|nr-data\.net/i, "New Relic", "monitoring"],
  [/logrocket\.(com|io)/i, "LogRocket", "monitoring"],
  // Support and chat.
  [/widget\.intercom\.io|intercomcdn/i, "Intercom", "support"],
  [/static\.zdassets\.com|zendesk\.com/i, "Zendesk", "support"],
  [/crisp\.chat/i, "Crisp", "support"],
  [/embed\.tawk\.to/i, "Tawk.to", "support"],
  [/js\.driftt\.com|drift\.com/i, "Drift", "support"],
  [/front\.com|helpscout\.net|beacon-v2/i, "Help Scout", "support"],
  // Product analytics, separate from page analytics.
  [/cdn\.mxpnl\.com|mixpanel/i, "Mixpanel", "analytics"],
  [/cdn\.amplitude\.com|amplitude\.com/i, "Amplitude", "analytics"],
  [/static\.hotjar\.com|hotjar\.com/i, "Hotjar", "analytics"],
  [/plausible\.io/i, "Plausible", "analytics"],
  [/cdn\.usefathom\.com/i, "Fathom", "analytics"],
  [/scripts\.simpleanalyticscdn\.com/i, "Simple Analytics", "analytics"],
  [/clarity\.ms/i, "Microsoft Clarity", "analytics"],
  [/cdn\.segment\.com/i, "Segment", "analytics"],
  [/posthog\.com|\/static\/array\.js/i, "PostHog", "analytics"],
  // Feature flags and experimentation.
  [/launchdarkly\.com/i, "LaunchDarkly", "tooling"],
  [/cdn\.optimizely\.com/i, "Optimizely", "tooling"],
  [/statsig\.com/i, "Statsig", "tooling"],
  [/growthbook\.io/i, "GrowthBook", "tooling"],
  // Payments and auth beyond the ones already covered.
  [/js\.stripe\.com/i, "Stripe", "payments"],
  [/paypal\.com\/sdk|paypalobjects/i, "PayPal", "payments"],
  [/js\.squareup(cdn)?\.com/i, "Square", "payments"],
  [/checkout\.(paddle|lemonsqueezy)\.com|paddle\.com/i, "Paddle", "payments"],
  [/auth0\.com|cdn\.auth0/i, "Auth0", "auth"],
  [/clerk\.[a-z.]+\/npm|clerk\.accounts\.dev/i, "Clerk", "auth"],
  [/accounts\.google\.com\/gsi/i, "Google Sign-In", "auth"],
  // Fonts, maps, media, search.
  [/fonts\.googleapis\.com|fonts\.gstatic\.com/i, "Google Fonts", "ui"],
  [/use\.typekit\.net|p\.typekit/i, "Adobe Fonts", "ui"],
  [/fonts\.bunny\.net/i, "Bunny Fonts", "ui"],
  [/maps\.googleapis\.com/i, "Google Maps", "tooling"],
  [/api\.mapbox\.com/i, "Mapbox", "tooling"],
  [/player\.vimeo\.com|vimeocdn/i, "Vimeo", "tooling"],
  [/youtube\.com\/(embed|iframe_api)|ytimg\.com/i, "YouTube", "tooling"],
  [/player\.mux\.com|mux\.com/i, "Mux", "tooling"],
  [/cdn\.jsdelivr\.net/i, "jsDelivr", "cdn"],
  [/cdnjs\.cloudflare\.com/i, "cdnjs", "cdn"],
  [/unpkg\.com/i, "unpkg", "cdn"],
  [/algolia(net)?\.com|algolia\.net/i, "Algolia", "tooling"],
  [/typesense\.org|typesense\.net/i, "Typesense", "tooling"],
  // Bot protection and captcha, which sit close to the security story.
  [/challenges\.cloudflare\.com/i, "Cloudflare Turnstile", "security"],
  [/(www\.)?google\.com\/recaptcha|recaptcha\.net/i, "reCAPTCHA", "security"],
  [/hcaptcha\.com/i, "hCaptcha", "security"],
  // Marketing and email capture.
  [/js\.hs-scripts\.com|hsforms\.(net|com)|hs-analytics\.net/i, "HubSpot", "marketing"],
  [/static\.klaviyo\.com|klaviyo\.com/i, "Klaviyo", "marketing"],
  [/chimpstatic\.com|list-manage\.com/i, "Mailchimp", "marketing"],
  [/connect\.facebook\.net/i, "Meta Pixel", "marketing"],
  [/analytics\.tiktok\.com/i, "TikTok Pixel", "marketing"],
  [/snap\.licdn\.com/i, "LinkedIn Insight", "marketing"],
  // sc-static.net only, NOT the word "snapchat": a site that merely LINKS to its Snapchat profile
  // in a footer would otherwise be reported as running the ad pixel. Same reasoning trimmed the
  // other loose word-patterns in this list - the whole point of an evidence-carrying detector is
  // undone by a rule that fires on a social link.
  [/sc-static\.net/i, "Snap Pixel", "marketing"],
];

// ---- DNS SIGNALS ------------------------------------------------------------------------------
// The CNAME target the takeover check already resolved, and the SPF record the email check
// already read. Both were reduced to a boolean and discarded.
const CNAME_SIGNALS = [
  [/\.vercel-dns\.com$|vercel-dns/i, "Vercel", "hosting", "conclusive"],
  [/\.netlify\.app$|netlify/i, "Netlify", "hosting", "conclusive"],
  [/\.cloudfront\.net$/i, "Amazon CloudFront", "cdn", "conclusive"],
  [/\.myshopify\.com$|shops\.myshopify/i, "Shopify", "platform", "conclusive"],
  [/\.github\.io$|ghs\.googlehosted\.com$/i, "GitHub Pages", "hosting", "strong"],
  [/\.herokudns\.com$|herokuapp\.com$/i, "Heroku", "hosting", "conclusive"],
  [/\.pages\.dev$/i, "Cloudflare Pages", "hosting", "conclusive"],
  [/\.workers\.dev$/i, "Cloudflare Workers", "hosting", "conclusive"],
  [/\.webflow\.io$|proxy-ssl\.webflow\.com$/i, "Webflow", "platform", "conclusive"],
  [/\.framer\.app$/i, "Framer", "platform", "conclusive"],
  [/\.wpengine\.com$/i, "WP Engine", "hosting", "conclusive"],
  [/\.fly\.dev$/i, "Fly.io", "hosting", "conclusive"],
  [/\.onrender\.com$/i, "Render", "hosting", "conclusive"],
  [/\.railway\.app$/i, "Railway", "hosting", "conclusive"],
  // AI BUILDERS ON CUSTOM DOMAINS. lib/fingerprint.mjs identifies a builder from the hostname or
  // from a marker in the served code, which covers an app still on its *.base44.app default. Once
  // it moves to its own domain both of those can go quiet, and the CNAME is what still points
  // home. Documented publicly in Wiz's Base44 research: custom domains all CNAME to the same
  // origin. Same reasoning for the others.
  [/base44\.onrender\.com$/i, "Base44", "platform", "conclusive"],
  [/\.lovable\.app$|lovableproject\.com$/i, "Lovable", "platform", "conclusive"],
  [/\.bolt\.host$/i, "Bolt", "platform", "conclusive"],
  [/\.replit\.app$|\.repl\.co$/i, "Replit", "platform", "conclusive"],
];

const SPF_SIGNALS = [
  [/include:_spf\.google\.com/i, "Google Workspace", "email", "conclusive"],
  [/include:spf\.protection\.outlook\.com/i, "Microsoft 365", "email", "conclusive"],
  [/include:sendgrid\.net/i, "SendGrid", "email", "conclusive"],
  [/include:.*amazonses\.com/i, "Amazon SES", "email", "conclusive"],
  [/include:.*mailgun\.org/i, "Mailgun", "email", "conclusive"],
  [/include:.*_spf\.resend\.com|include:.*resend/i, "Resend", "email", "conclusive"],
  [/include:.*postmarkapp\.com/i, "Postmark", "email", "conclusive"],
  [/include:.*zoho/i, "Zoho Mail", "email", "conclusive"],
  [/include:.*mailchimp|include:.*mcsv\.net/i, "Mailchimp", "email", "strong"],
  [/include:.*_spf\.mail\.icloud\.com/i, "iCloud Mail", "email", "conclusive"],
];

// TXT records that exist purely to prove domain ownership to a SaaS product. They are a direct
// statement that the domain owner set that product up.
const TXT_VERIFICATION_SIGNALS = [
  [/^google-site-verification=/i, "Google Search Console", "seo", "conclusive"],
  [/^MS=/i, "Microsoft 365", "email", "strong"],
  [/^facebook-domain-verification=/i, "Meta Business", "marketing", "conclusive"],
  [/^stripe-verification=/i, "Stripe", "payments", "conclusive"],
  [/^atlassian-domain-verification=/i, "Atlassian", "tooling", "conclusive"],
  [/^adobe-idp-site-verification=/i, "Adobe", "tooling", "conclusive"],
  [/^shopify-verification|^shopify-site-verification/i, "Shopify", "platform", "conclusive"],
  [/^_vercel$|^vc-domain-verify=/i, "Vercel", "hosting", "strong"],
  [/^apple-domain-verification=/i, "Apple", "tooling", "conclusive"],
  [/^openai-domain-verification=/i, "OpenAI", "ai", "conclusive"],
];

// ---- SOURCE MAP SIGNALS -----------------------------------------------------------------------
// `sources[]` in a public source map is a literal file listing of the project. It is the richest
// stack evidence a scan ever holds, and until now it was fetched, regexed for two keys, and
// discarded. Only DEPENDENCY paths are read - never the application's own file names, which are
// the author's private structure and none of our business to publish.
const SOURCEMAP_SIGNALS = [
  [/node_modules\/(react-dom|react)\//, "React", "framework", "conclusive"],
  [/node_modules\/vue\//, "Vue", "framework", "conclusive"],
  [/node_modules\/svelte\//, "Svelte", "framework", "conclusive"],
  [/node_modules\/@angular\//, "Angular", "framework", "conclusive"],
  [/node_modules\/next\//, "Next.js", "framework", "conclusive"],
  [/node_modules\/tailwindcss\//, "Tailwind CSS", "css", "conclusive"],
  [/node_modules\/@supabase\//, "Supabase", "backend", "conclusive"],
  [/node_modules\/firebase\//, "Firebase", "backend", "conclusive"],
  [/node_modules\/@stripe\//, "Stripe", "payments", "conclusive"],
  [/node_modules\/@clerk\//, "Clerk", "auth", "conclusive"],
  [/node_modules\/@prisma\/|node_modules\/prisma\//, "Prisma", "backend", "conclusive"],
  [/node_modules\/@tanstack\//, "TanStack Query", "library", "conclusive"],
  [/node_modules\/zod\//, "Zod", "library", "conclusive"],
  [/node_modules\/framer-motion\//, "Framer Motion", "library", "conclusive"],
  [/node_modules\/@radix-ui\//, "Radix UI", "ui", "conclusive"],
  [/node_modules\/lucide-react\//, "Lucide", "ui", "conclusive"],
  [/webpack:\/\//, "webpack", "build", "strong"],
  [/\/\.vite\/|vite\/modulepreload/, "Vite", "build", "strong"],
];

// ---- BUNDLE TEXT SIGNALS ----------------------------------------------------------------------
// WEAK ON PURPOSE. A bundle inlines its dependencies, so a string appearing in one is evidence
// that some code somewhere references it - not that this app uses it. These are here because they
// are the only signal for a few things, and they are labelled weak so the UI can say so.
const BUNDLE_SIGNALS = [
  [/__vite__|from"\/@vite\//, "Vite", "build", "strong"],
  [/webpackChunk|__webpack_require__/, "webpack", "build", "strong"],
  [/\bturbopack\b/i, "Turbopack", "build", "strong"],
  [/__NUXT__/, "Nuxt", "framework", "strong"],
  [/\$\$svelte|svelte\/internal/, "Svelte", "framework", "weak"],
  [/react-dom|createElement\(/, "React", "framework", "weak"],
];

// ---- VERSIONS: ONLY WHEN THE DEPLOYMENT PUBLISHES ONE ITSELF ---------------------------------
//
// The rule was "no version numbers, ever", and it was stricter than the doctrine requires. It
// conflated two different policies:
//
//   "Do not INFER vulnerability from a version"      correct, and unchanged
//   "Do not REPORT a version the site publishes"     wrong, and now reversed
//
// If a site serves `<meta name="generator" content="Hugo 0.148.2">`, that version is already
// public in its own HTML: we are not the disclosure vector, and refusing to repeat a measured
// observation to prevent an inference we are not making sits badly beside measure-never-manufacture.
//
// THE BOUNDARY THAT REPLACES IT: a version may be reported only where the deployment explicitly
// exposes it, and a version may never, on its own, produce a vulnerability, a severity or a
// remediation claim. Nothing here maps a version to a CVE, and nothing should: a version-to-CVE
// map from a passive banner is wrong more often than right, because distributions backport fixes
// without moving the version string.
//
// VERSION IS A PROPERTY OF AN OBSERVATION, NOT PART OF A TECHNOLOGY'S IDENTITY. It rides on the
// detection as an optional field with its own provenance, so the detector never becomes a
// version-matching engine, and "Next.js" with no readable version is a first-class answer.
//
// NEVER INFERRED. There is no "~14.x" and no bracketing from feature presence. Either the site
// stated it or we report nothing.
const VERSION_SIGNALS = [
  // [where, pattern with ONE capture group, technology, human-readable provenance]
  ["html", /<meta[^>]+name=["']generator["'][^>]+content=["']Astro\s+v?([0-9][\w.\-+]*)/i, "Astro", "generator metadata"],
  ["html", /<meta[^>]+name=["']generator["'][^>]+content=["']Hugo\s+v?([0-9][\w.\-+]*)/i, "Hugo", "generator metadata"],
  ["html", /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+v?([0-9][\w.\-+]*)/i, "WordPress", "generator metadata"],
  ["html", /<meta[^>]+name=["']generator["'][^>]+content=["']Ghost\s+v?([0-9][\w.\-+]*)/i, "Ghost", "generator metadata"],
  ["html", /<meta[^>]+name=["']generator["'][^>]+content=["']Gatsby\s+v?([0-9][\w.\-+]*)/i, "Gatsby", "generator metadata"],
  ["html", /<meta[^>]+name=["']generator["'][^>]+content=["']Docusaurus\s+v?([0-9][\w.\-+]*)/i, "Docusaurus", "generator metadata"],
  // Angular writes its version, and a build SHA, as a root attribute.
  ["html", /\sng-version=["']([0-9][\w.\-+]*)["']/i, "Angular", "ng-version attribute"],
  // A header the platform sets itself. Drupal deliberately publishes the MAJOR only, which is
  // exactly why we report what it said rather than a guess at the patch level.
  ["header:x-generator", /Drupal\s+([0-9][\w.]*)/i, "Drupal", "x-generator header"],
  ["header:x-powered-by", /PHP\/([0-9][\w.]*)/i, "PHP", "x-powered-by header"],
  ["header:server", /nginx\/([0-9][\w.]*)/i, "nginx", "server header"],
  ["header:server", /Apache\/([0-9][\w.]*)/i, "Apache", "server header"],
];

/** Read only versions the deployment published. Returns Map<technology, {version, source}>. */
function readVersions({ headers = {}, html = "" }) {
  const out = new Map();
  for (const [where, re, name, source] of VERSION_SIGNALS) {
    let subject = "";
    if (where === "html") subject = html;
    else if (where.startsWith("header:")) subject = String(headers[where.slice(7)] || "");
    if (!subject) continue;
    const m = re.exec(subject);
    if (m && m[1] && !out.has(name)) out.set(name, { version: m[1], versionSource: source });
  }
  return out;
}

// WHICH OBSERVATION CHANNEL PRODUCED A DETECTION.
//
// Needed so a later scan can tell "this is gone" from "I could not look". A technology seen in
// the bundles of scan A and absent from scan B means nothing at all if B could not read any
// bundle, and reporting that as REMOVED would be the same overclaim as reporting an unread script
// as clean. See lib/diff.mjs, which will not call an absence a removal unless the later snapshot
// could actually observe the channel the detection came from.
//
// Derived from the evidence prefix rather than passed at every call site, so the mapping lives
// beside the strings that produce it and cannot drift out of sync with fifteen callers. A test
// asserts every detection lands on a known channel, so a renamed prefix fails loudly instead of
// silently becoming "unknown".
const CHANNEL_PREFIX = [
  [/^cookie: /, "cookie"],
  // The combination signal emits its own prefix. Without this it fell through to "unknown", which
  // the diff treats as unobservable - so a Laravel detection from the cookie pair could never be
  // confirmed REMOVED, only ever reported as "could not confirm". Safe, but permanently mute.
  [/^cookie pair: /, "cookie"],
  [/^asset path: /, "assetpath"],
  [/^loads from /, "host"],
  [/^page markup: /, "markup"],
  [/^source map: /, "sourcemap"],
  [/^in served code: /, "bundle"],
  [/^(CNAME|MX|domain verification TXT): /, "dns"],
  [/^SPF record/, "dns"],
];

export function channelOf(evidence) {
  for (const [re, ch] of CHANNEL_PREFIX) if (re.test(evidence)) return ch;
  // Everything else is `header-name: value`, which is what the header signals emit.
  return /^[a-z0-9-]+: /i.test(evidence) ? "header" : "unknown";
}

function push(map, name, category, confidence, evidence) {
  const prev = map.get(name);
  const ch = channelOf(evidence);
  if (prev && RANK[prev.confidence] >= RANK[confidence]) {
    // Keep the stronger claim, but remember that more than one thing pointed at it.
    if (!prev.evidence.includes(evidence) && prev.evidence.length < 3) prev.evidence.push(evidence);
    if (!prev.channels.includes(ch)) prev.channels.push(ch);
    return;
  }
  map.set(name, {
    name,
    category,
    confidence,
    evidence: prev ? [evidence, ...prev.evidence].slice(0, 3) : [evidence],
    // EVERY channel that pointed at this technology, not just the strongest one's. A detection
    // confirmable from a response header does not become unconfirmable because it also appeared
    // in a bundle we could not read this time.
    channels: prev ? [...new Set([ch, ...prev.channels])] : [ch],
  });
}

function truncate(s, n = 120) {
  const t = String(s || "").replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

/**
 * @param {object} input everything already gathered by a scan
 * @param {Record<string,string>} input.headers root response headers, lowercased keys
 * @param {string} input.html the root HTML body
 * @param {string[]} input.scriptUrls same-origin + third-party script URLs referenced
 * @param {string} input.bundleText concatenated served code (already in hand as textBlobs)
 * @param {string[]} input.sourcemapPaths `sources[]` entries from any public source map
 * @param {string} input.cname the CNAME target the takeover check resolved
 * @param {string[]} input.txt apex TXT records
 * @param {string[]} input.mx MX hostnames
 * @returns {{items: Array, categories: string[]}}
 */
export function detectStack(input = {}) {
  const found = new Map();
  const headers = input.headers || {};

  // 1. Headers.
  for (const [key, test, name, category, confidence] of HEADER_SIGNALS) {
    const v = headers[key];
    if (v === undefined || v === null) continue;
    if (test && !test.test(String(v))) continue;
    push(found, name, category, confidence, `${key}: ${truncate(v, 60)}`);
  }

  // 2. Cookie NAMES only.
  // Prefer the real array. `set-cookie` as a single string is the joined form, which cannot be
  // split reliably because Expires values contain commas - the split below is a best effort for
  // callers that only have that, never the primary path.
  const setCookie = headers["set-cookie-list"] || headers["set-cookie"];
  const cookieNames = []
    .concat(Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [])
    .flatMap((line) => String(line).split(/,(?=[^;]+=)/))
    .map((c) => String(c).split("=")[0].trim())
    .filter(Boolean);
  for (const cname of cookieNames) {
    for (const [re, name, category, confidence] of COOKIE_SIGNALS) {
      if (re.test(cname)) push(found, name, category, confidence, `cookie: ${truncate(cname, 40)}`);
    }
  }

  // ---- COOKIE COMBINATIONS: signals that strengthen without establishing ------------------------
  //
  // The tables above evaluate one cookie at a time, so a signal can only ever establish a
  // technology or be left out entirely. Some evidence is genuinely weaker than that: `XSRF-TOKEN`
  // is Laravel's default CSRF cookie AND Angular's, so on its own it is a convention rather than a
  // fingerprint and must not name anything. A PAIR can be specific where neither member is.
  //
  // MEASURED, which is why this exists at all. Benchmarking Laravel detection found laravel.com and
  // nova.laravel.com undetected while genuinely running Laravel: their session cookies are
  // `laravelcom_session` and `laravel_nova_session`, because the name defaults to `{app}_session`
  // and the literal `laravel_session` only appears when nobody renamed the app. The cookie pair was
  // the only Laravel evidence either site emitted to an anonymous request.
  //
  // STRONG, NOT CONCLUSIVE. Any framework could set both; Laravel is simply the one that does by
  // default. Angular sets XSRF-TOKEN with no `*_session`, plain PHP sets `PHPSESSID`, and Rails
  // sets `_session_id` with a CSRF header rather than this cookie - all three are negative controls
  // in the test.
  const lower = cookieNames.map((c) => c.toLowerCase());
  const hasXsrf = lower.includes("xsrf-token");
  // `{app}_session`, excluding Rails' `_session_id` and a bare `session`.
  const appSession = cookieNames.find((c) => /^[a-z0-9][a-z0-9_-]*_session$/i.test(c));
  if (hasXsrf && appSession) {
    push(found, "Laravel", "framework", "strong",
      `cookie pair: XSRF-TOKEN + ${truncate(appSession, 30)}`);
  }

  // 3. Asset path conventions.
  for (const url of input.scriptUrls || []) {
    for (const [re, name, category, confidence] of PATH_SIGNALS) {
      if (re.test(url)) {
        let path = url;
        try { path = new URL(url).pathname; } catch {}
        push(found, name, category, confidence, `asset path: ${truncate(path, 60)}`);
      }
    }
  }

  // 3b. THIRD-PARTY SERVICES, from the hosts the page declares it LOADS FROM.
  //
  // Matched against RESOURCE urls only - script src, link href, iframe and img src - and never
  // against the raw HTML. Matching the whole document meant an ordinary <a href> in a footer
  // counted: a site linking to its own Snapchat profile was reported as running the ad pixel, and
  // a link to typesense.org as running Typesense. A vendor's marketing domain is usually also its
  // script domain, so no amount of per-pattern tightening fixes that; excluding <a href> does.
  //
  // Anchors are the only thing dropped. Iframes, stylesheets and preconnects stay, because those
  // are how several of these actually arrive.
  const resourceUrls = [
    ...(input.scriptUrls || []),
    ...[...String(input.html || "").matchAll(/<(?:script|iframe|img)[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]),
    ...[...String(input.html || "").matchAll(/<link[^>]+href=["']([^"']+)["']/gi)].map((m) => m[1]),
  ];
  const hostSubject = resourceUrls.join("\n");
  for (const [re, name, category] of HOST_SIGNALS) {
    const m = re.exec(hostSubject);
    if (m) push(found, name, category, "strong", `loads from ${truncate(m[0], 44)}`);
  }

  // 4. HTML markers.
  const html = input.html || "";
  for (const [re, name, category, confidence] of HTML_SIGNALS) {
    const m = re.exec(html);
    // Truncated hard. A couple of these match across a span of markup rather than one tag, so the
    // raw match is a wall of HTML - useless as evidence a person is meant to read at a glance.
    if (m) push(found, name, category, confidence, `page markup: ${truncate(m[0], 44)}`);
  }

  // 5. Source map dependency paths - the richest signal, and free.
  for (const p of input.sourcemapPaths || []) {
    for (const [re, name, category, confidence] of SOURCEMAP_SIGNALS) {
      if (re.test(p)) push(found, name, category, confidence, `source map: ${truncate(p, 60)}`);
    }
  }

  // 6. Bundle contents, weakest.
  const bundle = input.bundleText || "";
  if (bundle) {
    for (const [re, name, category, confidence] of BUNDLE_SIGNALS) {
      const m = re.exec(bundle);
      if (m) push(found, name, category, confidence, `in served code: ${truncate(m[0], 40)}`);
    }
  }

  // 7. DNS.
  if (input.cname) {
    for (const [re, name, category, confidence] of CNAME_SIGNALS) {
      if (re.test(input.cname)) push(found, name, category, confidence, `CNAME: ${truncate(input.cname, 60)}`);
    }
  }
  for (const rec of input.txt || []) {
    const line = String(rec);
    if (/^v=spf1/i.test(line)) {
      for (const [re, name, category, confidence] of SPF_SIGNALS) {
        if (re.test(line)) push(found, name, category, confidence, `SPF record names it`);
      }
    }
    for (const [re, name, category, confidence] of TXT_VERIFICATION_SIGNALS) {
      if (re.test(line)) push(found, name, category, confidence, `domain verification TXT: ${truncate(line.split("=")[0], 40)}`);
    }
  }
  for (const host of input.mx || []) {
    const h = String(host).toLowerCase();
    if (/aspmx.*google|googlemail\.com$/.test(h)) push(found, "Google Workspace", "email", "conclusive", `MX: ${truncate(h, 50)}`);
    else if (/outlook\.com$|protection\.outlook/.test(h)) push(found, "Microsoft 365", "email", "conclusive", `MX: ${truncate(h, 50)}`);
    else if (/zoho/.test(h)) push(found, "Zoho Mail", "email", "conclusive", `MX: ${truncate(h, 50)}`);
    else if (/protonmail|proton\.me/.test(h)) push(found, "Proton Mail", "email", "conclusive", `MX: ${truncate(h, 50)}`);
    else if (/mx\.cloudflare\.net$/.test(h)) push(found, "Cloudflare Email Routing", "email", "conclusive", `MX: ${truncate(h, 50)}`);
  }

  // Attach any version the DEPLOYMENT published, to the detection it belongs to. A version never
  // creates a detection: if we read "Hugo 0.148.2" from a generator tag but nothing else
  // identified Hugo, there is no Hugo row to hang it on and the version is discarded.
  const versions = readVersions({ headers, html });
  for (const [name, v] of versions) {
    const item = found.get(name);
    if (item) Object.assign(item, v);
  }

  const items = [...found.values()].sort((a, b) => {
    const d = RANK[b.confidence] - RANK[a.confidence];
    return d !== 0 ? d : a.name.localeCompare(b.name);
  });

  // IS A CDN STANDING IN FRONT OF THE ORIGIN?
  //
  // This matters because it changes what an empty result MEANS. TLS terminates at the edge and
  // the edge rewrites the response headers, so behind Cloudflare we are reading Cloudflare, not
  // the site. Reporting fewer technologies without saying so lets "there is nothing here" and
  // "we could not see past the edge" render identically - the same absence-of-looking problem the
  // receipt already refuses to have.
  //
  // It also means the opposite of what a naive reader assumes: a missing `x-powered-by` behind a
  // CDN is not the site failing to disclose, and it is not something to credit them for either.
  // It is us not being able to look.
  const edge = items.find((i) => i.category === "cdn");
  return {
    items,
    categories: [...new Set(items.map((i) => i.category))],
    originMasked: edge ? edge.name : null,
  };
}

// Display order for the categories, so the report reads outside-in: what serves it, what built
// it, what it talks to.
export const CATEGORY_ORDER = [
  "framework", "platform", "cms", "hosting", "cdn", "server", "language",
  "build", "css", "ui", "library", "backend", "auth", "payments",
  "email", "analytics", "marketing", "seo", "support", "ai", "tooling",
];

// ---- THE HUMAN-READABLE SUMMARY ---------------------------------------------------------------
//
// One plain sentence, because a founder asking "what is this built with" wants an answer, not a
// grid of eighty chips. This is the line BuiltWith never writes: it reads the grouped detections
// back as prose - "built with Next.js and React, hosted on Vercel, using Stripe for payments".
//
// ONLY THE CONFIDENT ONES. A weak signal ("react in a bundle string") is fine as a chip a reader
// can weigh, and wrong in a declarative sentence that asserts it. So the summary is built from
// conclusive and strong detections only; the weak ones stay in the chips with their "likely" tag.
//
// This is not an AI summary and does not call a model. It is a template over the same grouped
// data the chips use, so it can never say something the evidence does not - the whole product's
// rule, applied to prose.
const CLAUSE = {
  framework: (n) => `built with ${n}`,
  cms: (n) => `built on ${n}`,
  platform: (n) => `built on ${n}`,
  hosting: (n) => `hosted on ${n}`,
  cdn: (n) => `served through ${n}`,
  server: (n) => `running ${n}`,
  payments: (n) => `taking payments with ${n}`,
  analytics: (n) => `measured with ${n}`,
  auth: (n) => `authenticating with ${n}`,
  backend: (n) => `backed by ${n}`,
  email: (n) => `sending email through ${n}`,
  support: (n) => `with ${n} for support`,
};

// "A", "B" -> "A and B"; "A","B","C" -> "A, B and C".
function conjoin(names) {
  if (names.length <= 1) return names[0] || "";
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export function stackSummary(items, domain) {
  const strong = (items || []).filter((i) => i.confidence !== "weak");
  if (!strong.length) return null;

  const byCat = new Map();
  for (const it of strong) {
    if (!byCat.has(it.category)) byCat.set(it.category, []);
    byCat.get(it.category).push(it.name);
  }

  // Clauses in a reading order: what it IS, then where it runs, then what it talks to. Two names
  // per category at most, or the sentence sprawls; the chips carry the rest.
  const order = ["framework", "cms", "platform", "hosting", "cdn", "server", "payments", "auth", "backend", "analytics", "email", "support"];
  const clauses = [];
  for (const cat of order) {
    const names = byCat.get(cat);
    if (!names || !CLAUSE[cat]) continue;
    clauses.push(CLAUSE[cat](conjoin(names.slice(0, 2))));
    if (clauses.length >= 4) break; // a fifth clause is a paragraph, not a sentence
  }
  if (!clauses.length) return null;

  const subject = domain || "This site";
  // "appears to be", never "is": every signal here is something we SAW, and the scanner's whole
  // discipline is to say what it observed rather than assert what is true.
  return `${subject} appears to be ${clauses.join(", ")}.`;
}

export const CATEGORY_LABEL = {
  framework: "Framework", platform: "Platform", cms: "CMS", hosting: "Hosting",
  cdn: "CDN", server: "Web server", language: "Language", build: "Build tool",
  css: "Styling", ui: "UI library", library: "Library", backend: "Backend",
  auth: "Auth", payments: "Payments", email: "Email", analytics: "Analytics",
  marketing: "Marketing", seo: "SEO", support: "Support", ai: "AI", tooling: "Tooling",
};
