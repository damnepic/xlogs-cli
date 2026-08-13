# Publishing xlogs-scanner (XL-014)

Step-by-step to take this package from local to live on GitHub + npm. The code is built
and tested; this is the release checklist. Owner runs these (they need your GitHub and
npm credentials, which Claude does not have).

## 0. Name check (already done)

The bare name `xlogs` is TAKEN on npm (unrelated package by "yuedud" since 2025-04). This
package is therefore named **`xlogs-scanner`**. The installed command stays the short
`xlogs`. If you prefer the scoped name `@damnepic/xlogs` instead, change `name` in
package.json to `@damnepic/xlogs` and publish with `--access public` (step 6 note).

Verify the chosen name is still free right before publishing:

```bash
npm view xlogs-scanner version   # a 404 means available
```

## 1. Log in to npm

You need an npm account (npmjs.com) with 2FA on. Then:

```bash
npm whoami        # should print your username; if not:
npm login         # opens a browser / prompts for OTP
```

## 2. Final local verification

```bash
cd C:/xlogs-cli
node test/smoke.mjs                 # must print SMOKE TEST PASSED
node bin/xlogs.mjs https://example.com --quiet   # sanity run
npm pack --dry-run                  # shows EXACTLY what will publish
```

In the `npm pack --dry-run` output, confirm the file list is only `bin/`, `lib/`,
`README.md`, `LICENSE`, `package.json`. If anything private appears, stop: the `files`
allowlist in package.json is the gate, check it before continuing.

## 3. Create the GitHub repo

The package.json `repository` points at `github.com/damnepic/xlogs-cli`. Create that repo
(empty, public, no README/license so it does not conflict), then:

```bash
cd C:/xlogs-cli
git init
git add -A
git commit -m "xlogs-scanner: open-source read-only security scanner for AI-built apps"
git branch -M main
git remote add origin https://github.com/damnepic/xlogs-cli.git
git push -u origin main
```

Add repo topics on GitHub for discovery: `security`, `vibe-coding`, `supabase`, `scanner`,
`appsec`, `cli`. Set the About blurb and the xlogs.com link.

## 4. Tag the release

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 5. Publish to npm

```bash
cd C:/xlogs-cli
npm publish            # for an unscoped name like xlogs-scanner
# If you switched to the scoped name @damnepic/xlogs, instead run:
# npm publish --access public
```

npm will prompt for your 2FA OTP. On success it prints the published name + version.

## 6. Verify it is live

```bash
npm view xlogs-scanner
npx xlogs-scanner https://example.com     # runs it straight from the registry
```

Also open `https://www.npmjs.com/package/xlogs-scanner` and confirm the README renders.

## 7. Wire it back into the site + outreach

- The site already documents the CI gate with the installed `xlogs` command; no change
  needed there. If you want the npx one-liner on a page, it is `npx xlogs-scanner <url>`.
- Kick off `docs/research/roundup-outreach.md` in the main repo: the published package is
  the prerequisite for every pitch in it.
- Update the ledger row XL-014 to BUILT-WIRED with the npm + GitHub URLs.

## Releasing an update later

```bash
npm version patch      # bumps package.json + creates a git tag
git push && git push --tags
npm publish
```

## Guardrails

- The `files` allowlist is what keeps private code out of the tarball. Never remove it.
- This package must never contain telemetry. It is the open-source, offline-capable CLI;
  it makes only the scan's own outbound requests to the target URL, nothing to xlogs.com.
  (The hosted scanner's anonymous counters live in the private app, not here.)
- Keep it zero-dependency. A supply-chain-clean scanner is part of the pitch.
