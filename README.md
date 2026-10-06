# xlogs

[![xlogs](https://xlogs.com/api/badge?repo=damnepic/xlogs-cli)](https://xlogs.com/github-scan)
[![npm](https://img.shields.io/npm/v/xlogs-scanner)](https://www.npmjs.com/package/xlogs-scanner)
[![license](https://img.shields.io/npm/l/xlogs-scanner)](LICENSE)

**A free, read-only security scanner for AI-built web apps.** Point it at a deployed URL. It finds the mistakes that actually get exploited in vibe-coded apps, explains each one in plain English with the evidence behind it, and hands you a fix you can paste straight into your AI coding tool.

```bash
npx xlogs-scanner https://your-app.com
```

Zero dependencies. Node 18+. No account, no API key, no repository access.

---

## Why this exists

Apps built with Lovable, Bolt, v0, Replit, Base44 and Cursor ship fast and work well. The parts that keep them safe are settings nobody turns on: database access rules, where secrets live, response headers. The app looks finished either way, so the gap is invisible until someone finds it.

These are not exotic vulnerabilities. They are ordinary requests that succeed because a protection was never enabled:

- A Supabase database with Row Level Security off returns your tables to anyone holding the public key, and that key ships in every browser.
- A secret key pasted into a file to make a feature work reaches every visitor if that file is part of the frontend.
- Source maps left on in production let anyone reconstruct your original code.

xlogs checks for exactly these, from the outside, the way a stranger would see them.

## What it checks

| Check | What it proves |
|---|---|
| Publicly readable database | Asks your Supabase tables for data as a logged-out stranger. Rows coming back means anyone can read them. |
| Secret keys in the browser | Reads your shipped JavaScript against 9 key formats (Stripe, OpenAI, Anthropic, AWS, Google, GitHub, Slack, private keys, Supabase `service_role`). |
| Missing security headers | Reports absent CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. |
| Exposed source maps | Whether production serves `.map` files that rebuild your original code. |
| Private files served publicly | Whether `.env` or `.git` are reachable. |
| Dangling DNS | Whether a DNS record points at a service that is gone, so someone else could claim it. |
| Email spoofing protection | Whether your domain publishes SPF and DMARC. |

It also reports what built the app, where it is hosted, the external services it references, and other addresses on your domain found in public certificate logs.

## Read-only, always

Every request is an ordinary `GET`. There are no `POST`, `PUT`, `PATCH` or `DELETE` requests anywhere in this tool. It never logs in, never writes, and never tries to exploit what it finds. It needs no account and no repository access.

That is a design constraint, not a limitation we are apologising for. A scanner that attacks the thing it is scanning is a scanner you cannot safely point at production.

Private, loopback, link-local and cloud-metadata addresses are refused before any request, and that check runs again on every redirect hop.

**Scan only apps you own or are authorised to test.**

## Severity has to be earned

False positives are the reason people stop trusting security tools. So this one deliberately does *not* report:

- A **public Supabase anon key** in your bundle. It is designed to ship. Only a `service_role` key is flagged.
- Any other **JWT** it happens to find. Session tokens look like secrets and are not.
- A **200 response for `/.env`** on its own. Plenty of single-page apps answer 200 for every path, so the response has to actually look like an env file.
- A **`.map` URL that resolves but is not a source map.**
- A **CNAME pointing at your hosting provider.** That is what a normal custom domain looks like. Only a target that no longer resolves, or one whose provider says nothing is claimed there, is reported.
- **Missing SPF or DMARC on a platform subdomain** (`my-app.vercel.app`), because those records belong to the platform and you cannot change them.

There is no score out of 100. A single number has to be tuned to look meaningful, and the tuning is where honesty goes.

## Every scan shows its work

A clean result is only useful if you can tell "we looked and it held" from "we did not look". So each check reports what it actually did:

```
what we checked
  ✓ Database exposed to the public     Asked 6 tables for data as a logged-out stranger. None returned rows.
  ✓ Secret keys shipped to the browser Read 4 of 4 scripts your app loads, checking each against 9 key formats.
  ! Protective security headers        Checked 5 headers on your homepage response. 2 of 5 were set.
  · Original source code downloadable  No bundles referenced a source map, so there was nothing to expose.
```

If a check cannot complete, it says `inconclusive` rather than quietly passing.

## Use it in CI

```bash
npx xlogs-scanner https://your-app.com --fail-on high
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Nothing at or above `--fail-on` |
| `1` | A finding at or above `--fail-on` |
| `2` | A critical finding (when `--fail-on` is not used) |
| `3` | Usage error, or the target could not be reached |
| `4` | Nothing at or above `--fail-on`, but a security check could not run, so the gate cannot call it a pass |

Exit 4 is new. The most common cause: hosted Supabase stopped letting a public key list a project's tables in April 2026, so the database check cannot run on most Supabase apps. A gate that could not test your database has not passed it. Add `--allow-inconclusive` to accept such gaps explicitly; the gate still names every check that did not run.

The gate is read-only. It blocks a deploy; it never touches your repository and needs no token with write access.

### GitHub Actions

This repository is a GitHub Action. It runs the scanner from the tag you pin, so it needs nothing
from npm, no token and no checkout of your code:

```yaml
name: Security
on: deployment_status

permissions:
  security-events: write   # only for the SARIF upload; the scan itself needs no permission

jobs:
  xlogs:
    # deployment_status fires for pending and failed deployments too; scan only a live one.
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: damnepic/xlogs-cli@v0.2.2
        with:
          url: ${{ github.event.deployment_status.environment_url || github.event.deployment_status.target_url }}
          fail-on: high
          sarif: xlogs.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()   # upload the findings even when the gate failed the job
        with:
          sarif_file: xlogs.sarif
```

Inputs: `url` (required), `fail-on` (default `high`), `allow-inconclusive` (default `false`) and
`sarif` (optional path). The URL is handed to the scanner as an environment variable, never pasted
into a shell command, so an event payload cannot become code. There is deliberately no stack-only
input: a gate that skipped the private-file and database checks would pass by not looking.

If your preview deployments sit behind a login (Vercel Deployment Protection, for example), the
scanner reads the login page, not your app, and the gate fails with exit 4 rather than passing.
Point it at your production URL instead, on a schedule or after a production deploy.

Findings appear in the repository's Security tab, tagged with their CWE. Pin the action to a commit
SHA rather than a tag if your policy requires it.

## Use it from your coding agent (MCP)

`xlogs mcp` runs the same scanner as an MCP server over stdio, so Claude Code, Cursor, Windsurf or
any MCP client can scan your deployment and read back the findings, the receipt and the fixes.

```bash
claude mcp add xlogs -- npx -y github:damnepic/xlogs-cli#v0.2.2 mcp
```

Any other client takes the same command in its MCP config:

```json
{ "mcpServers": { "xlogs": { "command": "npx", "args": ["-y", "github:damnepic/xlogs-cli#v0.2.2", "mcp"] } } }
```

Four tools: `xlogs_scan` (findings, with a `stack_only` option for a site you do not own),
`xlogs_receipt` (what was and was not checked), `xlogs_fix` (one paste-ready fix document) and
`xlogs_supabase_audit_sql` (read-only SQL you run yourself). The scan runs on your machine; nothing
is sent to xlogs. Needs Node 18.18+ and git (npx fetches the tagged release from GitHub).

## Options

```
npx xlogs-scanner <url> [options]

  --fail-on <sev>  critical | high | medium | low
  --sarif <file>   write SARIF 2.1.0
  --json           full result as JSON
  --agent <name>   default | lovable | cursor | claude-code | manual
  --stack-only     read only what a browser already fetches (for sites you do not own)
  --allow-inconclusive  let --fail-on pass when a check could not run (still named)
  --quiet          findings only
  -h, --help       help
  -v, --version    version

npx xlogs-scanner mcp    run as an MCP server over stdio (see above)
```

## Use it as a library

```js
import { scanUrl } from "xlogs-scanner";
import { toSarif } from "xlogs/sarif";

const result = await scanUrl("https://your-app.com");
console.log(result.verdict.headline, result.findings.length);
```

## What it does not do

Being clear about this matters more than looking capable:

- **It does not read your source code.** It scans a deployed URL, so issues only visible in source, such as SQL injection or unsafe HTML rendering, are out of scope.
- **It does not scan dependencies for CVEs.** Use Snyk, Dependabot or similar.
- **It is not compliance evidence.** An xlogs scan is not an artifact for SOC 2, ISO 27001 or PCI DSS, and should never be presented as one.
- **It cannot see behind a login**, into cloud or container configuration, or inside Firebase security rules.

A clean scan means these checks found nothing. It does not mean your app is secure.

## Determinism

There is no LLM anywhere in the scan path. The checks are deterministic and the fixes come from a fixed knowledge base, so the same app returns the same result. You can re-run it and compare.

## The hosted version

[xlogs.com](https://xlogs.com) runs the same engine in the browser: paste a URL, get the same findings, fixes and coverage receipt, with no install. It is free and nothing is gated.

## License

MIT
