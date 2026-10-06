// The MCP tool definitions, with no imports (2026-10-06). mcp-server.mjs serves these and /mcp
// publishes them, so the page cannot describe a tool the server does not have, or describe one
// differently from what a coding agent is told.
//
// THE DESCRIPTION IS WHAT THE AGENT DECIDES WITH. The first version told agents the scan "never
// sends a request the site's own visitors do not". A full scan requests /.env and /.git/config and
// reads one row of each database table it finds; no visitor does that. An agent choosing whether to
// run a tool against a URL is owed the truth about what the tool sends.

const URL_PROP = { type: "string", description: "The deployed app's URL, e.g. https://myapp.vercel.app" };
const STACK_ONLY_PROP = {
  type: "boolean",
  description: "Read only what a browser loading the page already fetches: skips the private-file requests and the database read. Use it for a site you do not own. Defaults to false (the full scan, for your own deployment).",
};

export const MCP_TOOLS = [
  {
    name: "xlogs_scan",
    description:
      "Scan a deployed web app read-only for exposed secrets, publicly readable database tables, source maps, private files, missing security headers and DNS problems. Returns findings with evidence. Every request is a GET from this machine. Besides what a visitor fetches (the page, its scripts and source maps, a few of its own pages), a full scan requests files that must never be public (such as /.env and /.git/config) and /package-lock.json, and reads one row of each database table it finds as an anonymous user. It never writes, never sends credentials, and never exploits a finding. Run the full scan on your own deployment; for a site you do not own, pass stack_only: true. Free, no key.",
    inputSchema: {
      type: "object",
      properties: { url: URL_PROP, stack_only: STACK_ONLY_PROP },
      required: ["url"],
    },
  },
  {
    name: "xlogs_receipt",
    description:
      "What a scan CHECKED, not what it found: every check with its status (clear, found, not applicable, or could-not-complete) and the reason. Use this to tell 'nothing was found' apart from 'nothing was looked at'. Reuses the scan xlogs_scan just ran for the same URL instead of scanning again. Also lists what xlogs never checks on any site.",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string", description: "The deployed app's URL" }, stack_only: STACK_ONLY_PROP },
      required: ["url"],
    },
  },
  {
    name: "xlogs_fix",
    description:
      "Return one paste-ready document containing every finding's fix, ordered by severity, with what was observed and how to verify each change. Written for a coding agent to act on directly. Reuses the scan xlogs_scan just ran for the same URL instead of scanning again.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The deployed app's URL" },
        agent: { type: "string", description: "Which tool the fixes are written for: claude-code (default), cursor, lovable, codex, or manual" },
        stack_only: STACK_ONLY_PROP,
      },
      required: ["url"],
    },
  },
  {
    name: "xlogs_supabase_audit_sql",
    description:
      "Return read-only SQL the USER runs in their own Supabase editor to answer what an outside scan cannot: which tables have row level security off, what every policy's predicate actually is, which storage buckets are public, and what anon has been granted directly. Reads system catalogues only and selects from no application table. Sends no request at all; xlogs never connects and never receives the output.",
    inputSchema: { type: "object", properties: {} },
  },
];
