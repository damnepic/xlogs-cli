// `xlogs mcp` speaks MCP over stdio: initialize, list the tools, answer a call that sends no network
// request. Spawns the real binary, so this proves the packaged file set, not just the source.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const bin = fileURLToPath(new URL("../bin/xlogs.mjs", import.meta.url));
const child = spawn(process.execPath, [bin, "mcp"], { stdio: ["pipe", "pipe", "pipe"] });
let out = "";
child.stdout.on("data", (d) => (out += d));
const send = (m) => child.stdin.write(JSON.stringify(m) + "\n");
send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
send({ jsonrpc: "2.0", method: "notifications/initialized" });
send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "xlogs_supabase_audit_sql", arguments: {} } });
send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "no_such_tool", arguments: { url: "https://example.com" } } });
child.stdin.end();

const timer = setTimeout(() => { console.error("MCP SMOKE TEST FAILED: timed out"); child.kill(); process.exit(1); }, 20000);
child.on("close", () => {
  clearTimeout(timer);
  const byId = new Map(out.split("\n").filter(Boolean).map((l) => JSON.parse(l)).map((m) => [m.id, m]));
  const checks = [
    [byId.get(1)?.result?.serverInfo?.name === "xlogs-mcp", "initialize answers with the server name"],
    [JSON.stringify((byId.get(2)?.result?.tools || []).map((t) => t.name)) === JSON.stringify(["xlogs_scan", "xlogs_receipt", "xlogs_fix", "xlogs_supabase_audit_sql"]), "tools/list returns the four tools"],
    [(byId.get(2)?.result?.tools || [])[0]?.inputSchema?.properties?.stack_only?.type === "boolean", "xlogs_scan offers stack_only"],
    [/system catalogues/.test(byId.get(3)?.result?.content?.[0]?.text || "") && byId.get(3)?.result?.isError === false, "the SQL tool answers without a network request"],
    [byId.get(4)?.result?.isError === true && /unknown tool/.test(byId.get(4)?.result?.content?.[0]?.text || ""), "an unknown tool is refused before anything is sent"],
  ];
  let failed = 0;
  for (const [c, m] of checks) { console.log(`  ${c ? "ok  " : "FAIL"} ${m}`); if (!c) failed = 1; }
  console.log(failed ? "MCP SMOKE TEST FAILED" : "MCP SMOKE TEST PASSED");
  process.exit(failed);
});
