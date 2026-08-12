// Renders the shared knowledge object into a finding's remediation, and provides the
// stable finding-key for the Verify loop.
//
// Doctrine: the canonical security truth (requiredState + fixSteps + verify) lives ONCE
// per vuln in vulns.mjs. This file's `fixForAgent` is the ADAPTER: it translates that
// one truth into an instruction phrased for a given coding tool. The truth never
// fragments by agent — only its presentation does. So 50 vulns x 15 builders stays as
// 50 truths + one adapter, not 750 hand-written strings.

import { vulnForCategory } from "./vulns.mjs";

const AGENT_LABEL = { default: "your AI coding tool", lovable: "Lovable", cursor: "Cursor", "claude-code": "Claude Code", manual: "yourself" };

function fill(tpl, location) {
  return (tpl || "").replaceAll("{location}", location || "the spot shown");
}

// The adapter: canonical requiredState + fixSteps -> an instruction for one agent.
export function fixForAgent(v, agent, location) {
  const loc = location || "the spot shown";
  const steps = v.fixSteps.map((s) => fill(s, loc)).join("; ");
  if (agent === "manual") {
    return `Goal: ${v.requiredState}\nSteps: ${steps}.`;
  }
  const where = {
    lovable: "In my Lovable app",
    cursor: "In my codebase",
    "claude-code": "In my codebase",
    default: "In my app",
  }[agent] || "In my app";
  return `${where} (${loc}): ${v.title.toLowerCase()}. Please make this true: ${v.requiredState} Steps: ${steps}. Then tell me exactly what you changed, and do not print any secret values back to me.`;
}

// Render the plain-English remediation for one finding as markdown.
export function renderRemediation({ category, location }, { agent = "default" } = {}) {
  const v = vulnForCategory(category);
  if (!v) return "";
  const L = [];
  L.push(`  - **What this means:** ${v.plain}`);
  L.push(`  - **Fix it with ${AGENT_LABEL[agent] || AGENT_LABEL.default}** — paste this to your AI tool:`);
  L.push("");
  L.push("    ```text");
  L.push("    " + fixForAgent(v, agent, location));
  L.push("    ```");
  L.push(`  - **Verify:** ${v.verify}`);
  L.push(`  - _Technical: ${fill(v.evidence, location)}_`);
  return L.join("\n");
}

// A stable identity for a finding so the Verify loop can tell FIXED vs STILL-PRESENT
// vs NEW across two scans.
export function findingKey(kind, f) {
  if (kind === "confirmed") return `confirmed|${f.name}|${(f.repoLocations || []).join(",")}`;
  if (kind === "live-secret") return `live-secret|${f.name}|${f.value}`;
  if (kind === "exposure") return `exposure|${f.kind}|${f.url}`;
  if (kind === "header") return `header|${f.header}`;
  if (kind === "source") return `source|${f.ruleId}|${f.location}`;
  if (kind === "rls") return `rls|${f.table}`;
  return `${kind}|${JSON.stringify(f)}`;
}
