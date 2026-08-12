// SARIF 2.1.0 export (XL-041) — so an xlogs finding can be opened in VS Code, or
// uploaded to GitHub code scanning, like any other security tool's output.
//
// Free and ungated, like every other finding output: SARIF is a format, not a feature
// to sell. Doctrine 3 forbids gating it.
//
// Location note: xlogs scans a deployed URL, not a checkout, so artifactLocation.uri is
// the live URL of the affected asset. SARIF permits an absolute URI here. We never
// invent a file path or line number we did not observe, so no `region` is emitted.

const SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

// GitHub code scanning reads properties["security-severity"] (a CVSS-like number) to
// bucket findings. Mapping is stated explicitly rather than hidden in a helper.
const SEVERITY_SCORE = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" };
const SEVERITY_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };

function ruleFor(f) {
  const tags = ["security"];
  if (f.cwe) tags.push("external/cwe/" + f.cwe.toLowerCase().replace("cwe-", "cwe-"));
  if (f.owasp) tags.push("external/owasp/" + f.owasp.split(":")[0].toLowerCase());
  const rule = {
    id: f.vulnId || f.category,
    name: (f.vulnId || f.category).replace(/(^|-)(\w)/g, (_, a, b) => a.replace("-", "") + b.toUpperCase()),
    shortDescription: { text: f.title || f.category },
    fullDescription: { text: f.plain || f.title || f.category },
    help: {
      text: [f.plain, f.requiredState ? "Goal: " + f.requiredState : "", ...(f.fixSteps || [])].filter(Boolean).join("\n"),
      markdown: [
        f.plain ? `**What this means:** ${f.plain}` : "",
        f.whyAi ? `**Why AI tools cause it:** ${f.whyAi}` : "",
        f.requiredState ? `**Goal:** ${f.requiredState}` : "",
        (f.fixSteps || []).length ? "**Steps:**\n" + f.fixSteps.map((s) => `1. ${s}`).join("\n") : "",
        f.verify ? `**Verify:** ${f.verify}` : "",
      ].filter(Boolean).join("\n\n"),
    },
    defaultConfiguration: { level: SEVERITY_LEVEL[f.severity] || "warning" },
    properties: {
      tags,
      "security-severity": SEVERITY_SCORE[f.severity] || "5.5",
      precision: "high",
    },
  };
  if (f.cwe) rule.properties.cwe = f.cwe;
  if (f.owasp) rule.properties.owasp = f.owasp;
  return rule;
}

/**
 * Convert an xlogs scan result into a SARIF 2.1.0 log.
 * @param {object} result  the object returned by scanUrl()
 * @param {object} opts    { version, scannedAt }
 */
export function toSarif(result, { version = "0.1", scannedAt } = {}) {
  const findings = result?.findings || [];

  // One rule per distinct vuln class, in first-seen order.
  const seen = new Map();
  for (const f of findings) {
    const id = f.vulnId || f.category;
    if (!seen.has(id)) seen.set(id, ruleFor(f));
  }
  const rules = [...seen.values()];
  const ruleIndex = new Map([...seen.keys()].map((id, i) => [id, i]));

  const results = findings.map((f) => {
    const id = f.vulnId || f.category;
    // Prefer the concrete affected URL (an endpoint, a bundle, a map file); fall back
    // to the scanned URL. Never fabricate a path we did not observe.
    const uri = /^https?:\/\//i.test(f.location || "") ? f.location : result.url;
    const r = {
      ruleId: id,
      ruleIndex: ruleIndex.get(id),
      level: SEVERITY_LEVEL[f.severity] || "warning",
      message: { text: f.observed || f.plain || f.title || id },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
      properties: { severity: f.severity },
    };
    // Where the finding is about a named thing that is not a URL (a table, a header
    // list), record it as a property rather than pretending it is a file location.
    if (f.location && uri !== f.location) r.properties.affected = f.location;
    if (f.cwe) r.properties.cwe = f.cwe;
    return r;
  });

  return {
    $schema: SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "xlogs",
            fullName: "xlogs live security scanner",
            informationUri: "https://xlogs.com",
            semanticVersion: version,
            rules,
          },
        },
        // The scanned target, so a reader knows what this log describes.
        automationDetails: { id: `xlogs/${result.url || "scan"}` },
        invocations: [
          {
            executionSuccessful: !!result.reachable,
            ...(scannedAt || result.scannedAt ? { endTimeUtc: scannedAt || result.scannedAt } : {}),
          },
        ],
        results,
      },
    ],
  };
}
