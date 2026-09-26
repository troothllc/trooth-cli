// Step outputs for the Trooth lint action, in $GITHUB_OUTPUT form.
//
//   node action/outputs.mjs <report.json> <exit-code>
import { readFileSync } from "node:fs";

const [reportPath, codeArg] = process.argv.slice(2);
let doc = null;
try { doc = JSON.parse(readFileSync(reportPath, "utf8")); } catch { /* no document */ }
const f = (doc && doc.facts) || {};
const lines = [
  `facts-digest=${(doc && (doc.facts_digest || doc.digest)) || ""}`,
  `digest=${(doc && (doc.facts_digest || doc.digest)) || ""}`,
  `completeness=${(doc && doc.coverage && doc.coverage.completeness) || (doc && doc.facts ? "complete" : "")}`,
  `declarations-read=${Number(f.declarations_read || 0)}`,
  `inline-credential-literals=${Number(f.inline_credential_literals || 0)}`,
  `exit-code=${Number(codeArg || 0)}`,
];
console.log(lines.join("\n"));
