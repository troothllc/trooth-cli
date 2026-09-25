// The job summary for the Trooth lint action: what was read, as a table.
//
//   node action/summary.mjs <report.json> <exit-code> <stderr-file>
//
// Prints Markdown to stdout; action.yml appends it to $GITHUB_STEP_SUMMARY.
// It prints counts, type names and region strings: the same things the CLI
// prints, and nothing the CLI withholds. There is no verdict line, no
// threshold and no color, because lint has none to report.
import { readFileSync, existsSync } from "node:fs";

const [reportPath, codeArg, stderrPath] = process.argv.slice(2);
const code = Number(codeArg || "0");
const out = [];
out.push("## Trooth lint (advisory)");
out.push("");

if (code === 2) {
  const err = stderrPath && existsSync(stderrPath) ? readFileSync(stderrPath, "utf8").trim() : "";
  out.push(`The action could not run: ${err.split("\n")[0] || "usage error"}.`);
  console.log(out.join("\n"));
  process.exit(0);
}

let doc = null;
try { doc = JSON.parse(readFileSync(reportPath, "utf8")); } catch { /* handled below */ }

if (!doc || code === 1) {
  const root = doc?.root ? ` under \`${doc.root}\`` : "";
  out.push(`No infrastructure declarations were found${root}. lint reads \`.tf\`, \`.tf.json\`, Kubernetes YAML (apiVersion + kind), \`terraform show -json\` plan files and Dockerfiles. This is a fact about the directory the action was pointed at, not about your infrastructure.`);
  console.log(out.join("\n"));
  process.exit(0);
}

const f = doc.facts || {};
const sources = Object.entries(f.sources || {}).map(([k, v]) => `${k} ${v}`).join(" · ") || "none";
const regions = (f.regions_and_zones_declared || []).join(", ") || "none declared";
const types = (f.resource_types || []).map((t) => `${t.type} (${t.count})`).join(", ") || "none";

out.push(`Read \`${doc.root}\` with trooth ${doc.cli_version} at ${doc.observed_at}. Declared facts only, read locally; nothing was transmitted. No verdict and no assessment against any standard.`);
out.push("");
out.push("| Declared | |");
out.push("|---|---|");
out.push(`| Declaration files read | ${f.declarations_read ?? 0} (${sources}) |`);
out.push(`| Regions and zones | ${regions} |`);
out.push(`| Storage declarations | ${f.storage_declarations ?? 0} |`);
out.push(`| of those declaring encryption | ${f.storage_declaring_encryption ?? 0} |`);
out.push(`| Logging declarations | ${f.logging_declarations ?? 0} |`);
out.push(`| Identity declarations | ${f.identity_declarations ?? 0} |`);
out.push(`| Open to any address (0.0.0.0/0, ::/0) | ${f.declarations_open_to_any_address ?? 0} |`);
out.push(`| Marked public | ${f.declarations_marked_public ?? 0} |`);
out.push(`| Inline credential literals | ${f.inline_credential_literals ?? 0} (a count; the literals are never printed) |`);
out.push(`| Resource types | ${types} |`);
out.push(`| Digest | \`${doc.digest || ""}\` |`);
out.push("");
out.push("What these facts mean is your decision: declaring public ingress is not a failing, because a load balancer is supposed to be public. A green step says the read happened. It is not evidence that Trooth has ingested anything; nothing is sent to Trooth.");
console.log(out.join("\n"));
