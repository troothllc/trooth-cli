// tests/release-signing.test.mjs - golive231 (tracker C4): the publish job packs the tarball once, publishes that
// file, writes its SBOM and SHA256SUMS, signs each with cosign keyless, and attaches them to the tag's release; and
// docs/RELEASES.md tells a reader how to check them with the same identity the job signs under.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const wf = readFileSync(".github/workflows/publish.yml", "utf8");
const doc = readFileSync("docs/RELEASES.md", "utf8");
let n = 0;
const t = (name, fn) => { fn(); n++; console.log("  ok   " + name); };
const at = (s) => { const i = wf.indexOf(s); assert.ok(i >= 0, `publish.yml lacks: ${s}`); return i; };

t("the tarball is packed once and that file is published", () => {
  assert.ok(at("npm pack --pack-destination release") < at('npm publish "./release/trooth-'));
  assert.doesNotMatch(wf, /\n\s+run: npm publish --provenance --access public\n/);
  assert.match(wf, /npm publish "\.\/release\/trooth-\$\(node -p "require\('\.\/package\.json'\)\.version"\)\.tgz" --provenance --access public/);
});
t("an SBOM and SHA256SUMS are written after the publish", () => {
  assert.ok(at('npm sbom --sbom-format cyclonedx --omit dev > "release/trooth-$V.cdx.json"') > at('npm publish "./release/trooth-'));
  at('sha256sum "trooth-$V.tgz" "trooth-$V.cdx.json" > SHA256SUMS');
});
t("each release file is signed keyless and logged, then attached to the tag's release", () => {
  assert.ok(at("sigstore/cosign-installer@v3") < at('cosign sign-blob --yes --bundle "$f.sigstore.json" "$f"'));
  assert.ok(at("cosign sign-blob") < at('gh release upload "$GITHUB_REF_NAME" release/* --clobber'));
  assert.match(wf, /contents: write # the GitHub release/);
  assert.match(wf, /id-token: write # the OIDC token npm trusted publishing and Sigstore keyless signing exchange/);
});
t("the reader's check names the identity the job signs under", () => {
  assert.ok(doc.includes('--certificate-identity "https://github.com/troothllc/trooth-cli/.github/workflows/publish.yml@refs/tags/v$V"'));
  assert.ok(doc.includes('--certificate-oidc-issuer "https://token.actions.githubusercontent.com"'));
  assert.ok(doc.includes("sha256sum -c SHA256SUMS"));
});
t("C4a: GitHub's build provenance attestation for every release file, before the release is made", () => {
  assert.match(wf, /attestations: write/);
  assert.ok(at("actions/attest-build-provenance@v3") > at("cosign sign-blob"));
  assert.ok(at("actions/attest-build-provenance@v3") < at('gh release upload "$GITHUB_REF_NAME" release/* --clobber'));
  assert.match(wf, /subject-path: \|\n\s+release\/trooth-\*\.tgz\n\s+release\/trooth-\*\.cdx\.json\n\s+release\/SHA256SUMS/);
});

console.log(`\nrelease-signing: ${n} ok`);

