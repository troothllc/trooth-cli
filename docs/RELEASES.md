# Checking a `trooth` release

Each version of `trooth` published from a tag (from the release after 0.23.1, tracker C4) carries these files on its
GitHub release at https://github.com/troothllc/trooth-cli/releases:

| File | What it is |
|---|---|
| `trooth-<version>.tgz` | The exact tarball npm serves for that version. It is packed once in the publish job, and that file is the one published. |
| `trooth-<version>.cdx.json` | Its software bill of materials, CycloneDX, from `npm sbom --omit dev`. |
| `SHA256SUMS` | The SHA-256 of the two files above. |
| `<file>.sigstore.json` | A Sigstore bundle for each file above: a keyless cosign signature whose certificate names the publish workflow at that tag, logged in Rekor, the public transparency log. |

npm also holds a provenance statement for each version (`npm audit signatures` checks it).

## Check the signature

```
V=0.24.0   # the version you have
for f in trooth-$V.tgz trooth-$V.cdx.json SHA256SUMS; do
  cosign verify-blob "$f" --bundle "$f.sigstore.json" \
    --certificate-identity "https://github.com/troothllc/trooth-cli/.github/workflows/publish.yml@refs/tags/v$V" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
sha256sum -c SHA256SUMS
```

## Check where it was built (build provenance)

Each release file also has GitHub's build provenance attestation (SLSA): a signed statement that it was built by
`.github/workflows/publish.yml` on GitHub's hosted runners at the tagged commit, never on a workstation.

```sh
gh attestation verify trooth-$V.tgz --repo troothllc/trooth-cli
```

## Check that npm serves the same tarball

```
npm pack trooth@$V && sha256sum -c SHA256SUMS
```

Every line has to pass. A signature that does not check, a certificate naming another workflow or another tag, or a
checksum that does not match means the file did not come from this repository's publish job: do not install it, and
write to security@trooth.co.
