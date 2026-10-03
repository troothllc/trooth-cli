# Changelog

Each release of `trooth` on npm. The README's "Changed in" sections summarise the same entries.

## 0.6.0

### `check` reads the one record projection

- `trooth check <domain>` now sends `GET https://trooth.co/api/network/profile?q=<domain>&contract=2`. That route is the one public record projection. The website's record page, the REST API, the MCP server (`trooth_public_trust_profile`, `trooth_ai_data_use_disclosures`) and the llms.txt twin all read it, and the server validates it against [network-profile.v2.schema.json](https://trooth.co/schemas/network-profile.v2.schema.json) before sending it. Up to 0.5.1, `check` read `GET https://api.trooth.co/directory/api/vendors/<domain>`, a different body with different fields. So the CLI could not be held to the same contract as the other surfaces.
- The contract number is pinned in the request. A server that stops serving contract 2 refuses with 400, and the CLI exits 3 rather than misreading a new shape.
- `check --json` carries the projection body whole, under `record`. Each fact has its `key`, `category`, `label`, `value` and `origin`, its typed `claim` and its `record` (record version, issuer, source reference, freshness), exactly as the API serves them. `conflicts`, `witnessed`, `signing` and `methodology` come with it.
- `check --json` adds `source`. It says which surface answered (`record_projection` or `directory_fallback`), the URL read and the contract and schema. It also carries the record version: `record_version`, `record_digest` and `record_previous_digest` come from the `Trooth-Record-Version`, `Trooth-Record-Digest` and `Trooth-Record-Previous-Digest` headers, the same values the MCP server reports, and `record_updated_at` is the body's `updatedAt`. A value the server does not state is `null` and is never guessed.
- `check --json` also adds `slug`, `first_witnessed_at`, `coverage` (the last reading's counts, with their source), `facts_published` and `facts_contested`. `probes` and `authority_key_id` keep their 0.5 names: the same counts and the signing key id.
- From a projection read, `check --json` no longer emits `badge_id`, `attested`, `events`, `receipt_signature` or `first_published_at`, because the projection does not carry them. A fallback read still emits them.
- The human output prints the record version, the URL it read, the last reading's counts in the wording the MCP server uses, and every published fact under its category with the label of who stated or observed it. It also says what is signed.

### The fallback, labelled

- The directory feed is read only when the projection cannot be reached: a connection failure, the deadline, or a 5xx after one retry. A fallback answer is labelled as such in every mode. The human output starts with `FALLBACK READ.` and the reason, stderr says so, and `--json` carries `source.surface: "directory_fallback"`, `source.fallback: true` and `source.projection_error`, with `record_version: null`. The directory feed has no facts, no per-fact provenance and no record version.
- A 4xx, a contract mismatch, an ambiguous-name answer or a body that is not this domain's record is a contract error (exit 3). None of them triggers the fallback.
- New flag `--no-fallback`: an unreachable projection exits 3 and the directory feed is never read.

### Exit codes

- New: 6, withheld. The projection answered `found: true, withheld: true`: the record exists and is withheld while a report about it is reviewed. The reason is printed in Trooth's own words. This is neither an absence nor a finding.
- Exit 1 from a projection read means `found: false`: no published record.

### Environment

- New: `TROOTH_WEB`, the base URL of the record projection (default `https://trooth.co`). `TROOTH_API` now names only the fallback's base URL.

### Limits

- The projection's body limit is 2 MiB, the bound the server itself enforces before it sends (`PROFILE_RESPONSE_MAX_BYTES`). The directory feed keeps 1 MiB.

### Release provenance

- `.github/workflows/publish.yml` publishes on a version tag (`v0.6.0`) with `npm publish --provenance --access public`, authenticated by npm trusted publishing (GitHub OIDC, `id-token: write`). No npm token is stored in the repository. First the workflow checks that the tag equals `package.json`'s version and `trooth --version`, then it runs the metadata check and the test suite, then it prints the tarball. Publishing starts working once a maintainer registers the trusted publisher on npmjs.com: organization `troothllc`, repository `trooth-cli`, workflow `publish.yml`, no environment.

### Not changed

- `lint` is unchanged. `digest`, the 0.4 name of `facts_digest`, was to be removed in 0.6. It stays until 0.7, because the GitHub Action still exposes it as an output, and its `digest_scope` text now says 0.7.
- The GitHub Action's default `version` stays `0.5.1` until 0.6.0 is on the registry, because the action installs the version it names from npm.
