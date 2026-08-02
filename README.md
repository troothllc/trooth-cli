# @trooth/cli

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Run compliance scans, verify Trust Receipts, and check your Trust Score from the terminal. Free at the Bronze tier.

## Install

The npm release is in progress. Until it lands, install from source:

```bash
git clone https://github.com/troothllc/trooth-cli.git
cd trooth-cli
npm install
npm link
```

Node 18 or later required. When the package publishes, `npm install -g @trooth/cli` will be the one-line path.

## Quick start

```bash
# Get a free API key at https://www.trooth.co, then export it
export TROOTH_API_KEY=your_key_here

# Run a scan
trooth scan

# Scan against specific frameworks
trooth scan --frameworks eu-ai-act,soc2 --fail-on high

# Check current status
trooth status

# Verify a Trust Receipt locally
trooth verify ./receipt.json
```

## Commands

### `trooth scan`

Runs a compliance scan on the current project and exits non-zero if any finding meets the `--fail-on` threshold.

| Option | Default | Description |
|---|---|---|
| `--api-key <key>`, `-k` | `$TROOTH_API_KEY` | API key. Use environment variable for security. |
| `--frameworks <list>`, `-f` | all on tier | Comma-separated: `soc2,iso27001,eu-ai-act,nist-ai-rmf,hipaa`. |
| `--fail-on <severity>` | `critical` | Severity that causes non-zero exit: `critical`, `high`, `medium`, `low`, `none`. |
| `--host <url>` | `https://api.trooth.co` | API host. Override for staging environments. |
| `--json` | off | Output machine-readable JSON. |

### `trooth verify <receipt>`

Verify a Trooth Trust Receipt structurally. Cryptographic signature verification ships with `@trooth/verifier` in v1.0.

```bash
trooth verify ./trust-receipt.json
trooth verify ./trust-receipt.json --json
```

### `trooth status`

Show your current Trust Score, tier, and last-scan time.

```bash
trooth status
trooth status --json
```

## Configuration

The CLI reads configuration from the following sources, in this order:

1. Command-line flags (highest priority)
2. Environment variables: `TROOTH_API_KEY`, `TROOTH_HOST`
3. Defaults

## Use in CI

The simplest CI integration today is the dedicated [`troothllc/trooth-action`](https://github.com/troothllc/trooth-action), which wraps this CLI with PR-comment integration. Once the npm release lands, any pipeline can also run the CLI directly:

```bash
- run: npx @trooth/cli scan --fail-on critical
  env:
    TROOTH_API_KEY: ${{ secrets.TROOTH_API_KEY }}
```

## Status

The Trooth platform launched August 2, 2026. Until the npm release of this CLI lands, `scan` and `status` run in scaffold mode: they accept your inputs, validate configuration, and return placeholder responses so you can wire the CLI into your workflow now. This README will drop this section when the CLI runs fully against the production API.

## Security

Pass your API key via environment variable, not via a flag in a shared shell. Never commit the key. See [SECURITY.md](https://github.com/troothllc/.github/blob/main/SECURITY.md) for the vulnerability disclosure policy.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## About Trooth

Trooth runs the Trooth Network: the witnessed trust network for software and AI companies. Posture is witnessed from live systems against SOC 2, ISO 27001, the EU AI Act, NIST AI RMF, and HIPAA, and published on a public trust profile buyers can read with no login. Free at Bronze.

[trooth.co](https://www.trooth.co) · [Browse the Network](https://www.trooth.co/network) · [Trust Center](https://www.trooth.co/security)
