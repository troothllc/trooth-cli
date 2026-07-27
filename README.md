# @trooth/cli

[![npm version](https://img.shields.io/npm/v/@trooth/cli.svg)](https://www.npmjs.com/package/@trooth/cli)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node](https://img.shields.io/node/v/@trooth/cli.svg)](https://nodejs.org)

Run compliance scans, verify Trust Receipts, and check your Trust Score from the terminal. Free at the Bronze tier.

## Install

```bash
npm install -g @trooth/cli
```

Or run without installing:

```bash
npx @trooth/cli scan
```

Node 18 or later required.

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

Add a Trooth scan to any pipeline:

```bash
- run: npx @trooth/cli scan --fail-on critical
  env:
    TROOTH_API_KEY: ${{ secrets.TROOTH_API_KEY }}
```

GitHub Actions users may also use the dedicated [`troothllc/trooth-action`](https://github.com/troothllc/trooth-action), which wraps this CLI with PR-comment integration.

## Status during pre-launch

The Trooth API begins production scans on **August 2, 2026**. Before that date, `scan` and `status` commands run in scaffold mode. They accept your inputs, validate configuration, and return placeholder responses so you can wire the CLI into your workflow now.

## Security

Pass your API key via environment variable, not via a flag in a shared shell. Never commit the key. See [SECURITY.md](https://github.com/troothllc/.github/blob/main/SECURITY.md) for the vulnerability disclosure policy.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## About Trooth

Trooth provides cryptographic compliance infrastructure for AI products. Continuous monitoring against SOC 2, ISO 27001, EU AI Act, NIST AI RMF, and HIPAA. Free at Bronze.

[trooth.co](https://www.trooth.co) · [Trust Center](https://www.trooth.co/security)
