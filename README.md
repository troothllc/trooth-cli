# trooth

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![npm](https://img.shields.io/npm/v/trooth?label=npm%20trooth&color=D5C884)](https://www.npmjs.com/package/trooth)

Run Trooth from your terminal. Check any company's witnessed standing on the Trooth Network, scan a Terraform plan before it merges, and check your infrastructure for drift. Public reads need no key and no account.

Trooth is the witnessed trust network for software and AI companies. A company gets witnessed once, and buyers and their AI agents read a current, signed, dated record instead of chasing questionnaires and stale PDFs. This CLI is the read side and the build side in one command.

## Install

Published to npm as `trooth`. No install needed:

```bash
npx trooth check trooth.co
```

Or install it once:

```bash
npm i -g trooth
trooth check trooth.co
```

Node 18 or later.

## Check any company

Read-only, no account. `check` reads only the public witness directory and sends nothing about you.

```bash
trooth check trooth.co
```

You get the company's witnessed standing, the per-discipline breakdown, how many live probes passed, and the badge and scan IDs you can verify. When a company has no published standing yet, you get an honest "not listed", not a guess.

Pipe the record into a script with `--json`:

```bash
trooth check acme.com --json
```

## Scan a Terraform plan

`scan` sends a Terraform plan to Trooth Pre-Flight and reads it against SOC 2, ISO 27001, GDPR, HIPAA, NIST AI RMF, and the EU AI Act, before it merges. Advisory and report-only: Trooth reads your plan, never your environment, and never changes anything.

```bash
terraform show -json plan.tfplan > plan.json
trooth scan plan.json
```

By default `scan` is advisory and exits 0. Pass `--strict` to exit non-zero when findings exist, so you can gate a pull request on it.

## Check drift locally

```bash
trooth lint
```

`lint` is a local, read-only infrastructure-as-code drift check. It never transmits your code.

## Read Trooth from your AI assistant

Everything `check` reads is also open to an AI agent over the public, read-only MCP server at `https://api.trooth.co/public/mcp`. Add it to Claude, ChatGPT, or Cursor and ask about any company in plain words. See [trooth-mcp](https://github.com/troothllc/trooth-mcp).

## For companies

The read side is open to everyone. The other half of the Network is the write side: claim your page and get witnessed, so buyers and their agents read a real, current standing instead of asking you for a PDF. Start at [trooth.co/signup](https://trooth.co/signup).

## License

Apache 2.0. Trooth automates. Trooth never signs.
