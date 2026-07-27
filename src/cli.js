'use strict';

const { Command } = require('commander');
const pkg = require('../package.json');
const scan = require('./commands/scan');
const verify = require('./commands/verify');
const status = require('./commands/status');

const program = new Command();

program
  .name('trooth')
  .description('Trooth CLI: run compliance scans, verify Trust Receipts, and check status from your terminal.')
  .version(pkg.version, '-v, --version', 'output the current version')
  .helpOption('-h, --help', 'display help for command');

program
  .command('scan')
  .description('Run a compliance scan on the current project')
  .option('-k, --api-key <key>', 'Trooth API key. Defaults to env TROOTH_API_KEY.')
  .option('-f, --frameworks <list>', 'Comma-separated frameworks to scan against. Default: all on tier.')
  .option('--fail-on <severity>', 'Severity that fails the command: critical, high, medium, low, none.', 'critical')
  .option('--host <url>', 'Trooth API host.', 'https://api.trooth.co')
  .option('--json', 'Output JSON instead of human-readable text.', false)
  .action(scan);

program
  .command('verify <receipt>')
  .description('Verify a Trooth Trust Receipt without contacting Trooth servers')
  .option('--json', 'Output JSON instead of human-readable text.', false)
  .action(verify);

program
  .command('status')
  .description('Show your current Trust Score and recent scan history')
  .option('-k, --api-key <key>', 'Trooth API key. Defaults to env TROOTH_API_KEY.')
  .option('--host <url>', 'Trooth API host.', 'https://api.trooth.co')
  .option('--json', 'Output JSON instead of human-readable text.', false)
  .action(status);

program.addHelpText('after', `
Examples:
  $ trooth scan
  $ trooth scan --frameworks eu-ai-act,soc2 --fail-on high
  $ trooth verify ./receipt.json
  $ trooth status --json

Get a free API key at https://www.trooth.co.
Documentation: https://www.trooth.co/docs/api.
`);

program.parseAsync(process.argv).catch(function (err) {
  process.stderr.write('Error: ' + (err.message || err) + '\n');
  process.exit(1);
});
