'use strict';

const client = require('../client');

async function scan(options) {
  const frameworks = options.frameworks || '';
  const failOn = options.failOn || 'critical';

  if (!options.json) {
    process.stdout.write('Running Trooth compliance scan...\n');
    process.stdout.write('Frameworks: ' + (frameworks || 'all on tier') + '\n');
    process.stdout.write('Fail on:    ' + failOn + '\n\n');
  }

  const result = await client.request('POST', '/v1/scan', options, {
    frameworks: frameworks
  });

  if (result.scaffold) {
    const message = 'Trooth API not yet available (' + result.reason + '). Scaffold mode. Production scans begin August 2, 2026.';
    if (options.json) {
      process.stdout.write(JSON.stringify({ status: 'scaffold', reason: result.reason, score: null }, null, 2) + '\n');
    } else {
      process.stdout.write(message + '\n');
    }
    return;
  }

  if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  process.stdout.write('Trust Score:    ' + (result.score || 'unknown') + '\n');
  process.stdout.write('Status:         ' + (result.status || 'unknown') + '\n');
  process.stdout.write('Findings:       ' + (result.findings && result.findings.total ? result.findings.total : 0) + '\n');
  if (result.reportUrl) {
    process.stdout.write('Full report:    ' + result.reportUrl + '\n');
  }

  if (result.status === 'fail' && failOn !== 'none') {
    process.exit(1);
  }
}

module.exports = scan;
