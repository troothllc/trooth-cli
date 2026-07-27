'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Verify a Trooth Trust Receipt locally, without contacting Trooth servers.
 *
 * v0.1 performs basic structural validation. Cryptographic verification ships
 * with the production API on August 2, 2026. Until then, this command surfaces
 * the receipt's claimed fields and warns that signature verification is pending.
 */

async function verify(receiptPath, options) {
  const opts = options || {};
  let receipt;

  try {
    const absolute = path.resolve(process.cwd(), receiptPath);
    const raw = fs.readFileSync(absolute, 'utf8');
    receipt = JSON.parse(raw);
  } catch (err) {
    if (opts.json) {
      process.stdout.write(JSON.stringify({ valid: false, reason: 'read_failed', error: err.message }, null, 2) + '\n');
    } else {
      process.stderr.write('Failed to read receipt: ' + err.message + '\n');
    }
    process.exit(2);
    return;
  }

  const required = ['subject', 'issuedAt'];
  const missing = required.filter(function (field) {
    return !(field in receipt);
  });

  if (missing.length > 0) {
    const result = {
      valid: false,
      reason: 'missing_fields',
      missing: missing
    };
    if (opts.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      process.stderr.write('Receipt missing required fields: ' + missing.join(', ') + '\n');
    }
    process.exit(1);
    return;
  }

  const result = {
    structurallyValid: true,
    cryptographicallyVerified: false,
    cryptographicVerificationNote: 'Cryptographic verification ships with the Trooth production API on August 2, 2026.',
    subject: receipt.subject,
    issuedAt: receipt.issuedAt
  };

  if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return;
  }

  process.stdout.write('Receipt structurally valid: yes\n');
  process.stdout.write('Subject:    ' + receipt.subject + '\n');
  process.stdout.write('Issued at:  ' + receipt.issuedAt + '\n');
  process.stdout.write('\n');
  process.stdout.write('Cryptographic verification: ships with the Trooth production API on August 2, 2026.\n');
  process.stdout.write('For now, use https://www.trooth.co/security to verify against the canonical receipt registry.\n');
}

module.exports = verify;
