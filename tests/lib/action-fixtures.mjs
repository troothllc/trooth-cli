// tests/lib/action-fixtures.mjs - delegation receipts and action evidence
// references built and signed the way trooth-os-worker-f src/action-authz.ts
// builds them (delegationReceiptPayload, issueInner, responsibilityBoundary,
// signEvidence, signDelegationReceipt), with a throwaway Ed25519 key from
// node:crypto and a key list shaped like GET https://api.trooth.co/public/keys
// (governance.ts). Nothing here imports bin/lib/evidence.mjs, so the tests
// check the library against an independent signer.
import { generateKeyPairSync, sign, createHash, randomBytes } from 'node:crypto';

export const KID = 'trooth-evidence-2026-10';
const b64url = (buf) => Buffer.from(buf).toString('base64url');
const hex = (n) => randomBytes(n).toString('hex');
const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');

/** The Worker's canonicalJson (sorted keys, no spaces, undefined dropped). */
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}

/** A throwaway evidence key: { privateKey, publicHex }. */
export function makeKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, publicHex: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex') };
}

/** A key list entry exactly as governance.ts publishes the signed-reference key (before lifecycle events). */
export function keyEntry(key, over = {}) {
  return {
    kid: KID, public_key: key.publicHex, alg: 'Ed25519', encoding: 'hex',
    signs: 'short-lived signed references issued by api.trooth.co that name this kid',
    status: 'active', fingerprint: sha256Hex(key.publicHex).slice(0, 16), created_at: null, revoked_at: null,
    purpose: 'signed-references', activated_at: null, retired_at: null, compromised_at: null, events: [], first_listed_at: null, state: 'active',
    ...over,
  };
}

/** A fake /public/keys document with the evidence key and a ledger key beside it. */
export function keysDoc(key, over = {}) {
  const ledger = makeKey();
  return {
    keys: [
      { kid: 'trooth-runtime-2026-10', public_key: ledger.publicHex, alg: 'Ed25519', encoding: 'hex', status: 'active', purpose: 'trust-ledger', state: 'active', created_at: null, revoked_at: null, retired_at: null, compromised_at: null },
      keyEntry(key, over),
    ],
    active_kid: 'trooth-runtime-2026-10',
    active_kids: ['trooth-runtime-2026-10', KID],
    revocations: [],
    list_read_at: '2026-10-15T12:00:00.000Z',
  };
}

/** Sign a payload as signEvidence / signDelegationReceipt do: header JSON.stringify, payload canonical. */
export function signJws(payload, key, header) {
  const input = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(canonicalJson(payload)))}`;
  return `${input}.${b64url(sign(null, Buffer.from(input), key.privateKey))}`;
}
export const EVIDENCE_HEADER = { alg: 'EdDSA', typ: 'trooth-action-evidence+jwt', kid: KID };
export const RECEIPT_HEADER = { alg: 'EdDSA', typ: 'trooth-delegation-receipt+jwt', kid: KID };

export const APPROVAL = {
  approved_by: 'usr_0a1b2c3d', approved_at: '2026-10-15T11:58:00.000Z', method: 'identity_provider', acr: 'trooth:idp',
  auth_time: '2026-10-15T11:57:30.000Z', idp: { provider: 'okta', domain: 'acme-buyer.okta.com' },
};
const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

/** A delegation document as POST /v1/delegations stores it (the canonical form is digested). */
export function delegationDoc(over = {}) {
  return {
    format: 'trooth.delegation.v1', id: `dlg_${hex(10)}`,
    principal: { workspace: 'cmp_buyer01', user: 'usr_0a1b2c3d' },
    agent: { jkt: JKT, label: 'procurement agent' },
    role: 'buyer', target: { domain: 'vendor.example' }, actions: ['trooth_payment'],
    limit: { amount: '500.00', currency: 'USD' }, data_class: null, approval_above: '250.00',
    expires_at: '2026-11-14T12:00:00.000Z', created_at: '2026-10-15T11:58:00.000Z', approval: APPROVAL,
    ...over,
  };
}
export const delegationDigestOf = (d) => sha256Hex(canonicalJson(d));

/** delegationReceiptPayload(event, d, by, at, kid, approval). */
export function receiptPayload(d, { event = 'created', at = Date.parse('2026-10-15T11:58:00.000Z'), approval = APPROVAL, by = APPROVAL.approved_by } = {}) {
  return {
    format: 'trooth.delegation-receipt.v1', iss: 'https://api.trooth.co', iat: Math.floor(at / 1000), event,
    recorded_at: new Date(at).toISOString(), by, ...(approval ? { approval } : {}),
    delegation: {
      id: d.id, sha256: delegationDigestOf(d), format: 'trooth.delegation.v1',
      principal: { workspace: d.principal.workspace, user: d.principal.user }, agent: { jkt: d.agent.jkt },
      target: { domain: d.target.domain }, actions: d.actions, expires_at: d.expires_at,
    },
    meaning: event === 'created'
      ? 'Trooth recorded this delegation, with this digest, at recorded_at, approved as stated. It does not say that any action taken under it is proper.'
      : 'Trooth recorded the revocation of this delegation at recorded_at. Evidence references it had issued and not yet redeemed were revoked with it.',
    verify: { keys: 'https://api.trooth.co/public/keys', kid: KID },
  };
}

function boundary(d, actionApproval, reading) {
  return {
    version: 'trooth.responsibility-boundary.v1-draft',
    trooth_observed: [
      reading.status === 'read'
        ? `The public record of ${d.target.domain} as Trooth read it at ${reading.read_at ?? 'the stated time'}, signed and logged (statement digest in counterparty.reading).`
        : `Trooth could not read the public record of ${d.target.domain} for this reference; nothing about the counterparty is attested here.`,
      `Delegation ${d.id} as the workspace recorded it, and how it was approved.`,
      'That this action request fell within that delegation when Trooth checked it.',
    ],
    buyer_approved: [
      `Delegation ${d.id}: its agent, role, counterparty, actions, limit and expiry, approved by ${d.approval.approved_by} through ${d.approval.method === 'identity_provider' ? "the workspace's identity provider" : 'a fresh sign-in'} at ${d.approval.approved_at}.`,
      ...(actionApproval ? [`This action, approved by ${actionApproval.approved_by} through the workspace's identity provider at ${actionApproval.approved_at}.`] : []),
    ],
    vendor_represented: [`What ${d.target.domain} publishes about itself, including any signed declaration, is its own representation, labelled as such in its public record.`],
    not_established: [
      'That the goods or services will be delivered, or are as described.',
      'That a payment will be made, will settle, or that funds are available.',
      "That the agent will act within this authorization: the payment partner's own mandate and controls govern execution.",
      "Any person's legal authority to bind the counterparty or the buyer beyond what the delegation records.",
      'Anything after this reference expires.',
    ],
  };
}

export const READING = {
  status: 'read', read_at: '2026-10-15T09:00:00.000Z', log_index: 4211,
  statement_sha256: 'c'.repeat(64), source: 'https://api.trooth.co/scan/public-record/vendor.example',
};
export const PAYMENT_DETAIL = { type: 'trooth_payment', actions: ['pay'], locations: ['https://vendor.example/checkout'], instructedAmount: { currency: 'USD', amount: '125.00' }, creditorName: 'Vendor Inc.' };
export const DATA_DETAIL = { type: 'trooth_data_share', actions: ['share'], locations: ['https://vendor.example/intake'], datatypes: ['internal'] };

/** The payload issueInner builds. iat in seconds. */
export function evidencePayload(d, { iat = Math.floor(Date.now() / 1000), details = [PAYMENT_DETAIL], protocol = 'ap2', reference = 'mandate-0001-abcdef', actionApproval = null, reading = READING, ttl = 600 } = {}) {
  const jti = `ev_${hex(16)}`;
  return {
    format: 'trooth.action-evidence.v1', iss: 'https://api.trooth.co', iat, exp: iat + ttl, jti,
    authorization_id: `act_${hex(10)}`, authorization_details: details,
    binding: { protocol, reference_sha256: sha256Hex(`${protocol}\n${reference}`) },
    principal: { workspace: d.principal.workspace, user: d.principal.user },
    delegation: { id: d.id, sha256: delegationDigestOf(d), agent: { jkt: d.agent.jkt }, role: d.role, target: { domain: d.target.domain }, actions: d.actions, limit: d.limit, data_class: d.data_class ?? null, expires_at: d.expires_at },
    approval: { delegation: d.approval, action: actionApproval },
    counterparty: { domain: d.target.domain, reading },
    responsibility: boundary(d, actionApproval, reading),
    verify: { keys: 'https://api.trooth.co/public/keys', kid: KID, status: `https://api.trooth.co/public/action-evidence/${jti}` },
  };
}

/*
 * Witness log commitments, as trooth-os-worker-f src/action-authz.ts
 * signLogCommitment signs them (header JSON.stringify {alg, kid, typ},
 * payload canonical {format, kind, sha256, iat}) and as
 * trooth-scan-worker src/log-internal.ts wraps them in a log entry.
 */
export const COMMITMENT_HEADER = { alg: 'EdDSA', kid: KID, typ: 'trooth-log-commitment+jwt' };

/** A commitment to `original` (a compact JWS) of `kind`. */
export function commitment(original, kind, key, { iat = Math.floor(Date.now() / 1000), extra = {}, header = COMMITMENT_HEADER, sha256 } = {}) {
  return signJws({ format: 'trooth.log-commitment.v1', kind, sha256: sha256 ?? sha256Hex(original), iat, ...extra }, key, header);
}

/** GET /scan/log/v1/entries/<index> for a commitment, as LogCore.entry answers. */
export function logEntry(index, kind, commitmentJws, sha256) {
  return {
    index, kind, statement_id: `trooth:statement:${sha256}`, logged_at: '2026-10-15T12:00:05.000Z',
    entry: { kind, statement: { alg: 'EdDSA', canonicalization: 'jws-compact', key_id: KID, payload: commitmentJws, signature: '' } },
  };
}
export { sha256Hex };
