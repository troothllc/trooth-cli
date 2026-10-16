// Types for trooth/evidence (bin/lib/evidence.mjs). docs/ACTION-EVIDENCE.md describes both objects and the rules.
import type { ActionEvidencePayload, DelegationReceiptPayload, KeyList, PublicKey } from './trooth.js';

export type { ActionEvidencePayload, DelegationReceiptPayload };

export declare const EVIDENCE_FORMAT: 'trooth.action-evidence.v1';
export declare const EVIDENCE_TYP: 'trooth-action-evidence+jwt';
export declare const DELEGATION_RECEIPT_FORMAT: 'trooth.delegation-receipt.v1';
export declare const DELEGATION_RECEIPT_TYP: 'trooth-delegation-receipt+jwt';
export declare const DELEGATION_FORMAT: 'trooth.delegation.v1';
export declare const EVIDENCE_KEY_KID: 'trooth-evidence-2026-10';
export declare const SIGNED_REFERENCES_PURPOSE: 'signed-references';
export declare const ISSUER: 'https://api.trooth.co';
export declare const KEYS_URL: string;
export declare const STATUS_URL_PREFIX: string;
/** https://api.trooth.co/scan/log/v1/entries/ */
export declare const LOG_ENTRY_URL_PREFIX: string;
export declare const LOG_COMMITMENT_FORMAT: 'trooth.log-commitment.v1';
export declare const LOG_COMMITMENT_TYP: 'trooth-log-commitment+jwt';
export declare const LOG_KIND_OF_TYP: { 'trooth-action-evidence+jwt': 'action_evidence'; 'trooth-delegation-receipt+jwt': 'delegation_receipt' };
/** 600: an evidence reference lives ten minutes. */
export declare const EVIDENCE_TTL_S: number;
export declare const CLOCK_SKEW_S: number;
export declare const MAX_JWS_BYTES: number;
export declare const PUBLIC_STATES: readonly ['issued', 'redeemed', 'expired', 'revoked'];

/** Input that is not a compact JWS, or JSON that holds none. */
export declare class EvidenceInputError extends Error {}

/** The key list: the JSON of https://api.trooth.co/public/keys, or its keys array. */
export type Keys = KeyList | PublicKey[] | { keys: Array<Record<string, unknown>> } | Array<Record<string, unknown>>;

/**
 * valid: everything holds (and for a reference, it has not expired). expired: a reference that holds
 * and whose exp has passed. not_trusted: malformed, alg not EdDSA, kid not on the list or not purpose
 * signed-references, the key not trusted at iat, or the signature does not verify. mismatch: the
 * signature verifies, but typ, format, iss, the claims, the lifetime, the binding or the delegation
 * digest do not hold.
 */
export type CheckStatus = 'valid' | 'expired' | 'not_trusted' | 'mismatch';

export interface KeyCheck {
  state: 'active' | 'retired' | 'compromised' | 'revoked_unrecorded' | 'unknown';
  purpose: string | null;
  trusted: boolean;
  reason: string;
}

export interface ApprovalSummary {
  approved_by: string | null;
  approved_at: string | null;
  method: 'session_reauth' | 'identity_provider' | string | null;
  acr: string | null;
  idp: { provider: string | null; domain: string | null } | null;
}

export interface DelegationScope {
  role: string | null;
  limit: { amount: string | null; currency: string | null } | null;
  data_class: string | null;
  /** Only a delegation document carries it; an evidence reference does not. */
  approval_above: string | null;
}

interface CheckBase<P> {
  status: CheckStatus;
  /** The first problem, or null. */
  reason: string | null;
  problems: string[];
  signature: 'valid' | 'invalid' | 'not_checked';
  kid: string | null;
  key: KeyCheck | null;
  header: Record<string, unknown> | null;
  /** The decoded payload, or null when it could not be decoded. Read it only when signature is 'valid'. */
  payload: P | null;
  /** SHA-256 (hex) of the compact JWS string, as the Worker stores it. */
  sha256: string | null;
  issued_at: string | null;
  expires_at: string | null;
}

export interface EvidenceSummary {
  jti: string | null;
  authorization_id: string | null;
  action: 'trooth_payment' | 'trooth_data_share' | string | null;
  verb: 'pay' | 'share' | string | null;
  amount: string | null;
  currency: string | null;
  data_class: string | null;
  creditor_name: string | null;
  description: string | null;
  locations: string[];
  target_domain: string | null;
  principal: { workspace: string | null; user: string | null } | null;
  delegation: (DelegationScope & { id: string | null; sha256: string | null; agent_jkt: string | null; actions: string[]; expires_at: string | null }) | null;
  approval: { delegation: ApprovalSummary | null; action: ApprovalSummary | null };
  /** matches_mandate: null when no mandate was given to check. */
  binding: { protocol: string | null; reference_sha256: string | null; matches_mandate: boolean | null } | null;
  boundary_version: string | null;
  counterparty: { domain: string | null; status: 'read' | 'not_read' | string | null; read_at: string | null; log_index: number | null; statement_sha256: string | null; source: string | null };
  issued_at: string | null;
  expires_at: string | null;
}

export interface EvidenceCheck extends CheckBase<ActionEvidencePayload> {
  kind: 'action-evidence';
  jti: string | null;
  /** https://api.trooth.co/public/action-evidence/<jti>, never fetched by the library. */
  state_url: string | null;
  /** null when the check stopped before the claims (not_trusted). */
  summary: EvidenceSummary | null;
}

export interface DelegationReceiptSummary {
  event: 'created' | 'revoked' | string | null;
  delegation_id: string | null;
  delegation_sha256: string | null;
  agent_jkt: string | null;
  actions: string[];
  target_domain: string | null;
  principal: { workspace: string | null; user: string | null } | null;
  expires_at: string | null;
  /** Whether the delegation's expires_at has passed. A receipt itself does not expire. */
  delegation_expired: boolean | null;
  recorded_at: string | null;
  by: string | null;
  approval: ApprovalSummary | null;
  scope_source: 'not supplied' | 'delegation document, digest matches' | 'delegation document, digest does not match';
  /** From the delegation document, only when its digest is the one the receipt names. */
  scope: DelegationScope | null;
  meaning: string | null;
}

export interface DelegationReceiptCheck extends CheckBase<DelegationReceiptPayload> {
  kind: 'delegation-receipt';
  summary: DelegationReceiptSummary | null;
}

/** The Worker's canonical JSON: sorted keys, no spaces, undefined members dropped. */
export declare function canonicalJson(v: unknown): string;
/** SHA-256 (hex) of `${protocol}\n${reference}`: binding.reference_sha256 for that mandate. */
export declare function bindingReferenceSha(protocol: string, reference: string): string;
/** SHA-256 (hex) of a delegation document's canonical JSON (digest, revoked_at and receipts left out). */
export declare function delegationDigest(delegation: Record<string, unknown>): string;
export declare function looksLikeJws(s: string): boolean;
/** The compact JWS in a saved file: the JWS itself, or the JSON the API answers with. Throws EvidenceInputError. */
export declare function extractJws(text: string, kind: 'evidence' | 'delegation'): { jws: string; delegation: Record<string, unknown> | null; log: LogPlace | null };

/** Where the API says an object sits in the witness log (`log`, or `receipt_log`); index null while pending. */
export interface LogPlace { statement_id: string | null; index: number | null; url: string | null }

/** The payload of a witness log commitment: exactly these four keys. */
export interface LogCommitmentPayload {
  format: 'trooth.log-commitment.v1';
  kind: LogKind;
  /** Lowercase hex SHA-256 of the original compact JWS (UTF-8). */
  sha256: string;
  iat: number;
}
export type LogKind = 'delegation_receipt' | 'action_evidence';

/** A witness log commitment checked against the original JWS. */
export interface LogCommitmentCheck {
  /** The kind the original should be logged as (from its typ, or opts.kind); null when unknown. */
  kind: LogKind | null;
  status: 'valid' | 'not_trusted' | 'mismatch';
  reason: string | null;
  problems: string[];
  signature: 'valid' | 'invalid' | 'not_checked';
  kid: string | null;
  key: KeyCheck | null;
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  committed_sha256: string | null;
  /** SHA-256 (hex) of the original JWS as given. */
  expected_sha256: string;
  committed_at: string | null;
  issued_at: string | null;
}

/** The commitment JWS in a GET /scan/log/v1/entries/<n> answer (its envelope payload). Throws EvidenceInputError. */
export declare function commitmentFromLogEntry(entry: unknown): { kind: LogKind; jws: string; index: number | null; statement_id: string | null; logged_at: string | null };
/** Check a log commitment: signature (same keys), typ, format, kind and sha256 = SHA-256 of originalJws. Never throws on bad input. */
export declare function verifyLogCommitment(commitmentJws: string, originalJws: string, keys: Keys, opts?: { kind?: LogKind }): LogCommitmentCheck;

/** What --log adds to the --json output: null without --log (or when the object did not check). */
export interface LogOutput {
  index: number;
  index_source: 'the input JSON' | '--log-index';
  url: string;
  /** unreadable: the entry could not be read (exit 3). */
  status: 'valid' | 'not_trusted' | 'mismatch' | 'unreadable';
  /** 0, 3, 8 or 9. */
  code: number;
  reason: string | null;
  problems: string[];
  kind: LogKind | null;
  statement_id?: string | null;
  logged_at?: string | null;
  committed_sha256: string | null;
  committed_at: string | null;
  kid: string | null;
  key?: KeyCheck | null;
  signature: 'valid' | 'invalid' | 'not_checked';
  commitment?: string;
}
/** Decode without checking. Throws EvidenceInputError. */
export declare function decodeJws(jws: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: string; signature: Uint8Array };

/** Check an action evidence reference. Never throws on bad input. */
export declare function verifyEvidence(jws: string, keys: Keys, opts?: { now?: number; binding?: { protocol: string; reference: string } }): EvidenceCheck;
/** Check a delegation receipt; with opts.delegation, also its document's digest. Never throws on bad input. */
export declare function verifyDelegationReceipt(jws: string, keys: Keys, opts?: { now?: number; delegation?: Record<string, unknown> }): DelegationReceiptCheck;

/** What `trooth evidence verify --json` prints when the input could be read. */
export interface EvidenceVerifyOutput extends EvidenceCheck {
  ok: boolean;
  /** The exit code: 0, 1, 3 (--log: the entry could not be read), 8, 9, 11 or 12. */
  exit: number;
  /** null without --online (or when the check did not reach the claims). */
  online: { url: string; state: 'issued' | 'redeemed' | 'expired' | 'revoked' | null; expires_at?: string | null; redeemed_at?: string | null; not_found: boolean } | null;
  log: LogOutput | null;
  sources: { keys: string; keys_read_at: string | null; state: string | null; log: string | null };
}

/** What `trooth delegation verify --json` prints when the input could be read. */
export interface DelegationVerifyOutput extends DelegationReceiptCheck {
  ok: boolean;
  /** The exit code: 0, 3 (--log: the entry could not be read), 8 or 9. */
  exit: number;
  log: LogOutput | null;
  sources: { keys: string; keys_read_at: string | null; delegation: string | null; log: string | null };
}
