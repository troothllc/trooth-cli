// The JavaScript and TypeScript SDK: `import { verifyStatement } from 'trooth/verify'`.
// Declarations for bin/lib/verify.mjs; the document types are generated from
// schemas/ into ./trooth.d.ts. The rules are docs/VERIFY.md.
import type { WitnessStatement, PublicKey, EvidenceManifest, VerificationBundle, VerifyResult as VerifyResultDoc, LogReceipt, LoggedCorrection, CorrectionCheck } from './trooth.js';

export * from './trooth.js';

export declare const WITNESS_STATEMENT_V1: 'trooth.witness-statement.v1';
export declare const WITNESS_STATEMENT_V2: 'trooth.witness-statement.v2';
export declare const WITNESS_STATEMENT_V3: 'trooth.witness-statement.v3';
export declare const VERIFICATION_BUNDLE_V1: 'trooth.verification-bundle.v1';
export declare const JCS_LABEL: 'RFC8785';
export declare const REASONS: Readonly<Record<string, 'not read' | 'not as expected'>>;
export declare const ASSURANCE: Readonly<{ v1: string; v2: string; v3: string }>;
export declare const CORRECTION_V1: 'trooth.correction.v1';
export declare const CORRECTION_REASONS: readonly string[];

/** The witness statement log's answer for one statement (docs/LOG.md). */
export interface LogInputs {
  /** Log verifier keys to check checkpoints against (signed-note format). */
  vkeys: string[];
  /** The receipt, or null when the log holds no entry for the statement. */
  receipt: LogReceipt | null;
  corrections: LoggedCorrection[];
  /** Set when the log could not be read: reported, never a verdict. */
  unavailable?: string;
}

/** What verifyStatement returns: the verify-result document plus `trusted`. `domain`, `keys_read_at` and `sources` are added by the CLI. */
export type VerifyResult = Omit<VerifyResultDoc, 'domain' | 'sources'> & { trusted: boolean };

export interface VerifyInputs {
  /** The envelope exactly as published; `payload` is the exact signed string. */
  statement: WitnessStatement;
  /** The `keys` array of https://api.trooth.co/public/keys, or a saved copy. */
  keys: PublicKey[];
  /** The exact bytes of the check mapping the payload names. Undefined means not supplied. */
  mappingBytes?: Uint8Array;
  /** The evidence manifest. Undefined means not supplied. */
  manifest?: EvidenceManifest;
  /** The domain you are about to rely on. Undefined means no domain to compare. */
  domain?: string;
  /** The log's answer. Undefined means the log was not asked. */
  log?: LogInputs;
}

export declare function verifyStatement(inputs: VerifyInputs): VerifyResult;
export declare function verifyBundle(bundle: VerificationBundle, options?: { domain?: string; vkeys?: string[] }): VerifyResult & { keys_read_at: string | null };
export declare function verifyCorrection(input: { correction: WitnessStatement; receipt: LogReceipt; keys: PublicKey[]; vkeys: string[]; statementIdValue: string }): CorrectionCheck;
export declare function bundleInputs(bundle: VerificationBundle): { statement: WitnessStatement; keys: PublicKey[]; keysReadAt: string | null; mappingBytes?: Uint8Array; manifest?: EvidenceManifest; domain?: string };
export declare function makeBundle(inputs: { domain?: string | null; statement: WitnessStatement; manifest?: EvidenceManifest; keys: PublicKey[]; keysReadAt?: string | null; keysSource?: string | null; mappingUrl?: string | null; mappingBytes?: Uint8Array; createdAt?: string; log?: { vkey: string; receipt: LogReceipt | null; corrections: LoggedCorrection[] } }): VerificationBundle;
export declare function sha256Digest(bytes: Uint8Array | string): string;
export declare function canonicalManifest(entries: EvidenceManifest): string;
export declare function countProblems(payload: unknown): string[];
export declare function keyState(key: PublicKey | null | undefined): 'active' | 'retired' | 'compromised' | 'revoked_unrecorded' | 'unknown';
export declare function keyTrust(kid: string, keys: PublicKey[], signedAt: string | null): VerifyResult['key'];
export declare function keyBytes(key: PublicKey): Uint8Array;
export declare class BundleError extends Error {}
