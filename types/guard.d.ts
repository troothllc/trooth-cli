// Types for trooth/guard (bin/lib/guard.mjs). docs/GUARD.md describes the behavior.

export type ReasonCode =
  | 'RULE_PASSED' | 'EVIDENCE_MISSING' | 'EVIDENCE_STALE' | 'EVIDENCE_DISPUTED' | 'NO_RECORD'
  | 'SIGNATURE_INVALID' | 'KEY_NOT_TRUSTED' | 'NOT_IN_LOG' | 'SUBJECT_MISMATCH' | 'SCHEMA_UNSUPPORTED'
  | 'ABSOLUTE_RULE_FAILED' | 'SOURCE_UNREACHABLE';

export interface Reason {
  code: ReasonCode;
  fact_id?: string;
  rule_id?: string;
  needed?: string;
  detail?: string;
}

export interface Evidence {
  fact_id: string;
  statement_sha256: string;
  log_index: number | null;
  observed_at: string;
  stale_after: string | null;
}

/** schemas/guard-decision.v1.schema.json */
export interface Decision {
  decision: 'allow' | 'hold' | 'deny';
  reasons: Reason[];
  subject: string;
  policy: { id: string; version: number; sha256: string };
  evidence: Evidence[];
  /** The intercepted call (tool, host, argument names). Local only; never sent to Trooth. */
  action?: { tool: string; host: string | null; argument_names: string[]; stored: string; host_fields?: string[] };
  decided_at: string;
}

export type ClaimName =
  | 'trooth_reading' | 'legal_entity_registry_record' | 'no_sanctions_name_match' | 'no_sam_exclusion_name_match'
  | 'domain_registration_record' | 'security_txt_published' | 'domain_control_confirmed' | `check:${string}`;

export interface Rule {
  id: string;
  require: { claim: ClaimName; max_age_days: number | null } | { signature: 'valid'; key_status: Array<'active' | 'retired_before_use'> };
  on_fail: 'hold' | 'deny';
  absolute: boolean;
}

/** A parsed, checked policy (schemas/guard-policy.v1.schema.json is the document form). */
export interface Policy {
  readonly id: string;
  readonly version: number;
  /** SHA-256 (hex) of the RFC 8785 canonical JSON of the document as parsed. */
  readonly sha256: string;
  readonly applies_to: { tools: string[]; http: Array<{ method: string; host: string }> };
  readonly host_from: string[];
  readonly log: { required: boolean; min_witnesses: number };
  readonly rules: Rule[];
  readonly destinations: { allowed: string[]; watch: string[] };
  readonly unknown_counterparty: 'hold' | 'deny';
  readonly source_unreachable: 'hold' | 'deny';
  /** The document as parsed. */
  readonly document: unknown;
}

export interface ToolCall { name: string; arguments: unknown }

export interface GuardOptions {
  policy: Policy;
  /** Injected for tests; default globalThis.fetch. */
  fetch?: typeof fetch;
  now?: () => number;
  /** Default maxAgeSeconds 900. */
  cache?: { dir: string; maxAgeSeconds?: number } | null;
  /** Read only cached bundles, never the network. Needs cache. */
  offline?: boolean;
  /** Default 'hold'. 'allow' is refused (throws). */
  failMode?: 'hold' | 'deny';
  /** Log verifier keys; default the ones pinned in this release. */
  vkeys?: string[];
  /** Witness cosigner keys; default the pinned witnesses. */
  witnesses?: Array<string | { vkey: string; operator?: string }>;
  /** Default https://api.trooth.co and https://trooth.co. */
  api?: string;
  web?: string;
  /** Per-request deadline in milliseconds; default 10000. */
  timeoutMs?: number;
  /** Deadline for a whole decision in milliseconds; default 30000. Past it: hold, SOURCE_UNREACHABLE. */
  deadlineMs?: number;
}

export interface SavedBundle {
  domain: string;
  saved: boolean;
  path?: string;
  reason?: string;
  witness_statement?: boolean;
  public_record?: boolean;
  signature?: 'valid' | 'invalid' | 'absent';
  key_status?: string;
  log?: string;
  witnesses?: number;
}

export interface Guard {
  readonly policy: Policy;
  /** The policy's applies_to.tools ("*" allowed); look-alike and case-folded names are covered too. */
  applies(toolName: string): boolean;
  /** The one host the typed arguments name, or null (none, or more than one). */
  targetHost(toolCall: ToolCall): string | null;
  decide(input: { tool: string; host: string | null; args?: unknown }): Promise<Decision>;
  /** null when the tool is not covered. */
  decideToolCall(toolCall: ToolCall): Promise<Decision | null>;
  /** Read one domain's signed bundle from the network into the cache (trooth guard cache). */
  saveBundle(domain: string): Promise<SavedBundle>;
  readCached(domain: string): unknown;
}

export class PolicyError extends Error {}
export const GUARD_DECISION_SCHEMA: 'https://trooth.co/schemas/guard-decision.v1.json';
export const REASON_CODES: ReasonCode[];
export function parsePolicy(text: string, format?: 'yaml' | 'json'): Policy;
export function loadPolicy(path: string): Promise<Policy>;
export function normalizePolicy(doc: unknown): Policy;
export function createGuard(opts: GuardOptions): Guard;
/** The decision table as a pure function over abstract facts (bin/lib/guard-decide.mjs). */
export function decideFrom(facts: Record<string, unknown>, policy: Policy): Decision;
export function validateDecision(d: unknown): string[];
