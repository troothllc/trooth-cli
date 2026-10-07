// Declarations for the Trooth guard adapters: trooth/guard/openai-agents,
// trooth/guard/langchain, trooth/guard/langgraph, trooth/guard/http and
// trooth/guard/errors (docs/GUARD-ADAPTERS.md). The adapters import no
// framework package; framework helpers are passed in.

export type GuardDecisionValue = 'allow' | 'hold' | 'deny';
export type GuardReasonCode =
  | 'RULE_PASSED' | 'EVIDENCE_MISSING' | 'EVIDENCE_STALE' | 'EVIDENCE_DISPUTED' | 'NO_RECORD'
  | 'SIGNATURE_INVALID' | 'KEY_NOT_TRUSTED' | 'NOT_IN_LOG' | 'SUBJECT_MISMATCH' | 'SCHEMA_UNSUPPORTED'
  | 'ABSOLUTE_RULE_FAILED' | 'SOURCE_UNREACHABLE';

/** The parts of a Decision (schemas/guard-decision.v1.schema.json) the adapters read. */
export interface GuardDecisionLike {
  decision: GuardDecisionValue;
  reasons: { code: GuardReasonCode | string; detail?: string; rule_id?: string; fact_id?: string; needed?: string }[];
  subject: string;
  policy: { id: string | null; version: number | null; sha256: string | null };
  evidence: unknown[];
  action?: { tool?: string | null; host?: string | null; [k: string]: unknown } | null;
  decided_at: string;
  [k: string]: unknown;
}

/** The Guard interface from trooth/guard that the adapters use. */
export interface GuardLike {
  policy?: { applies_to?: { tools?: string[]; http?: { method?: string; host: string }[] }; [k: string]: unknown };
  applies(toolName: string): boolean;
  targetHost(toolCall: { name: string; arguments: unknown }): string | null;
  decide(input: { tool: string; host: string | null; args?: unknown }): Promise<GuardDecisionLike>;
  decideToolCall(toolCall: { name: string; arguments: unknown }): Promise<GuardDecisionLike | null>;
}

// ---- trooth/guard/errors -------------------------------------------------
export declare class GuardError extends Error {
  constructor(decision: GuardDecisionLike, message?: string);
  readonly decision: GuardDecisionLike;
  readonly reasons: string[];
}
export declare class GuardHold extends GuardError { readonly code: 'TROOTH_GUARD_HOLD'; }
export declare class GuardDeny extends GuardError { readonly code: 'TROOTH_GUARD_DENY'; }
export declare function errorFor(decision: GuardDecisionLike): GuardHold | GuardDeny | null;
export declare function describeDecision(decision: GuardDecisionLike): string;
export declare function reasonCodes(decision: GuardDecisionLike): string[];
export declare function failClosedDecision(guard: GuardLike | null, input: { tool?: string | null; host?: string | null }, detail: string): GuardDecisionLike;
export declare function isApproval(resume: unknown): boolean;
/** The Decision behind an error a framework threw (it walks .cause and .error), or null. */
export declare function guardDecisionOf(err: unknown): GuardDecisionLike | null;

// ---- trooth/guard/openai-agents -------------------------------------------
export interface ToolGuardrailFunctionOutputLike {
  behavior: { type: 'allow' } | { type: 'rejectContent'; message: string } | { type: 'throwException' };
  outputInfo?: { covered: boolean; decision?: GuardDecisionLike; approved_by_person?: boolean };
}
export interface ToolInputGuardrailLike {
  type: 'tool_input';
  name: string;
  run(data: { context: any; agent: any; toolCall: { name: string; arguments: string; callId: string } }): Promise<ToolGuardrailFunctionOutputLike>;
}
export declare function troothToolInputGuardrail(guard: GuardLike, opts?: { name?: string; onHold?: 'reject' | 'throw' }): ToolInputGuardrailLike;
export declare function troothNeedsApproval(guard: GuardLike, toolName: string, opts?: { onDecision?: (d: GuardDecisionLike) => void }): (runContext: any, input: unknown, callId?: string) => Promise<boolean>;
export declare function guardTool<T extends { name: string; needsApproval?: boolean | ((...a: any[]) => Promise<boolean>); inputGuardrails?: any[] }>(guard: GuardLike, toolOptions: T, opts?: { name?: string; onHold?: 'reject' | 'throw'; onDecision?: (d: GuardDecisionLike) => void }): T & { needsApproval: boolean | ((runContext: any, input: unknown, callId?: string) => Promise<boolean>); inputGuardrails: any[] };
export declare function troothAgentInputGuardrail(guard: GuardLike, opts: { name?: string; extract: (input: unknown, context: unknown) => { tool: string; host: string | null; args?: unknown }[] | Promise<{ tool: string; host: string | null; args?: unknown }[]> }): {
  name: string;
  runInParallel: false;
  execute(args: { input: unknown; context: unknown; agent?: unknown }): Promise<{ tripwireTriggered: boolean; outputInfo: { decisions: GuardDecisionLike[] } }>;
};

// ---- trooth/guard/langchain -----------------------------------------------
export declare const HOLD_INTERRUPT_TYPE: 'trooth_guard_hold';
export interface ToolCallRequestLike { toolCall: { name: string; args: unknown; id?: string }; tool?: unknown; state?: unknown; runtime?: unknown; }
export declare function troothMiddleware(guard: GuardLike, opts?: {
  name?: string;
  interrupt?: (payload: unknown) => unknown;
  ToolMessage?: new (fields: { content: string; tool_call_id?: string; name?: string; status?: 'success' | 'error' }) => unknown;
  onHold?: 'interrupt' | 'message' | 'throw';
  onDeny?: 'throw' | 'message';
  onDecision?: (d: GuardDecisionLike) => void;
}): { name: string; wrapToolCall(request: ToolCallRequestLike, handler: (request: ToolCallRequestLike) => unknown): Promise<unknown> };

// ---- trooth/guard/langgraph -----------------------------------------------
export declare function createGuardNode(guard: GuardLike, opts: {
  interrupt: (payload: unknown) => unknown;
  messagesKey?: string;
  decisionsKey?: string;
  Command?: new (args: { goto?: string; update?: unknown; resume?: unknown }) => unknown;
  denyGoto?: string;
  holdGoto?: string;
  /** Required with denyGoto or holdGoto: the tool node. The graph then has no static edge from the guard node. */
  toolsGoto?: string;
  onDecision?: (d: GuardDecisionLike) => void;
}): (state: Record<string, unknown>) => Promise<Record<string, unknown> | unknown>;

// ---- trooth/guard/http ----------------------------------------------------
export declare function guardFetch(fetchFn: typeof fetch, guard: GuardLike, opts?: { onDecision?: (d: GuardDecisionLike) => void }): typeof fetch;
export declare function httpRules(guard: GuardLike): { method: string; host: RegExp }[];
export declare function requestTarget(input: unknown, init?: { method?: string }): { method: string; host: string } | null;
export declare function coversRequest(rules: { method: string; host: RegExp }[], target: { method: string; host: string } | null): boolean;
