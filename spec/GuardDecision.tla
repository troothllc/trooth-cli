--------------------------- MODULE GuardDecision ---------------------------
(***************************************************************************)
(* The Trooth guard's decision table (docs/GUARD.md section 5), the same    *)
(* table bin/lib/guard-decide.mjs implements and tests/guard-model.test.mjs *)
(* checks exhaustively in JavaScript. Every abstract input is chosen in     *)
(* Init, the decision is computed from it, and TLC checks the invariants    *)
(* over every initial state. Nothing ever changes after Init, so the state  *)
(* space is exactly the set of input combinations.                          *)
(*                                                                          *)
(* Inputs: where the evidence came from (or that no source answered),      *)
(* whether a record exists, whether its version is supported, the          *)
(* signature, the key's status at signing time, whether the signed subject *)
(* is the host or a parent of it, the log, how many pinned witnesses       *)
(* cosigned, the policy's log, unknown_counterparty and source_unreachable *)
(* choices, and up to MaxRules rules, each a hold rule or an absolute rule *)
(* whose claim is present, missing, stale or disputed. A policy with        *)
(* on_fail deny and no absolute, or allow for either choice, is refused by *)
(* parsePolicy, so it is not an input here.                                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxRules, MinWitnesses, MaxWitnesses

Sources     == {"network", "cache", "unreachable"}
Sigs        == {"valid", "invalid", "absent"}
KeyStatuses == {"active", "retired_before_use", "retired_after_use", "revoked", "compromised", "unknown"}
Trusted     == {"active", "retired_before_use"}
LogStates   == {"included", "not_logged", "unavailable", "proof_invalid"}
ClaimStates == {"present", "missing", "stale", "disputed"}
Kinds       == {"hold", "absolute"}
Choices     == {"hold", "deny"}
Decisions   == {"allow", "hold", "deny"}
NoRule      == [kind |-> "none", state |-> "none"]
RuleCfgs    == [kind : Kinds, state : ClaimStates]

VARIABLES source, record, schemaOk, sig, key, subjectOk, log, witnesses,
          logRequired, unknownCp, unreachable, rules, decision

vars == <<source, record, schemaOk, sig, key, subjectOk, log, witnesses,
          logRequired, unknownCp, unreachable, rules, decision>>

RuleIdx   == {i \in 1..MaxRules : rules[i] # NoRule}
(* A claim stands only on a valid signature. *)
RuleOk(i) == sig = "valid" /\ rules[i].state = "present"

FailedSigKeySubject == sig = "invalid" \/ (sig # "absent" /\ key \notin Trusted) \/ ~subjectOk
FailedLogProof      == sig # "absent" /\ log = "proof_invalid"
FailedProof         == FailedSigKeySubject \/ FailedLogProof
LogHold             == sig # "absent" /\ logRequired /\ (log # "included" \/ witnesses < MinWitnesses)
AbsoluteFailed      == \E i \in RuleIdx : rules[i].kind = "absolute" /\ ~RuleOk(i)
HoldRuleFailed      == \E i \in RuleIdx : rules[i].kind = "hold" /\ ~RuleOk(i)

(* The table, in its order. *)
Decide ==
  IF source = "unreachable" THEN unreachable          \* 1. never allow
  ELSE IF ~record THEN unknownCp                       \* 2. NO_RECORD
  ELSE IF ~schemaOk THEN "hold"                        \* 3. SCHEMA_UNSUPPORTED
  ELSE IF FailedSigKeySubject THEN "deny"              \* 4. SIGNATURE_INVALID, KEY_NOT_TRUSTED, SUBJECT_MISMATCH
  ELSE IF FailedLogProof THEN "deny"                   \* 5. NOT_IN_LOG, failed proof
  ELSE IF AbsoluteFailed THEN "deny"                   \* 6. ABSOLUTE_RULE_FAILED
  ELSE IF LogHold \/ HoldRuleFailed THEN "hold"        \* 5, 6. NOT_IN_LOG, EVIDENCE_*
  ELSE "allow"                                         \* 7. RULE_PASSED per rule

Init ==
  /\ source \in Sources
  /\ record \in BOOLEAN
  /\ schemaOk \in BOOLEAN
  /\ sig \in Sigs
  /\ key \in KeyStatuses
  /\ subjectOk \in BOOLEAN
  /\ log \in LogStates
  /\ witnesses \in 0..MaxWitnesses
  /\ logRequired \in BOOLEAN
  /\ unknownCp \in Choices
  /\ unreachable \in Choices
  /\ rules \in [1..MaxRules -> RuleCfgs \cup {NoRule}]
  /\ rules[1] # NoRule
  /\ decision = Decide

Next == UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK == decision \in Decisions

(* allow implies every required check held. *)
AllowOnlyWithEvidence ==
  decision = "allow" =>
    /\ source # "unreachable" /\ record /\ schemaOk
    /\ sig = "valid" /\ key \in Trusted /\ subjectOk
    /\ log # "proof_invalid"
    /\ (logRequired => (log = "included" /\ witnesses >= MinWitnesses))
    /\ \A i \in RuleIdx : rules[i].state = "present"

(* source unreachable never yields allow. *)
UnreachableNeverAllows == source = "unreachable" => decision # "allow"

(* deny happens only for a failed proof or an absolute rule, or where the   *)
(* customer's policy itself chose deny for no record or no source.          *)
DenyOnlyForProofOrAbsolute ==
  decision = "deny" =>
    \/ FailedProof
    \/ AbsoluteFailed
    \/ (source = "unreachable" /\ unreachable = "deny")
    \/ (source # "unreachable" /\ ~record /\ unknownCp = "deny")

(* Missing, stale or disputed evidence alone never denies. *)
MissingEvidenceOnlyHolds ==
  (source # "unreachable" /\ record /\ ~FailedProof /\ ~AbsoluteFailed) => decision # "deny"

(* The same inputs always give the same decision: the decision is a function of them. *)
Deterministic == decision = Decide
=============================================================================
