"""Check a Trooth witness statement: the rules of docs/VERIFY.md.

A port of bin/lib/verify.mjs. It trusts nothing Trooth's website or API says
about a statement. tests/vectors/ in github.com/troothllc/trooth-cli holds the
cases every implementation must agree on, and this package's tests run them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .jcs import is_canonical
from .tlog import check_receipt

WITNESS_STATEMENT_V1 = "trooth.witness-statement.v1"
WITNESS_STATEMENT_V2 = "trooth.witness-statement.v2"
WITNESS_STATEMENT_V3 = "trooth.witness-statement.v3"
VERIFICATION_BUNDLE_V1 = "trooth.verification-bundle.v1"
JCS_LABEL = "RFC8785"
CORRECTION_V1 = "trooth.correction.v1"
CORRECTION_REASONS = ("evaluator_defect", "mapping_defect", "source_misread", "signing_key_compromised", "dispute_upheld", "withdrawn_by_trooth")
_SID = re.compile(r"^trooth:statement:[0-9a-f]{64}$")

REASONS = {
    "source_unavailable": "not read",
    "timeout": "not read",
    "evaluator_limitation": "not read",
    "carried_from_earlier_reading": "not read",
    "check_misconfigured": "not read",
    "contrary_observation": "not as expected",
    "expected_item_absent": "not as expected",
}

ASSURANCE = {
    "v1": "A valid v1 signature shows that Trooth's key signed these outcome bytes for this reading. It does not bind the check mapping, the evaluator version, the subject scope or the evidence sources.",
    "v2": "A valid v2 signature shows that Trooth's key signed these outcome bytes together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, an independently established time, or anything the reading did not read.",
    "v3": "A valid v3 signature shows that Trooth's key signed these RFC 8785 canonical outcome bytes, naming the subject by its stable id and the signing key inside the signed bytes, together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, an independently established time, or anything the reading did not read.",
}

_SIG = re.compile(r"^ed25519:([A-Za-z0-9+/]+={0,2})$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class BundleError(ValueError):
    """The document is not a usable verification bundle."""


def sha256_digest(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def statement_id(payload: str) -> str:
    return "trooth:statement:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_manifest(entries: List[Dict[str, Any]]) -> str:
    if not isinstance(entries, list):
        raise ValueError("the manifest is not a list")
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("check_id"), str):
            raise ValueError("a manifest entry has no check_id")
    ordered = sorted(entries, key=lambda e: e["check_id"].encode("utf-16-be", "surrogatepass"))
    seen = set()
    out = []
    for e in ordered:
        if e["check_id"] in seen:
            raise ValueError(f"the manifest lists {e['check_id']} twice")
        seen.add(e["check_id"])
        if "source" in e:
            out.append({"check_id": e["check_id"], "source": e["source"]})
        else:
            out.append({"check_id": e["check_id"], "commitment": e.get("commitment")})
    return json.dumps(out, separators=(",", ":"), ensure_ascii=False)


def _ms(v: Any) -> Optional[float]:
    """Milliseconds since the epoch for an ISO time or a number; None when absent or unparseable."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    s = str(v)
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp() * 1000
    except ValueError:
        return None


def _iso(v: Any) -> Optional[str]:
    return str(v) if _ms(v) is not None else None


def key_state(k: Optional[Dict[str, Any]]) -> str:
    if not k:
        return "unknown"
    if _ms(k.get("compromised_at")) is not None:
        return "compromised"
    status = str(k.get("status") or "").lower()
    if status == "compromised":
        return "compromised"
    if _ms(k.get("retired_at")) is not None or status == "retired":
        return "retired"
    if status == "revoked" or _ms(k.get("revoked_at")) is not None:
        return "revoked_unrecorded"
    if status in ("active", ""):
        return "active"
    return "unknown"


def key_trust(kid: str, keys: List[Dict[str, Any]], signed_at: Optional[str]) -> Dict[str, Any]:
    k = next((x for x in keys or [] if isinstance(x, dict) and x.get("kid") == kid), None)
    state = key_state(k)
    if state == "active":
        return {"kid": kid, "state": state, "trusted": True, "reason": "The key is active."}
    if state == "retired":
        retired, at = _ms(k.get("retired_at")), _ms(signed_at)
        if retired is not None and at is not None and at < retired:
            return {"kid": kid, "state": state, "trusted": True, "reason": f"Retired at {_iso(k.get('retired_at'))}; this signature carries the earlier time {signed_at}."}
        if retired is not None:
            return {"kid": kid, "state": state, "trusted": False, "reason": f"Retired at {_iso(k.get('retired_at'))}; this signature carries {signed_at or 'no time'}, which is not before it."}
        return {"kid": kid, "state": state, "trusted": False, "reason": "Retired with no recorded retirement time."}
    if state == "compromised":
        return {"kid": kid, "state": state, "trusted": False, "reason": "The key is compromised. No signature from it is relied on."}
    if state == "revoked_unrecorded":
        return {"kid": kid, "state": state, "trusted": False, "reason": "The key is revoked with no recorded reason, so it is treated as compromised."}
    return {"kid": kid, "state": state, "trusted": False, "reason": "The key id is not on the key list, so it is not a Trooth key."}


def _b64(s: str) -> bytes:
    """Standard base64 with or without padding, as every implementation reads it."""
    t = s.rstrip("=")
    return base64.b64decode(t + "=" * (-len(t) % 4), validate=True)


def key_bytes(k: Dict[str, Any]) -> bytes:
    v = str(k.get("public_key") or "")
    try:
        if k.get("encoding") == "hex" or (re.fullmatch(r"[0-9a-fA-F]{64}", v) and k.get("encoding") != "base64"):
            return bytes.fromhex(v)
        return _b64(v)
    except (ValueError, binascii.Error):
        return b""


def _ed25519_valid(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _domain_id(domain: Any) -> Optional[str]:
    if not isinstance(domain, str):
        return None
    v = domain.lower().rstrip(".") if domain.endswith(".") else domain.lower()
    return f"trooth:domain:{v}" if _DOMAIN.match(v) else None


def count_problems(p: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    checks = p.get("checks") if isinstance(p.get("checks"), list) else []
    read = sum(1 for c in checks if c.get("outcome") != "not read")
    as_expected = sum(1 for c in checks if c.get("outcome") == "as expected")
    for c in checks:
        if c.get("outcome") not in ("as expected", "not as expected", "not read"):
            problems.append(f'{c.get("id")}: outcome "{c.get("outcome")}" is not one of the three')
    counts = p.get("counts") or {}
    if counts.get("read") != read:
        problems.append(f"counts.read is {counts.get('read')}; the checks give {read}")
    if counts.get("as_expected") != as_expected:
        problems.append(f"counts.as_expected is {counts.get('as_expected')}; the checks give {as_expected}")
    if p.get("statement") in (WITNESS_STATEMENT_V2, WITNESS_STATEMENT_V3):
        c = counts
        try:
            if c.get("read") + c.get("not_read") != c.get("in_reading"):
                problems.append("read + not_read does not equal in_reading")
            if c.get("as_expected") + c.get("not_as_expected") != c.get("read"):
                problems.append("as_expected + not_as_expected does not equal read")
        except TypeError:
            problems.append("a count is missing or not a number")
        if c.get("in_reading") != len(checks):
            problems.append(f"in_reading is {c.get('in_reading')}; {len(checks)} checks are listed")
        if (p.get("subject_scope") or {}).get("checks_in_scope") != len(checks):
            problems.append("subject_scope.checks_in_scope does not equal the checks listed")
        for ch in checks:
            if ch.get("outcome") == "as expected":
                continue
            r = ch.get("reason")
            if not isinstance(r, dict) or r.get("code") not in REASONS:
                problems.append(f'{ch.get("id")}: "{ch.get("outcome")}" carries no known reason')
                continue
            if REASONS[r["code"]] != ch.get("outcome"):
                problems.append(f'{ch.get("id")}: reason {r["code"]} cannot go with "{ch.get("outcome")}"')
            if r.get("withheld") and r.get("source_ref"):
                problems.append(f'{ch.get("id")}: marked withheld but publishes a source')
            if r.get("withheld") and not r.get("withheld_reason"):
                problems.append(f'{ch.get("id")}: withheld with no reason given')
    if p.get("statement") == WITNESS_STATEMENT_V3:
        want = _domain_id(p.get("domain"))
        if not want or p.get("subject_id") != want:
            problems.append(f"subject_id is {p.get('subject_id')}; the payload's domain gives {want or 'no valid id'}")
        if (p.get("subject_scope") or {}).get("domain") != p.get("domain"):
            problems.append("subject_scope.domain does not equal domain")
    return problems


def verify_correction(correction: Any, receipt: Any, keys: List[Dict[str, Any]], vkeys: List[str], statement_id_value: Optional[str]) -> Dict[str, Any]:
    """Check one trooth.correction.v1 envelope against the statement it may supersede."""
    res: Dict[str, Any] = {"valid": False, "correction_statement_id": None, "code": None, "effect": None, "replacement": None, "issued_at": None, "reason": None}

    def fail(why: str) -> Dict[str, Any]:
        return {**res, "reason": why}

    if not isinstance(correction, dict) or not isinstance(correction.get("payload"), str):
        return fail("no correction payload")
    res["correction_statement_id"] = statement_id(correction["payload"])
    try:
        p = json.loads(correction["payload"])
    except ValueError:
        return fail("the correction payload is not JSON")
    if not isinstance(p, dict) or p.get("statement") != CORRECTION_V1:
        return fail("not a trooth.correction.v1 payload")
    if correction.get("alg") != "Ed25519" or correction.get("canonicalization") != JCS_LABEL or not is_canonical(correction["payload"]):
        return fail("the correction is not RFC 8785 bytes signed with Ed25519")
    signer = p.get("signer") if isinstance(p.get("signer"), dict) else {}
    if signer.get("key_id") != correction.get("key_id") or signer.get("issuer") != "trooth.co":
        return fail("the signer inside the correction is not the envelope key")
    reason = p.get("reason") if isinstance(p.get("reason"), dict) else {}
    res.update({"code": reason.get("code"), "effect": p.get("effect"), "replacement": p.get("replacement"), "issued_at": p.get("issued_at")})
    if p.get("supersedes") != statement_id_value:
        return fail("the correction supersedes another statement")
    if reason.get("code") not in CORRECTION_REASONS:
        return fail("the correction reason code is not known")
    ok_effect = (p.get("effect") == "withdrawn" and p.get("replacement") is None) or (
        p.get("effect") == "replaced" and isinstance(p.get("replacement"), str) and bool(_SID.match(p["replacement"])))
    if not ok_effect:
        return fail("the correction effect and replacement disagree")
    m = _SIG.match(str(correction.get("signature") or ""))
    published = next((k for k in keys or [] if isinstance(k, dict) and k.get("kid") == correction.get("key_id")), None)
    try:
        sig = _b64(m.group(1)) if m else b""
    except (ValueError, binascii.Error):
        sig = b""
    if not m or not published or not _ed25519_valid(key_bytes(published), sig, correction["payload"].encode("utf-8")):
        return fail("the correction signature does not check")
    kt = key_trust(str(correction.get("key_id")), keys, p.get("issued_at") if isinstance(p.get("issued_at"), str) else None)
    if not kt["trusted"]:
        return fail(f"the correction key is not trusted: {kt['reason']}")
    r = check_receipt("correction", correction, receipt, vkeys)
    if r["status"] != "included":
        return fail(f"the correction is not shown in the log: {r['reason']}")
    return {**res, "valid": True, "reason": f"entry {r['index']} of the log"}


def _check_log(statement: Dict[str, Any], log: Dict[str, Any], keys: List[Dict[str, Any]], sid: Optional[str]) -> Dict[str, Any]:
    vkeys = log.get("vkeys") if isinstance(log.get("vkeys"), list) else []
    out: Dict[str, Any] = {"status": "not_logged", "index": None, "tree_size": None, "reason": None, "corrections": [], "superseded_by": None}
    if log.get("unavailable"):
        out.update({"status": "unavailable", "reason": str(log["unavailable"])})
        return out
    if log.get("receipt"):
        r = check_receipt("witness_statement", statement, log["receipt"], vkeys)
        out.update({"status": r["status"], "index": r["index"], "tree_size": r["tree_size"], "reason": r["reason"]})
    else:
        out["reason"] = "The log holds no entry for this statement."
    for c in log.get("corrections") or []:
        c = c if isinstance(c, dict) else {}
        v = verify_correction(c.get("statement"), c.get("receipt"), keys, vkeys, sid)
        out["corrections"].append(v)
        if v["valid"] and not out["superseded_by"]:
            out["superseded_by"] = v["correction_statement_id"]
    return out


def verify_statement(statement: Dict[str, Any], keys: List[Dict[str, Any]], mapping_bytes: Optional[bytes] = None,
                     manifest: Optional[List[Dict[str, Any]]] = None, domain: Optional[str] = None,
                     log: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Check one statement. Returns a dict shaped like schemas/verify-result.schema.json."""
    statement = statement or {}
    raw = statement.get("payload")
    payload: Any = None
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = None
    if not isinstance(payload, dict):
        payload = None
    st = payload.get("statement") if payload else None
    version = {WITNESS_STATEMENT_V1: "v1", WITNESS_STATEMENT_V2: "v2", WITNESS_STATEMENT_V3: "v3"}.get(st, "unknown")
    read_at = payload.get("read_at") if payload and isinstance(payload.get("read_at"), str) else None
    key = key_trust(str(statement.get("key_id") or ""), keys, read_at)

    v3_formed = version != "v3" or (
        statement.get("canonicalization") == JCS_LABEL and is_canonical(raw)
        and isinstance(payload.get("signer"), dict) and payload["signer"].get("key_id") == statement.get("key_id"))

    signature = "malformed"
    m = _SIG.match(str(statement.get("signature") or ""))
    published = next((k for k in keys or [] if isinstance(k, dict) and k.get("kid") == statement.get("key_id")), None)
    if m and statement.get("alg") == "Ed25519" and isinstance(raw, str) and version != "unknown" and v3_formed:
        try:
            sig = _b64(m.group(1))
        except (ValueError, binascii.Error):
            sig = b""
        signature = "valid" if published and _ed25519_valid(key_bytes(published), sig, raw.encode("utf-8")) else "invalid"

    trusted = signature == "valid" and key["trusted"]
    result: Dict[str, Any] = {
        "version": version,
        "signature": signature,
        "key": key,
        "trusted": trusted,
        "subject": {"signed": payload.get("domain") if payload else None, "asked": domain, "status": "not_checked"},
        "binding": {"status": "unchecked", "mapping": "not_supplied", "manifest": "not_supplied"},
        "counts": {"identities_hold": False, "problems": []},
        "read_at": read_at,
        "reading_id": payload.get("reading_id") if payload else None,
        "statement_id": statement_id(raw) if isinstance(raw, str) else None,
        "assurance": ASSURANCE.get(version, "Not a Trooth witness statement this checker knows."),
        "verdict": "signature_not_trusted",
    }
    if not trusted:
        return result

    result["counts"]["problems"] = count_problems(payload)
    result["counts"]["identities_hold"] = not result["counts"]["problems"]
    if domain is not None:
        want = str(domain).lower()
        if want.endswith("."):
            want = want[:-1]
        result["subject"]["status"] = "match" if str(payload.get("domain") or "").lower() == want else "mismatch"
    if version == "v1":
        result["binding"] = {"status": "absent", "mapping": "absent", "manifest": "absent"}
    else:
        if mapping_bytes is None:
            mapping = "not_supplied"
        else:
            mapping = "match" if sha256_digest(mapping_bytes) == (payload.get("methodology") or {}).get("mapping_digest") else "mismatch"
        man = "not_supplied"
        if manifest is not None:
            try:
                em = payload.get("evidence_manifest") or {}
                man = "match" if sha256_digest(canonical_manifest(manifest)) == em.get("digest") and len(manifest) == em.get("entries") else "mismatch"
            except ValueError:
                man = "mismatch"
        status = "mismatch" if "mismatch" in (mapping, man) else ("bound" if mapping == man == "match" else "partially_checked")
        result["binding"] = {"status": status, "mapping": mapping, "manifest": man}

    if log is not None:
        result["log"] = _check_log(statement, log, keys, result["statement_id"])
    lg = result.get("log")
    if not result["counts"]["identities_hold"] or result["subject"]["status"] == "mismatch" or result["binding"]["status"] == "mismatch":
        result["verdict"] = "mismatch"
    elif lg and lg["status"] in ("proof_invalid", "checkpoint_invalid"):
        result["verdict"] = "mismatch"
    elif lg and lg["superseded_by"]:
        result["verdict"] = "superseded"
    elif version == "v1":
        result["verdict"] = "checked_v1"
    elif result["binding"]["status"] == "bound":
        result["verdict"] = "checked"
    else:
        result["verdict"] = "partially_checked"
    return result


def verify_bundle(bundle: Dict[str, Any], domain: Optional[str] = None, vkeys: Optional[List[str]] = None) -> Dict[str, Any]:
    """Check a trooth.verification-bundle.v1 document with no network. Raises BundleError."""
    if not isinstance(bundle, dict) or bundle.get("bundle") != VERIFICATION_BUNDLE_V1:
        raise BundleError(f"not a {VERIFICATION_BUNDLE_V1} document")
    st = bundle.get("statement")
    if not isinstance(st, dict) or not isinstance(st.get("payload"), str):
        raise BundleError("the bundle carries no statement with a payload")
    keys = bundle.get("keys")
    if not isinstance(keys, dict) or not isinstance(keys.get("keys"), list):
        raise BundleError("the bundle carries no key list")
    manifest = bundle.get("manifest")
    if manifest is not None and not isinstance(manifest, list):
        raise BundleError("the bundle manifest is not a list")
    mapping_bytes = None
    mp = bundle.get("mapping")
    if mp is not None:
        b64 = mp.get("bytes_base64") if isinstance(mp, dict) else None
        if not isinstance(b64, str) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", b64) or len(b64) % 4:
            raise BundleError("the bundle mapping is not standard base64")
        mapping_bytes = base64.b64decode(b64)
    asked = domain if domain is not None else (bundle.get("domain") if isinstance(bundle.get("domain"), str) else None)
    log = None
    bl = bundle.get("log")
    if isinstance(bl, dict):
        log = {"vkeys": vkeys if vkeys else ([bl["vkey"]] if isinstance(bl.get("vkey"), str) else []),
               "receipt": bl.get("receipt"), "corrections": bl.get("corrections") if isinstance(bl.get("corrections"), list) else []}
    r = verify_statement(st, keys["keys"], mapping_bytes, manifest, asked, log)
    r["keys_read_at"] = keys.get("list_read_at") if isinstance(keys.get("list_read_at"), str) else None
    return r
