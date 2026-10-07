"""Checking Trooth's witness statement log (docs/LOG.md): RFC 9162 Merkle proofs,
C2SP checkpoints and C2SP signed notes with Ed25519. The same rules as
bin/lib/tlog.mjs and sdk/go/trooth/tlog.go."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .jcs import canonicalize

LOG_ORIGIN = "trooth.co/witness-log/v1"
ENTRY_KINDS = ("witness_statement", "correction", "public_record")


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


def leaf_hash(entry: bytes) -> bytes:
    return _h(b"\x00", entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01", left, right)


def entry_bytes(kind: str, statement: Dict[str, Any]) -> bytes:
    if kind not in ENTRY_KINDS:
        raise ValueError(f"unknown log entry kind: {kind}")
    s = statement or {}
    for f in ("payload", "signature", "key_id", "alg", "canonicalization"):
        if not isinstance(s.get(f), str):
            raise ValueError(f"the statement has no {f}")
    env = {k: s[k] for k in ("alg", "canonicalization", "key_id", "payload", "signature")}
    return canonicalize({"kind": kind, "statement": env}).encode("utf-8")


def verify_inclusion(index: int, size: int, leaf: bytes, proof: List[bytes], root: bytes) -> bool:
    if index < 0 or index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if len(p) != 32 or sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: List[bytes]) -> bool:
    if first < 0 or first > second:
        return False
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if first == 0:
        return len(proof) == 0
    path = list(proof)
    if any(len(p) != 32 for p in path):
        return False
    if first & (first - 1) == 0:
        path = [first_root] + path
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


def note_key_hash(name: str, key: bytes) -> bytes:
    return _h(name.encode("utf-8"), b"\x0a\x01", key)[:4]


def parse_vkey(vkey: str) -> Dict[str, Any]:
    m = re.fullmatch(r"([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})", str(vkey).strip())
    if not m:
        raise ValueError("not a signed-note verifier key")
    raw = base64.b64decode(m.group(3))
    if len(raw) != 33 or raw[0] != 1:
        raise ValueError("the verifier key is not an Ed25519 key")
    key = raw[1:]
    if note_key_hash(m.group(1), key).hex() != m.group(2):
        raise ValueError("the verifier key hash does not match its key")
    return {"name": m.group(1), "hash": note_key_hash(m.group(1), key), "key": key}


def verify_note(note: str, vkey: str) -> Optional[str]:
    v = parse_vkey(vkey)
    s = str(note)
    split = s.rfind("\n\n")
    if split < 0 or not s.endswith("\n"):
        return None
    text = s[: split + 1]
    for line in s[split + 2 :].split("\n")[:-1]:
        m = re.fullmatch("— (\\S+) ([A-Za-z0-9+/]+={0,2})", line)
        if not m or m.group(1) != v["name"]:
            continue
        try:
            raw = base64.b64decode(m.group(2))
        except (ValueError, binascii.Error):
            continue
        if len(raw) != 68 or raw[:4] != v["hash"]:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(v["key"]).verify(raw[4:], text.encode("utf-8"))
            return text
        except (InvalidSignature, ValueError):
            continue
    return None


def parse_checkpoint(text: str) -> Dict[str, Any]:
    lines = str(text).split("\n")
    if len(lines) < 4 or lines[-1] != "":
        raise ValueError("the checkpoint is not three lines and a newline")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    if not re.fullmatch(r"0|[1-9][0-9]{0,18}", size_s):
        raise ValueError("the checkpoint size is not a decimal number")
    try:
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("the checkpoint root is not base64")
    if len(root) != 32 or base64.b64encode(root).decode() != root_b64:
        raise ValueError("the checkpoint root is not 32 bytes of base64")
    return {"origin": origin, "size": int(size_s), "root": root}


def open_checkpoint(note: str, vkey: str, origin: str = LOG_ORIGIN) -> Dict[str, Any]:
    text = verify_note(note, vkey)
    if text is None:
        raise ValueError("the checkpoint signature does not check against the log key")
    cp = parse_checkpoint(text)
    if cp["origin"] != origin:
        raise ValueError(f"the checkpoint names the log {cp['origin']}, not {origin}")
    return cp


def _b32(s: Any) -> Optional[bytes]:
    if not isinstance(s, str):
        return None
    try:
        b = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        return None
    return b if len(b) == 32 and base64.b64encode(b).decode() == s else None


def check_receipt(kind: str, statement: Dict[str, Any], receipt: Any, vkeys: List[str]) -> Dict[str, Any]:
    def out(status: str, reason: str) -> Dict[str, Any]:
        r = receipt if isinstance(receipt, dict) else {}
        return {"status": status, "index": r.get("index"), "tree_size": r.get("tree_size"), "reason": reason}

    if not isinstance(receipt, dict):
        return out("proof_invalid", "no receipt")
    if receipt.get("log") != LOG_ORIGIN:
        return out("proof_invalid", f"the receipt names the log {receipt.get('log')}")
    cp, why = None, "no log key to check against"
    for k in vkeys or []:
        try:
            cp = open_checkpoint(receipt.get("checkpoint", ""), k)
            break
        except ValueError as e:
            why = str(e)
    if cp is None:
        return out("checkpoint_invalid", why)
    idx, size = receipt.get("index"), receipt.get("tree_size")
    if not isinstance(idx, int) or isinstance(idx, bool) or not isinstance(size, int) or isinstance(size, bool):
        return out("proof_invalid", "the receipt index or size is not an integer")
    if cp["size"] != size:
        return out("proof_invalid", "the receipt size is not the checkpoint size")
    if receipt.get("root_hash") != base64.b64encode(cp["root"]).decode():
        return out("proof_invalid", "the receipt root is not the checkpoint root")
    proof = [_b32(p) for p in (receipt.get("inclusion_proof") or [])]
    if any(p is None for p in proof):
        return out("proof_invalid", "a proof hash is not 32 bytes of base64")
    try:
        leaf = leaf_hash(entry_bytes(kind, statement))
    except ValueError as e:
        return out("proof_invalid", str(e))
    if not verify_inclusion(idx, size, leaf, proof, cp["root"]):  # type: ignore[arg-type]
        return out("proof_invalid", "the inclusion proof does not reach the signed root")
    return out("included", f"entry {idx} of a signed tree of {size}")
