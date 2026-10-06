// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.

package trooth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// LogOrigin is the origin line of Trooth's witness statement log (docs/LOG.md).
const LogOrigin = "trooth.co/witness-log/v1"

var (
	vkeyRe    = regexp.MustCompile(`^([^+\s]+)\+([0-9a-f]{8})\+([A-Za-z0-9+/]+={0,2})$`)
	sigLineRe = regexp.MustCompile("^— (\\S+) ([A-Za-z0-9+/]+={0,2})$")
	sizeRe    = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
)

func h(parts ...[]byte) []byte {
	d := sha256.New()
	for _, p := range parts {
		d.Write(p)
	}
	return d.Sum(nil)
}

// LeafHash is SHA-256(0x00 || entry), as RFC 9162 defines a leaf.
func LeafHash(entry []byte) []byte { return h([]byte{0}, entry) }

// NodeHash is SHA-256(0x01 || left || right).
func NodeHash(l, r []byte) []byte { return h([]byte{1}, l, r) }

// EntryBytes is the exact log entry for a statement: RFC 8785 JSON of {kind, statement}.
func EntryBytes(kind string, s WitnessStatement) ([]byte, error) {
	if kind != "witness_statement" && kind != "correction" {
		return nil, fmt.Errorf("unknown log entry kind: %s", kind)
	}
	if s.Payload == "" || s.Signature == "" || s.KeyID == "" || s.Alg == "" || s.Canonicalization == "" {
		return nil, errors.New("the statement is missing an envelope field")
	}
	var b strings.Builder
	b.WriteString(`{"kind":`)
	if err := str(&b, kind); err != nil {
		return nil, err
	}
	b.WriteString(`,"statement":{`)
	for i, kv := range [][2]string{{"alg", s.Alg}, {"canonicalization", s.Canonicalization}, {"key_id", s.KeyID}, {"payload", s.Payload}, {"signature", s.Signature}} {
		if i > 0 {
			b.WriteByte(',')
		}
		_ = str(&b, kv[0])
		b.WriteByte(':')
		if err := str(&b, kv[1]); err != nil {
			return nil, err
		}
	}
	b.WriteString("}}")
	return []byte(b.String()), nil
}

func eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyInclusion checks an RFC 9162 inclusion proof.
func VerifyInclusion(index, size uint64, leaf []byte, proof [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range proof {
		if len(p) != 32 || sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && eq(r, root)
}

// VerifyConsistency checks an RFC 9162 consistency proof between two tree sizes.
func VerifyConsistency(first, second uint64, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if first > second {
		return false
	}
	if first == second {
		return len(proof) == 0 && eq(firstRoot, secondRoot)
	}
	if first == 0 {
		return len(proof) == 0
	}
	for _, p := range proof {
		if len(p) != 32 {
			return false
		}
	}
	path := proof
	if first&(first-1) == 0 {
		path = append([][]byte{firstRoot}, proof...)
	}
	if len(path) == 0 {
		return false
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && eq(fr, firstRoot) && eq(sr, secondRoot)
}

// Vkey is a parsed signed-note Ed25519 verifier key.
type Vkey struct {
	Name string
	Hash []byte
	Key  ed25519.PublicKey
}

// NoteKeyHash is SHA-256(name || 0x0A || 0x01 || key)[0:4].
func NoteKeyHash(name string, key []byte) []byte {
	return h([]byte(name), []byte{0x0a, 0x01}, key)[:4]
}

// ParseVkey parses <name>+<hash hex>+<base64(0x01 || key)>.
func ParseVkey(s string) (Vkey, error) {
	m := vkeyRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Vkey{}, errors.New("not a signed-note verifier key")
	}
	raw, err := base64.StdEncoding.DecodeString(m[3])
	if err != nil || len(raw) != 33 || raw[0] != 1 {
		return Vkey{}, errors.New("the verifier key is not an Ed25519 key")
	}
	key := raw[1:]
	if hex.EncodeToString(NoteKeyHash(m[1], key)) != m[2] {
		return Vkey{}, errors.New("the verifier key hash does not match its key")
	}
	return Vkey{Name: m[1], Hash: NoteKeyHash(m[1], key), Key: ed25519.PublicKey(key)}, nil
}

// VerifyNote returns the note text when a signature line by the key verifies over it.
func VerifyNote(note string, v Vkey) (string, bool) {
	split := strings.LastIndex(note, "\n\n")
	if split < 0 || !strings.HasSuffix(note, "\n") {
		return "", false
	}
	text := note[:split+1]
	lines := strings.Split(note[split+2:], "\n")
	for _, line := range lines[:len(lines)-1] {
		m := sigLineRe.FindStringSubmatch(line)
		if m == nil || m[1] != v.Name {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil || len(raw) != 68 || !eq(raw[:4], v.Hash) {
			continue
		}
		if ed25519.Verify(v.Key, []byte(text), raw[4:]) {
			return text, true
		}
	}
	return "", false
}

// Checkpoint is a parsed C2SP checkpoint.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   []byte
}

// OpenCheckpoint verifies a signed checkpoint against a key and parses it.
func OpenCheckpoint(note, vkey string) (Checkpoint, error) {
	v, err := ParseVkey(vkey)
	if err != nil {
		return Checkpoint{}, err
	}
	text, ok := VerifyNote(note, v)
	if !ok {
		return Checkpoint{}, errors.New("the checkpoint signature does not check against the log key")
	}
	lines := strings.Split(text, "\n")
	if len(lines) < 4 || lines[len(lines)-1] != "" || !sizeRe.MatchString(lines[1]) {
		return Checkpoint{}, errors.New("not a checkpoint")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, errors.New("the checkpoint size is out of range")
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != 32 || base64.StdEncoding.EncodeToString(root) != lines[2] {
		return Checkpoint{}, errors.New("the checkpoint root is not 32 bytes of base64")
	}
	if lines[0] != LogOrigin {
		return Checkpoint{}, fmt.Errorf("the checkpoint names the log %s, not %s", lines[0], LogOrigin)
	}
	return Checkpoint{Origin: lines[0], Size: size, Root: root}, nil
}

func b32(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return nil
	}
	return b
}

// ReceiptCheck is the outcome of CheckReceipt.
type ReceiptCheck struct {
	Status   string
	Index    *int64
	TreeSize *int64
	Reason   string
}

// CheckReceipt checks a log receipt for one statement against the log keys.
func CheckReceipt(kind string, s WitnessStatement, r *LogReceipt, vkeys []string) ReceiptCheck {
	if r == nil {
		return ReceiptCheck{Status: "proof_invalid", Reason: "no receipt"}
	}
	idx, size := r.Index, r.TreeSize
	out := func(status, reason string) ReceiptCheck {
		return ReceiptCheck{Status: status, Index: &idx, TreeSize: &size, Reason: reason}
	}
	if r.Log != LogOrigin {
		return out("proof_invalid", "the receipt names another log")
	}
	var cp *Checkpoint
	why := "no log key to check against"
	for _, k := range vkeys {
		c, err := OpenCheckpoint(r.Checkpoint, k)
		if err == nil {
			cp = &c
			break
		}
		why = err.Error()
	}
	if cp == nil {
		return out("checkpoint_invalid", why)
	}
	if r.Index < 0 || r.TreeSize < 1 || cp.Size != uint64(r.TreeSize) {
		return out("proof_invalid", "the receipt size is not the checkpoint size")
	}
	if r.RootHash != base64.StdEncoding.EncodeToString(cp.Root) {
		return out("proof_invalid", "the receipt root is not the checkpoint root")
	}
	proof := make([][]byte, 0, len(r.InclusionProof))
	for _, p := range r.InclusionProof {
		b := b32(p)
		if b == nil {
			return out("proof_invalid", "a proof hash is not 32 bytes of base64")
		}
		proof = append(proof, b)
	}
	entry, err := EntryBytes(kind, s)
	if err != nil {
		return out("proof_invalid", err.Error())
	}
	if !VerifyInclusion(uint64(r.Index), uint64(r.TreeSize), LeafHash(entry), proof, cp.Root) {
		return out("proof_invalid", "the inclusion proof does not reach the signed root")
	}
	return out("included", fmt.Sprintf("entry %d of a signed tree of %d", r.Index, r.TreeSize))
}
