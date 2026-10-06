// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.

// Package trooth checks a Trooth witness statement with no trust in Trooth's
// website or API: the rules of docs/VERIFY.md in github.com/troothllc/trooth-cli.
// It uses only the Go standard library, and its tests run that repository's
// vectors. A "checked" verdict means Trooth's key signed these outcome bytes
// for this domain, bound to the exact check mapping and evidence manifest; it
// does not establish the company's identity, an independent time, or that the
// company is safe, compliant or authorized for anything.
package trooth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Statement versions, the bundle format and the v3 canonicalization label.
const (
	WitnessStatementV1   = "trooth.witness-statement.v1"
	WitnessStatementV2   = "trooth.witness-statement.v2"
	WitnessStatementV3   = "trooth.witness-statement.v3"
	VerificationBundleV1 = "trooth.verification-bundle.v1"
	JCSLabel             = "RFC8785"
)

// Reasons maps each v2/v3 reason code to the one outcome it may go with.
var Reasons = map[string]string{
	"source_unavailable":           "not read",
	"timeout":                      "not read",
	"evaluator_limitation":         "not read",
	"carried_from_earlier_reading": "not read",
	"check_misconfigured":          "not read",
	"contrary_observation":         "not as expected",
	"expected_item_absent":         "not as expected",
}

// Assurance says what a valid signature of each version shows and does not show.
var Assurance = map[string]string{
	"v1": "A valid v1 signature shows that Trooth's key signed these outcome bytes for this reading. It does not bind the check mapping, the evaluator version, the subject scope or the evidence sources.",
	"v2": "A valid v2 signature shows that Trooth's key signed these outcome bytes together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, an independently established time, or anything the reading did not read.",
	"v3": "A valid v3 signature shows that Trooth's key signed these RFC 8785 canonical outcome bytes, naming the subject by its stable id and the signing key inside the signed bytes, together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company's identity, an independently established time, or anything the reading did not read.",
}

// ErrBundle is returned when a document is not a usable verification bundle.
var ErrBundle = errors.New("not a usable verification bundle")

var (
	sigRe    = regexp.MustCompile(`^ed25519:([A-Za-z0-9+/]+={0,2})$`)
	hex64Re  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	b64Re    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

// Inputs to VerifyStatement. A nil Mapping or Manifest means not supplied,
// which is never reported as a match. A nil Domain means no domain to compare.
type Inputs struct {
	Statement WitnessStatement
	Keys      []PublicKey
	Mapping   []byte
	Manifest  *EvidenceManifest
	Domain    *string
}

// SHA256Digest returns sha256:<lowercase hex> over the exact bytes.
func SHA256Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// StatementID returns trooth:statement:<hex sha256 of the exact payload bytes>.
func StatementID(payload string) string {
	s := sha256.Sum256([]byte(payload))
	return "trooth:statement:" + hex.EncodeToString(s[:])
}

// CanonicalManifest returns the canonical manifest bytes a v2/v3 statement binds.
func CanonicalManifest(m EvidenceManifest) (string, error) {
	entries := append(EvidenceManifest(nil), m...)
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := utf16.Encode([]rune(entries[i].CheckID)), utf16.Encode([]rune(entries[j].CheckID))
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
	var sb strings.Builder
	sb.WriteByte('[')
	for i, e := range entries {
		if e.CheckID == "" {
			return "", errors.New("a manifest entry has no check_id")
		}
		if i > 0 {
			if entries[i-1].CheckID == e.CheckID {
				return "", fmt.Errorf("the manifest lists %s twice", e.CheckID)
			}
			sb.WriteByte(',')
		}
		sb.WriteString(`{"check_id":`)
		if err := str(&sb, e.CheckID); err != nil {
			return "", err
		}
		if e.Source != nil {
			sb.WriteString(`,"source":`)
			if err := str(&sb, *e.Source); err != nil {
				return "", err
			}
		} else {
			sb.WriteString(`,"commitment":`)
			if e.Commitment == nil {
				sb.WriteString("null")
			} else if err := str(&sb, *e.Commitment); err != nil {
				return "", err
			}
		}
		sb.WriteByte('}')
	}
	sb.WriteByte(']')
	return sb.String(), nil
}

func parseTime(s *string) (time.Time, bool) {
	if s == nil || *s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	return t, err == nil
}

// KeyState returns the lifecycle state of a published key (docs/VERIFY.md section 3).
func KeyState(k *PublicKey) string {
	if k == nil {
		return "unknown"
	}
	if _, ok := parseTime(k.CompromisedAt); ok {
		return "compromised"
	}
	status := strings.ToLower(k.Status)
	if status == "compromised" {
		return "compromised"
	}
	if _, ok := parseTime(k.RetiredAt); ok || status == "retired" {
		return "retired"
	}
	if _, ok := parseTime(k.RevokedAt); ok || status == "revoked" {
		return "revoked_unrecorded"
	}
	if status == "active" || status == "" {
		return "active"
	}
	return "unknown"
}

func findKey(keys []PublicKey, kid string) *PublicKey {
	for i := range keys {
		if keys[i].Kid == kid {
			return &keys[i]
		}
	}
	return nil
}

// KeyTrustAt decides whether a valid signature from kid, carrying signedAt, is relied on.
func KeyTrustAt(kid string, keys []PublicKey, signedAt *string) KeyTrust {
	k := findKey(keys, kid)
	state := KeyState(k)
	switch state {
	case "active":
		return KeyTrust{Kid: kid, State: state, Trusted: true, Reason: "The key is active."}
	case "retired":
		r, rok := parseTime(k.RetiredAt)
		a, aok := parseTime(signedAt)
		if rok && aok && a.Before(r) {
			return KeyTrust{Kid: kid, State: state, Trusted: true, Reason: fmt.Sprintf("Retired at %s; this signature carries the earlier time %s.", *k.RetiredAt, *signedAt)}
		}
		if rok {
			return KeyTrust{Kid: kid, State: state, Trusted: false, Reason: fmt.Sprintf("Retired at %s; this signature carries a time that is not before it.", *k.RetiredAt)}
		}
		return KeyTrust{Kid: kid, State: state, Trusted: false, Reason: "Retired with no recorded retirement time."}
	case "compromised":
		return KeyTrust{Kid: kid, State: state, Trusted: false, Reason: "The key is compromised. No signature from it is relied on."}
	case "revoked_unrecorded":
		return KeyTrust{Kid: kid, State: state, Trusted: false, Reason: "The key is revoked with no recorded reason, so it is treated as compromised."}
	}
	return KeyTrust{Kid: kid, State: "unknown", Trusted: false, Reason: "The key id is not on the key list, so it is not a Trooth key."}
}

func b64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// KeyBytes returns the raw public key a key-list entry carries (hex or base64).
func KeyBytes(k *PublicKey) []byte {
	enc := ""
	if k.Encoding != nil {
		enc = *k.Encoding
	}
	if enc == "hex" || (hex64Re.MatchString(k.PublicKey) && enc != "base64") {
		b, _ := hex.DecodeString(k.PublicKey)
		return b
	}
	b, _ := b64(k.PublicKey)
	return b
}

// payload is a decoded payload with numbers kept exact.
type payload map[string]any

func decodePayload(s string) payload {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func (p payload) str(k string) (string, bool) { s, ok := p[k].(string); return s, ok }
func (p payload) obj(k string) payload        { m, _ := p[k].(map[string]any); return m }

func num(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func eqNum(v any, want int) bool { i, ok := num(v); return ok && i == int64(want) }

// CountProblems lists each identity the payload's counts and checks break. Empty means they hold.
func CountProblems(p payload) []string {
	problems := []string{}
	checks, _ := p["checks"].([]any)
	read, asExpected := 0, 0
	for _, c := range checks {
		cm, _ := c.(map[string]any)
		o, _ := cm["outcome"].(string)
		if o != "not read" {
			read++
		}
		if o == "as expected" {
			asExpected++
		}
		if o != "as expected" && o != "not as expected" && o != "not read" {
			problems = append(problems, fmt.Sprintf("%v: outcome %q is not one of the three", cm["id"], o))
		}
	}
	counts := p.obj("counts")
	if !eqNum(counts["read"], read) {
		problems = append(problems, fmt.Sprintf("counts.read is %v; the checks give %d", counts["read"], read))
	}
	if !eqNum(counts["as_expected"], asExpected) {
		problems = append(problems, fmt.Sprintf("counts.as_expected is %v; the checks give %d", counts["as_expected"], asExpected))
	}
	st, _ := p.str("statement")
	if st == WitnessStatementV2 || st == WitnessStatementV3 {
		r, ok1 := num(counts["read"])
		nr, ok2 := num(counts["not_read"])
		ir, ok3 := num(counts["in_reading"])
		ae, ok4 := num(counts["as_expected"])
		nae, ok5 := num(counts["not_as_expected"])
		if !(ok1 && ok2 && ok3) || r+nr != ir {
			problems = append(problems, "read + not_read does not equal in_reading")
		}
		if !(ok1 && ok4 && ok5) || ae+nae != r {
			problems = append(problems, "as_expected + not_as_expected does not equal read")
		}
		if !eqNum(counts["in_reading"], len(checks)) {
			problems = append(problems, fmt.Sprintf("in_reading is %v; %d checks are listed", counts["in_reading"], len(checks)))
		}
		if !eqNum(p.obj("subject_scope")["checks_in_scope"], len(checks)) {
			problems = append(problems, "subject_scope.checks_in_scope does not equal the checks listed")
		}
		for _, c := range checks {
			cm, _ := c.(map[string]any)
			o, _ := cm["outcome"].(string)
			if o == "as expected" {
				continue
			}
			rm, _ := cm["reason"].(map[string]any)
			code, _ := rm["code"].(string)
			goesWith, known := Reasons[code]
			if rm == nil || !known {
				problems = append(problems, fmt.Sprintf("%v: %q carries no known reason", cm["id"], o))
				continue
			}
			if goesWith != o {
				problems = append(problems, fmt.Sprintf("%v: reason %s cannot go with %q", cm["id"], code, o))
			}
			withheld, _ := rm["withheld"].(bool)
			srcRef, _ := rm["source_ref"].(string)
			why, _ := rm["withheld_reason"].(string)
			if withheld && srcRef != "" {
				problems = append(problems, fmt.Sprintf("%v: marked withheld but publishes a source", cm["id"]))
			}
			if withheld && why == "" {
				problems = append(problems, fmt.Sprintf("%v: withheld with no reason given", cm["id"]))
			}
		}
	}
	if st == WitnessStatementV3 {
		d, _ := p.str("domain")
		want := ""
		if v := strings.TrimSuffix(strings.ToLower(d), "."); len(v) <= 253 && domainRe.MatchString(v) {
			want = "trooth:domain:" + v
		}
		if sid, _ := p.str("subject_id"); want == "" || sid != want {
			problems = append(problems, fmt.Sprintf("subject_id is %v; the payload's domain gives %q", p["subject_id"], want))
		}
		if sd, _ := p.obj("subject_scope")["domain"].(string); sd != d {
			problems = append(problems, "subject_scope.domain does not equal domain")
		}
	}
	return problems
}

func sp(s string) *string { return &s }

// VerifyStatement checks one statement. The result has the shape of schemas/verify-result.schema.json.
func VerifyStatement(in Inputs) VerifyResult {
	st := in.Statement
	p := decodePayload(st.Payload)
	version := "unknown"
	stName, _ := p.str("statement")
	switch stName {
	case WitnessStatementV1:
		version = "v1"
	case WitnessStatementV2:
		version = "v2"
	case WitnessStatementV3:
		version = "v3"
	}
	var readAt *string
	if s, ok := p.str("read_at"); ok {
		readAt = sp(s)
	}
	key := KeyTrustAt(st.KeyID, in.Keys, readAt)

	v3Formed := true
	if version == "v3" {
		signerKid, _ := p.obj("signer")["key_id"].(string)
		v3Formed = st.Canonicalization == JCSLabel && IsCanonical(st.Payload) && p.obj("signer") != nil && signerKid == st.KeyID
	}
	signature := "malformed"
	if m := sigRe.FindStringSubmatch(st.Signature); m != nil && st.Alg == "Ed25519" && version != "unknown" && v3Formed {
		signature = "invalid"
		if k := findKey(in.Keys, st.KeyID); k != nil {
			pub := KeyBytes(k)
			sig, err := b64(m[1])
			if err == nil && len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(ed25519.PublicKey(pub), []byte(st.Payload), sig) {
				signature = "valid"
			}
		}
	}

	var signedDomain, readingID *string
	if s, ok := p.str("domain"); ok {
		signedDomain = sp(s)
	}
	if s, ok := p.str("reading_id"); ok {
		readingID = sp(s)
	}
	assurance, ok := Assurance[version]
	if !ok {
		assurance = "Not a Trooth witness statement this checker knows."
	}
	r := VerifyResult{
		Version:     version,
		Signature:   signature,
		Key:         key,
		Subject:     Subject{Signed: signedDomain, Asked: in.Domain, Status: "not_checked"},
		Binding:     Binding{Status: "unchecked", Mapping: "not_supplied", Manifest: "not_supplied"},
		Counts:      CountCheck{IdentitiesHold: false, Problems: []string{}},
		ReadAt:      readAt,
		ReadingID:   readingID,
		StatementID: sp(StatementID(st.Payload)),
		Assurance:   assurance,
		Verdict:     "signature_not_trusted",
	}
	if in.Domain != nil {
		r.Domain = in.Domain
	} else {
		r.Domain = signedDomain
	}
	if !(signature == "valid" && key.Trusted) {
		return r
	}

	r.Counts.Problems = CountProblems(p)
	r.Counts.IdentitiesHold = len(r.Counts.Problems) == 0
	if in.Domain != nil {
		want := strings.TrimSuffix(strings.ToLower(*in.Domain), ".")
		d, _ := p.str("domain")
		if strings.ToLower(d) == want {
			r.Subject.Status = "match"
		} else {
			r.Subject.Status = "mismatch"
		}
	}
	if version == "v1" {
		r.Binding = Binding{Status: "absent", Mapping: "absent", Manifest: "absent"}
	} else {
		mapping := "not_supplied"
		if in.Mapping != nil {
			md, _ := p.obj("methodology")["mapping_digest"].(string)
			if SHA256Digest(in.Mapping) == md {
				mapping = "match"
			} else {
				mapping = "mismatch"
			}
		}
		man := "not_supplied"
		if in.Manifest != nil {
			em := p.obj("evidence_manifest")
			digest, _ := em["digest"].(string)
			c, err := CanonicalManifest(*in.Manifest)
			if err == nil && SHA256Digest([]byte(c)) == digest && eqNum(em["entries"], len(*in.Manifest)) {
				man = "match"
			} else {
				man = "mismatch"
			}
		}
		status := "partially_checked"
		if mapping == "mismatch" || man == "mismatch" {
			status = "mismatch"
		} else if mapping == "match" && man == "match" {
			status = "bound"
		}
		r.Binding = Binding{Status: status, Mapping: mapping, Manifest: man}
	}
	switch {
	case !r.Counts.IdentitiesHold || r.Subject.Status == "mismatch" || r.Binding.Status == "mismatch":
		r.Verdict = "mismatch"
	case version == "v1":
		r.Verdict = "checked_v1"
	case r.Binding.Status == "bound":
		r.Verdict = "checked"
	default:
		r.Verdict = "partially_checked"
	}
	return r
}

// VerifyBundle checks a trooth.verification-bundle.v1 document with no network.
// A non-nil domain overrides the domain the bundle names.
func VerifyBundle(doc []byte, domain *string) (VerifyResult, error) {
	var b VerificationBundle
	if err := json.Unmarshal(doc, &b); err != nil {
		return VerifyResult{}, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	if b.Bundle != VerificationBundleV1 {
		return VerifyResult{}, fmt.Errorf("%w: not a %s document", ErrBundle, VerificationBundleV1)
	}
	if b.Statement.Payload == "" {
		return VerifyResult{}, fmt.Errorf("%w: no statement with a payload", ErrBundle)
	}
	if b.Keys.Keys == nil {
		return VerifyResult{}, fmt.Errorf("%w: no key list", ErrBundle)
	}
	var mapping []byte
	if b.Mapping != nil {
		if !b64Re.MatchString(b.Mapping.BytesBase64) || len(b.Mapping.BytesBase64)%4 != 0 {
			return VerifyResult{}, fmt.Errorf("%w: the mapping is not standard base64", ErrBundle)
		}
		m, err := base64.StdEncoding.DecodeString(b.Mapping.BytesBase64)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("%w: the mapping is not standard base64", ErrBundle)
		}
		mapping = m
		if mapping == nil {
			mapping = []byte{}
		}
	}
	asked := domain
	if asked == nil {
		asked = b.Domain
	}
	r := VerifyStatement(Inputs{Statement: b.Statement, Keys: b.Keys.Keys, Mapping: mapping, Manifest: b.Manifest, Domain: asked})
	r.KeysReadAt = b.Keys.ListReadAt
	return r, nil
}
