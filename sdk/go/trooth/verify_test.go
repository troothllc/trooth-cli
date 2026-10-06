package trooth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var vecDir = filepath.Join("..", "..", "..", "tests", "vectors")

type vector struct {
	Name      string            `json:"name"`
	Note      string            `json:"note"`
	Statement WitnessStatement  `json:"statement"`
	Keys      []PublicKey       `json:"keys"`
	Mapping   json.RawMessage   `json:"mapping"`
	Manifest  *EvidenceManifest `json:"manifest"`
	Domain    string            `json:"domain"`
	Expect    struct {
		Verdict   string `json:"verdict"`
		Signature string `json:"signature"`
	} `json:"expect"`
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	var doc struct {
		MappingFile      string   `json:"mapping_file"`
		OtherMappingFile string   `json:"other_mapping_file"`
		Vectors          []vector `json:"vectors"`
	}
	if err := json.Unmarshal(read(t, "vectors.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 27 {
		t.Fatalf("only %d vectors", len(doc.Vectors))
	}
	mapping, other := read(t, doc.MappingFile), read(t, doc.OtherMappingFile)
	for _, v := range doc.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var mb []byte
			switch string(v.Mapping) {
			case "true":
				mb = mapping
			case `"other"`:
				mb = other
			}
			d := v.Domain
			r := VerifyStatement(Inputs{Statement: v.Statement, Keys: v.Keys, Mapping: mb, Manifest: v.Manifest, Domain: &d})
			if r.Verdict != v.Expect.Verdict || r.Signature != v.Expect.Signature {
				t.Fatalf("%s: got %s/%s, want %s/%s (%v)", v.Note, r.Verdict, r.Signature, v.Expect.Verdict, v.Expect.Signature, r.Counts.Problems)
			}
		})
	}
}

func TestBundles(t *testing.T) {
	var doc struct {
		Bundles []struct {
			Name   string          `json:"name"`
			Bundle json.RawMessage `json:"bundle"`
			Domain *string         `json:"domain"`
			Expect struct {
				Verdict   string `json:"verdict"`
				Signature string `json:"signature"`
				Error     string `json:"error"`
			} `json:"expect"`
		} `json:"bundles"`
	}
	if err := json.Unmarshal(read(t, "bundles.json"), &doc); err != nil {
		t.Fatal(err)
	}
	for _, b := range doc.Bundles {
		b := b
		t.Run(b.Name, func(t *testing.T) {
			r, err := VerifyBundle(b.Bundle, b.Domain)
			if b.Expect.Error != "" {
				if !errors.Is(err, ErrBundle) {
					t.Fatalf("want ErrBundle, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Verdict != b.Expect.Verdict || r.Signature != b.Expect.Signature {
				t.Fatalf("got %s/%s, want %s/%s", r.Verdict, r.Signature, b.Expect.Verdict, b.Expect.Signature)
			}
		})
	}
}

func TestRealTroothBundle(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "bundles", "trooth.co-2026-10-06.bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyBundle(b, nil)
	if err != nil || r.Verdict != "checked" {
		t.Fatalf("got %v, %v", r.Verdict, err)
	}
}

func TestCanonical(t *testing.T) {
	c, err := Canonicalize([]byte(`{"😀":1,"דּ":2,"b":[true,null,"a\u0000\u001f\"\\/"]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"b\":[true,null,\"a\\u0000\\u001f\\\"\\\\/\"],\"\U0001F600\":1,\"דּ\":2}"
	if c != want {
		t.Fatalf("got %s", c)
	}
	for _, bad := range []string{`0.5`, `9007199254740992`, `1e400`} {
		if _, err := Canonicalize([]byte(bad)); !errors.Is(err, ErrNotCanonical) {
			t.Fatalf("%s: want ErrNotCanonical, got %v", bad, err)
		}
	}
	if IsCanonical(`{"b":2,"a":1}`) || !IsCanonical(`{"a":1,"b":2}`) || IsCanonical(`{"a":1e0}`) {
		t.Fatal("IsCanonical disagrees with the profile")
	}
}

func TestLogVectors(t *testing.T) {
	var doc struct {
		Vkey        string            `json:"vkey"`
		Impostor    string            `json:"impostor_vkey"`
		Checkpoints map[string]string `json:"checkpoints"`
		Cases       []struct {
			Name      string            `json:"name"`
			Note      string            `json:"note"`
			Statement WitnessStatement  `json:"statement"`
			Keys      []PublicKey       `json:"keys"`
			Manifest  *EvidenceManifest `json:"manifest"`
			Domain    string            `json:"domain"`
			Log       struct {
				Vkeys       []string           `json:"vkeys"`
				Receipt     *LogReceipt        `json:"receipt"`
				Corrections []LoggedCorrection `json:"corrections"`
			} `json:"log"`
			Expect struct {
				Verdict string  `json:"verdict"`
				Log     *string `json:"log"`
			} `json:"expect"`
		} `json:"cases"`
		Consistency []struct {
			Name   string   `json:"name"`
			First  uint64   `json:"first"`
			Second uint64   `json:"second"`
			FR     string   `json:"first_root"`
			SR     string   `json:"second_root"`
			Proof  []string `json:"proof"`
			Expect bool     `json:"expect"`
		} `json:"consistency"`
	}
	if err := json.Unmarshal(read(t, "log.json"), &doc); err != nil {
		t.Fatal(err)
	}
	mapping := read(t, "mapping-test-1.0.0.json")
	for _, c := range doc.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			d := c.Domain
			r := VerifyStatement(Inputs{Statement: c.Statement, Keys: c.Keys, Mapping: mapping, Manifest: c.Manifest, Domain: &d, Log: &LogInputs{Vkeys: c.Log.Vkeys, Receipt: c.Log.Receipt, Corrections: c.Log.Corrections}})
			var got *string
			if r.Log != nil {
				got = &r.Log.Status
			}
			if r.Verdict != c.Expect.Verdict || (got == nil) != (c.Expect.Log == nil) || (got != nil && *got != *c.Expect.Log) {
				t.Fatalf("%s: got %s/%v, want %s/%v", c.Note, r.Verdict, got, c.Expect.Verdict, c.Expect.Log)
			}
		})
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	for _, c := range doc.Consistency {
		var p [][]byte
		for _, x := range c.Proof {
			p = append(p, dec(x))
		}
		if VerifyConsistency(c.First, c.Second, dec(c.FR), dec(c.SR), p) != c.Expect {
			t.Fatalf("consistency %s", c.Name)
		}
	}
	if cp, err := OpenCheckpoint(doc.Checkpoints["5"], doc.Vkey); err != nil || cp.Size != 5 {
		t.Fatalf("checkpoint 5: %v", err)
	}
	if _, err := OpenCheckpoint(doc.Checkpoints["5"], doc.Impostor); err == nil {
		t.Fatal("an impostor key opened the checkpoint")
	}
}
