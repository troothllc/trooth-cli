// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.

package trooth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrNotCanonical is returned when a value has no canonical form under the
// trooth.witness-statement.v3 profile of RFC 8785: integers between
// -(2^53 - 1) and 2^53 - 1 only, valid UTF-8, no lone surrogates.
var ErrNotCanonical = errors.New("no canonical form under the v3 profile")

const maxSafe = 1<<53 - 1

// Canonicalize returns the RFC 8785 canonical text of a JSON document, under
// the same rules as bin/lib/jcs.mjs and sdk/python/trooth_verify/jcs.py.
func Canonicalize(doc []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if dec.More() {
		return "", errors.New("trailing data after the JSON value")
	}
	var b strings.Builder
	if err := canon(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// IsCanonical reports whether text is already the canonical form of the JSON it holds.
func IsCanonical(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	c, err := Canonicalize([]byte(text))
	return err == nil && c == text
}

func canon(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return str(b, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || f > maxSafe || f < -maxSafe {
			return fmt.Errorf("%w: the number %s is not an integer between -(2^53 - 1) and 2^53 - 1", ErrNotCanonical, x)
		}
		b.WriteString(strconv.FormatInt(int64(f), 10))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := str(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := canon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrNotCanonical, v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func str(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: a string is not valid UTF-8 or holds a lone surrogate", ErrNotCanonical)
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
