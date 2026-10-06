# Trooth verifier (Go)

Check a Trooth witness statement yourself, with no trust in Trooth's website or API. Standard library only. It follows [docs/VERIFY.md](../../docs/VERIFY.md) and passes every case in [tests/vectors](../../tests/vectors).

```
go get github.com/troothllc/trooth-cli/sdk/go@latest
```

```go
import trooth "github.com/troothllc/trooth-cli/sdk/go/trooth"

doc, _ := os.ReadFile("trooth.co.bundle.json") // written by: trooth verify trooth.co --save-bundle trooth.co.bundle.json
r, err := trooth.VerifyBundle(doc, nil)
fmt.Println(r.Verdict) // checked, checked_v1, partially_checked, signature_not_trusted or mismatch
```

`trooth.VerifyStatement(trooth.Inputs{...})` checks inputs you read yourself; a nil `Mapping` or `Manifest` means not supplied, which is never reported as a match. The types in `types.go` are generated from [schemas/](../../schemas).

Bundles written by `trooth` 0.9.0 and later carry the witness statement log's answer; the receipt and any correction are checked too, and a valid correction gives the verdict `superseded` ([docs/LOG.md](../../docs/LOG.md)). Pass your own pinned log key to replace the one a bundle carries.

A `checked` verdict means Trooth's key signed these outcome bytes for this domain, bound to the exact check mapping and evidence manifest. It does not establish the company's identity, an independent time, or that the company is safe, compliant or authorized for anything.

Run the tests from this folder: `go test ./...`. Licensed under the Apache License 2.0.
