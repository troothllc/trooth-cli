# trooth-verify (Python)

Check a Trooth witness statement yourself, with no trust in Trooth's website or API. A port of `trooth verify` that follows [docs/VERIFY.md](../../docs/VERIFY.md) and passes every case in [tests/vectors](../../tests/vectors).

```
pip install "git+https://github.com/troothllc/trooth-cli#subdirectory=sdk/python"
```

```python
import json
from trooth_verify import verify_bundle

bundle = json.load(open("trooth.co.bundle.json"))  # written by: trooth verify trooth.co --save-bundle trooth.co.bundle.json
result = verify_bundle(bundle)
print(result["verdict"])  # checked, checked_v1, partially_checked, signature_not_trusted or mismatch
```

`verify_statement(statement, keys, mapping_bytes, manifest, domain)` checks inputs you read yourself. The result has the shape of [schemas/verify-result.schema.json](../../schemas/verify-result.schema.json). `trooth_verify.models` holds Pydantic v2 models generated from [schemas/](../../schemas) (install with the `models` extra).

Bundles written by `trooth` 0.9.0 and later carry the witness statement log's answer; the receipt and any correction are checked too, and a valid correction gives the verdict `superseded` ([docs/LOG.md](../../docs/LOG.md)). Pass your own pinned log key to replace the one a bundle carries.

A `checked` verdict means Trooth's key signed these outcome bytes for this domain, bound to the exact check mapping and evidence manifest. It does not establish the company's identity, an independent time, or that the company is safe, compliant or authorized for anything.

Run the tests from this folder: `python3 -m unittest discover -s tests`. Licensed under the Apache License 2.0.
