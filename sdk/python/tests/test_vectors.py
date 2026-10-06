"""Every vector and bundle in tests/vectors/ of trooth-cli, through this package."""

import json
import pathlib
import unittest

from trooth_verify import BundleError, canonicalize, is_canonical, statement_id, verify_bundle, verify_statement

ROOT = pathlib.Path(__file__).resolve().parents[3]
VEC = ROOT / "tests" / "vectors"


class Vectors(unittest.TestCase):
    def test_vectors(self):
        doc = json.loads((VEC / "vectors.json").read_text("utf-8"))
        mapping = (VEC / doc["mapping_file"]).read_bytes()
        other = (VEC / doc["other_mapping_file"]).read_bytes()
        self.assertGreaterEqual(len(doc["vectors"]), 27)
        for v in doc["vectors"]:
            with self.subTest(v["name"]):
                mb = mapping if v["mapping"] is True else other if v["mapping"] == "other" else None
                r = verify_statement(v["statement"], v["keys"], mb, v["manifest"], v["domain"])
                self.assertEqual(r["verdict"], v["expect"]["verdict"], v["note"])
                self.assertEqual(r["signature"], v["expect"]["signature"], v["note"])

    def test_bundles(self):
        for b in json.loads((VEC / "bundles.json").read_text("utf-8"))["bundles"]:
            with self.subTest(b["name"]):
                if "error" in b["expect"]:
                    with self.assertRaises(BundleError):
                        verify_bundle(b["bundle"], b.get("domain"))
                    continue
                r = verify_bundle(b["bundle"], b.get("domain"))
                self.assertEqual(r["verdict"], b["expect"]["verdict"], b["note"])
                self.assertEqual(r["signature"], b["expect"]["signature"], b["note"])

    def test_real_trooth_bundle(self):
        b = json.loads((ROOT / "tests" / "fixtures" / "bundles" / "trooth.co-2026-10-06.bundle.json").read_text("utf-8"))
        r = verify_bundle(b)
        self.assertEqual(r["verdict"], "checked")
        self.assertEqual(r["statement_id"], statement_id(b["statement"]["payload"]))

    def test_canonical_v3_payload_is_reproduced(self):
        doc = json.loads((VEC / "vectors.json").read_text("utf-8"))
        p = next(v for v in doc["vectors"] if v["name"] == "valid-v3")["statement"]["payload"]
        self.assertTrue(is_canonical(p))
        self.assertEqual(canonicalize(json.loads(p)), p)
        self.assertEqual(canonicalize({"\U0001F600": 1, "דּ": 2, "b": 0}), '{"b":0,"\U0001F600":1,"דּ":2}')


class Log(unittest.TestCase):
    def test_log_cases(self):
        from trooth_verify import verify_statement
        doc = json.loads((VEC / "log.json").read_text("utf-8"))
        v = json.loads((VEC / "vectors.json").read_text("utf-8"))
        mapping = (VEC / v["mapping_file"]).read_bytes()
        for c in doc["cases"]:
            with self.subTest(c["name"]):
                r = verify_statement(c["statement"], c["keys"], mapping, c["manifest"], c["domain"], c["log"])
                self.assertEqual(r["verdict"], c["expect"]["verdict"], c["note"])
                self.assertEqual(r["log"]["status"] if r.get("log") else None, c["expect"]["log"], c["note"])

    def test_consistency(self):
        import base64
        from trooth_verify import verify_consistency
        doc = json.loads((VEC / "log.json").read_text("utf-8"))
        for c in doc["consistency"]:
            with self.subTest(c["name"]):
                d = lambda s: base64.b64decode(s)
                self.assertEqual(verify_consistency(c["first"], c["second"], d(c["first_root"]), d(c["second_root"]), [d(p) for p in c["proof"]]), c["expect"])

    def test_checkpoints(self):
        from trooth_verify import open_checkpoint
        doc = json.loads((VEC / "log.json").read_text("utf-8"))
        self.assertEqual(open_checkpoint(doc["checkpoints"]["5"], doc["vkey"])["size"], 5)
        with self.assertRaises(ValueError):
            open_checkpoint(doc["checkpoints"]["5"], doc["impostor_vkey"])


class Models(unittest.TestCase):
    def test_models_load_vectors(self):
        try:
            from trooth_verify import models
        except ImportError:
            self.skipTest("pydantic is not installed (pip install trooth-verify[models])")
        doc = json.loads((VEC / "vectors.json").read_text("utf-8"))
        for name, cls in (("valid-v2", models.WitnessPayloadV2), ("valid-v3", models.WitnessPayloadV3), ("valid-v1", models.WitnessPayloadV1)):
            v = next(x for x in doc["vectors"] if x["name"] == name)
            cls.model_validate_json(v["statement"]["payload"])
            models.WitnessStatement.model_validate(v["statement"])
        b = json.loads((VEC / "bundles.json").read_text("utf-8"))["bundles"][0]["bundle"]
        models.VerificationBundle.model_validate(b)


if __name__ == "__main__":
    unittest.main()
