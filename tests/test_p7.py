"""P7 / contract C8: rule 5 (secrets) and host-built manifest paths.

The first third-party pair SEALED on both families with one rule-5 hit each, kind `api_key`, at
`$.coverage.<key>`: a manifest path whose directory name, read together with its parent directories,
looks token-shaped to the GENERIC high-entropy heuristic. C8 sets that one heuristic aside ONLY in a
structural position the schema defines as a repo path (a coverage key, a `path` field outside the run
echo) and ONLY where rule 2 validated that exact string against the bound manifest. Everything else is
scanned as before. Every value here is synthetic and assembled at runtime from a fixed seed; no sealed
report is read. Case (h2) reads only the sealed pair's host-built manifest.json, never prints a path,
and skips when that file is absent.
"""
import base64
import copy
import json
import random
import string
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deepfixture import DEEP, GATE, REPO, Pair, _synth_jwt, run  # noqa: E402

sys.path.insert(0, str(DEEP))
import deepgate  # noqa: E402
import deeplib  # noqa: E402

GENERIC = "generic_high_entropy"
B62 = string.ascii_letters + string.digits
SEALED_MANIFEST = Path.home() / ".athena/scout/deep/pairs/20261007T082235Z-81a82e/manifest.json"


def dets(s: str) -> set:
    return {d for _k, _l, d in deeplib.scan_text_detailed(s)}


def generic_only(s: str) -> bool:
    return dets(s) == {GENERIC} and not any(rx.search(s) for _n, rx in deeplib.CRED_SHAPES) \
        and not any(deeplib.scan_text(d) for _e, d in deepgate.decoded_views(s))


def _gen(n: int, alphabet: str, ok, seed: int) -> str:
    rng = random.Random(seed)
    for _ in range(20000):
        r = "".join(rng.choice(alphabet) for _ in range(n))
        if ok(r):
            return r
    raise AssertionError("no candidate")


def variants(path: str) -> dict:
    """Normalization variants and encoded forms of a path. None of them is the admitted string."""
    return {"dot_slash": "./" + path, "swapcase": path.swapcase(), "trailing_slash": path + "/",
            "lookalike": path.replace(".txt", ".tхt"),  # Cyrillic small ha for the x
            "url_encoded": urllib.parse.quote(path, safe=""),
            "base64": base64.b64encode(path.encode()).decode()}


def _tok_ok(r: str) -> bool:
    p = f"data/{r}.txt"
    return generic_only(p) and all(deeplib.scan_text(v) for v in variants(p).values())


# (a) a benign token-shaped file name: generic heuristic only, every variant still flagged by the scanner
RUN40 = _gen(40, B62, _tok_ok, 7)
TOK = f"data/{RUN40}.txt"
# (h1) the sealed pair's SHAPE: a 23-char run inside a nested path; only the whole path reads as a token
SHAPE = "brand/assets/archive/{}/README.md".format(_gen(
    23, B62 + "_", lambda r: generic_only(f"brand/assets/archive/{r}/README.md")
    and not any(deeplib.scan_text(seg) for seg in f"brand/assets/archive/{r}/README.md".split("/")), 11))
# (g) a token-shaped name the preflight EXCLUDES (its content holds an email): never a manifest path
EXCL = f"private/{_gen(40, B62, lambda r: generic_only(f'private/{r}.txt'), 13)}.txt"
EMAIL_BODY = "contact: " + "jane.q" + "@" + "corp-mail" + ".net\n"
# (e) concrete patterns as manifest file names, assembled at runtime
AWS = "keys/" + "AK" + "IA" + _gen(16, string.ascii_uppercase + string.digits,
                                   lambda r: dets("keys/AKIA" + r + ".txt") == {"vendor:aws_access_key_id"}, 17) + ".txt"
B64NAME = base64.urlsafe_b64encode(("pass" + "word = " + "Q7xk2LmP" + "9vRt4Wz8").encode()).decode().rstrip("=") + ".txt"
JWTNAME = _synth_jwt("p7-name", "Q") + ".txt"

BENIGN_REPO = {**REPO, TOK: "plain notes\n", SHAPE: "# archive\n\nold artwork\n", EXCL: EMAIL_BODY}
CONCRETE_REPO = {**REPO, AWS: "plain notes\n", B64NAME: "plain notes\n", JWTNAME: "plain notes\n"}


class _GateCase(unittest.TestCase):
    repo = BENIGN_REPO

    @classmethod
    def setUpClass(cls):
        cls.p = Pair(("claude",), repo=cls.repo)
        cls.base = cls.p.report()

    @classmethod
    def tearDownClass(cls):
        cls.p.cleanup()

    def setUp(self):
        self.r = copy.deepcopy(self.base)

    def gate(self, report=None, bait=None, extra=()):
        pd = self.p.pd
        return deepgate.gate_report(
            report if report is not None else self.r, manifest=self.p.manifest, box=pd / "box" / "repo",
            schema=json.loads((pd / "run-schema.json").read_text()), echo=self.p.echo(), bait=bait or self.p.bait,
            extra_canaries=list(extra), box_verdict="PASS", receipts=self.p.receipts())[0]

    def r5(self, rec):
        return rec["rules"]["5_secrets"]

    def key_index(self, path, report=None):
        return list((report or self.r)["coverage"]).index(path)


# =========================================================================== schema enumeration
class StructuralPositions(unittest.TestCase):
    def test_positions_come_from_the_base_schema(self):
        base = json.loads((DEEP / "deep-report.schema.json").read_text())
        self.assertEqual(set(deepgate.schema_path_positions(base)),
                         {("findings", "[]", "path"), ("private_info", "[]", "path"),
                          ("instruction_shaped", "[]", "path"), ("coverage", "<key>"),
                          ("run", "exclusions", "[]", "path")})
        # the run echo's exclusion paths are not admitted paths: never structural
        self.assertEqual(set(deepgate.structural_positions(base)),
                         {("findings", "[]", "path"), ("private_info", "[]", "path"),
                          ("instruction_shaped", "[]", "path"), ("coverage", "<key>")})
        self.assertEqual(deepgate.BASE_SCHEMA_OBJ, base)

    def test_detector_provenance_keeps_kinds_stable(self):
        for s in (TOK, SHAPE, AWS, "x " + "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5, "mail jane.q" + "@corp-mail.net"):
            self.assertEqual(deeplib.scan_text(s), [(k, l) for k, l, _d in deeplib.scan_text_detailed(s)])
        self.assertTrue(dets(TOK) == {GENERIC} and dets(SHAPE) == {GENERIC})
        self.assertEqual(dets(AWS), {"vendor:aws_access_key_id"})
        self.assertEqual({k for k, _ in deeplib.scan_text(TOK)}, {"api_key"})
        self.assertEqual({k for k, _ in deeplib.scan_text(AWS)}, {"api_key"})  # same kind, different detector
        self.assertTrue(set(d for s in (TOK, AWS, JWTNAME) for d in dets(s)) <= deeplib.DETECTORS)
        self.assertTrue(deeplib.DETECTORS <= deepgate.VOCAB)


# =========================================================================== (a) structural PASS
class StructuralBenign(_GateCase):
    def test_a_token_shaped_manifest_path_as_coverage_key_and_finding_path_passes(self):
        self.assertIn(TOK, self.p.manifest["files"])
        self.assertIn(SHAPE, self.p.manifest["files"])
        self.assertNotIn(EXCL, self.p.manifest["files"])  # preflight excluded it (content), (g) relies on it
        self.r["findings"].append({**self.r["findings"][0], "path": TOK, "line": 1})
        self.r["private_info"].append({"path": TOK, "line": 1, "kind": "other_private"})
        self.r["instruction_shaped"].append({"path": TOK, "line": 1, "paraphrase": "nothing addressed to readers"})
        rec = self.gate()
        self.assertEqual(rec["verdict"], "PASS", rec["failed_rules"])
        r5 = self.r5(rec)
        self.assertEqual(r5["scanner_hit_count"], 0)
        sup = {(h["json_path"], h["kind"], h["detector"]) for h in r5["structural_generic_suppressed"]}
        nf, npi, nis = len(self.r["findings"]) - 1, len(self.r["private_info"]) - 1, len(self.r["instruction_shaped"]) - 1
        self.assertEqual(sup, {(f"$.coverage[key {self.key_index(TOK)}]", "api_key", GENERIC),
                               (f"$.coverage[key {self.key_index(SHAPE)}]", "api_key", GENERIC),
                               (f"$.findings[{nf}].path", "api_key", GENERIC),
                               (f"$.private_info[{npi}].path", "api_key", GENERIC),
                               (f"$.instruction_shaped[{nis}].path", "api_key", GENERIC)})
        n_struct = len(self.r["coverage"]) + len(self.r["findings"]) + len(self.r["private_info"]) + len(self.r["instruction_shaped"])
        self.assertEqual(r5["structural_strings_checked"], n_struct)
        self.assertNotIn(RUN40, json.dumps(rec))  # json paths and kinds only

    def test_line_out_of_range_position_gets_no_exemption(self):
        self.r["findings"].append({**self.r["findings"][0], "path": TOK, "line": 99})
        rec = self.gate()
        self.assertIn("2_paths", rec["failed_rules"])
        self.assertIn("5_secrets", rec["failed_rules"])

    # ---- (b) prose that equals or contains the path ----------------------------------------
    def test_b_prose_equal_to_or_containing_the_path_fails(self):
        cases = {"$.findings[0].risk": lambda r: r["findings"][0].__setitem__("risk", TOK),
                 "$.findings[0].fix": lambda r: r["findings"][0].__setitem__("fix", "Delete " + TOK + " now."),
                 "$.summary": lambda r: r.__setitem__("summary", "It ships " + TOK + "."),
                 "$.strengths[0]": lambda r: r["strengths"].__setitem__(0, TOK),
                 "$.instruction_shaped[0].paraphrase": lambda r: r["instruction_shaped"][0].__setitem__("paraphrase", TOK)}
        for jp, mut in cases.items():
            with self.subTest(at=jp):
                r = copy.deepcopy(self.base)
                mut(r)
                rec = self.gate(r)
                self.assertIn("5_secrets", rec["failed_rules"])
                self.assertIn((jp, "api_key", GENERIC),
                              {(h["json_path"], h["kind"], h["detector"]) for h in self.r5(rec)["scanner_hits"]})

    # ---- (c) a token-shaped coverage key that is not a manifest path -----------------------
    def test_c_non_manifest_token_shaped_key_fails_rules_2_and_5(self):
        other = f"data/{RUN40[::-1]}.txt"
        self.assertTrue(deeplib.scan_text(other))
        self.r["coverage"][other] = "read"
        rec = self.gate()
        self.assertIn("2_paths", rec["failed_rules"])
        self.assertIn("5_secrets", rec["failed_rules"])
        self.assertIn(("$.coverage.<key>", GENERIC),
                      {(h["json_path"], h["detector"]) for h in self.r5(rec)["scanner_hits"]})
        self.assertNotIn(f"$.coverage[key {self.key_index(other)}]",
                         {h["json_path"] for h in self.r5(rec)["structural_generic_suppressed"]})

    # ---- (d) normalized variants and encoded forms, in every position ----------------------
    def test_d_variants_and_encodings_are_scanned_in_any_position(self):
        for name, v in variants(TOK).items():
            self.assertTrue(deeplib.scan_text(v), name)
            for where in ("coverage_key", "finding_path", "risk"):
                with self.subTest(variant=name, where=where):
                    r = copy.deepcopy(self.base)
                    if where == "coverage_key":
                        r["coverage"][v] = "read"
                    elif where == "finding_path":
                        r["findings"][0]["path"] = v
                    else:
                        r["findings"][0]["risk"] = v
                    rec = self.gate(r)
                    self.assertIn("5_secrets", rec["failed_rules"])
                    if where != "risk":
                        self.assertIn("2_paths", rec["failed_rules"])
                    # the admitted TOK coverage key is still the only structural suppression of TOK's kind
                    self.assertGreaterEqual(self.r5(rec)["scanner_hit_count"], 1)

    # ---- (f) bait values and canaries, including as or inside a structural string ----------
    def test_f_bait_and_canaries_fail_everywhere(self):
        b = self.p.bait
        # a known value that IS the token run of an admitted structural path: the blob check catches it
        cases = {"bait_value_in_structural": (dict(b, values=b["values"] + [RUN40]), (), "bait_values_present", 1),
                 "canary_is_structural_token": (dict(b, canary_token=RUN40), (), "canary_present", True),
                 "extra_canary_in_structural": (b, (RUN40,), "extra_canaries_present", 1)}
        for name, (bait, extra, field, want) in cases.items():
            with self.subTest(case=name):
                rec = self.gate(copy.deepcopy(self.base), bait=bait, extra=extra)
                self.assertIn("5_secrets", rec["failed_rules"])
                self.assertEqual(self.r5(rec)[field], want)
                self.assertEqual(self.r5(rec)["scanner_hit_count"], 0)  # only the blob check fired
        # a real bait value in prose and the real canary as a coverage key
        r = copy.deepcopy(self.base)
        r["findings"][0]["risk"] = "value " + b["values"][0]
        self.assertGreaterEqual(self.r5(self.gate(r))["bait_values_present"], 1)
        r = copy.deepcopy(self.base)
        r["coverage"][b["canary_token"]] = "read"
        rec = self.gate(r)
        self.assertIn("5_secrets", rec["failed_rules"])
        self.assertTrue(self.r5(rec)["canary_present"])

    # ---- (g) a token-shaped preflight exclusion ---------------------------------------------
    def test_g_excluded_path_gets_no_exemption(self):
        # as a coverage key: not a manifest path, so rule 2 fails and rule 5 scans it
        self.r["coverage"][EXCL] = "read"
        rec = self.gate()
        self.assertIn("2_paths", rec["failed_rules"])
        self.assertIn("5_secrets", rec["failed_rules"])
        self.assertIn(("$.coverage.<key>", GENERIC), {(h["json_path"], h["detector"]) for h in self.r5(rec)["scanner_hits"]})
        # in the run echo's exclusion path field (the echo the host gave carries it sanitized)
        r = copy.deepcopy(self.base)
        self.assertTrue(r["run"]["exclusions"])
        self.assertNotIn(EXCL, json.dumps(r["run"]))
        r["run"]["exclusions"][0]["path"] = EXCL
        rec = self.gate(r)
        self.assertIn("3_run_echo", rec["failed_rules"])
        self.assertIn("5_secrets", rec["failed_rules"])
        self.assertIn(("$.run.exclusions[0].path", GENERIC),
                      {(h["json_path"], h["detector"]) for h in self.r5(rec)["scanner_hits"]})

    # ---- (h1) the sealed pair's shape, synthetic --------------------------------------------
    def test_h1_sealed_shape_synthetic_passes_with_one_listed_suppression(self):
        rec = self.gate()
        self.assertEqual(rec["verdict"], "PASS", rec["failed_rules"])
        sup = self.r5(rec)["structural_generic_suppressed"]
        self.assertIn({"json_path": f"$.coverage[key {self.key_index(SHAPE)}]", "kind": "api_key", "detector": GENERIC}, sup)
        self.assertEqual(len(sup), 2)  # SHAPE and TOK, the two token-shaped admitted paths


# =========================================================================== (e) concrete names
class StructuralConcrete(_GateCase):
    repo = CONCRETE_REPO

    def test_e_concrete_patterns_in_structural_positions_still_fail(self):
        for f in (AWS, B64NAME, JWTNAME):
            self.assertIn(f, self.p.manifest["files"])
        self.r["findings"][0]["path"] = AWS
        self.r["findings"][0]["line"] = 1
        rec = self.gate()
        self.assertNotIn("2_paths", rec["failed_rules"])  # every structural string is a validated manifest path
        self.assertIn("5_secrets", rec["failed_rules"])
        hits = {(h["json_path"], h["detector"], h.get("encoding")) for h in self.r5(rec)["scanner_hits"]}
        self.assertIn(("$.coverage.<key>", "vendor:aws_access_key_id", None), hits)
        self.assertIn(("$.findings[0].path", "vendor:aws_access_key_id", None), hits)
        self.assertIn(("$.coverage.<key>", "box_credential_shape:jwt", None), hits)  # CRED_SHAPES still apply
        self.assertIn(("$.coverage.<key>", "vendor:jwt", None), hits)
        self.assertIn(("$.coverage.<key>", "assignment", "base64"), hits)  # decoded content still applies
        self.assertFalse(any(h["detector"] == GENERIC and "encoding" not in h for h in self.r5(rec)["scanner_hits"]
                             if h["json_path"] in ("$.coverage.<key>", "$.findings[0].path")))


# =========================================================================== (h2) the real manifest's paths
NEEDS_SEALED_MANIFEST = unittest.skipUnless(SEALED_MANIFEST.exists(), "sealed pair manifest not on this host")


@NEEDS_SEALED_MANIFEST
class SealedManifestShape(unittest.TestCase):
    """A synthetic report over the sealed pair's REAL host-built manifest paths, neutral prose. Only
    manifest.json is read. No assertion message or output carries a path."""

    def test_h2_real_manifest_paths_as_coverage_keys_pass_rule_5(self):
        man = json.loads(SEALED_MANIFEST.read_text())
        files = man["files"]
        flagged = [i for i, f in enumerate(files) if deeplib.scan_text(f)]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(dets(list(files)[flagged[0]]), {GENERIC})
        with tempfile.TemporaryDirectory() as td:
            box = Path(td)
            for f in files:
                (box / f).parent.mkdir(parents=True, exist_ok=True)
                (box / f).write_text("")
            echo = {"source_commit": "c" * 40, "source_sha256": "d" * 64, "manifest_sha256": man["manifest_sha256"],
                    "model": "m", "reviewer_cli": "x", "reviewer_cli_version": "1", "exclusions": [],
                    "truncation": {"max_file_bytes": 0, "files_truncated": 0}}
            areas = {a: {"status": "examined", "note": "looked at it"} for a in deepgate.AREAS}
            report = {"schema_version": "deep-report/2", "summary": "A neutral synthetic summary.",
                      "findings": [], "strengths": ["Readable."], "private_info": [], "instruction_shaped": [],
                      "areas": areas, "coverage": {f: "read" for f in files}, "run": echo}
            no_canary = "p7-none-" + "z" * 8
            bait = {"values": [], "canary_token": no_canary, "credential_files": [], "canary_file": ""}
            rec, _ = deepgate.gate_report(report, manifest=man, box=box, schema=deepgate.BASE_SCHEMA_OBJ, echo=echo,
                                          bait=bait, extra_canaries=[], box_verdict="PASS", receipts=None)
        r5 = rec["rules"]["5_secrets"]
        self.assertTrue(r5["result"] == "PASS" and r5["scanner_hit_count"] == 0)
        self.assertEqual(rec["rules"]["2_paths"]["result"], "PASS")
        self.assertEqual(r5["structural_strings_checked"], len(files))
        self.assertEqual(r5["structural_generic_suppressed"],
                         [{"json_path": f"$.coverage[key {flagged[0]}]", "kind": "api_key", "detector": GENERIC}])
        self.assertEqual(rec["failed_rules"], ["9_read_depth"])  # no receipts in this pure call, by design


# =========================================================================== owner deliverable
class NamingWarnings(unittest.TestCase):
    def test_generic_name_is_a_warning_with_its_path(self):
        out = deepgate.naming_warnings(["README.md", TOK, SHAPE])
        self.assertEqual(out, [{"path": SHAPE, "kind": "token_shaped_name", "path_withheld": False, "note": deepgate.NAMING_NOTE},
                               {"path": TOK, "kind": "token_shaped_name", "path_withheld": False, "note": deepgate.NAMING_NOTE}])

    def test_concrete_or_known_value_path_is_withheld(self):
        kv = "p7known" + "Zq"
        known_path = f"notes/{kv}.txt"
        self.assertFalse(deeplib.scan_text(known_path))
        out = deepgate.naming_warnings([AWS, JWTNAME, B64NAME, known_path, "README.md"], known_values=[kv])
        self.assertEqual(len(out), 4)
        for w in out:
            self.assertEqual((w["path"], w["kind"], w["path_withheld"]), ("path withheld", "token_shaped_name", True))
        blob = json.dumps(out)
        for secret in (AWS, AWS[5:-4], JWTNAME, B64NAME, kv):
            self.assertNotIn(secret, blob)
        self.assertEqual(sorted(k for w in out for k in w["matched_kinds"]),
                         sorted(["access_token", "api_key", "box_credential_shape:jwt", "known_value", "password"]))
        md = deepgate.render_md({"scope": {"source": "s", "commit": "c", "tarball_sha256": "t", "files_reviewed": 1,
                                           "files_withheld": [], "exceptions_applied": [], "exceptions_declared_by": None,
                                           "naming_warnings": out, "not_covered": ["x"]},
                                 "reports": {}, "reviewers": {}})
        self.assertIn("path withheld", md)
        self.assertNotIn(AWS, md)


# =========================================================================== (h3) end to end
class SealedShapeReleases(unittest.TestCase):
    """The sealed pair's shape through the real CLI: two families checked, gated, audited, released,
    delivered. Before C8 this sealed on `5_secrets`; it must RELEASE, and the owner hears a naming warning."""

    def setUp(self):
        self.p = Pair(("claude", "codex"), repo={**REPO, SHAPE: "# archive\n\nold artwork\n"})
        self.p.write_claude_evidence(self.p.report("claude"))
        self.p.write_codex_evidence(self.p.report("codex"))

    def tearDown(self):
        dd = self.p.pd / "deliverable"
        if dd.exists():
            dd.chmod(0o700)
        self.p.cleanup()

    def test_h3_release_and_deliver(self):
        for fam in ("claude", "codex"):
            self.assertEqual(self.p.check(fam)[0], 0)
            rc, g = self.p.gate(fam)
            self.assertEqual((rc, g["verdict"]), (0, "PASS"), g["failed_rules"])
            idx = self.p.files.index(SHAPE)
            self.assertEqual(g["rules"]["5_secrets"]["structural_generic_suppressed"],
                             [{"json_path": f"$.coverage[key {idx}]", "kind": "api_key", "detector": GENERIC}])
        for fam in ("claude", "codex"):
            self.p.audit(fam)
        q = run(GATE, "release", str(self.p.pd), ok=False)
        rel = json.loads((self.p.pd / "release.json").read_text())
        self.assertEqual((q.returncode, rel["status"]), (0, "RELEASED"), rel.get("reasons"))
        run(GATE, "deliver", str(self.p.pd))
        out = json.loads((self.p.pd / "deliverable" / "owner-review.json").read_text())
        self.assertEqual(out["scope"]["naming_warnings"],
                         [{"path": SHAPE, "kind": "token_shaped_name", "path_withheld": False, "note": deepgate.NAMING_NOTE}])
        self.assertIn("token_shaped_name", (self.p.pd / "deliverable" / "owner-review.md").read_text())


if __name__ == "__main__":
    unittest.main()
