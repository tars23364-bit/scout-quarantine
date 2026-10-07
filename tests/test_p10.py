"""P10 / contract C11: Serafina's three residuals against C10.

R1  the marker reservation covers every admitted PATH, including a file whose text is redaction-eligible
    (C10 skipped `rel in redacted` before the path check); gate rule 10 FAILs on any admitted path that
    carries a marker prefix, since no record can explain one.
R2  the inspector screens its WHOLE emitted object (diagnostic names and never_opened entries included)
    and applies the canary / box-dummy screens to the decoded (base64, hex) views of every string.
R3  inspect reads every record through pinned directory descriptors: the pair dir and each intermediate
    directory are opened O_DIRECTORY|O_NOFOLLOW, their identity checked against the lstat, and the leaf
    opened relative to its pinned parent, so a directory swapped after the check is not followed.

Every private-looking value is synthetic, assembled at runtime; no real owner data, bait or credential
is read, and nothing under ~/.athena is touched.
"""
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from deepfixture import DEEP, GATE, REPO, Pair, run  # noqa: E402
import test_p9  # noqa: E402  (module import: its TestCases must not be collected again here)
from test_p8 import FILLER, PW, REDACT  # noqa: E402

sys.path.insert(0, str(DEEP))
import deepgate  # noqa: E402
import deeplib  # noqa: E402

MARKED_PATHS = (".claude/rules/[REDACTED:password#1].md", ".claude/rules/[redacted-line:x].md")
FLAGGED = f'db_password = "{PW}"\n' + FILLER          # a detected assignment + harmless filler (her R1 body)
CLEAN = "ordinary instructions\n"


# =========================================================================== R1
class MarkerPathReserved(unittest.TestCase):
    def _run(self, path, body, opts):
        p = Pair(("claude",), repo={**REPO, path: body}, preflight_opts=opts)
        pf = json.loads((p.pd / "preflight.json").read_text())
        ex = {e["path"]: e for e in pf["excluded"]}
        return p, pf, ex

    def _assert_nowhere(self, p, path):
        self.assertNotIn(path, p.manifest["files"])
        self.assertFalse(any(deeplib.MARKER_PREFIX_RE.search(f) for f in p.manifest["files"]))
        box = p.pd / "box" / "repo"
        self.assertFalse(any(deeplib.MARKER_PREFIX_RE.search(q.relative_to(box).as_posix())
                             for q in box.rglob("*")))

    def _gate(self, p, red):
        return deepgate.gate_report(p.report(), manifest=p.manifest, box=p.pd / "box" / "repo",
                                    schema=json.loads((p.pd / "run-schema.json").read_text()), echo=p.echo(),
                                    bait=p.bait, extra_canaries=[], box_verdict="PASS", receipts=p.receipts(),
                                    redaction=red)[0]

    def test_flagged_text_marker_path_redact_mode(self):
        """Her R1 case: redaction-eligible text under a marker path. C10 admitted it redacted:true."""
        for path in MARKED_PATHS:
            with self.subTest(path=path):
                p, pf, ex = self._run(path, FLAGGED, REDACT)
                try:
                    self.assertEqual((ex[path]["reason"], ex[path]["redaction_fallback"]),
                                     ("private_info", "marker_collision"))
                    self._assert_nowhere(p, path)
                    red = json.loads((p.pd / "redaction.json").read_text())
                    self.assertEqual(red["files"], [])
                    self.assertIn({"path": path, "reason": "marker_collision"}, red["fallbacks"])
                    self.assertEqual(pf["redaction"]["files"], 0)
                    gate = self._gate(p, red)
                    self.assertEqual(gate["rules"]["10_redaction"]["result"], "CLEAR")
                    self.assertEqual(gate["verdict"], "PASS")   # the marked file never reached the box
                finally:
                    p.cleanup()

    def test_clean_text_marker_path_both_modes(self):
        for path in MARKED_PATHS:
            for opts in ((), REDACT):
                with self.subTest(path=path, opts=opts):
                    p, _pf, ex = self._run(path, CLEAN, opts)
                    try:
                        self.assertEqual(ex[path]["reason"], "marker_reserved")
                        self.assertEqual(ex[path].get("redaction_fallback"), "marker_collision" if opts else None)
                        self._assert_nowhere(p, path)
                    finally:
                        p.cleanup()

    def test_flagged_text_marker_path_default_mode(self):
        p, _pf, ex = self._run(MARKED_PATHS[0], FLAGGED, ())
        try:
            self.assertEqual(ex[MARKED_PATHS[0]]["reason"], "private_info")
            self.assertNotIn("redaction_fallback", ex[MARKED_PATHS[0]])
            self._assert_nowhere(p, MARKED_PATHS[0])
        finally:
            p.cleanup()

    def test_unmarked_flagged_file_still_redacted(self):
        """Control: the same body under an ordinary path is still admitted as a redacted derivative."""
        p, _pf, _ex = self._run(".claude/rules/db.md", FLAGGED, REDACT)
        try:
            self.assertTrue(p.manifest["files"][".claude/rules/db.md"].get("redacted"))
        finally:
            p.cleanup()

    def test_rule10_fails_on_a_marker_path(self):
        for path in MARKED_PATHS:
            with self.subTest(path=path):
                man = {"files": {"a.md": {}, path: {"sha256": "x", "lines": 1}}}
                probs = deepgate.redaction_problems(None, man, {"a.md": "plain\n", path: "plain\n"})
                self.assertEqual(probs, [{"path": "[withheld]", "problem": "redaction_marker_in_path"}])
                # a marker path in the manifest only (no box text) is still refused
                self.assertEqual(deepgate.redaction_problems(None, man, {"a.md": "plain\n"}),
                                 [{"path": "[withheld]", "problem": "redaction_marker_in_path"}])
        self.assertEqual(deepgate.redaction_problems(None, {"files": {"a.md": {}}}, {"a.md": "plain\n"}), [])
        self.assertIn("redaction_marker_in_path", deepgate.VOCAB)

    def test_gate_fails_a_box_that_admitted_a_marker_path(self):
        """The second check: a box/manifest that carries a marker path (as C10 produced) FAILs rule 10."""
        p, _pf, _ex = self._run(".claude/rules/db.md", FLAGGED, REDACT)
        try:
            red = json.loads((p.pd / "redaction.json").read_text())
            path = MARKED_PATHS[0]
            box = p.pd / "box" / "repo"
            (box / path).parent.mkdir(parents=True, exist_ok=True)
            (box / ".claude/rules/db.md").rename(box / path)
            p.manifest["files"][path] = p.manifest["files"].pop(".claude/rules/db.md")
            for f in red["files"]:
                if f["path"] == ".claude/rules/db.md":
                    f["path"] = path
            gate = self._gate(p, red)
            self.assertEqual(gate["rules"]["10_redaction"]["result"], "FAIL")
            self.assertIn({"path": "[withheld]", "problem": "redaction_marker_in_path"},
                          gate["rules"]["10_redaction"]["problems"])
            self.assertEqual(gate["verdict"], "FAIL")
        finally:
            p.cleanup()


# =========================================================================== R2
SYN_CANARY = "CANARY-" + "abcdef123456"          # her ENCODED-CANARY.json shape (synthetic)


def _encodings(v: str) -> dict[str, str]:
    b = v.encode()
    return {"plain": v, "base64": base64.b64encode(b).decode(), "base64url": base64.urlsafe_b64encode(b).decode(),
            "hex": b.hex(), "HEX": b.hex().upper()}


def _emitted_strings(node):
    """Every key and string value of an emitted object."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for x in node:
            yield from _emitted_strings(x)
    elif isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _emitted_strings(v)


def _recognized(s: str) -> list[str]:
    """The no-leak check, applied the way the inspector must: the string and each decoded view of it."""
    return [t for t in (s, *(d for _e, d in deepgate.decoded_views(s)))
            if deepgate.INSPECT_CANARY_RE.search(t) or deeplib.BOX_MARKER in t]


class EncodedShapesWithheld(unittest.TestCase):
    def test_her_fixture_plain_base64_hex(self):
        """ENCODED-CANARY.json: plain withheld; base64 and hex printed under C10 although decoded_views
        recognised the shape. Now all are withheld, and the decoder still recognises each."""
        for name, enc in _encodings(SYN_CANARY).items():
            with self.subTest(enc=name):
                self.assertEqual(deepgate._typed(enc, deepgate.LABEL), (deepgate.WITHHELD, False))
                self.assertTrue(_recognized(enc))

    def test_house_canary_and_box_marker_shapes(self):
        canary = "CANARY-" + "0123456789ABCDEF01234567"           # deeplib's shape: 24 upper hex
        dummy = "sk-ant-oat01-" + deeplib.BOX_MARKER + "q" * 40
        for v in (canary, dummy, f"label {deeplib.BOX_MARKER} here"):
            for name, enc in _encodings(v).items():
                with self.subTest(v=v[:12], enc=name):
                    self.assertEqual(deepgate._typed(enc, deepgate.LABEL)[0], deepgate.WITHHELD)

    def test_ordinary_values_still_print(self):
        for v in ("fixture repo", "a" * 64, "2026-10-07T07:42:45Z", "claude-opus-5-5", "v1.2.3"):
            self.assertEqual(deepgate._typed(v, deepgate.LABEL), (v, True))


class DynamicNamesNeverPrinted(unittest.TestCase):
    def test_canary_suffix_in_root_and_family_names(self):
        with tempfile.TemporaryDirectory() as td:
            pd = Path(td)
            (pd / "pair.json").write_text(json.dumps({"id": SYN_CANARY}))
            (pd / "source-pin.json").write_text(json.dumps({"kind": "git", "label": _encodings(SYN_CANARY)["base64"]}))
            (pd / "bait.json").write_text("{}")
            (pd / f"box-dummy-{SYN_CANARY}.json").write_text("{}")
            (pd / f"session-spec-{_encodings(SYN_CANARY)['hex']}.json").write_text("{}")
            for fam in ("claude", "codex"):
                (pd / fam).mkdir()
                (pd / fam / f"session-spec-{SYN_CANARY}.json").write_text("{}")
                (pd / fam / f"box-dummy-{_encodings(SYN_CANARY)['base64url']}.json").write_text("{}")
                (pd / fam / "box-dummy-audit.json").write_text("{}")
            view = deepgate.inspect_pair(pd)
            dumped = json.dumps(view)
            for enc in _encodings(SYN_CANARY).values():
                self.assertNotIn(enc, dumped)
            self.assertEqual([s for s in _emitted_strings(view) if _recognized(s)], [])
            self.assertEqual(view["never_opened"], sorted(["bait.json", "box-dummy*.json", "session-spec*.json",
                                                           "claude/box-dummy*.json", "claude/session-spec*.json",
                                                           "codex/box-dummy*.json", "codex/session-spec*.json"]))
            self.assertEqual(view["never_opened_count"]["claude/box-dummy*.json"], 2)
            self.assertEqual(view["records"]["pair.json"]["id"], deepgate.WITHHELD)
            self.assertEqual(view["records"]["source-pin.json"]["label"], deepgate.WITHHELD)

    def test_full_object_screen_counts(self):
        cnt = {"keys_dropped": 0, "values_withheld": 0}
        b64 = _encodings(SYN_CANARY)["base64"]
        out = deepgate._screen_emitted({"a": [b64, "ok"], b64: 1, "b": {"c": SYN_CANARY}}, cnt)
        self.assertEqual(out, {"a": [deepgate.WITHHELD, "ok"], "b": {"c": deepgate.WITHHELD}})
        self.assertEqual(cnt, {"keys_dropped": 1, "values_withheld": 2})


class InspectNoLeakDecoded(test_p9.InspectNoLeakAllowedSlots):
    """P8 + P9's no-leak test, extended for R2: the pair's own canary token planted base64- and
    hex-encoded in allowed slots and as dynamic file-name suffixes at root and family level; every
    emitted key and string, AND every decoded view of each, carries no recognised shape."""

    def setUp(self):
        super().setUp()
        pd = self.p.pd
        enc = _encodings(self.p.bait["canary_token"])
        self.planted |= set(enc.values())

        def patch(name, fn):
            q = pd / name
            rec = json.loads(q.read_text())
            fn(rec)
            q.write_text(json.dumps(rec))
        patch("source-pin.json", lambda r: r.update(label=enc["base64"]))
        for fam in ("claude", "codex"):
            patch(f"{fam}/run-meta.json", lambda r: r.update(reviewer_cli_version=enc["hex"]))
            patch(f"{fam}/gate.json", lambda r: r.update(reviewer_model=enc["base64url"].rstrip("=")))
            (pd / fam / f"box-dummy-{enc['plain']}.json").write_text("{}")
            (pd / fam / f"session-spec-{enc['base64url']}.json").write_text("{}")
        (pd / f"box-dummy-{enc['hex']}.json").write_text("{}")
        (pd / f"session-spec-{enc['plain']}.json").write_text("{}")
        self.out = run(GATE, "inspect", str(pd)).stdout

    def test_every_emitted_string_decoded(self):
        v = json.loads(self.out)
        hits = [s for s in _emitted_strings(v) if _recognized(s)]
        self.assertEqual(hits, [])
        self.assertIn("claude/session-spec*.json", v["never_opened"])
        self.assertEqual(v["records"]["source-pin.json"]["label"], deepgate.WITHHELD)
        self.assertEqual(v["records"]["claude/run-meta.json"]["reviewer_cli_version"], deepgate.WITHHELD)


if __name__ == "__main__":
    unittest.main()
