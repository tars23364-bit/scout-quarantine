"""P5: the peer reviewer's review of the P4/C5 package (2026-10-07, REVISE), finding F2a.

  F2a  `_is_root` compared literal strings, so `00:00`, `00000:10001`, `+0:0` and `-0:0` passed as
       non-root at the proxy's launch declaration AND in its inspect evidence (docker's Config.User is
       the configured string; moby resolves numeric components with strconv.Atoi, so all of them ARE
       uid 0). One helper, deepsession.user_identity, now judges every user string, declaration and
       evidence alike: spelling (`uid_noncanonical`) and policy (`runs_as_root`) are separate reasons.

Every negative here is made BEFORE the audit binds the records (descriptor and terminal receipt
re-hashed, matching evidence), so only the policy can catch it; each must end SEALED with the
specific reason. The positives (`10001:10001`, the credproxy image's own default `credproxy`, and a
canonical numeric non-root proxy user) must still RELEASE.
Run: python3 -m unittest discover -s tests
"""
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEEP = HERE.parent / "deep"
sys.path.insert(0, str(DEEP))
sys.path.insert(0, str(HERE))
import deepgate  # noqa: E402
import deeplib  # noqa: E402
import deepsession  # noqa: E402
from deepfixture import Pair  # noqa: E402
from test_p4 import BOX, PROXY, REPO, PairCase  # noqa: E402

UID = deepsession.user_identity
NONCANON, ROOT = "uid_noncanonical", "runs_as_root"

# her shape and the brief's list: every spelling must SEAL at the declaration AND at the evidence
SPELLINGS = {
    "00:00": [NONCANON], "00000:10001": [NONCANON], "+0:0": [NONCANON], "-0:0": [NONCANON],
    "0:00": [NONCANON, ROOT], "10001:00": [NONCANON], " 0:0": [NONCANON], "0x0": [NONCANON],
    "root:0": [ROOT],
}


# =========================================================================== the helper
class UserIdentityUnit(unittest.TestCase):
    def test_canonical_non_root_identities_pass(self):
        for u in ("10001:10001", "credproxy", "credproxy:credproxy", "10002", "10002:10002", "1", "1:1",
                  "4294967294", "4294967294:4294967294", "_svc", "a.b-c_d",
                  "10001:0", "10001:root"):     # the group half's VALUE carries no policy (C5 has none)
            self.assertEqual(UID(u), [], repr(u))

    def test_canonical_root_still_fails_the_separate_policy(self):
        for u in ("0", "0:0", "root", "root:0", "root:root", "0:10001", "root:10001", "", None):
            self.assertEqual(UID(u), [ROOT], repr(u))

    def test_range_edges_and_overflow(self):
        self.assertEqual(UID("0"), [ROOT])
        self.assertEqual(UID("1"), [])
        self.assertEqual(UID(str(2 ** 32 - 2)), [])
        for u in (str(2 ** 32 - 1), str(2 ** 32), "9" * 40, "1" + "0" * 39,
                  f"10001:{2 ** 32 - 1}", f"10001:{2 ** 32}", "10001:" + "9" * 40):
            self.assertEqual(UID(u), [NONCANON], repr(u))

    def test_non_ascii_digits_are_refused_not_coerced(self):
        for u in ("１０００１",          # fullwidth 10001
                  "０",                                    # fullwidth 0
                  "١٠٠٠١",           # Arabic-Indic 10001
                  "٠",                                    # Arabic-Indic 0
                  "1​", "0​", "​0",             # a digit beside a zero-width space
                  "10001:１", "०",                    # Devanagari 0
                  "rоot"):                                # a Cyrillic letter in a name
            self.assertIn(NONCANON, UID(u), repr(u))

    def test_whitespace_is_a_refusal_not_a_strip(self):
        for u in (" 0:0", "0:0 ", "\t0", "0\n", "10001:10001\n", " 10001:10001", "10001 :10001", "10001: 10001",
                  " ", "\n", "credproxy "):
            self.assertIn(NONCANON, UID(u), repr(u))

    def test_other_noncanonical_spellings(self):
        for u, want in SPELLINGS.items():
            self.assertEqual(UID(u), want, repr(u))
        for u in ("00", "010001:10001", "+10001", "-1", "1e3", "0x2711", "0o0", "1_0", "1.0",
                  "10001:", ":10001", ":", "a:b:c", "10001:10001:10001", "1abc", "root!", "-"):
            self.assertIn(NONCANON, UID(u), repr(u))

    def test_old_helper_is_gone(self):
        self.assertFalse(hasattr(deepsession, "_is_root"))


# =========================================================================== declarations (every vector)
class DeclarationMatrix(unittest.TestCase):
    def box_spec(self, fam, role, user):
        run_args = [x for x in BOX if x not in ("--user", "10001:10001")] + ["--user", user] \
            + (REPO if role == "reviewer" else []) + ["img"]
        cli = (["claude", "-p", "--permission-mode", "dontAsk"] if fam == "claude"
               else ["codex", "exec", "-s", "read-only", "-"])
        sp = {"family": fam, "role": role, "run_args": run_args, "cli": cli}
        if fam == "claude":
            sp["exec_env"] = {"CLAUDE_CODE_OAUTH_TOKEN": deeplib.box_dummy("claude")["values"][0]}
        return sp

    def test_every_box_vector_names_the_reason(self):
        for fam in ("claude", "codex"):
            for role in ("reviewer", "auditor", "probe"):
                self.assertEqual(deepsession.validate_spec(self.box_spec(fam, role, "10001:10001")), [], (fam, role))
                for u, want in SPELLINGS.items():
                    errs = deepsession.validate_spec(self.box_spec(fam, role, u))
                    for c in want:
                        self.assertTrue(any(e.startswith(f"box: {c} (") for e in errs), (fam, role, u, errs))
                    self.assertIn(f"box_{want[0]}", deeplib.launch_codes(errs))

    def test_the_proxy_vector_names_the_reason(self):
        self.assertEqual(deepsession.validate_proxy_run(PROXY), [])                 # image default
        for ok in ("credproxy", "10002:10002", "10002"):
            self.assertEqual(deepsession.validate_proxy_run(["--user", ok] + PROXY), [], ok)
        for u, want in SPELLINGS.items():
            for form in (["--user", u], [f"--user={u}"], ["-u", u]):
                codes = deeplib.launch_codes(deepsession.validate_proxy_run(form + PROXY))
                if NONCANON in want:
                    self.assertIn("proxy_uid_noncanonical", codes, (u, form))
                if ROOT in want:
                    self.assertIn("proxy_the_proxy_never_runs_as_root", codes, (u, form))
                self.assertFalse(any(u.strip() in c for c in codes if u.strip()), codes)


# =========================================================================== evidence (unit)
class EvidenceMatrix(PairCase):
    def kw(self, fam="claude"):
        r = json.loads((self.p.pd / fam / "run-meta.json").read_text())
        d = json.loads((self.p.pd / fam / "runtime.json").read_text())
        return r["runtime_evidence"], d

    def test_matching_evidence_still_names_the_reason(self):
        ev0, d = self.kw()
        self.assertEqual(ev0["proxy"]["user"], "credproxy")       # the locked image's own default
        for u, want in SPELLINGS.items():
            ev = json.loads(json.dumps(ev0))
            ev["proxy"]["user"] = u
            got = deepsession.evidence_problems(ev, box_args=d["box_run_args"], box_name=ev["box_name"],
                                                proxy_args=["--user", u] + d["proxy_run_args"],
                                                proxy_name=ev["proxy_name"], role="reviewer")
            self.assertEqual(sorted(got), sorted(f"inspect_proxy_{c}" for c in want), u)
            ev = json.loads(json.dumps(ev0))
            ev["box"]["user"] = u
            box_args = [x if x != "10001:10001" else u for x in d["box_run_args"]]
            got = deepsession.evidence_problems(ev, box_args=box_args, box_name=ev["box_name"],
                                                proxy_args=d["proxy_run_args"], proxy_name=ev["proxy_name"])
            for c in want:
                self.assertIn(f"inspect_box_{c}", got, u)


# =========================================================================== end to end, before binding
class PrebindingF2a(PairCase):
    """Her paired shape: the declaration AND the matching inspect evidence changed before binding,
    both hashes recomputed, both audits run; release and public admission must refuse."""

    def mutate(self, fam, target, decl=None, evid=None):
        if decl is not None:
            f = self.p.pd / fam / "runtime.json"
            d = json.loads(f.read_text())
            if target == "proxy":
                d["proxy_run_args"][0:0] = ["--user", decl]
            else:
                d["box_run_args"][d["box_run_args"].index("--user") + 1] = decl
            d["descriptor_sha256"] = deeplib.descriptor_sha(d)
            f.write_text(json.dumps(d))
        if evid is not None:
            f = self.p.pd / fam / "run-meta.json"
            m = json.loads(f.read_text())
            m["runtime_evidence"][target]["user"] = evid
            m["terminal"]["runtime_evidence_sha256"] = deeplib.canon_sha(m["runtime_evidence"])
            f.write_text(json.dumps(m))
        for g in ("claude", "codex"):
            self.p.audit(g)

    def sealed(self, *needles):
        rel = self.assertSealed(*needles)
        status = deepgate.admit(self.p.pd)
        self.assertNotEqual(status[0].get("status") if isinstance(status, tuple) else None, "RELEASED")
        return rel

    def test_proxy_matching_declaration_and_evidence(self):
        for u, want in SPELLINGS.items():
            fam = "codex" if u == "-0:0" else "claude"
            with self.subTest(user=u):
                self.fresh()
                self.mutate(fam, "proxy", decl=u, evid=u)
                needles = [f"{fam}: runtime: proxy_launch_vector_not_valid"]
                if NONCANON in want:
                    needles += [f"{fam}: runtime: proxy_launch:proxy_uid_noncanonical",
                                f"{fam}: runtime: inspect_proxy_uid_noncanonical"]
                if ROOT in want:
                    needles += [f"{fam}: runtime: proxy_launch:proxy_the_proxy_never_runs_as_root",
                                f"{fam}: runtime: inspect_proxy_runs_as_root"]
                rel = self.sealed(*needles)
                self.assertNotIn(f"{fam}: runtime: inspect_proxy_user_not_declared", rel["reasons"])

    def test_box_matching_declaration_and_evidence(self):
        for u, want in SPELLINGS.items():
            with self.subTest(user=u):
                self.fresh()
                self.mutate("claude", "box", decl=u, evid=u)
                needles = ["claude: runtime: box_launch_vector_not_valid",
                           f"claude: runtime: box_launch:box_{want[0]}",
                           f"claude: runtime: inspect_box_{want[0]}"]
                self.sealed(*needles)

    def test_only_one_side_mutated_still_fires_the_mismatch(self):
        # declaration only (the evidence still says the image default): both refusals
        self.mutate("claude", "proxy", decl="00:00")
        self.sealed("claude: runtime: proxy_launch:proxy_uid_noncanonical",
                    "claude: runtime: inspect_proxy_user_not_declared")
        # evidence only, under a canonical declaration: the mismatch AND the spelling
        self.fresh()
        self.mutate("claude", "proxy", decl="10002:10002", evid="00:00")
        self.sealed("claude: runtime: inspect_proxy_user_not_declared",
                    "claude: runtime: inspect_proxy_uid_noncanonical")
        # evidence only, no --user declared (the launcher's real vector): the spelling alone
        self.fresh()
        self.mutate("claude", "proxy", evid="00:00")
        self.sealed("claude: runtime: inspect_proxy_uid_noncanonical")
        # the box: either side alone
        self.fresh()
        self.mutate("codex", "box", decl="00:00")
        self.sealed("codex: runtime: box_launch:box_uid_noncanonical",
                    "codex: runtime: inspect_box_user_not_the_declared_uid")
        self.fresh()
        self.mutate("codex", "box", evid="00:00")
        self.sealed("codex: runtime: inspect_box_user_not_the_declared_uid",
                    "codex: runtime: inspect_box_uid_noncanonical")

    def test_positive_controls_release(self):
        # 10001:10001 boxes with the credproxy image default (the fixture as it stands)
        for g in ("claude", "codex"):
            self.p.audit(g)
        rc, rel = self.release()
        self.assertEqual((rc, rel["status"]), (0, "RELEASED"), rel.get("reasons"))
        self.assertEqual(deepgate.admit(self.p.pd)[0].get("status"), "RELEASED")
        # the image default named explicitly on both sides, and a canonical numeric non-root proxy
        for u in ("credproxy", "10002:10002"):
            with self.subTest(user=u):
                self.fresh()
                self.mutate("claude", "proxy", decl=u, evid=u)
                rc, rel = self.release()
                self.assertEqual((rc, rel["status"]), (0, "RELEASED"), rel.get("reasons"))


# =========================================================================== P6: oversized decimals
# the peer reviewer's P5 review (ACCEPT, one low residual): `int(h)` on a canonical decimal longer than Python's
# default int-conversion limit (4300 digits) raised ValueError, so release sealed on "release check raised
# ValueError" instead of naming `uid_noncanonical`. A component of more than ten digits is now refused
# before any int conversion. Every case here runs with the interpreter limit at its DEFAULT, in this
# process and in the release subprocess (PYTHONINTMAXSTRDIGITS removed from its environment).
import os  # noqa: E402
from unittest import mock  # noqa: E402

DEFAULT_INT_DIGITS = sys.int_info.default_max_str_digits


class DefaultIntLimit(unittest.TestCase):
    """The interpreter's int-conversion limit at its default for the whole class, here and in every
    subprocess it starts; restored afterwards."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._old_limit = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(DEFAULT_INT_DIGITS)
        cls._env = mock.patch.dict(os.environ)
        cls._env.start()
        os.environ.pop("PYTHONINTMAXSTRDIGITS", None)

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()
        sys.set_int_max_str_digits(cls._old_limit)
        super().tearDownClass()


class LongNumericUnit(DefaultIntLimit):
    def test_the_limit_is_the_default_and_bites(self):
        self.assertEqual(sys.get_int_max_str_digits(), 4300)
        int("9" * 4300)
        with self.assertRaises(ValueError):
            int("9" * 4301)

    def test_ten_digits_is_judged_by_value(self):
        for user in ("4294967294", "10001:4294967294", "1000000000", "10001:1000000000"):
            self.assertEqual(UID(user), [], user)
        for user in ("4294967295", "9999999999", "10001:4294967295", "10001:9999999999"):
            self.assertEqual(UID(user), [NONCANON], user)

    def test_long_components_are_refused_in_both_halves(self):
        for n in (11, 40, 4300, 4301, 100_000):
            for form, comp in (("nines", "9" * n), ("pow10", "1" + "0" * (n - 1))):
                for half, user in (("uid", comp), ("gid", "10001:" + comp), ("uid:gid", comp + ":10001")):
                    with self.subTest(digits=n, half=half, form=form):
                        self.assertEqual(UID(user), [NONCANON])
        # a long root-looking user half still carries no root reason: it is not canonical `0`
        self.assertEqual(UID("0" * 4301), [NONCANON])
        self.assertEqual(UID("0" * 4301 + ":0"), [NONCANON])

    def test_long_components_never_reach_int(self):
        spy = mock.Mock(side_effect=int)
        with mock.patch.object(deepsession, "int", spy, create=True):
            for n in (11, 4301, 100_000):
                spy.reset_mock()
                self.assertEqual(UID("9" * n + ":" + "9" * n), [NONCANON])
                spy.assert_not_called()
            spy.reset_mock()
            self.assertEqual(UID("10001:10001"), [])
            self.assertEqual(spy.call_count, 2)          # ten digits or fewer: judged by value, as C6


class PrebindingLongNumeric(DefaultIntLimit, PrebindingF2a):
    """Her paired shape with a 4301-digit component, declaration and matching evidence, before binding:
    release and admission SEAL with `uid_noncanonical` at both checks, and nothing raises."""

    def no_exception(self, rel):
        for r in rel["reasons"]:
            self.assertNotIn("raised", r)

    def test_proxy_pair_uid_and_gid(self):
        for group in (False, True):
            user = ("10002:" if group else "") + "9" * 4301
            with self.subTest(component="gid" if group else "uid"):
                self.fresh()
                self.mutate("claude", "proxy", decl=user, evid=user)
                rel = self.sealed("claude: runtime: proxy_launch_vector_not_valid",
                                  "claude: runtime: proxy_launch:proxy_uid_noncanonical",
                                  "claude: runtime: inspect_proxy_uid_noncanonical")
                self.no_exception(rel)
                self.assertNotIn("claude: runtime: inspect_proxy_user_not_declared", rel["reasons"])

    def test_box_pair_uid_and_gid(self):
        for group in (False, True):
            user = ("10001:" if group else "") + "9" * 4301
            with self.subTest(component="gid" if group else "uid"):
                self.fresh()
                self.mutate("codex", "box", decl=user, evid=user)
                rel = self.sealed("codex: runtime: box_launch_vector_not_valid",
                                  "codex: runtime: box_launch:box_uid_noncanonical",
                                  "codex: runtime: inspect_box_uid_noncanonical")
                self.no_exception(rel)

    # the inherited F2a cases are exercised once, in PrebindingF2a itself
    test_proxy_matching_declaration_and_evidence = None
    test_box_matching_declaration_and_evidence = None
    test_only_one_side_mutated_still_fires_the_mismatch = None
    test_positive_controls_release = None


class SeraLongNumericReproducerInverted(DefaultIntLimit, PairCase):
    """the peer reviewer's long_numeric_probe.py (P5 review, 2026-10-07), verbatim in shape: `--user` with a
    4301-digit uid (or `10002:` + a 4301-digit gid) prepended to the Claude reviewer's proxy vector and
    the matching inspect user set, before binding, both hashes recomputed, both audits run. Under C6
    release exited 4 SEALED on "release check raised ValueError"; it must SEAL on the named reason."""

    def test_long_numeric_pair(self):
        for group in (False, True):
            with self.subTest(component="gid" if group else "uid"):
                self.fresh()
                user = ("10002:" if group else "") + "9" * 4301
                f = self.p.pd / "claude/runtime.json"
                d = json.loads(f.read_text())
                d["proxy_run_args"][0:0] = ["--user", user]
                d["descriptor_sha256"] = deeplib.descriptor_sha(d)
                f.write_text(json.dumps(d))
                f = self.p.pd / "claude/run-meta.json"
                m = json.loads(f.read_text())
                m["runtime_evidence"]["proxy"]["user"] = user
                m["terminal"]["runtime_evidence_sha256"] = deeplib.canon_sha(m["runtime_evidence"])
                f.write_text(json.dumps(m))
                for fam in self.p.families:
                    self.p.audit(fam)
                rc, rel = self.release()
                admitted, reports = deepgate.admit(self.p.pd)
                self.assertEqual((rc, rel["status"], admitted["status"], len(reports)), (4, "SEALED", "SEALED", 0))
                self.assertIn("claude: runtime: proxy_launch:proxy_uid_noncanonical", rel["reasons"])
                self.assertIn("claude: runtime: inspect_proxy_uid_noncanonical", rel["reasons"])
                self.assertNotIn("release check raised ValueError", rel["reasons"])
                self.assertFalse([r for r in admitted.get("reasons", []) if "raised" in r], admitted.get("reasons"))


if __name__ == "__main__":
    unittest.main()
