"""Gating of the codex auditor's isolation flags (lib/scoutlib.py codex_isolation_args).

Run: python3 -m unittest discover -s tests   (stdlib only; pytest also collects it)
No real codex is invoked: a fake runner stands in for subprocess.run.
"""
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import scoutlib  # noqa: E402

# Shape of `codex features list` on codex-cli 0.153.0 (trimmed).
LIST_0153 = """\
apps                                     stable             true
browser_use                              stable             true
browser_use_external                     stable             true
browser_use_full_cdp_access              stable             true
computer_use                             stable             true
image_generation                         stable             true
in_app_browser                           stable             true
mcp_2026_07_28                           under development  false
WARNING: This output is designed for human readability. For machine-readable output, please use --format.
"""

# An older build: knows only some features and has no web_search config key.
LIST_OLD = """\
apps                                     stable             true
image_generation                         beta               true
"""


def fake_runner(features_stdout, features_rc=0, accepts_web_search=True, raise_exc=None):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if raise_exc:
            raise raise_exc
        if argv[:3] == ["codex", "features", "list"] and "-c" in argv:
            return SimpleNamespace(returncode=0 if accepts_web_search else 1, stdout="", stderr="")
        if argv[:3] == ["codex", "features", "list"]:
            return SimpleNamespace(returncode=features_rc, stdout=features_stdout, stderr="")
        raise AssertionError(f"unexpected argv {argv}")

    run.calls = calls
    return run


class CodexIsolationArgs(unittest.TestCase):
    def test_current_build_disables_every_feature_and_web_search(self):
        args, skipped = scoutlib.codex_isolation_args(fake_runner(LIST_0153))
        for f in scoutlib.CODEX_DISABLE_FEATURES:
            i = args.index(f)
            self.assertEqual(args[i - 1], "--disable", f)
        self.assertEqual(args[-2:], ["-c", 'web_search="disabled"'])
        self.assertEqual(skipped, [])

    def test_old_build_only_gets_flags_it_knows(self):
        args, skipped = scoutlib.codex_isolation_args(fake_runner(LIST_OLD, accepts_web_search=False))
        self.assertEqual(args, ["--disable", "apps", "--disable", "image_generation"])
        self.assertIn("browser_use_full_cdp_access", skipped)
        self.assertIn("web_search", skipped)
        self.assertNotIn("-c", args)

    def test_no_features_subcommand_means_no_disable_flags(self):
        args, skipped = scoutlib.codex_isolation_args(fake_runner("", features_rc=2, accepts_web_search=False))
        self.assertEqual(args, [])
        self.assertEqual(set(skipped), set(scoutlib.CODEX_DISABLE_FEATURES) | {"web_search"})

    def test_runner_failure_degrades_without_raising(self):
        args, skipped = scoutlib.codex_isolation_args(fake_runner("", raise_exc=subprocess.TimeoutExpired("codex", 60)))
        self.assertEqual(args, [])
        self.assertTrue(skipped)

    def test_box_extras_are_added_and_gated_and_host_default_is_unchanged(self):
        listing = LIST_0153 + "".join(f"{f:<40} stable             true\n" for f in scoutlib.CODEX_BOX_EXTRA_DISABLE[:-1])
        args, skipped = scoutlib.codex_isolation_args(fake_runner(listing), extra=scoutlib.CODEX_BOX_EXTRA_DISABLE)
        for f in scoutlib.CODEX_BOX_EXTRA_DISABLE[:-1]:
            self.assertEqual(args[args.index(f) - 1], "--disable", f)
        self.assertIn(scoutlib.CODEX_BOX_EXTRA_DISABLE[-1], skipped)  # unknown to this build: not passed
        self.assertNotIn(scoutlib.CODEX_BOX_EXTRA_DISABLE[-1], args)
        self.assertIn("analytics.enabled=false", args)
        host, _ = scoutlib.codex_isolation_args(fake_runner(listing))
        self.assertNotIn("plugins", host)
        self.assertNotIn("analytics.enabled=false", host)

    def test_warning_line_is_not_a_feature(self):
        names = scoutlib._codex_known_features(fake_runner(LIST_0153))
        self.assertNotIn("WARNING:", names)
        self.assertIn("mcp_2026_07_28", names)


if __name__ == "__main__":
    unittest.main()
