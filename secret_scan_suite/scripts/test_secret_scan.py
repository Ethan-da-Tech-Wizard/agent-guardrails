#!/usr/bin/env python3
"""Tests for scripts/secret_scan.py. Fake credentials are assembled at runtime so this file holds no scannable secret.

Covers detection without leaking values, placeholder filtering, baseline accept/alarm behaviour, fail-closed handling of
unreadable inputs and receipts, and the incremental cache. All work happens in temporary folders.

Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'
"""
import json, os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

# Synthetic AWS-shaped key ids, assembled at runtime so no key-shaped literal sits in the file.
FIXTURE_KEY_A = "AKIA" + "IOSFODNN7" + "EXAMPLE"  # AWS documentation example id (placeholder-shaped on purpose)
FIXTURE_KEY_B = "AKIA" + "TESTKEYONLY" + "QWERT"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan as ss

# Runtime-assembled fake credentials (one per rule shape) used as scan input.
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
ANT = "sk-ant-" + "api03-" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"


class T(unittest.TestCase):
    """Behavioural tests for detection, baseline, receipts and fail-closed handling."""

    def setUp(self):
        # Fresh temp root (self.r) and a state folder (self.d) per test.
        self.t = tempfile.TemporaryDirectory(); self.r = Path(self.t.name).resolve(); self.d = self.r / "state"

    def tearDown(self):
        self.t.cleanup()

    def w(self, name, txt):
        """Helper: write txt to a file named name under the temp root (creating folders) and return its path."""
        p = self.r / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(txt); return p

    def test_detects_and_never_prints_secret(self):
        # Proves: three token types are found and neither the receipt nor the return value contains the secret text.
        f = self.w("a.env", f"x=1\nTOKEN={GH}\nK={AWS}\n{ANT}\n")
        r, new = ss.check(self.r, self.d, [f])
        self.assertEqual({x["type"] for x in new}, {"github-token", "aws-access-key", "anthropic-key"})
        blob = json.dumps(r) + (self.d / f"SECRETS.{ss.HOST}.json").read_text()
        for secret in (AWS, GH, ANT):
            self.assertNotIn(secret, blob)

    def test_placeholders_and_clean_ignored(self):
        # Proves: documentation-style placeholder values produce no findings.
        f = self.w("b.md", "key = " + FIXTURE_KEY_A + "\nuse sk-ant-<your key here> and ghp_xxxx\n")
        self.assertEqual(ss.scan(self.r, [f]), [])

    def test_private_key_block_and_wg_key(self):
        # Proves: a PEM header and a real WireGuard key are found, while an @TEMPLATE@ marker is not.
        f = self.w("c.txt", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nPrivateKey = @PRIVATE_KEY@\n" + "PrivateKey = " + "A" * 43 + "=\n")
        self.assertEqual({x["type"] for x in ss.scan(self.r, [f])}, {"private-key-block", "wireguard-private-key"})

    def test_accept_then_quiet_and_new_one_alarms(self):
        # Proves: accepted findings go quiet, a different new one is reported, and the alarm view surfaces it.
        f = self.w("d.env", f"{GH}\n")
        ss.accept(self.r, self.d, [f]); self.assertEqual(ss.check(self.r, self.d, [f])[1], [])
        g = self.w("e.env", f"{AWS}\n"); self.assertEqual(len(ss.check(self.r, self.d, [f, g])[1]), 1)
        self.assertTrue(any(k.startswith("secret:") for k in ss.alarm_problems(d=self.d)))

    def test_binary_big_and_skipdir_skipped(self):
        # Proves: binary files and files under a skip prefix are not scanned.
        b = self.r / "x.bin"; b.write_bytes(b"\0\0" + GH.encode())
        s = self.w("third_party/z.txt", GH)
        old = ss.SKIP_DIRS; ss.SKIP_DIRS = ("third_party/",); self.addCleanup(setattr, ss, "SKIP_DIRS", old)
        self.assertEqual(ss.scan(self.r, [b, s]), [])

    def test_alarm_quiet(self):
        # Proves: with no receipt, the alarm view reports that the scanner never ran.
        self.assertIn("secret:quiet", ss.alarm_problems(d=self.d))

    def test_incomplete_scan_is_persisted_as_alarm(self):
        # Proves: a failed scan is recorded as incomplete (not clean) and surfaces as an alarm.
        with mock.patch.object(ss, "scan", side_effect=ss.ScanUnavailable("permission denied")):
            r, new = ss.check(self.r, self.d, [])
        self.assertFalse(r["complete"])
        self.assertIsNone(r["findings"])
        self.assertEqual(new, [])
        self.assertIn("secret:scan-unavailable", r["problems"])
        self.assertIn("secret:scan-unavailable", ss.alarm_problems(d=self.d))

    def test_git_inventory_failure_is_not_empty_success(self):
        # Proves: a git failure raises instead of returning an empty file list.
        failed = mock.Mock(returncode=128, stdout=b"", stderr=b"repository unavailable")
        with mock.patch.object(ss.subprocess, "run", return_value=failed):
            with self.assertRaises(ss.ScanUnavailable):
                ss.files(self.r)

    def test_unreadable_scan_input_is_not_skipped_as_nonfile(self):
        # Proves: a permission error while inspecting a file fails the scan rather than silently skipping it.
        p = self.w("restricted.txt", "ordinary text\n")
        original = Path.stat
        def denied(path, *args, **kwargs):
            if path == p:
                raise PermissionError("denied")
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "stat", new=denied):
            with self.assertRaises(ss.ScanUnavailable):
                ss.scan(self.r, [p])

    def test_file_deleted_between_listing_and_read_is_skipped_but_permission_errors_still_fail(self):
        # Proves: a vanished file is skipped, but a permission error on read still fails closed.
        gone = self.r / "sync-conflict-copy.html"  # listed, then a sync tool removed it before the read
        self.assertEqual(ss.scan(self.r, [gone]), [])
        p = self.w("kept.txt", "ordinary text\n")
        original = Path.read_bytes
        def denied(path, *a, **k):
            if path == p:
                raise PermissionError("denied")
            return original(path, *a, **k)
        with mock.patch.object(Path, "read_bytes", new=denied):
            with self.assertRaises(ss.ScanUnavailable):
                ss.scan(self.r, [p])

    def test_dangling_symlink_is_skipped_not_scan_failure(self):
        # Proves: a symlink to a missing target is ignored without aborting the scan.
        link = self.r / "dangling.md"
        link.symlink_to(self.r / "missing target.md")
        good = self.w("leak.txt", "key " + AWS + "\n")
        found = ss.scan(self.r, [link, good])
        self.assertEqual([f["file"] for f in found], ["leak.txt"])

    def test_corrupt_baseline_and_malformed_receipt_are_alarms(self):
        # Proves: an unreadable baseline gives an incomplete scan, and a malformed receipt gives a receipt-unavailable alarm.
        self.d.mkdir(parents=True, exist_ok=True)
        (self.d / "secrets_known.json").write_text("not json")
        with mock.patch.object(ss, "scan", return_value=[]):
            r, _ = ss.check(self.r, self.d, [])
        self.assertFalse(r["complete"])
        self.assertIn("secret:scan-unavailable", r["problems"])
        latest = self.d / f"SECRETS.{ss.HOST}.json"
        latest.write_text("not json")
        self.assertIn("secret:receipt-unavailable", ss.alarm_problems(d=self.d))

    def test_legacy_or_wrong_host_receipt_is_not_clean(self):
        # Proves: a receipt lacking the completeness flag, or written for another host, is never treated as clean.
        self.d.mkdir(parents=True, exist_ok=True)
        latest = self.d / f"SECRETS.{ss.HOST}.json"
        latest.write_text('{"checked": 1, "host": "' + ss.HOST + '", "problems": {}}')
        self.assertIn("secret:scan-unavailable", ss.alarm_problems(d=self.d))
        latest.write_text('{"checked": 1, "host": "other-host", "complete": true, "problems": {}}')
        self.assertIn("secret:receipt-unavailable", ss.alarm_problems(d=self.d))



class IncrementalCache(unittest.TestCase):
    """The workspace scan skips files unchanged since the last scan, but must never hide a finding."""

    def setUp(self):
        import tempfile
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.cache = self.root / "cache.json"
        self._old = os.environ.get("SECRET_SCAN_CACHE")
        os.environ["SECRET_SCAN_CACHE"] = str(self.cache)
        self.addCleanup(lambda: os.environ.pop("SECRET_SCAN_CACHE", None) if self._old is None else os.environ.__setitem__("SECRET_SCAN_CACHE", self._old))
        self.f = self.root / "a.txt"
        self.f.write_text("nothing here\n")

    def run_scan(self):
        """Helper: scan the single test file with the cache enabled."""
        return ss.scan(self.root, [self.f], cache=True)

    def test_unchanged_file_is_not_reread_and_results_match(self):
        # Proves: an unchanged file is served from the cache (scan_text not called) with identical results.
        first = self.run_scan()
        calls = []
        real = ss.scan_text
        ss.scan_text = lambda t: calls.append(1) or real(t)
        try:
            second = self.run_scan()
        finally:
            ss.scan_text = real
        self.assertEqual((first, calls), (second, []))

    def test_a_changed_file_is_rescanned_and_a_new_secret_is_found(self):
        # Proves: editing a file (new mtime) invalidates its cache entry so a newly added secret is found.
        self.assertEqual(self.run_scan(), [])
        self.f.write_text(FIXTURE_KEY_B + "\n")
        os.utime(self.f, (self.f.stat().st_atime, self.f.stat().st_mtime + 5))
        hits = self.run_scan()
        self.assertEqual([h["type"] for h in hits], ["aws-access-key"])

    def test_an_old_finding_stays_reported_while_the_file_is_unchanged(self):
        # Proves: a cached finding is replayed, not lost, on later scans.
        self.f.write_text(FIXTURE_KEY_B + "\n")
        a = self.run_scan()
        b = self.run_scan()
        self.assertEqual((len(a), a), (1, b))

    def test_a_changed_rule_invalidates_the_whole_cache(self):
        # Proves: changing the rule set discards cached hits so stale findings are not replayed.
        self.f.write_text(FIXTURE_KEY_B + "\n")
        self.run_scan()
        saved = dict(ss.RULES)
        ss.RULES.clear()
        ss.RULES["other"] = ss.re.compile(r"zzzzzz")
        try:
            self.assertEqual(self.run_scan(), [])                       # the old hit must NOT be replayed under different rules
        finally:
            ss.RULES.clear()
            ss.RULES.update(saved)

    def test_a_corrupt_cache_is_ignored_and_never_changes_results(self):
        # Proves: an unparseable cache file is ignored and the finding is still reported.
        self.f.write_text(FIXTURE_KEY_B + "\n")
        self.cache.write_text("{not json")
        self.assertEqual(len(self.run_scan()), 1)

    def test_the_cache_stores_fingerprints_never_the_secret(self):
        # Proves: the cache file never contains the secret text.
        self.f.write_text(FIXTURE_KEY_B + "\n")
        self.run_scan()
        self.assertNotIn(FIXTURE_KEY_B, self.cache.read_text())

    def test_a_file_list_scan_without_cache_flag_does_not_touch_the_cache(self):
        # Proves: an explicit file-list scan without the cache flag leaves no cache file.
        ss.scan(self.root, [self.f])
        self.assertFalse(self.cache.exists())


class CommandLineTargetAndState(unittest.TestCase):
    """The CLI scans an explicit target (default: the current directory) and keeps its state outside the component folder."""

    SCRIPT = str(Path(__file__).resolve().parent / "secret_scan.py")

    def setUp(self):
        import subprocess
        self.td = tempfile.TemporaryDirectory(); self.addCleanup(self.td.cleanup)
        self.base = Path(self.td.name).resolve()
        self.repo = self.base / "repo"; self.repo.mkdir()
        self.home = self.base / "home"; self.home.mkdir()
        self.state = self.base / "state"
        self.env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "SECRET_SCAN_DIR": str(self.state),
                    "SECRET_SCAN_CACHE": str(self.base / "cache.json"), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=self.env)
        (self.repo / "leak.env").write_text(AWS + "\n")
        self.comp = ss.COMPONENT_DIR

    def run_cli(self, *args, cwd=None):
        """Run the real script as a subprocess in `cwd` (default: the repo) and return the CompletedProcess."""
        import subprocess
        return subprocess.run([sys.executable, "-B", self.SCRIPT, *args], cwd=str(cwd or self.repo), env=self.env,
                              capture_output=True, text=True)

    def snapshot(self):
        """Return the sorted relative names of everything under the component folder (ignoring bytecode caches)."""
        return sorted(str(p.relative_to(self.comp)) for p in self.comp.rglob("*") if "__pycache__" not in p.parts)

    def test_no_argument_scans_the_current_directory_not_the_script_folder(self):
        # Proves: `check` with no PATH scans the cwd (finds the planted key there), reports the target, and never the script's own folder.
        before = self.snapshot()
        r = self.run_cli("check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("leak.env:1 aws-access-key", r.stdout)
        self.assertIn(str(self.repo), r.stdout)                      # the scanned target is stated
        self.assertNotIn(AWS, r.stdout + r.stderr)                    # never the secret itself
        self.assertEqual(self.snapshot(), before)                     # nothing written into the component folder

    def test_clean_current_directory_is_clean_even_though_another_folder_has_keys(self):
        # Proves: the scan target really is the cwd: an empty repo gives exit 0 while the other repo (not the cwd) holds a key.
        import subprocess
        other = self.base / "clean"; other.mkdir(); subprocess.run(["git", "init", "-q", str(other)], check=True, env=self.env)
        (other / "note.txt").write_text("nothing\n")
        self.assertEqual(self.run_cli("check", cwd=other).returncode, 0)

    def test_explicit_path_argument_is_used(self):
        # Proves: `check PATH` scans PATH regardless of the cwd.
        r = self.run_cli("check", str(self.repo), cwd=self.base)
        self.assertEqual(r.returncode, 1); self.assertIn("aws-access-key", r.stdout)

    def test_state_goes_to_the_state_dir_only(self):
        # Proves: the receipt lands in SECRET_SCAN_DIR, not in the scanned repo, and `accept` then makes the next check pass.
        self.run_cli("check")
        self.assertTrue((self.state / f"SECRETS.{ss.HOST}.json").exists())
        self.assertFalse((self.repo / "data").exists())
        self.assertEqual(self.run_cli("accept").returncode, 0)
        self.assertEqual(self.run_cli("check").returncode, 0)

    def test_default_state_dir_is_user_level(self):
        # Proves: without SECRET_SCAN_DIR the state dir is $XDG_STATE_HOME/secret_scan (absolute) or ~/.local/state/secret_scan,
        # and a relative XDG_STATE_HOME is ignored.
        self.assertEqual(ss.default_state_dir({"SECRET_SCAN_DIR": "/x/y"}), Path("/x/y"))
        self.assertEqual(ss.default_state_dir({"XDG_STATE_HOME": "/s"}), Path("/s/secret_scan"))
        with mock.patch.object(Path, "home", return_value=Path("/h")):
            self.assertEqual(ss.default_state_dir({}), Path("/h/.local/state/secret_scan"))
            self.assertEqual(ss.default_state_dir({"XDG_STATE_HOME": "relative/dir"}), Path("/h/.local/state/secret_scan"))

    def test_state_inside_the_component_folder_is_refused(self):
        # Proves: pointing the state folder at the component folder fails loudly (exit 2) and creates nothing there.
        before = self.snapshot()
        self.env["SECRET_SCAN_DIR"] = str(self.comp / "data" / "state")
        r = self.run_cli("check")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr); self.assertIn("refusing", r.stderr)
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises(ValueError):
            ss.check(self.repo, self.comp / "data", [])

    def test_bad_usage_and_missing_folder(self):
        # Proves: unknown commands and non-folders exit 2 without scanning.
        self.assertEqual(self.run_cli("frobnicate").returncode, 2)
        self.assertEqual(self.run_cli("check", str(self.base / "nope")).returncode, 2)

    def test_accept_in_a_non_git_folder_is_a_clean_error_not_a_traceback(self):
        # Regression (M6): `accept` caught only ValueError, so a folder that is not a git work tree printed a Python traceback.
        plain = self.base / "plain"; plain.mkdir(); (plain / "k.env").write_text(AWS + "\n")
        for cmd in ("accept", "check"):
            r = self.run_cli(cmd, str(plain), cwd=self.base)
            self.assertEqual(r.returncode, 2 if cmd == "accept" else 1, (cmd, r.stdout, r.stderr))
            self.assertNotIn("Traceback", r.stderr + r.stdout)
            self.assertTrue("cannot scan" in r.stderr or "PROBLEM" in r.stdout, (cmd, r.stdout, r.stderr))

    def test_state_files_are_owner_only_and_symlinked_temp_is_not_followed(self):
        # Regression (L1): the state folder is created 0700, receipts 0600, and a symlink pre-planted at the temp name is not written through.
        victim = self.base / "victim.txt"; victim.write_text("precious")
        self.state.mkdir()
        (self.state / f"SECRETS.{ss.HOST}.json.tmp").symlink_to(victim)
        self.run_cli("check")
        self.assertEqual(victim.read_text(), "precious")
        self.assertEqual((self.state / f"SECRETS.{ss.HOST}.json").stat().st_mode & 0o777, 0o600)
        fresh = self.base / "fresh_state"
        ss.check(self.repo, fresh, [])
        self.assertEqual(fresh.stat().st_mode & 0o777, 0o700)


class OwnFileNameAndSkipDirs(unittest.TestCase):
    """Only the scanner's OWN two files are exempt; look-alike names elsewhere and folder-prefix skipping behave exactly."""

    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup); self.r = Path(self.t.name).resolve()

    def test_a_file_named_secret_scan_py_in_a_scanned_repo_is_scanned(self):
        # Regression (M4): skipping by base name let any file called secret_scan.py / test_secret_scan.py hide a credential.
        for name in ("secret_scan.py", "sub/test_secret_scan.py"):
            p = self.r / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text("K = '%s'\n" % GH)
        got = {x["file"] for x in ss.scan(self.r, [self.r / "secret_scan.py", self.r / "sub/test_secret_scan.py"])}
        self.assertEqual(got, {"secret_scan.py", "sub/test_secret_scan.py"})

    def test_the_scanners_own_files_are_still_skipped(self):
        # The real component files (which mention key shapes) are exempt, by exact path.
        own = [Path(ss.__file__).resolve(), Path(ss.__file__).resolve().with_name("test_secret_scan.py")]
        self.assertEqual(ss.scan(self.r, own), [])

    def test_skip_dirs_match_whole_folders_only(self):
        # Regression (L4): the prefix "vendor" also skipped "vendors/..." and "vendor_x.txt". Now only "vendor" itself and below.
        old = ss.SKIP_DIRS; ss.SKIP_DIRS = ("vendor",); self.addCleanup(setattr, ss, "SKIP_DIRS", old)
        files = []
        for name in ("vendor/a.txt", "vendors/b.txt", "vendor_x.txt"):
            p = self.r / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(GH + "\n"); files.append(p)
        self.assertEqual({x["file"] for x in ss.scan(self.r, files)}, {"vendors/b.txt", "vendor_x.txt"})


class TokenShapeRegressions(unittest.TestCase):
    """Regressions for placeholder ordering, prefixed tokens, encrypted private keys and cache file modes (each fails on the previous behaviour)."""

    def kinds(self, text):
        """Rule names reported for `text`."""
        return [k for _, k, _ in ss.scan_text(text)]

    def test_placeholder_before_a_real_key_on_one_line_does_not_hide_it(self):
        """L1: the AWS documentation id placed first used to make the scanner judge only that first match and drop the real key."""
        self.assertEqual(self.kinds(FIXTURE_KEY_A + " " + AWS), ["aws-access-key"])
        self.assertEqual(self.kinds("x=" + FIXTURE_KEY_A + " y=" + AWS), ["aws-access-key"])

    def test_placeholder_word_glued_after_a_token_does_not_hide_it(self):
        """L1: 'ghp_<36 real chars>example' used to be dropped because the greedy match swallowed the word 'example'."""
        self.assertEqual(self.kinds(GH + "example"), ["github-token"])
        # a placeholder INSIDE the key characters still counts as a placeholder
        self.assertEqual(self.kinds("ghp_" + "x" * 40), [])

    def test_underscore_prefixed_and_suffixed_aws_key_is_found(self):
        """L2: \\b treats '_' as a word character, so KEY_AKIA... and AKIA..._X were missed."""
        self.assertEqual(self.kinds("MY_KEY_" + AWS), ["aws-access-key"])
        self.assertEqual(self.kinds(AWS + "_PROD"), ["aws-access-key"])
        self.assertEqual(self.kinds("X" + AWS), [])  # glued to a letter: still not a key id

    def test_encrypted_private_key_header_is_found(self):
        """L3: PKCS#8 'BEGIN ENCRYPTED PRIVATE KEY' was not matched."""
        self.assertEqual(self.kinds("-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"), ["private-key-block"])

    def test_cache_file_is_owner_only_in_a_private_new_folder(self):
        """M6: the scan cache (file names + fingerprints) was created 0644 in a 0755 folder although the README says state is owner-only."""
        import stat as st, tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); (root / "a.txt").write_text("hi\n")
            cache = root / "newdir" / "c.json"
            old_umask = os.umask(0o022)
            self.addCleanup(os.umask, old_umask)
            with mock.patch.dict(os.environ, {"SECRET_SCAN_CACHE": str(cache)}):
                ss.scan(root, [root / "a.txt"], cache=True)
            self.assertTrue(cache.exists())
            self.assertEqual(st.S_IMODE(cache.stat().st_mode), 0o600)
            self.assertEqual(st.S_IMODE(cache.parent.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
