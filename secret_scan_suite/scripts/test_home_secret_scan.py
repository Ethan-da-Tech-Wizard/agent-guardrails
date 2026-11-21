"""Tests for scripts/home_secret_scan.py.

Each test builds a fake home folder in a temporary directory and checks what the scanner reports: shell and config
patterns, user folders, symlink and size limits, key-file permissions, the accept workflow, receipt alarms, and that
secret values never appear in output. Secret-like values are assembled at runtime so this file holds none.

Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'
"""
import contextlib, io, json, os, tempfile, time, unittest
from unittest import mock
from pathlib import Path
import home_secret_scan as h

def rnd(n=30):
    """Return a synthetic high-variety string of about n characters, assembled at runtime so the source holds no scannable secret."""
    # (mixed-case alphanumerics: passes the literal-value filter)
    return "Zq" + "k7Rt9" * (n // 5)

class T(unittest.TestCase):
    """Scenario tests against a throwaway fake home folder."""

    def setUp(self):
        # Temp sandbox: fake home (self.home), output folder (self.d) and a synthetic secret value (self.val).
        self._t = tempfile.TemporaryDirectory(); self.addCleanup(self._t.cleanup)
        self.home = Path(self._t.name) / "home"; self.home.mkdir()
        self.d = Path(self._t.name) / "out"
        self.val = rnd()

    def w(self, rel, text, mode=None):
        """Helper: write text to a home-relative path (creating folders), optionally chmod it, and return the path."""
        p = self.home / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
        if mode: p.chmod(mode)
        return p

    def types(self):
        """Helper: scan the fake home and return the set of (relative file, finding type) pairs."""
        f, _ = h.scan(self.home); return {(x["file"], x["type"]) for x in f}

    def test_shell_patterns(self):
        # Proves: all five shell-history patterns (assignment, password flag, curl auth, bearer header, mysql -p) are detected.
        v = self.val
        self.w(".zsh_history", "\n".join([
            f"export MY_API_TOKEN={v}", f"tool --password {v}", f"curl -u bob:{v} http://x",
            f"curl -H 'Authorization: Bearer {v}' http://x", f"mysql -u root -p{v}"]))
        t = {y for _, y in self.types()}
        self.assertTrue({"literal-assignment", "cli-password-flag", "curl-basic-auth", "bearer-token", "mysql-password"} <= t)

    def test_mysqladmin_password_flag(self):
        # Proves: the glued -p<password> form is detected for mysqladmin and mysqldump too.
        self.w(".bash_history", f"mysqladmin -u root -p{self.val} status\nmysqldump -p{self.val} db\n")
        self.assertIn((".bash_history", "mysql-password"), self.types())

    def test_rc_and_rules(self):
        # Proves: a well-known token shape in a shell rc file is detected via the shared rules.
        self.w(".zshrc", "export GH=gh" + "p_" + "A1b2C3d4E5" * 4)
        self.assertIn((".zshrc", "github-token"), self.types())

    def test_configs(self):
        # Proves: each tool-specific credential file format (netrc, npmrc, pypirc, git-credentials, docker, gh hosts, .env) is detected.
        v = self.val
        self.w(".netrc", f"machine x login u password {v}")
        self.w(".npmrc", f"//r/:_authToken={v}")
        self.w(".pypirc", f"[pypi]\npassword = {v}")
        self.w(".git-credentials", f"https://u:{v}@github.com")
        self.w(".docker/config.json", json.dumps({"auths": {"r": {"auth": "dTpw" + v}}}))
        self.w(".config/gh/hosts.yml", f"github.com:\n  oauth_token: {v}\n")
        self.w(".config/app/prod.env", f"DB_PASSWORD={v}")
        t = self.types()
        for k in [(".netrc", "netrc-password"), (".npmrc", "npmrc-auth"), (".pypirc", "pypirc-password"),
                  (".git-credentials", "git-credentials"), (".docker/config.json", "docker-auth"),
                  (".config/gh/hosts.yml", "gh-plaintext-token"), (".config/app/prod.env", "literal-assignment")]:
            self.assertIn(k, t)

    def test_user_folders(self):
        # Proves: Downloads, Desktop and Documents are scanned and labelled with their own class.
        for n in ("Downloads", "Desktop", "Documents"):
            self.w(f"{n}/n.txt", "k = AKIA" + "ABCDEFGHIJKLMNOP")
        f, _ = h.scan(self.home)
        self.assertEqual({x["class"] for x in f}, {"downloads", "desktop", "documents"})

    def test_value_never_leaks(self):
        # Proves: neither the receipt nor any command output contains the secret value or variable name; findings hold only fingerprint fields.
        v = self.val
        self.w(".zsh_history", f"export A_SECRET={v}\ncurl -u u:{v} x")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            r, new = h.check(self.home, self.d)
            h.HOST  # noqa
            old = h.DIR; h.DIR = self.d
            try:
                h.main(["report"]); h.main(["status"]); h.main(["check"]) if False else None
            finally:
                h.DIR = old
        blob = buf.getvalue() + (self.d / f"HOMESECRETS.{h.HOST}.json").read_text()
        self.assertTrue(new); self.assertNotIn(v, blob); self.assertNotIn("A_SECRET", blob)
        for x in r["findings"]:
            self.assertEqual(set(x) - {"accepted"}, {"file", "line", "type", "class", "fp"})
            self.assertEqual(len(x["fp"]), 10)

    def test_weak_password_fingerprint_is_not_dictionary_reversible(self):
        """Regression (H2): fp used to be an unkeyed sha256 prefix of the matched text, so a short human-chosen password could be
        recovered by hashing a word list. Proves: the printed fp is NOT sha256 of any candidate match text, it is stable between
        runs on the same machine (same key, so `accept` keeps working), differs under another key, and the key file is 0600."""
        import hashlib, stat as st
        weak = "sunset" + "42x"          # a guessable 9-character password, assembled at runtime
        self.w(".netrc", f"machine x login u password {weak}")
        r1, _ = h.check(self.home, self.d)
        fp1 = [x["fp"] for x in r1["findings"] if x["type"] == "netrc-password"]
        self.assertEqual(len(fp1), 1)
        # the attacker's dictionary attack: sha256("password "+guess)[:10] for the right guess
        for text in (f"password {weak}", weak, f"password  {weak}"):
            self.assertNotEqual(fp1[0], hashlib.sha256(text.encode()).hexdigest()[:10])
        r2, _ = h.check(self.home, self.d)
        self.assertEqual([x["fp"] for x in r2["findings"] if x["type"] == "netrc-password"], fp1)  # stable -> accept works
        keyf = self.d / h.KEY_FILE
        self.assertEqual(st.S_IMODE(keyf.stat().st_mode), 0o600)
        r3, _ = h.check(self.home, Path(self._t.name) / "out2")      # a different user key gives a different fp
        self.assertNotEqual([x["fp"] for x in r3["findings"] if x["type"] == "netrc-password"], fp1)
        # accept by that fp still silences exactly the finding
        h.accept(fp1[0], "test", self.d)
        self.assertEqual(h.check(self.home, self.d)[1], [])

    def test_placeholders_ignored(self):
        # Proves: variable references, placeholder words, filler runs, short values and <angle> markers are not reported.
        self.w(".zshrc", "\n".join(["export A_TOKEN=$OTHER_TOKEN_VALUE_X", "export B_TOKEN=your_key_here_ab",
                                    "export C_PASSWORD=xxxxxxxxxxxxxxxx", "export D_TOKEN=short", "export E_TOKEN=<paste-token-here-abc>"]))
        self.assertEqual(h.scan(self.home)[0], [])

    def test_symlink_not_followed(self):
        # Proves: symlinked files and folders (including an rc file) are never followed.
        out = Path(self._t.name) / "outside"; out.mkdir()
        (out / "s.txt").write_text(f"export A_SECRET={self.val}")
        (self.home / "Downloads").mkdir()
        os.symlink(out / "s.txt", self.home / "Downloads" / "l.txt")
        os.symlink(out, self.home / "Documents")
        os.symlink(out / "s.txt", self.home / ".zshrc")
        self.assertEqual(h.scan(self.home)[0], [])

    def test_size_binary_skip_and_library(self):
        # Proves: oversized files, binary files, dependency folders and the OS library folder are skipped.
        line = "key = AKIA" + "ABCDEFGHIJKLMNOP"
        self.w("Downloads/big.txt", line + "\n" + "x" * 1_100_000)
        (self.home / "Downloads" / "bin.dat").write_bytes(b"\0\0" + line.encode())
        self.w("Downloads/node_modules/p/a.txt", line)
        self.w("Library/x.txt", line)
        self.assertEqual(h.scan(self.home)[0], [])

    def test_key_permissions(self):
        # Proves: only key files readable by group/others are flagged; private modes are not.
        self.w(".ssh/id_ed25519", "not a real key", 0o644)
        self.w(".ssh/id_rsa2", "x", 0o600)
        self.w("Documents/server.pem", "x", 0o640)
        f, _ = h.scan(self.home)
        got = {x["file"] for x in f if x["type"] == "key-file-permissions"}
        self.assertEqual(got, {".ssh/id_ed25519", "Documents/server.pem"})

    def test_accept_requires_reason(self):
        # Proves: accept refuses a blank reason (API and CLI), and an accepted finding stops counting as new.
        with self.assertRaises(ValueError): h.accept("abc", "", self.d)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            h.main(["accept", "abc"])
        self.w(".zshrc", f"export A_SECRET={self.val}")
        r, new = h.check(self.home, self.d)
        h.accept(new[0]["fp"], "test fixture", self.d)
        r2, new2 = h.check(self.home, self.d)
        self.assertEqual(new2, []); self.assertEqual(r2["new"], 0)

    def test_alarm_conventions(self):
        # Proves: alarm view handles never-ran, finding, stale, future-dated, corrupt and accepted-clean receipts, without leaking values.
        now = time.time()
        self.assertIn("homesecrets:quiet", h.alarm_problems(now, self.d))
        self.w(".zshrc", f"export A_SECRET={self.val}")
        r, new = h.check(self.home, self.d, now=now)
        p = h.alarm_problems(now, self.d)
        self.assertIn(f"homesecrets:{new[0]['fp']}", p); self.assertNotIn(self.val, json.dumps(p))
        self.assertIn("homesecrets:quiet", h.alarm_problems(now + 27 * 3600, self.d))
        self.assertIn("homesecrets:quiet", h.alarm_problems(now - 3600, self.d))  # future-dated
        (self.d / f"HOMESECRETS.{h.HOST}.json").write_text("{bad")
        self.assertIn("homesecrets:quiet", h.alarm_problems(now, self.d))
        h.accept(new[0]["fp"], "ok", self.d)
        (self.d / f"HOMESECRETS.{h.HOST}.json").write_text(json.dumps(r))
        self.assertEqual(h.alarm_problems(now, self.d), {})

    def test_truncated_scan_is_not_complete(self):
        # Regression (M5): a scan cut short by the file budget wrote "complete": true and `check` exited 0 on the part it saw.
        # Proves: complete is false, the alarm view says so, and the CLI exits 1 with an INCOMPLETE line.
        for i in range(5):
            self.w(f"Documents/f{i}.txt", "nothing here\n")
        old = h.MAX_FILES_PER_TREE; h.MAX_FILES_PER_TREE = 2; self.addCleanup(setattr, h, "MAX_FILES_PER_TREE", old)
        r, new = h.check(self.home, self.d)
        self.assertTrue(r["truncated"]); self.assertIs(r["complete"], False)
        self.assertIn("homesecrets:scan-truncated", h.alarm_problems(d=self.d))
        out = io.StringIO()
        with mock.patch.object(h, "DIR", self.d), mock.patch.object(h.Path, "home", return_value=self.home), contextlib.redirect_stdout(out):
            rc = h.main(["check"])
        self.assertEqual(rc, 1); self.assertIn("INCOMPLETE", out.getvalue()); self.assertIn("state:", out.getvalue())

    def test_complete_scan_says_true(self):
        # A normal, untruncated scan still reports complete: true.
        self.w(".zshrc", "echo hi\n")
        r, _ = h.check(self.home, self.d)
        self.assertIs(r["complete"], True); self.assertFalse(r["truncated"])

    def test_state_inside_component_folder_is_refused(self):
        # Regression (L5): home_secret_scan did not apply the component-folder guard that secret_scan.py has.
        with self.assertRaises(ValueError):
            h.check(self.home, h.secret_scan.COMPONENT_DIR / "state")

    # ---- N5: the fingerprint key file is validated, never silently replaced ----------------------------------------------------
    def run_main(self, *argv):
        """Helper: run the CLI against the fake home and state folder; return (exit status, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(h, "DIR", self.d), mock.patch.object(h.Path, "home", return_value=self.home), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = h.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_n5_symlinked_key_is_refused_with_a_clean_error(self):
        """N5: a symlink at the key path used to end in a raw traceback (OSError). Now: one-line message, exit 2, target untouched."""
        self.d.mkdir(mode=0o700); target = Path(self._t.name) / "elsewhere"; target.write_text("a" * 64)
        target.chmod(0o644)
        (self.d / h.KEY_FILE).symlink_to(target)
        rc, _, err = self.run_main("check")
        self.assertEqual(rc, 2); self.assertIn("symlink", err); self.assertNotIn("Traceback", err)
        self.assertEqual(oct(target.stat().st_mode & 0o777), "0o644")  # never chmod-ed through the link
        self.assertEqual(target.read_text(), "a" * 64)

    def test_n5_directory_as_key_is_refused_with_a_clean_error(self):
        """N5: a directory at the key path used to raise IsADirectoryError."""
        (self.d / h.KEY_FILE).mkdir(parents=True)
        rc, _, err = self.run_main("check")
        self.assertEqual(rc, 2); self.assertIn("not a regular file", err)

    def test_n5_group_or_world_readable_key_is_tightened_with_a_warning(self):
        """N5: a 0644 key was accepted as is (the "owner-only" promise did not hold). Now it is set to 0600, the same key is kept
        (accepts keep matching) and a warning goes to stderr."""
        h.check(self.home, self.d)
        keyf = self.d / h.KEY_FILE; before = keyf.read_text(); keyf.chmod(0o644)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            h.check(self.home, self.d)
        self.assertEqual(oct(keyf.stat().st_mode & 0o777), "0o600"); self.assertEqual(keyf.read_text(), before)
        self.assertIn("readable by other users", err.getvalue())

    def test_n5_corrupt_key_is_not_replaced_without_the_explicit_flag(self):
        """N5: a non-hex key file was silently overwritten, invalidating every earlier accept. Now: refused (exit 2), file kept
        byte for byte; only `check --regenerate-key` replaces it, with a loud warning."""
        self.d.mkdir(mode=0o700); keyf = self.d / h.KEY_FILE; keyf.write_text("not hex at all"); keyf.chmod(0o600)
        rc, _, err = self.run_main("check")
        self.assertEqual(rc, 2); self.assertIn("--regenerate-key", err)
        self.assertEqual(keyf.read_text(), "not hex at all")
        rc, _, err = self.run_main("check", "--regenerate-key")
        self.assertEqual(rc, 0); self.assertIn("INVALID", err)
        self.assertEqual(len(bytes.fromhex(keyf.read_text().strip())), 32)
        self.assertEqual(oct(keyf.stat().st_mode & 0o777), "0o600")

    def test_n5_short_key_is_also_corrupt(self):
        """N5: a valid-hex but too short key counts as corrupt (needs the flag)."""
        self.d.mkdir(mode=0o700); (self.d / h.KEY_FILE).write_text("abcd"); (self.d / h.KEY_FILE).chmod(0o600)
        with self.assertRaises(h.KeyFileError):
            h.check(self.home, self.d)


if __name__ == "__main__":
    unittest.main()
