#!/usr/bin/env python3
"""Tests for git_secret_hook.py, run against real throwaway git repositories.

Why it exists: the hook is a safety gate that decides whether a commit or push
may proceed, so its behaviour is proven end to end (real `git init`, real
staging, real hook scripts invoked by git) instead of with mocks.

Design / safety notes:
  * Every repository lives in a temporary directory that is removed after each
    test; nothing outside it is touched.
  * Global and system git configuration are pointed at the null device so a
    developer's own settings (for example a hooks path) cannot change results.
  * Fake credentials are assembled from fragments at runtime so that no
    credential-shaped literal sits in this file and trips other scanners.
  * Tests assert the hook never echoes a matched secret value, only a
    file:line, a finding type and a short fingerprint.

Usage:
    python3 -B -m unittest discover -s scripts -p 'test_*.py'
"""
import contextlib, io, os, subprocess, sys, tempfile, unittest
from unittest import mock
from pathlib import Path

# Synthetic AWS-shaped key id, assembled at runtime so no key-shaped literal sits in the file.
FIXTURE_KEY_A = "AKIA" + "IOSFODNN7" + "EXAMPLE"  # AWS documentation example id (placeholder-shaped on purpose)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import git_secret_hook as h

# Isolate from the machine's real global git config (it may set core.hooksPath).
# Child processes inherit these, so hook subprocesses are isolated as well.
os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
os.environ["GIT_CONFIG_SYSTEM"] = os.devnull

# Fake GitHub-style personal token (prefix + 36 chars), split so the literal never appears whole.
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
# Fake AWS-style access key id (AKIA + 16 upper-case chars); not a documentation placeholder, so it must be flagged.
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
# Absolute path of the hook script under test, used to run it as a subprocess.
HOOK = str(h.SELF)


def sh(repo, *a, check=True):
    """Run `git -C repo ...` with global/system config disabled; return the CompletedProcess (raises if check and non-zero)."""
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=check, env=env)


class T(unittest.TestCase):
    """Base fixture plus core pre-commit / pre-push / install tests; each test gets a fresh one-commit repo."""

    def setUp(self):
        """Create a temp dir holding a repo with one clean initial commit (made with --no-verify)."""
        self.t = tempfile.TemporaryDirectory(); self.r = Path(self.t.name).resolve()
        self.repo = self.r / "repo"; self.repo.mkdir()
        sh(self.repo, "init", "-q", "-b", "main")
        sh(self.repo, "config", "user.email", "t@t"); sh(self.repo, "config", "user.name", "t")
        sh(self.repo, "config", "commit.gpgsign", "false")
        self.w("README.md", "hello\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "init", "--no-verify")

    def tearDown(self):
        """Delete the temporary directory and everything in it."""
        self.t.cleanup()

    def w(self, name, txt):
        """Write txt to a file (creating parents) inside the test repo and return its path."""
        p = self.repo / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(txt); return p

    def run_hook(self, *args, stdin="", cwd=None):
        """Run the hook script as a subprocess (bytecode writing off) with optional stdin; return the result."""
        return subprocess.run([sys.executable, "-B", HOOK, *args], cwd=cwd or self.repo, input=stdin, capture_output=True, text=True)

    def stage(self, name, txt):
        """Write a file and `git add` it so it appears in the staged diff."""
        self.w(name, txt); sh(self.repo, "add", name)

    def test_clean_commit_passes(self):
        """A benign staged change is allowed (exit 0)."""
        self.stage("a.py", "x = 1\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_secret_blocked_never_echoed(self):
        """A staged token blocks the commit, is reported as file:line type, and its value is never printed."""
        self.stage("a.py", f"x = 1\nT = '{GH}'\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.py:2 github-token", r.stderr)
        self.assertNotIn(GH, r.stdout + r.stderr)
        self.assertNotIn(GH[4:], r.stdout + r.stderr)

    def test_only_added_lines_scanned(self):
        """A secret already in history that appears only as unchanged context in the diff is not re-flagged."""
        self.w("old.txt", f"{AWS}\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "o", "--no-verify")
        self.w("old.txt", f"{AWS}\nmore\n"); sh(self.repo, "add", "-A")  # secret line unchanged context
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_placeholder_and_allow_marker(self):
        """Documentation-style placeholders and lines carrying the allow marker are not blocked."""
        self.stage("a.md", "key = " + FIXTURE_KEY_A + "\nuse ghp_xxxx\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)
        self.stage("b.py", f"T = '{GH}'  # secret-scan:allow test fixture\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_env_blocked_example_allowed(self):
        """Sensitive file names (.env, private keys) block; .example/.sample variants do not."""
        self.stage(".env.example", "A=1\n"); self.stage("x.env.sample", "A=1\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)
        self.stage(".env", "A=1\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1); self.assertIn(".env:0 sensitive-file", r.stderr)
        sh(self.repo, "reset", "-q"); self.stage("keys/id_rsa", "x\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 1)

    def push(self, lref, lsha, rref, rsha, remote="origin"):
        """Feed the hook one line of git's pre-push stdin format (local ref/sha, remote ref/sha) and return the result."""
        return self.run_hook("pre-push", remote, "u", stdin=f"{lref} {lsha} {rref} {rsha}\n")

    def test_pre_push_ranges(self):
        """Pre-push scans only outgoing commits: update, new branch, no-op, deletion and clean history all behave correctly."""
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.stage("c.py", f"T = '{GH}'\n"); sh(self.repo, "commit", "-qm", "leak", "--no-verify")
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        r = self.push("refs/heads/main", tip, "refs/heads/main", base)
        self.assertEqual(r.returncode, 1); self.assertIn("c.py:1 github-token", r.stderr); self.assertNotIn(GH, r.stderr)
        r = self.push("refs/heads/feat", tip, "refs/heads/feat", "0" * 40)  # new branch
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.push("refs/heads/main", tip, "refs/heads/main", tip).returncode, 0)
        self.assertEqual(self.push("(delete)", "0" * 40, "refs/heads/old", tip).returncode, 0)
        self.assertEqual(self.push("refs/heads/main", base, "refs/heads/main", "0" * 40).returncode, 0)  # clean history

    def hooks(self):
        """Return the repo's .git/hooks directory."""
        return self.repo / ".git" / "hooks"

    def test_install_chain_idempotent_uninstall(self):
        """Install keeps a pre-existing hook chained, is idempotent, blocks secrets, and uninstall restores the original."""
        old = self.hooks() / "pre-commit"
        old.write_text("#!/bin/sh\necho OLDHOOK >> \"$(dirname \"$0\")/ran\"\nexit 0\n"); old.chmod(0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 0)
            first = (self.hooks() / "pre-commit").read_text()
            self.assertEqual(h.install([self.repo]), 0)
        self.assertEqual(first, (self.hooks() / "pre-commit").read_text())
        self.assertTrue((self.hooks() / "pre-commit.pre-secret-hook").exists())
        self.assertTrue(h.installed(self.repo))
        # clean commit runs old hook then passes; secret commit blocked
        self.w("ok.txt", "fine\n"); sh(self.repo, "add", "-A")
        self.assertEqual(sh(self.repo, "commit", "-qm", "ok", check=False).returncode, 0)
        self.assertIn("OLDHOOK", (self.hooks() / "ran").read_text())
        self.w("bad.txt", f"{GH}\n"); sh(self.repo, "add", "-A")
        r = sh(self.repo, "commit", "-qm", "bad", check=False)
        self.assertNotEqual(r.returncode, 0); self.assertNotIn(GH, r.stdout + r.stderr)
        sh(self.repo, "reset", "-q")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.uninstall([self.repo]), 0)
        self.assertIn("OLDHOOK", old.read_text())
        self.assertFalse((self.hooks() / "pre-commit.pre-secret-hook").exists())
        self.assertFalse((self.hooks() / "pre-push").exists())
        self.assertFalse(h.installed(self.repo))

    def test_installed_pre_push_blocks(self):
        """With the hooks installed, a real `git push` of a leaked key to a bare remote is refused."""
        with contextlib.redirect_stdout(io.StringIO()):
            h.install([self.repo])
        bare = self.r / "bare.git"; sh(self.r, "init", "-q", "--bare", str(bare))
        sh(self.repo, "remote", "add", "origin", str(bare))
        self.w("s.txt", f"{AWS}\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "s", "--no-verify")
        r = sh(self.repo, "push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0); self.assertIn("BLOCKED", r.stderr); self.assertNotIn(AWS, r.stderr)

    def test_install_refuses_foreign_hookspath(self):
        """Install refuses (exit 1) when core.hooksPath is set, since hooks there are managed elsewhere."""
        sh(self.repo, "config", "core.hooksPath", ".githooks")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 1)
        self.assertIn("core.hooksPath", err.getvalue())
        self.assertFalse((self.hooks() / "pre-commit").exists())

    def test_status_under(self):
        """`status --under DIR` lists repositories below DIR as installed or NOT installed."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            h.install([self.repo])
            other = self.r / "other"; other.mkdir(); sh(other, "init", "-q")
            h.status(["--under", str(self.r)])
        txt = out.getvalue()
        self.assertRegex(txt, r"installed\s+" + str(self.repo)); self.assertRegex(txt, r"NOT installed\s+" + str(other))

    def test_git_missing_warns_exit_zero(self):
        """With git absent from PATH the hook warns loudly but exits 0 so work is never wedged."""
        env = {**os.environ, "PATH": "/nonexistent"}
        r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0); self.assertIn("WARNING", r.stderr)


class LockAndIdentity(T):
    """Lock/unlock, MAC and hostname detection, and the environment-variable options (inherits the base fixture and tests)."""

    def test_mac_and_hostname_blocked_values_not_echoed(self):
        """A real-looking MAC address and a .local host name block the commit without echoing the MAC."""
        mac = ":".join(["02", "00", "5e", "12", "34", "56"])
        self.stage("m.txt", f"nic {mac}\n")
        r = self.run_hook("pre-commit"); self.assertEqual(r.returncode, 1)
        self.assertIn("mac-address", r.stderr); self.assertNotIn(mac, r.stderr)
        sh(self.repo, "reset", "-q")
        self.stage("h.txt", "ssh testbox" + ".local\n")
        r = self.run_hook("pre-commit"); self.assertEqual(r.returncode, 1); self.assertIn("local-hostname", r.stderr)

    def test_placeholder_mac_ok(self):
        """All-zero, all-same-byte and malformed MAC-like strings are treated as placeholders and allowed."""
        self.stage("m.txt", ":".join(["00"] * 6) + " " + ":".join(["aa"] * 6) + " xx:yy\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_lock_blocks_every_push_and_flags_remote(self):
        """Lock makes every push fail, reports a configured remote (exit 1), and unlock removes the lock."""
        bare = self.r / "bare.git"; sh(self.r, "init", "-q", "--bare", str(bare))
        self.assertEqual(self.run_hook("lock", str(self.repo)).returncode, 0)
        sh(self.repo, "remote", "add", "fake", str(bare))
        self.assertEqual(self.run_hook("lock", str(self.repo)).returncode, 1)  # remote present is reported
        p = sh(self.repo, "push", "fake", "main", check=False)
        self.assertNotEqual(p.returncode, 0); self.assertIn("FORBIDDEN", p.stderr)
        self.assertEqual(sh(bare, "branch", "--list").stdout.strip(), "")
        sh(self.repo, "remote", "remove", "fake")
        self.assertTrue(h.locked(self.repo))
        self.run_hook("unlock", str(self.repo)); self.assertFalse(h.locked(self.repo))


    def test_hostnames_from_roles_file_next_to_script(self):
        """Host names listed in a roles file beside the script (with alias and spelling variants) block, without being echoed."""
        import json as _j
        d = self.r / "inst"; d.mkdir()
        # Copy the scripts into a fresh dir so the roles file can sit beside them.
        for f in ("git_secret_hook.py", "secret_scan.py"):
            (d / f).write_text((Path(HOOK).parent / f).read_text())
        (d / "host_roles.json").write_text(_j.dumps({"hosts": {"testbox-alpha": {"aliases": ["test beta"]}}}))
        self.stage("a.txt", '"host-1": "TestBox_Alpha",\n')
        run = lambda: subprocess.run([sys.executable, "-B", str(d / "git_secret_hook.py"), "pre-commit"], cwd=self.repo, capture_output=True, text=True)
        r = run(); self.assertEqual(r.returncode, 1); self.assertNotIn("testbox", (r.stdout + r.stderr).lower())
        self.stage("a.txt", "fine\n"); self.assertEqual(run().returncode, 0)

    def test_skip_env_is_namespaced_and_loud(self):
        """Only the tool-specific skip variable disables the scan (a generic SKIP does not), and it prints a loud warning."""
        with contextlib.redirect_stdout(io.StringIO()):
            h.install([self.repo])
        self.w("bad.txt", f"{GH}\n"); sh(self.repo, "add", "-A")
        generic = {**os.environ, "SKIP": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        r = subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "x"], capture_output=True, text=True, env=generic)
        self.assertNotEqual(r.returncode, 0)  # a generic SKIP variable must NOT disable the scan
        own = {**os.environ, "SECRET_HOOK_SKIP": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        r = subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "x"], capture_output=True, text=True, env=own)
        self.assertEqual(r.returncode, 0); self.assertIn("SECRET_HOOK_SKIP", r.stderr); self.assertIn("SKIPPED", r.stderr)

    def test_local_host_ok_env(self):
        """A .local name listed in the allow-list environment variable is let through."""
        self.stage("h.txt", "ssh testbox" + ".local\n")
        env = dict(os.environ, SECRET_HOOK_LOCAL_HOST_OK="testbox" + ".local")
        r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)

    def test_env_redactions_file(self):
        """A redactions file named by environment variable supplies private host names that then block."""
        import json as _j
        f = self.r / "red.json"; f.write_text(_j.dumps({"hosts": ["secretbox-one"]}))
        self.stage("b.txt", "secretbox_one\n")
        env = dict(os.environ, SECRET_HOOK_REDACTIONS_FILE=str(f))
        r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 1)


class Regressions(unittest.TestCase):
    """Regressions: the hook must not be bypassable by file CONTENT (diff-parsing tricks) or by file NAMES (git quoting).

    Re-uses the fixture helpers of class T without inheriting (and so re-running) its tests.
    """
    setUp, tearDown, w, run_hook, stage, push = T.setUp, T.tearDown, T.w, T.run_hook, T.stage, T.push

    def commit_unverified(self, msg="x"):
        """Commit the staged changes with --no-verify (simulating a commit that skipped the hook); return the new HEAD sha."""
        sh(self.repo, "commit", "-qm", msg, "--no-verify")
        return sh(self.repo, "rev-parse", "HEAD").stdout.strip()

    def assert_blocked_both_ways(self, name, content, expect_in_err=None):
        """Stage `content` (bytes) as file `name`: pre-commit must block it; then commit with --no-verify and pre-push must block too."""
        p = self.repo / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(content)
        sh(self.repo, "add", "-A")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1, "pre-commit let it through: " + r.stderr)
        self.assertNotIn(GH, r.stdout + r.stderr)
        if expect_in_err:
            self.assertIn(expect_in_err, r.stderr)
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        tip = self.commit_unverified()
        r = self.push("refs/heads/main", tip, "refs/heads/main", base)
        self.assertEqual(r.returncode, 1, "pre-push let it through: " + r.stderr)
        self.assertNotIn(GH, r.stdout + r.stderr)

    # ---- B1: three ways an ADDED line used to be skipped -------------------------------------------------------------
    def test_added_line_that_looks_like_a_file_header_is_still_scanned(self):
        """B1a: content "++ <secret>" makes the diff line "+++ <secret>", which was taken for a file header and skipped."""
        self.assert_blocked_both_ways("a.txt", f"++ key={GH}\n".encode(), "github-token")

    def test_added_dev_null_line_does_not_null_the_path_of_later_lines(self):
        """B1b: content "++ /dev/null" (diff line "+++ /dev/null") used to blank the path so the rest of the hunk was skipped."""
        self.assert_blocked_both_ways("b.txt", f"++ /dev/null\nT = '{GH}'\n".encode(), "b.txt:2 github-token")

    def test_lone_cr_and_other_unicode_line_separators_do_not_hide_a_secret(self):
        """B1c: str.splitlines() also splits on CR, VT, FF, FS, GS, RS, NEL, LS, PS, which cut an added line in two so the
        second fragment no longer started with "+" and was dropped. Proves each separator is harmless in pre-commit AND pre-push."""
        seps = {"CR": "\r", "VT": "\x0b", "FF": "\x0c", "FS": "\x1c", "GS": "\x1d", "RS": "\x1e",
                "NEL": "\u0085", "LS": "\u2028", "PS": "\u2029", "CRLF": "\r\n"}
        for i, (label, sep) in enumerate(seps.items()):
            with self.subTest(sep=label):
                self.assert_blocked_both_ways(f"sep{i}.txt", f"foo{sep}key={GH}\n".encode("utf-8"))

    def test_clean_content_with_odd_separators_and_header_lookalikes_is_not_blocked(self):
        """The fix must not create false positives: header look-alikes, "/dev/null" and odd separators with no secret pass."""
        self.stage("ok.txt", "++ /dev/null\n++ b/other\n-- x\nfoo\rbar\x0cbaz\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_scan_patch_state_machine_directly(self):
        """scan_patch units: hunk counts rule, a "+++" inside a hunk is content, a real "+++" outside is a header, "\\ No newline"
        does not shift line numbers, unknown path is reported rather than skipped, commit markers switch the label."""
        sha = "a" * 40
        patch = "\n".join([
            f"@@secret-hook-commit {sha}",
            "",
            "diff --git a/f.py b/f.py", "--- a/f.py", "+++ b/f.py",
            "@@ -1,0 +5,3 @@",
            "+ok", "+++ /dev/null", f"+++ {GH}",
            "@@ -9 +9 @@", "-old", f"+{GH}", "\\ No newline at end of file",
            "diff --git a/g.py b/g.py", "--- /dev/null", "+++ b/g.py", "@@ -0,0 +1 @@", f"+{GH}", ""])
        got = [(f["commit"], f["file"], f["line"]) for f in h.scan_patch(patch)]
        self.assertEqual(got, [(sha, "f.py", 7), (sha, "f.py", 9), (sha, "g.py", 1)])
        # no header at all: still scanned, reported under a placeholder name
        self.assertEqual([f["file"] for f in h.scan_patch(f"@@ -0,0 +1 @@\n+{GH}\n")], ["(unknown)"])
        # deleted file: only removed lines, nothing to scan
        self.assertEqual(h.scan_patch(f"--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-{GH}\n"), [])

    def test_pre_push_input_split_only_on_lf(self):
        """push_ranges must not split git's stdin on exotic separators either."""
        a, b = "1" * 40, "2" * 40
        self.assertEqual(len(h.push_ranges(f"refs/heads/m {a} refs/heads/m {b}\n", "origin")), 1)

    # ---- B2: git-quoted file names in pre-push ------------------------------------------------------------------------
    def test_pre_push_blocks_sensitive_names_that_git_quotes(self):
        """B2: plain `git log --name-only` C-quotes names holding TAB, quote, backslash or newline (even with core.quotepath=off),
        so ".env" became `.env"` and slipped through pre-push. Proves each such name is blocked in pre-commit and in pre-push."""
        for i, d in enumerate(("tab\there", 'quo"te', "back\\slash", "new\nline")):
            with self.subTest(dirname=d):
                self.assert_blocked_both_ways(f"{d}/.env" if i % 2 == 0 else f"{d}/id_rsa", b"A=1\n", "sensitive-file")

    def test_unquote_path(self):
        """unquote_path decodes git's C-style quoting (escapes and UTF-8 octal) and leaves plain names alone."""
        self.assertEqual(h.unquote_path('"tab\\there/.env"'), "tab\there/.env")
        self.assertEqual(h.unquote_path('"a\\"b\\\\c"'), 'a"b\\c')
        self.assertEqual(h.unquote_path('"caf\\303\\251"'), "caf\u00e9")
        self.assertEqual(h.unquote_path("plain name\t"), "plain name")
        self.assertEqual(h.unquote_path('"unterminated'), '"unterminated')

    def test_name_with_odd_characters_is_reported_and_secret_still_found(self):
        """A quoted file name must not break the content scan's file attribution either."""
        self.stage("tab\there.txt", f"x\nT='{GH}'\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1); self.assertIn("tab\there.txt:2 github-token", r.stderr)

    # ---- L6: user diff prefix settings -------------------------------------------------------------------------------
    def test_diff_prefix_config_does_not_mangle_reported_names(self):
        """L6: diff.noprefix / diff.mnemonicPrefix changed the header shape ("i/" or none) so names were mangled. Proves the
        reported name is exact under both settings."""
        for key in ("diff.noprefix", "diff.mnemonicPrefix"):
            with self.subTest(cfg=key):
                sh(self.repo, "reset", "-q", "--hard"); sh(self.repo, "clean", "-qfd")
                sh(self.repo, "config", key, "true")
                self.stage("src/mod.py", f"T='{GH}'\n")
                r = self.run_hook("pre-commit")
                self.assertIn("src/mod.py:1 github-token", r.stderr, r.stderr)
                sh(self.repo, "config", "--unset", key)

    # ---- M3: identity fingerprints -----------------------------------------------------------------------------------
    def test_identity_findings_print_no_fingerprint(self):
        """M3: a hash of a MAC address or host name can be brute-forced back to the value, so identity findings print "-"."""
        mac = ":".join(["02", "00", "5e", "12", "34", "56"])
        import hashlib
        full = hashlib.sha256(mac.lower().encode()).hexdigest()
        self.stage("m.txt", f"nic {mac} and testbox" + ".local\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1)
        self.assertIn("m.txt:1 mac-address -", r.stderr); self.assertIn("m.txt:1 local-hostname -", r.stderr)
        self.assertNotIn(full[:10], r.stderr); self.assertNotIn(mac, r.stderr)
        self.assertEqual({fp for _, fp in h.scan_identity(f"{mac}")}, {"-"})

    # ---- L7: hook files are replaced, never written through a symlink -------------------------------------------------
    def test_install_does_not_write_through_a_symlinked_hook(self):
        """L7: if .git/hooks/pre-commit is a symlink to a file that carries our marker, install must replace the link, not edit the target."""
        hooks = self.repo / ".git" / "hooks"; hooks.mkdir(exist_ok=True)
        target = self.r / "elsewhere.txt"; target.write_text(h.MARKER + "\nOLD\n")
        (hooks / "pre-commit").symlink_to(target)
        with contextlib.redirect_stdout(io.StringIO()):
            h.install([self.repo])
        self.assertEqual(target.read_text(), h.MARKER + "\nOLD\n")
        self.assertFalse((hooks / "pre-commit").is_symlink())
        self.assertIn("pre-commit", (hooks / "pre-commit").read_text())


class HardeningRegressions(unittest.TestCase):
    """Regressions for binary files, diff-config overrides, URL push targets, commit messages, file names, host names and install safety. Each test fails on the code that existed before the fix.

    Re-uses the fixture helpers of class T without inheriting (and so re-running) its tests.
    """
    setUp, tearDown, w, run_hook, stage, push = T.setUp, T.tearDown, T.w, T.run_hook, T.stage, T.push
    assert_blocked_both_ways = Regressions.assert_blocked_both_ways
    commit_unverified = Regressions.commit_unverified

    # ---- H1: content git treats as binary must still be scanned ----------------------------------------------------------
    def test_h1_file_with_a_nul_byte_is_scanned(self):
        """H1: one NUL byte made git print "Binary files differ" (no hunks), so a token in the file committed and pushed."""
        self.assert_blocked_both_ways("conf.dat", b"head\0\nT=" + GH.encode() + b"\n", "github-token")

    def test_h1_minus_diff_attribute_is_scanned(self):
        """H1: a `-diff` attribute (lockfiles, generated files) also hid the content; --text overrides it."""
        self.w(".gitattributes", "*.lock -diff\n"); sh(self.repo, "add", "-A"); self.commit_unverified("attrs")
        self.assert_blocked_both_ways("deps.lock", f"T={GH}\n".encode(), "github-token")

    def test_h1_textconv_filter_cannot_rewrite_the_scanned_text(self):
        """H1: a repo-local diff.textconv driver must not change what is scanned (--no-textconv)."""
        sh(self.repo, "config", "diff.hide.textconv", "true")
        self.w(".gitattributes", "*.cfg diff=hide\n"); sh(self.repo, "add", "-A"); self.commit_unverified("attrs")
        self.assert_blocked_both_ways("a.cfg", f"T={GH}\n".encode(), "github-token")

    # ---- M1: user diff configuration must not hide added lines -----------------------------------------------------------
    def test_m1_suppress_blank_empty_with_inter_hunk_context(self):
        """M1: diff.suppressBlankEmpty + diff.interHunkContext made git emit blank context lines as "" inside a merged hunk; the
        old parser dropped the hunk and ignored the following added line."""
        sh(self.repo, "config", "diff.suppressBlankEmpty", "true"); sh(self.repo, "config", "diff.interHunkContext", "5")
        self.w("n.txt", "l1\n\nl3\n"); sh(self.repo, "add", "-A"); self.commit_unverified("base")
        self.assert_blocked_both_ways("n.txt", f"l1x\n\nl3\nT={GH}\n".encode(), "github-token")

    def test_m1_parser_treats_empty_line_as_context_and_fails_closed(self):
        """M1: scan_patch itself (no git): an empty line inside a hunk is context; a "+" line after a malformed hunk is still scanned."""
        patch = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1,3 +1,4 @@\n-old\n+new\n\n l3\n+T=" + GH + "\n"
        self.assertEqual([(f["file"], f["line"], f["type"]) for f in h.scan_patch(patch)], [("f", 4, "github-token")])
        broken = "diff --git a/f b/f\n+++ b/f\n@@ -1,2 +1,2 @@\n-x\n?? junk\n+T=" + GH + "\n"
        self.assertEqual([f["type"] for f in h.scan_patch(broken)], ["github-token"])

    # ---- M2: a URL push must not skip commits that exist on other remotes ------------------------------------------------
    def test_m2_url_push_scans_commits_present_on_another_remote(self):
        """M2: `git push <URL>` made the hook exclude commits reachable from ANY remote, so a leaked commit that had been pushed to a
        private remote went out to a different URL unscanned. A configured remote NAME keeps the exclusion."""
        self.stage("s.txt", f"T={GH}\n"); tip = self.commit_unverified("leak")
        bare = self.r / "priv.git"; sh(self.r, "init", "-q", "--bare", str(bare))
        sh(self.repo, "remote", "add", "priv", str(bare)); sh(self.repo, "push", "-q", "priv", "main", "--no-verify")
        new_branch = f"refs/heads/main {tip} refs/heads/main {'0' * 40}\n"
        by_name = self.run_hook("pre-push", "priv", str(bare), stdin=new_branch)
        self.assertEqual(by_name.returncode, 0, by_name.stderr)             # already on that very remote: nothing new leaves
        for target in ("https://example.invalid/x.git", "file://" + str(bare), "git@example.invalid:x.git", str(bare)):
            r = self.run_hook("pre-push", target, target, stdin=new_branch)
            self.assertEqual(r.returncode, 1, target + ": " + r.stderr)
            self.assertNotIn(GH, r.stdout + r.stderr)

    # ---- M3: commit messages are scanned at push --------------------------------------------------------------------------
    def test_m3_token_in_a_commit_message_blocks_the_push(self):
        """M3: a token pasted into a commit message used to push with rc 0. Reported as (commit-message), never echoed."""
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        sh(self.repo, "commit", "-q", "--allow-empty", "--no-verify", "-m", "oops " + GH)
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        r = self.push("refs/heads/main", tip, "refs/heads/main", base)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("(commit-message):1 github-token", r.stderr); self.assertNotIn(GH, r.stdout + r.stderr)

    # ---- M4 / M5: sensitive file names ------------------------------------------------------------------------------------
    def test_m4_sensitive_file_name_list_is_broad_and_has_no_obvious_false_positives(self):
        """M4: these names were all committed without a block before."""
        for bad in (".git-credentials", ".pgpass", ".npmrc", ".pypirc", ".envrc", "_netrc", ".htpasswd", "id_rsa.bak", "id_rsa_old",
                    "ssh/id_ed25519-backup", "secrets.json", "service-account.json", ".aws/credentials", "home/.aws/credentials",
                    "infra/terraform.tfstate", "x.tfstate", "a.jks", "vault.kdbx", "kubeconfig", ".kube/config", ".docker/config.json",
                    "secring.gpg", "tls/server.pem", "a.p12", "k.key", "redactions.json", "x/host_roles.json", "retired_hosts.json"):
            self.assertTrue(h.sensitive_name(bad), bad)
        for ok in ("id_rsa.pub", "keys/id_ed25519.pub", ".env.example", ".npmrc.example", "credentials", "config", "config.json",
                   "src/aws/credentials.md", "docs/credentials.md", "README.md", "monkey.py", "identity.txt", "kube/config", "settings.json"):
            self.assertFalse(h.sensitive_name(ok), ok)

    def test_m4_allow_names_env_exempts_a_reviewed_file(self):
        """M4: a project .npmrc that holds only registry settings can be exempted by base name (SECRET_HOOK_ALLOW_NAMES)."""
        self.assertTrue(h.sensitive_name(".npmrc"))
        with mock.patch.object(h, "ALLOW_NAMES", {".npmrc"}):
            self.assertFalse(h.sensitive_name("pkg/.npmrc"))

    def test_m4_pre_commit_blocks_a_pgpass_and_an_aws_credentials_file(self):
        """M4 end to end: staged .pgpass and .aws/credentials block the commit by name."""
        self.stage(".pgpass", "h:5432:d:u:p\n"); self.stage("x/.aws/credentials", "[default]\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1); self.assertIn(".pgpass:0 sensitive-file", r.stderr); self.assertIn(".aws/credentials:0 sensitive-file", r.stderr)

    # ---- L4: .local file names are not host names -------------------------------------------------------------------------
    def test_l4_env_local_and_settings_local_json_are_not_hosts(self):
        """L4: prose mentioning the dotenv local-override file or a local settings JSON file blocked a commit as a local-hostname."""
        self.stage("README.md", "Copy .env" + ".local and edit settings" + ".local.json (also app" + ".local.yml).\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(h.scan_identity("ssh box1" + ".local."))   # a real mDNS name at the end of a sentence still counts

    # ---- L5 / L6: install-time safety ------------------------------------------------------------------------------------
    def test_l5_status_reports_inactive_when_hookspath_is_set_after_install(self):
        """L5: core.hooksPath set after install silently disables the hooks; status must say so instead of "installed"."""
        with contextlib.redirect_stdout(io.StringIO()):
            h.install([self.repo])
        sh(self.repo, "config", "core.hooksPath", ".githooks")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            h.status([str(self.repo)])
        self.assertIn("INACTIVE", out.getvalue()); self.assertIn("core.hooksPath", out.getvalue())

    def test_l6_install_refuses_a_symlinked_hooks_folder(self):
        """L6: with .git/hooks -> shared folder, install used to write (and uninstall remove) hooks in the shared target."""
        shared = self.r / "shared"; shared.mkdir()
        hooks = self.repo / ".git" / "hooks"
        if hooks.is_dir() and not hooks.is_symlink():
            import shutil; shutil.rmtree(hooks)
        hooks.symlink_to(shared)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 1)
            self.assertEqual(h.lock(self.repo), 1)
        self.assertIn("symlink", err.getvalue())
        self.assertEqual(list(shared.iterdir()), [])
        self.assertTrue(hooks.is_symlink())


    # ---- N1: type changes (T) must be scanned and name-checked, at commit AND at push ------------------------------------
    def _type_change_blocked(self, name, before, after, expect):
        """Helper: commit `name` in the shape `before` ("link:<target>" or "file:<text>") without the hook, replace it with the
        shape `after`, stage it, and require BOTH pre-commit and pre-push to block with `expect` in the report."""
        p = self.repo / name
        def put(shape):
            """Create `name` as a symlink or a regular file according to `shape`."""
            if p.is_symlink() or p.exists():
                p.unlink()
            kind, _, val = shape.partition(":")
            if kind == "link":
                os.symlink(val, p)
            else:
                p.write_text(val)
        put(before); sh(self.repo, "add", "-A"); self.commit_unverified("before")
        put(after); sh(self.repo, "add", "-A")
        # sanity: git really sees this as a type change (status T), otherwise the test would not exercise the T filter
        self.assertIn("T", sh(self.repo, "diff", "--cached", "--name-status").stdout.split()[0])
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1, "pre-commit let a type change through: " + r.stderr)
        self.assertIn(expect, r.stderr); self.assertNotIn(GH, r.stdout + r.stderr)
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        tip = self.commit_unverified("type change")
        r = self.push("refs/heads/main", tip, "refs/heads/main", base)
        self.assertEqual(r.returncode, 1, "pre-push let a type change through: " + r.stderr)
        self.assertIn(expect, r.stderr); self.assertNotIn(GH, r.stdout + r.stderr)

    def test_n1_symlink_replaced_by_dot_env_file_is_name_blocked(self):
        """N1: a committed symlink named .env replaced by a regular .env file is a type change (T). The old ACMR filter dropped it,
        so the sensitive-file rule never ran at commit or at push and the file reached the remote."""
        self._type_change_blocked(".env", "link:somewhere", "file:A=1\n", ".env:0 sensitive-file")

    def test_n1_token_in_symlink_to_regular_file_change_is_scanned(self):
        """N1: symlink -> regular file whose content holds a token: the old pre-commit filter skipped the type change, so the
        content was never scanned at commit (push was only caught by the unfiltered log)."""
        self._type_change_blocked("sl", "link:target", f"file:T={GH}\n", "github-token")

    def test_n1_token_in_regular_file_to_symlink_target_is_scanned(self):
        """N1: the reverse type change, regular file -> symlink whose TARGET TEXT is a token (git stores the target as the blob)."""
        self._type_change_blocked("rl", "file:plain\n", "link:" + GH, "github-token")

    # ---- N2: a root commit must be scanned at push even with log.showRoot=false ----------------------------------------------
    def test_n2_root_commit_scanned_with_show_root_false(self):
        """N2: with log.showRoot=false `git log -p` prints no diff for a root commit, so a first commit made without the hook
        (innocent file name, token inside) pushed with rc 0. The scan now passes --root."""
        other = self.r / "root2"; other.mkdir()
        sh(other, "init", "-q", "-b", "main"); sh(other, "config", "user.email", "t@t"); sh(other, "config", "user.name", "t")
        sh(other, "config", "commit.gpgsign", "false"); sh(other, "config", "log.showRoot", "false")
        (other / "notes.txt").write_text(f"T={GH}\n"); sh(other, "add", "-A"); sh(other, "commit", "-qm", "root", "--no-verify")
        tip = sh(other, "rev-parse", "HEAD").stdout.strip()
        r = self.run_hook("pre-push", "origin", "x", stdin=f"refs/heads/main {tip} refs/heads/main {'0' * 40}\n", cwd=other)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("github-token", r.stderr); self.assertNotIn(GH, r.stdout + r.stderr)

    # ---- N3: more credential file names ---------------------------------------------------------------------------------------
    def test_n3_more_credential_names_block_and_templates_stay_allowed(self):
        """N3: .env-production / .env_prod, production.env, backups of key files and any-suffix id_rsa were not blocked."""
        for bad in (".env-production", ".env_prod", "cfg/.env-staging", "production.env", "x.pem.bak", "private.key.old", "a.p12.orig",
                    "secrets.json.bak", "id_rsa2", "id_ed25519_work", "id_rsa~", ".env" + ".local" + ".bak", "k.key.bak.old"):
            self.assertTrue(h.sensitive_name(bad), bad)
        for ok in (".env.example", ".env.sample", ".env-example", ".env_sample", "prod.env.template", "id_rsa.pub", "id_ed25519.pub",
                   "notes.bak", "readme.old", "environment.md", ".environment", "monkey.bak", "x.pem.example"):
            self.assertFalse(h.sensitive_name(ok), ok)

    def test_n3_pre_commit_blocks_dash_env_and_pem_backup(self):
        """N3 end to end: the staged names are reported as sensitive-file."""
        self.stage(".env-production", "A=1\n"); self.stage("cert.pem.bak", "x\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1)
        self.assertIn(".env-production:0 sensitive-file", r.stderr); self.assertIn("cert.pem.bak:0 sensitive-file", r.stderr)

    # ---- N4: Python attribute / call uses are not host names; *.local.lan is -----------------------------------------------
    def test_n4_threading_local_and_similar_are_not_hosts(self):
        """N4: a threading-local factory call failed a commit as local-hostname. Calls, subscripts, assignments and import paths pass."""
        loc = ".local"  # assembled so this file itself holds no bare host-shaped literal
        for line in ("x = threading" + loc + "()", "ctx = werkzeug" + loc + " (1)", "v = cfg" + loc + "[0]", "self" + loc + " = 1",
                     "from werkzeug" + loc + " import Local", "import app" + loc, "x = threading" + loc + "()  # per-thread"):
            self.assertEqual([k for k, _ in h.scan_identity(line) if k == "local-hostname"], [], line)

    def test_n4_real_hosts_still_block_including_local_lan(self):
        """N4 decision: a .local host still blocks in ssh/URL/port/sentence-end uses, and so does the same name with a "lan" tail;
        that spelling followed by a file extension stays exempt."""
        loc = ".local"
        for line in ("ssh me@box1" + loc, "http://box1" + loc + "/x", "box1" + loc + ":22", "ping box1" + loc + ".",
                     "ssh box1" + loc + ".lan", "host = box1" + loc + ".lan", "x == box1" + loc):
            self.assertTrue([k for k, _ in h.scan_identity(line) if k == "local-hostname"], line)
        self.assertEqual(h.scan_identity("see app" + loc + ".lan.json"), [])

    # ---- N7: status of a symlinked hooks folder -------------------------------------------------------------------------------
    def test_n7_status_reports_a_symlinked_hooks_folder_as_unsafe(self):
        """N7: status said "NOT installed" for a repo whose .git/hooks is a symlink (install refuses it). It must say UNSAFE."""
        shared = self.r / "shared7"; shared.mkdir()
        hooks = self.repo / ".git" / "hooks"
        if hooks.is_dir() and not hooks.is_symlink():
            import shutil; shutil.rmtree(hooks)
        hooks.symlink_to(shared)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            h.status([str(self.repo)])
        self.assertIn("UNSAFE", out.getvalue()); self.assertIn("symlink", out.getvalue()); self.assertNotIn("NOT installed", out.getvalue())


class DistroWordTests(unittest.TestCase):
    """A distro name that is also a machine name: prose is fine, a real host token still blocks."""
    def setUp(self):
        """Replace the private-host loader with a fixed list so no files are consulted."""
        self._old = h._private_hosts
        h._private_hosts = lambda: ["ubuntu", "somehostx"]

    def tearDown(self):
        """Restore the real private-host loader."""
        h._private_hosts = self._old

    def hits(self, line):
        """Return the private-hostname findings (type only) for one line of text."""
        return [t for t, _ in h.scan_identity(line) if t == "private-hostname"]

    def test_distro_word_in_prose_is_not_a_host(self):
        """Capitalised distro names in ordinary prose or tables are not flagged."""
        # Each line must produce zero hits.
        for line in ("Targets Ubuntu 24.04 and Ubuntu 22.04 LTS", "| Ubuntu | Linux distribution |",
                     "Debian-based; Ubuntu Linux package names differ", "the Ubuntu Project mirrors"):
            self.assertEqual(self.hits(line), [], line)

    def test_real_host_token_still_blocks(self):
        """Lowercase tokens or ones next to host words (ssh, @, host:, server...) are still flagged."""
        # Each line must produce at least one hit.
        for line in ("ssh ubuntu", "ping ubuntu now", "user@ubuntu", "host: ubuntu", "the Ubuntu server", "Ubuntu machine",
                     "ubuntu", "name=ubuntu"):
            self.assertTrue(self.hits(line), line)

    def test_other_private_host_always_blocks(self):
        """A non-distro private name is flagged regardless of case or context."""
        self.assertTrue(self.hits("deploy to SomeHostX tonight"))

    def test_longer_word_containing_distro_is_not_a_host(self):
        """A longer word that merely contains a distro name (as a domain label) is not a host."""
        self.assertEqual(self.hits("registry.ubuntuproject.org"), [])


if __name__ == "__main__":
    unittest.main()
