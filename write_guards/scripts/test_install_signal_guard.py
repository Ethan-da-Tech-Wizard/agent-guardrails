"""Tests for install_signal_guard.sh using a throw-away PYTHONUSERBASE (the real user site folder is never touched).

Why: the installer adds a start-up hook to the user-site Python of one installation, so its safety properties (opt-in, reversible,
no code injection through odd paths, loud failure when the guard file disappears) are checked end to end with real
subprocesses. Skipped automatically when bash is missing.
Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'
"""
import os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

# Folder of this test and the installer script it exercises.
HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "install_signal_guard.sh"


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class InstallerTest(unittest.TestCase):
    """End-to-end tests of the installer's modes and failure handling."""

    def setUp(self):
        """Point PYTHONUSERBASE at a temporary folder so the real user site is never touched."""
        self.t = tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.base = Path(self.t.name) / "userbase"
        self.env = {**os.environ, "PYTHONUSERBASE": str(self.base)}
        self.env.pop("PYTHONNOUSERSITE", None)

    def run_script(self, *args, script=SCRIPT):
        """Run the installer (or a modified copy given as `script`) with `args`; return the CompletedProcess."""
        return subprocess.run(["bash", str(script), *args], capture_output=True, text=True, env=self.env)

    def site_files(self):
        """Return the sorted names of installer-created files under the temporary user base."""
        return sorted(p.name for p in self.base.rglob("write_guards_signal_guard*") if p.is_file() and not p.name.endswith(".pyc"))

    def test_default_is_status_and_changes_nothing(self):
        """Proves: running with no arguments only reports "not installed" and creates no files."""
        r = self.run_script()
        self.assertEqual(r.returncode, 0); self.assertIn("not installed", r.stdout)
        self.assertEqual(self.site_files(), [])

    def test_install_requires_yes(self):
        """Proves: --install alone is refused (exit 2) and writes nothing; explicit --yes is required."""
        r = self.run_script("--install")
        self.assertEqual(r.returncode, 2); self.assertEqual(self.site_files(), [])

    def test_install_verify_remove(self):
        """Proves: install creates the two hook files, plain Python still starts silently, the guard is active under unittest, remove cleans up."""
        r = self.run_script("--install", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.site_files(), ["write_guards_signal_guard.pth", "write_guards_signal_guard_boot.py"])
        out = subprocess.run([sys.executable, "-c", "print('plain start ok')"], capture_output=True, text=True, env=self.env)
        self.assertEqual(out.stdout.strip(), "plain start ok"); self.assertEqual(out.stderr, "")
        out = subprocess.run([sys.executable, "-c", "import os, unittest; os.kill(1, 0)"], capture_output=True, text=True, env=self.env)
        self.assertIn("signal_guard blocked", out.stderr)
        self.assertIn("installed", self.run_script("--status").stdout)
        self.assertEqual(self.run_script("--remove").returncode, 0)
        self.assertEqual(self.site_files(), [])

    def test_path_with_quote_cannot_inject(self):
        """Proves: a checkout path containing quote characters installs cleanly and cannot inject code into the boot file."""
        d = Path(self.t.name) / "we'ird \"dir\""; d.mkdir(); d.chmod(0o755)
        for f in ("install_signal_guard.sh", "signal_guard.py"):
            shutil.copy(str(HERE / f), str(d / f))
        r = self.run_script("--install", "--yes", script=d / "install_signal_guard.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = subprocess.run([sys.executable, "-c", "print('ok')"], capture_output=True, text=True, env=self.env)
        self.assertEqual((out.stdout.strip(), out.stderr), ("ok", ""))

    def copy_checkout(self, name):
        """Copy the installer and guard into <tmp>/<name>/scripts (a mini checkout) with private permissions; return the script path."""
        root = Path(self.t.name) / name; d = root / "scripts"; d.mkdir(parents=True)
        for f in ("install_signal_guard.sh", "signal_guard.py"):
            shutil.copy(str(HERE / f), str(d / f))
        root.chmod(0o755); d.chmod(0o755)
        return root, d, d / "install_signal_guard.sh"

    def test_refuses_group_or_world_writable_checkout(self):
        """Proves: if the guard file, its scripts folder or the checkout folder is group/world writable the install is refused (exit 2) and writes nothing."""
        for what in ("file", "scripts", "root"):
            for bits in (0o020, 0o002):
                with self.subTest(what=what, bits=oct(bits)):
                    root, d, script = self.copy_checkout("co_%s_%o" % (what, bits))
                    target = {"file": d / "signal_guard.py", "scripts": d, "root": root}[what]
                    target.chmod((target.stat().st_mode & 0o7777) | bits)
                    r = self.run_script("--install", "--yes", script=script)
                    self.assertEqual(r.returncode, 2, r.stderr)
                    self.assertIn("writable by group or others", r.stderr)
                    self.assertEqual(self.site_files(), [])

    def test_private_checkout_installs(self):
        """Proves: the same mini checkout with owner-only write installs fine (the check has no false positive)."""
        root, d, script = self.copy_checkout("good")
        self.assertEqual(self.run_script("--install", "--yes", script=script).returncode, 0)

    def test_boot_file_refuses_to_load_a_guard_made_writable_after_install(self):
        """Proves: if the checkout becomes group-writable after install, Python still starts but warns "NOT active" and does not load the guard."""
        root, d, script = self.copy_checkout("later")
        self.assertEqual(self.run_script("--install", "--yes", script=script).returncode, 0)
        d.chmod(0o775)
        out = subprocess.run([sys.executable, "-c", "import os, unittest; os.kill(1, 0)"], capture_output=True, text=True, env=self.env)
        self.assertIn("NOT active", out.stderr); self.assertNotIn("signal_guard blocked", out.stderr)

    def test_script_documents_the_code_execution_risk(self):
        """Proves: the installer's own header states the code-execution risk and the owner/permission requirement."""
        head = SCRIPT.read_text()
        self.assertIn("code execution", head); self.assertIn("not writable by group or others", head)

    def test_refuses_when_a_placeholder_token_is_present(self):
        """Proves: a copy of the installer containing an unfilled template token refuses to run and installs nothing."""
        d = Path(self.t.name) / "copy"; d.mkdir()
        shutil.copy(str(HERE / "signal_guard.py"), str(d / "signal_guard.py"))
        text = SCRIPT.read_text() + "\n# " + "{" + "{SOME_TOKEN}" + "}\n"
        (d / "install_signal_guard.sh").write_text(text)
        r = self.run_script("--install", "--yes", script=d / "install_signal_guard.sh")
        self.assertEqual(r.returncode, 2); self.assertIn("placeholder", r.stderr)
        self.assertEqual(self.site_files(), [])

    def test_loud_warning_if_guard_file_goes_missing(self):
        """Proves: if signal_guard.py is deleted after install, Python still starts but prints a "NOT active" warning to stderr."""
        d = Path(self.t.name) / "mv"; d.mkdir(); d.chmod(0o755)
        for f in ("install_signal_guard.sh", "signal_guard.py"):
            shutil.copy(str(HERE / f), str(d / f))
        self.assertEqual(self.run_script("--install", "--yes", script=d / "install_signal_guard.sh").returncode, 0)
        (d / "signal_guard.py").unlink()
        out = subprocess.run([sys.executable, "-c", "print('still runs')"], capture_output=True, text=True, env=self.env)
        self.assertEqual(out.stdout.strip(), "still runs")
        self.assertIn("NOT active", out.stderr)

    def test_remove_works_when_guard_file_is_missing(self):
        """Regression (B4): --remove used to exit 2 ("missing .../signal_guard.py") when signal_guard.py was gone, which is exactly
        when the start-up warning tells you to run it. Proves: after the guard is deleted, --remove exits 0 and deletes both
        files, --status still works, and the warning names both files so they can be removed by hand."""
        d = Path(self.t.name) / "gone"; d.mkdir(); d.chmod(0o755)
        for f in ("install_signal_guard.sh", "signal_guard.py"):
            shutil.copy(str(HERE / f), str(d / f))
        script = d / "install_signal_guard.sh"
        self.assertEqual(self.run_script("--install", "--yes", script=script).returncode, 0)
        (d / "signal_guard.py").unlink()
        warn = subprocess.run([sys.executable, "-c", "pass"], capture_output=True, text=True, env=self.env).stderr
        self.assertIn("write_guards_signal_guard_boot.py", warn); self.assertIn("write_guards_signal_guard.pth", warn)
        self.assertEqual(self.run_script("--status", script=script).returncode, 0)
        r = self.run_script("--remove", script=script)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.site_files(), [])
        # --install still insists on the guard file.
        self.assertEqual(self.run_script("--install", "--yes", script=script).returncode, 2)

    def test_works_through_a_symlink(self):
        """Regression (B4): started through a symlink the script looked for signal_guard.py next to the LINK. Proves: install,
        status and remove all work via a symlink located in another folder."""
        d = Path(self.t.name) / "real"; d.mkdir()
        for f in ("install_signal_guard.sh", "signal_guard.py"):
            shutil.copy(str(HERE / f), str(d / f))
        d.chmod(0o755)
        link_dir = Path(self.t.name) / "links"; link_dir.mkdir()
        link = link_dir / "isg.sh"; link.symlink_to(d / "install_signal_guard.sh")
        for args, code in ((("--install", "--yes"), 0), (("--status",), 0), (("--remove",), 0)):
            r = self.run_script(*args, script=link)
            self.assertEqual(r.returncode, code, (args, r.stderr))
        self.assertEqual(self.site_files(), [])


if __name__ == "__main__":
    unittest.main()
