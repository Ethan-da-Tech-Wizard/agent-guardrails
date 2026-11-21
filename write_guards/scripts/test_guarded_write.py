"""guarded_write: two real writers race on one file; exactly one wins, the other gets ConcurrentModification and writes nothing.

Why: the compare-and-swap guarantee is only meaningful if it holds under real concurrency, so besides unit checks there are
a threaded race and a two-process race through the command line.
Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'  (uses only a temporary directory, removed afterwards).
"""
import os, subprocess, sys, tempfile, threading, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import guarded_write as gw

# Absolute path of the script under test, used to launch real subprocesses.
SCRIPT = str(Path(__file__).resolve().parent / "guarded_write.py")



class T(unittest.TestCase):
    """Compare-and-swap behaviour of guarded_write, in-process, threaded and across real processes."""

    def setUp(self):
        """Create a temp directory holding a shared file with known content."""
        self.td = tempfile.TemporaryDirectory(); self.addCleanup(self.td.cleanup)
        self.f = Path(self.td.name) / "shared.py"
        self.f.write_text("base\n")

    def test_write_succeeds_when_unchanged_and_returns_new_hash(self):
        """Proves: with a matching hash the write lands, the returned hash is the new content's, and no temp file is left."""
        h = gw.sha256_of(self.f)
        new = gw.write_if_unchanged(self.f, b"mine\n", h)
        self.assertEqual(self.f.read_text(), "mine\n")
        self.assertEqual(new, gw.sha256_of(self.f))
        self.assertEqual([p.name for p in Path(self.td.name).iterdir()], ["shared.py"])   # no temp litter

    def test_stale_hash_is_refused_and_nothing_is_written(self):
        """Proves: if the file changed after it was hashed the write is refused and the other writer's content survives."""
        h = gw.sha256_of(self.f)
        self.f.write_text("someone else\n")
        with self.assertRaises(gw.ConcurrentModification):
            gw.write_if_unchanged(self.f, b"mine\n", h)
        self.assertEqual(self.f.read_text(), "someone else\n")

    def test_two_threads_same_expected_hash_exactly_one_wins(self):
        """Proves: two threads holding the same hash cannot both succeed; one writes, one gets a conflict."""
        h = gw.sha256_of(self.f)
        results, barrier = [], threading.Barrier(2)

        def writer(tag):
            """Thread body: start together with the other writer, then try the guarded write and record the outcome."""
            barrier.wait()
            try:
                gw.write_if_unchanged(self.f, ("from %s\n" % tag).encode(), h); results.append((tag, "ok"))
            except gw.ConcurrentModification:
                results.append((tag, "conflict"))
        ts = [threading.Thread(target=writer, args=(t,)) for t in "AB"]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sorted(r[1] for r in results), ["conflict", "ok"])
        winner = next(t for t, r in results if r == "ok")
        self.assertEqual(self.f.read_text(), "from %s\n" % winner)

    def test_two_real_processes_race_through_the_cli(self):
        """Proves: two real CLI processes with the same expected hash end with exit codes 0 and 3, and one writer's text in the file."""
        h = subprocess.run([sys.executable, SCRIPT, "hash", str(self.f)], capture_output=True, text=True).stdout.strip()
        procs = [subprocess.Popen([sys.executable, SCRIPT, "write", str(self.f), "--expect", h], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for i, p in enumerate(procs):
            p.stdin.write(("writer %d\n" % i).encode()); p.stdin.close()
        codes = sorted(p.wait() for p in procs)
        for p in procs:
            p.stdout.close(); p.stderr.close()
        self.assertEqual(codes, [0, 3])                    # one wrote, one got CONCURRENT MODIFICATION
        self.assertIn(self.f.read_text(), ("writer 0\n", "writer 1\n"))

    def test_expect_missing_creates_once_and_refuses_an_existing_file(self):
        """Proves: expecting "missing" creates a new file once, and a second create-only write is refused."""
        new = Path(self.td.name) / "new.txt"
        gw.write_if_unchanged(new, b"x", None)
        with self.assertRaises(gw.ConcurrentModification):
            gw.write_if_unchanged(new, b"y", None)
        self.assertEqual(new.read_text(), "x")

    def test_symlink_target_is_refused(self):
        """Proves: writing through a symlink raises ValueError instead of modifying the link's target."""
        link = Path(self.td.name) / "link.py"; link.symlink_to(self.f)
        with self.assertRaises(ValueError):
            gw.write_if_unchanged(link, b"z", gw.sha256_of(self.f))

    def test_file_mode_is_preserved(self):
        """Proves: replacing a file keeps its permission bits (0750 here), not the temp file's restrictive default."""
        self.f.chmod(0o750)
        gw.write_if_unchanged(self.f, b"m", gw.sha256_of(self.f))
        self.assertEqual(self.f.stat().st_mode & 0o777, 0o750)


class LockFolderSafety(unittest.TestCase):
    """A pre-existing lock folder is never trusted: wrong mode, wrong owner or a symlink must fail loudly and write nothing."""

    def setUp(self):
        """Point the system temp folder at a private temp dir so the real lock folder is untouched; make a target file."""
        self.td = tempfile.TemporaryDirectory(); self.addCleanup(self.td.cleanup)
        self.tmp = Path(self.td.name) / "tmp"; self.tmp.mkdir(mode=0o700)
        self._old = tempfile.tempdir; tempfile.tempdir = str(self.tmp); self.addCleanup(setattr, tempfile, "tempdir", self._old)
        self.f = Path(self.td.name) / "shared.txt"; self.f.write_text("base\n")
        self.lockdir = self.tmp / ("write-guards-locks-%d" % os.getuid())

    def attempt(self):
        """Try a guarded write of b"new"; return nothing (raises if the lock folder is refused)."""
        gw.write_if_unchanged(self.f, b"new\n", gw.sha256_of(self.f))

    def test_fresh_folder_is_created_private_and_works(self):
        """Proves: with no folder present one is created with mode 700 and the write succeeds."""
        self.attempt()
        self.assertEqual(self.f.read_text(), "new\n")
        self.assertEqual(self.lockdir.stat().st_mode & 0o777, 0o700)

    def test_existing_private_folder_is_accepted(self):
        """Proves: a pre-existing folder that is ours with mode 700 is used normally (no false alarm)."""
        self.lockdir.mkdir(mode=0o700); self.attempt()
        self.assertEqual(self.f.read_text(), "new\n")

    def test_group_or_world_accessible_folder_is_refused(self):
        """Proves: an existing folder with group/other bits (755, 770, 707) is refused and the target is unchanged."""
        for mode in (0o755, 0o770, 0o707):
            with self.subTest(mode=oct(mode)):
                if self.lockdir.exists():
                    self.lockdir.chmod(0o700); self.lockdir.rmdir()
                self.lockdir.mkdir(); self.lockdir.chmod(mode)
                with self.assertRaises(gw.UnsafeLockDirectory) as cm:
                    self.attempt()
                self.assertIn("mode", str(cm.exception))
                self.assertEqual(self.f.read_text(), "base\n")
                self.assertEqual(list(self.lockdir.iterdir()), [])        # no lock file was created in the unsafe folder

    def test_symlinked_folder_is_refused(self):
        """Proves: a symlink at the lock-folder name (pointing at a private real folder) is refused, and nothing is created behind it."""
        real = Path(self.td.name) / "elsewhere"; real.mkdir(mode=0o700)
        self.lockdir.symlink_to(real)
        with self.assertRaises(gw.UnsafeLockDirectory):
            self.attempt()
        self.assertEqual(list(real.iterdir()), []); self.assertEqual(self.f.read_text(), "base\n")

    def test_plain_file_at_the_folder_name_is_refused(self):
        """Proves: a regular file squatting on the lock-folder name is refused rather than crashing obscurely."""
        self.lockdir.write_text("x")
        with self.assertRaises(gw.UnsafeLockDirectory):
            self.attempt()

    def test_folder_owned_by_someone_else_is_refused(self):
        """Proves: an existing folder whose owner uid differs from ours is refused (simulated by faking getuid, since chown needs root)."""
        self.lockdir.mkdir(mode=0o700)
        from unittest import mock
        with mock.patch.object(gw.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(gw.UnsafeLockDirectory) as cm:
                gw._open_lock_fd(self.f)
        self.assertIn("owned by uid", str(cm.exception))

    def test_symlinked_lock_file_is_refused(self):
        """Proves: a symlink planted at the lock file's name inside a good folder is not followed (O_NOFOLLOW)."""
        self.lockdir.mkdir(mode=0o700)
        victim = Path(self.td.name) / "victim.txt"; victim.write_text("precious")
        import hashlib
        name = hashlib.sha256(str(self.f.resolve()).encode()).hexdigest()[:32] + ".lock"
        (self.lockdir / name).symlink_to(victim)
        with self.assertRaises(gw.UnsafeLockDirectory):
            self.attempt()
        self.assertEqual(victim.read_text(), "precious")

    def test_cli_exits_2_loudly_on_an_unsafe_folder(self):
        """Proves: the command line exits 2 with a message naming the problem when the lock folder is unsafe, and does not write."""
        self.lockdir.mkdir(); self.lockdir.chmod(0o755)
        h = gw.sha256_of(self.f)
        env = dict(os.environ, TMPDIR=str(self.tmp))
        r = subprocess.run([sys.executable, SCRIPT, "write", str(self.f), "--expect", h], input=b"new\n", capture_output=True, env=env)
        self.assertEqual(r.returncode, 2); self.assertIn(b"refusing", r.stderr)
        self.assertEqual(self.f.read_text(), "base\n")


class NewFileFlow(unittest.TestCase):
    """Regression (M7): the documented hash-then-write flow must work for a file that does not exist yet."""

    def setUp(self):
        """Temp directory, and the path of a file that is not created yet."""
        self.td = tempfile.TemporaryDirectory(); self.addCleanup(self.td.cleanup)
        self.new = Path(self.td.name) / "new.txt"
        self.env = dict(os.environ, TMPDIR=self.td.name)

    def cli(self, *args, data=b"x\n"):
        """Run guarded_write.py with args and stdin data; return the CompletedProcess."""
        return subprocess.run([sys.executable, "-B", SCRIPT, *args], input=data, capture_output=True, env=self.env)

    def test_hash_of_missing_then_write_expect_missing_creates_the_file(self):
        """Proves: `hash` prints "missing" for a new file and `write --expect missing` then creates it (exit 0, mode 0644)."""
        r = self.cli("hash", str(self.new)); self.assertEqual(r.stdout.strip(), b"missing")
        r = self.cli("write", str(self.new), "--expect", r.stdout.decode().strip(), data=b"hello\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.new.read_text(), "hello\n")
        self.assertEqual(self.new.stat().st_mode & 0o777, 0o644 & ~self._umask())

    @staticmethod
    def _umask():
        """Return the current umask without changing it."""
        um = os.umask(0); os.umask(um); return um

    def test_expect_missing_refuses_when_file_now_exists(self):
        """Proves: `--expect missing` on a file that appeared meanwhile exits 3 (concurrent modification), content untouched."""
        self.new.write_text("someone else\n")
        r = self.cli("write", str(self.new), "--expect", "missing")
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(self.new.read_text(), "someone else\n")

    def test_expect_flag_form_still_works_and_hash_is_case_insensitive(self):
        """Proves: --expect-missing works, and an UPPER-CASE pasted digest is accepted for an existing file."""
        self.assertEqual(self.cli("write", str(self.new), "--expect-missing").returncode, 0)
        h = gw.sha256_of(self.new).upper()
        r = self.cli("write", str(self.new), "--expect", h, data=b"two\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.new.read_text(), "two\n")


if __name__ == "__main__":
    unittest.main()
