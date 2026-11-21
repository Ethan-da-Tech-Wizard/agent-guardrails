"""Tests for write_guard: real processes race for the same file, escape attempts are refused, stale locks are reclaimed.

Why: the guard is only useful if exactly one writer wins a race and no path trick (dotdot, symlink, prefix-sharing sibling)
writes outside the declared root. These tests use real forked processes and real CLI subprocesses, not mocks.
Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'
Everything happens inside a fresh temporary directory that is removed afterwards.
"""
import json, multiprocessing as mp, os, shutil, subprocess, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import write_guard as wg


def _read(path, mode="r"):
    """Read a whole file and close it (a bare open(...).read() leaks the handle and raises ResourceWarning)."""
    with open(path, mode) as fh:
        return fh.read()


def _write(path, text):
    """Write text to a file and close it."""
    with open(path, "w") as fh:
        fh.write(text)

# Directory of this test file and the CLI script under test.
HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "write_guard.py")


def _worker(barrier, q, path, task_root, agent, content, hold):
    """Child process: wait at the barrier, safe_write while holding the lock `hold` seconds, report OK/BLOCKED/ERR on queue q."""
    try:
        barrier.wait(10)
        wg.safe_write(path, content, task_root, agent, "s-" + agent, _hook=lambda: time.sleep(hold))
        q.put((agent, "OK"))
    except wg.BlockedByLock as e:
        q.put((agent, "BLOCKED"))
    except Exception as e:
        q.put((agent, "ERR " + repr(e)))


def _app_worker(barrier, q, path, task_root, agent, hold):
    """Child process: like _worker but calls safe_append with a line naming the agent."""
    try:
        barrier.wait(10)
        wg.safe_append(path, "line-from-" + agent, task_root, agent, "s", _hook=lambda: time.sleep(hold))
        q.put((agent, "OK"))
    except wg.BlockedByLock:
        q.put((agent, "BLOCKED"))
    except Exception as e:
        q.put((agent, "ERR " + repr(e)))


def cli(*args, env=None, inp=b""):
    """Run write_guard.py as a subprocess with `args` and stdin `inp`; return the CompletedProcess (bytes output)."""
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-B", CLI] + list(args), input=inp, capture_output=True, env=e)


class Base(unittest.TestCase):
    """Shared fixture: self.tmp is a fresh real-path temp dir, self.root a "root" folder inside it; removed on cleanup."""

    def setUp(self):
        """Create the temporary directory tree and register its removal."""
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="wgtest-"))
        self.root = os.path.join(self.tmp, "root")
        os.makedirs(self.root)
        self.addCleanup(shutil.rmtree, self.tmp, True)


class Race(Base):
    """Concurrent writers contending for one file."""

    def test_race_in_process_api(self):
        """Proves: of two simultaneous library writers exactly one wins, the file holds the winner's content, no lock is left."""
        ctx = mp.get_context("fork")
        for i in range(5):
            target = os.path.join(self.root, "f%d.txt" % i)
            b = ctx.Barrier(2)
            q = ctx.Queue()
            ps = [ctx.Process(target=_worker, args=(b, q, target, self.root, ag, ("content-" + ag).encode(), 0.5))
                  for ag in ("A", "B")]
            [p.start() for p in ps]
            res = dict(q.get(timeout=20) for _ in ps)
            [p.join() for p in ps]
            self.assertEqual(sorted(res.values()), ["BLOCKED", "OK"], res)
            winner = [k for k, v in res.items() if v == "OK"][0]
            with open(target, "rb") as f:
                self.assertEqual(f.read(), ("content-" + winner).encode())
            self.assertEqual(os.listdir(os.path.join(self.root, "data", "locks")), [])
            print("race[%d] winner=%s" % (i, winner), file=sys.stderr)

    def test_race_cli(self):
        """Proves: two CLI processes colliding give exit 0 and exit 75; the loser's message names the winning holder."""
        target = os.path.join(self.root, "c.txt")
        for i in range(5):
            env = {"WRITE_GUARD_HOLD_S": "0.6"}
            def launch(ag):
                return subprocess.Popen([sys.executable, "-B", CLI, "write", "--path", target, "--task-root", self.root,
                                         "--agent", ag, "--session", "s"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, **env))
            ps = {ag: launch(ag) for ag in ("A", "B")}
            outs = {}
            for ag, p in ps.items():  # feed both stdins first so they collide
                p.stdin.write(("cli-" + ag + str(i)).encode())
                p.stdin.close()
            for ag, p in ps.items():
                p.wait(timeout=20)
                outs[ag] = (p.returncode, p.stderr.read().decode())
                p.stderr.close(); p.stdout.close()
            codes = sorted(v[0] for v in outs.values())
            self.assertEqual(codes, [0, 75], outs)
            winner = [k for k, v in outs.items() if v[0] == 0][0]
            loser_err = [v[1] for v in outs.values() if v[0] == 75][0]
            self.assertTrue(loser_err.startswith("BLOCKED-BY-LOCK path="), loser_err)
            self.assertIn("holder_pid=", loser_err)
            self.assertIn("holder_agent=" + winner, loser_err)
            with open(target, "rb") as f:
                self.assertEqual(f.read(), ("cli-" + winner + str(i)).encode())


class PathValidation(Base):
    """Writes outside the declared task root are refused before anything is created."""

    def test_sibling_refused_cli(self):
        """Proves: a path in a sibling folder exits 2 with a REFUSED message and creates no file, folder or lock dir."""
        sib = os.path.join(self.tmp, "sibling")
        target = os.path.join(sib, "x.txt")
        r = cli("write", "--path", target, "--task-root", self.root, "--agent", "A", inp=b"hi")
        self.assertEqual(r.returncode, 2)
        msg = r.stderr.decode().strip()
        self.assertIn("resolved=" + target, msg)
        self.assertIn("declared_root=" + self.root, msg)
        self.assertTrue(msg.startswith("REFUSED write: resolved="))
        print("refused msg: " + msg, file=sys.stderr)
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(sib))
        self.assertFalse(os.path.exists(os.path.join(self.root, "data")))

    def test_directory_target_exits_2_without_traceback(self):
        """Regression (L8): `write --path <existing directory>` used to crash with an IsADirectoryError traceback and exit 1,
        outside the documented exit codes. Proves: exit 2, one REFUSED line, no traceback, the directory is untouched."""
        d = os.path.join(self.root, "adir")
        os.makedirs(d)
        r = cli("write", "--path", d, "--task-root", self.root, "--agent", "A", inp=b"hi")
        self.assertEqual(r.returncode, 2, r.stderr)
        err = r.stderr.decode()
        self.assertIn("REFUSED write:", err)
        self.assertNotIn("Traceback", err)
        self.assertTrue(os.path.isdir(d))

    def test_dotdot(self):
        """Proves: a ".." escape from the root raises PathOutsideRoot and creates nothing."""
        t = os.path.join(self.root, "..", "esc", "x.txt")
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(t, b"x", self.root, "A", "s")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "esc")))

    def test_symlink_out(self):
        """Proves: a symlinked directory or file pointing outside the root is refused and the outside content is untouched."""
        out = os.path.join(self.tmp, "outside")
        os.makedirs(out)
        os.symlink(out, os.path.join(self.root, "link"))
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(os.path.join(self.root, "link", "x.txt"), b"x", self.root, "A", "s")
        self.assertEqual(os.listdir(out), [])
        # symlinked file too
        victim = os.path.join(out, "v.txt")
        _write(victim, "orig")
        os.symlink(victim, os.path.join(self.root, "fl"))
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(os.path.join(self.root, "fl"), b"x", self.root, "A", "s")
        self.assertEqual(_read(victim), "orig")

    def test_prefix_trap(self):
        """Proves: a sibling whose name merely starts with the root's name (root-evil) is not treated as inside the root."""
        evil = self.root + "-evil"
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(os.path.join(evil, "x.txt"), b"x", self.root, "A", "s")
        self.assertFalse(os.path.exists(evil))

    def test_normal_and_nested(self):
        """Proves: normal nested writes create parent folders and a second write replaces the first."""
        p = os.path.join(self.root, "a", "b", "c.txt")
        wg.safe_write(p, b"data", self.root, "A", "s")
        self.assertEqual(_read(p, "rb"), b"data")
        wg.safe_write(p, b"data2", self.root, "A", "s")
        self.assertEqual(_read(p, "rb"), b"data2")


class ModeAndCorruptLock(Base):
    """safe_write keeps file permissions; a lock file holding non-object JSON is treated as corrupt."""

    def test_documented_limits_read_only_file_replaced_and_hard_link_broken(self):
        """N8: pins the behaviour the README documents. safe_write replaces a 0444 file (atomic rename needs folder, not file,
        permission) and keeps the 0444 mode; a hard link to the old file keeps the OLD content. If this ever changes (for
        example 0444 gets refused) the README limits and this test must be changed together."""
        p = os.path.join(self.root, "ro.txt"); _write(p, "old"); os.chmod(p, 0o444)
        link = os.path.join(self.root, "hl.txt"); os.link(p, link)
        wg.safe_write(p, "new", self.root, "a", "s")
        self.assertEqual(_read(p), "new"); self.assertEqual(os.stat(p).st_mode & 0o777, 0o444)
        self.assertEqual(_read(link), "old")  # the hard link was broken, not updated
        readme = _read(os.path.join(HERE, "..", "README.md"))
        self.assertIn("read-only", readme); self.assertIn("hard link", readme)  # the limit is documented

    def test_safe_write_preserves_existing_mode(self):
        """Regression (M10): mkstemp makes the temp file 0600, so safe_write used to turn an existing 0644 file into 0600.
        Proves: 0644 stays 0644, 0640 stays 0640, a brand-new file gets the normal umask-based mode (not 0600)."""
        p = os.path.join(self.root, "out.txt")
        _write(p, "old"); os.chmod(p, 0o644)
        wg.safe_write(p, b"new", self.root, "A", "s")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)
        os.chmod(p, 0o640)
        wg.safe_write(p, b"newer", self.root, "A", "s")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o640)
        q = os.path.join(self.root, "fresh.txt")
        wg.safe_write(q, b"x", self.root, "A", "s")
        um = os.umask(0); os.umask(um)
        self.assertEqual(os.stat(q).st_mode & 0o777, 0o666 & ~um)

    def test_lock_file_with_non_object_json_is_reclaimable_not_a_crash(self):
        """Regression (L9): a lock file containing [] used to make acquire() crash with AttributeError.
        Proves: for [] and 5 the lock is treated as corrupt (dead holder) and the write succeeds."""
        p = os.path.join(self.root, "f.txt")
        for junk in ("[]", "5", "null", '"x"'):
            lp = wg.lock_path_for(p, self.root)
            os.makedirs(os.path.dirname(lp), exist_ok=True)
            _write(lp, junk)
            wg.safe_write(p, b"ok", self.root, "A", "s")
            self.assertEqual(_read(p, "rb"), b"ok")


def dead_pid():
    """Return the pid of a process that has already exited (so it is reliably not alive)."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


class Stale(Base):
    """Stale-lock detection, reclaim logging, heartbeat and release ownership."""

    def _plant(self, path, pid, ttl=300, age=0):
        """Create a lock file for `path` as if held by `pid`, optionally aged by `age` seconds; return (lock path, record)."""
        lp = wg.lock_path_for(path, self.root)
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        rec = {"pid": pid, "session": "old", "agent_id": "OLD", "path": path,
               "acquired_at": "2020-01-01T00:00:00.000000Z", "ttl_s": ttl, "host": "h"}
        _write(lp, json.dumps(rec))
        if age:
            t = time.time() - age
            os.utime(lp, (t, t))
        return lp, rec

    def _log(self):
        """Return the parsed lines of the reclaim log."""
        with open(os.path.join(self.root, "data", "locks", "reclaim.log.jsonl")) as f:
            return [json.loads(l) for l in f]

    def test_dead_pid(self):
        """Proves: a lock whose holder process is dead is reclaimed, and the takeover is logged with reason pid-dead."""
        p = os.path.join(self.root, "d.txt")
        dp = dead_pid()
        lp, rec = self._plant(p, dp, age=5)
        wg.safe_write(p, b"new", self.root, "NEW", "s")
        self.assertEqual(_read(p, "rb"), b"new")
        lines = self._log()
        self.assertEqual(len(lines), 1)
        L = lines[0]
        self.assertEqual(L["reason"], "pid-dead")
        self.assertEqual(L["holder"], rec)
        self.assertEqual(L["reclaimer"]["agent_id"], "NEW")
        self.assertIsNotNone(L["holder_last_heartbeat"])

    def test_ttl_live_pid(self):
        """Proves: a lock held by a live pid is still reclaimed once its ttl has elapsed, logged with reason ttl."""
        p = os.path.join(self.root, "t.txt")
        self._plant(p, os.getpid(), ttl=10, age=100)
        wg.safe_write(p, b"new", self.root, "NEW", "s")
        L = self._log()[0]
        self.assertEqual(L["reason"], "ttl")
        self.assertEqual(L["holder"]["pid"], os.getpid())

    def test_live_blocks_and_touch_heartbeat(self):
        """Proves: touch() refreshes a lock so it blocks others (library and CLI exit 75) and nothing is logged as reclaimed."""
        p = os.path.join(self.root, "l.txt")
        lp, _ = self._plant(p, os.getpid(), ttl=10, age=100)
        self.assertTrue(wg.touch(p, self.root))  # heartbeat revives it
        with self.assertRaises(wg.BlockedByLock) as cm:
            wg.acquire(p, "NEW", "s", self.root)
        self.assertEqual(cm.exception.holder["agent_id"], "OLD")
        self.assertFalse(os.path.exists(os.path.join(self.root, "data", "locks", "reclaim.log.jsonl")))
        r = cli("write", "--path", p, "--task-root", self.root, "--agent", "N", inp=b"x")
        self.assertEqual(r.returncode, 75)
        self.assertIn("BLOCKED-BY-LOCK path=", r.stderr.decode())

    def test_release_only_own_and_cli_reclaim(self):
        """Proves: release() ignores other agents' locks; the CLI reclaim-stale removes only dead locks; lock-status lists the rest."""
        p = os.path.join(self.root, "o.txt")
        lp, _ = self._plant(p, os.getpid())
        self.assertFalse(wg.release(p, "OTHER", self.root))
        self.assertTrue(os.path.exists(lp))
        lp2, _ = self._plant(os.path.join(self.root, "z.txt"), dead_pid())
        r = cli("reclaim-stale", "--root", self.root)
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(lp2))
        self.assertTrue(os.path.exists(lp))
        r = cli("lock-status", "--root", self.root)
        self.assertEqual(len(json.loads(r.stdout)), 1)


class Release(Base):
    """Locks are always released."""

    def test_released_after_exception(self):
        """Proves: if the write fails midway the lock is released, no target file appears, and a later write works."""
        p = os.path.join(self.root, "e.txt")
        def boom():
            raise RuntimeError("x")
        with self.assertRaises(RuntimeError):
            wg.safe_write(p, b"x", self.root, "A", "s", _hook=boom)
        self.assertEqual(os.listdir(os.path.join(self.root, "data", "locks")), [])
        self.assertFalse(os.path.exists(p))
        wg.safe_write(p, b"ok", self.root, "A", "s")


class Append(Base):
    """Appending under a lock."""

    def test_concurrent_appenders(self):
        """Proves: with 8 simultaneous appenders every success wrote exactly one intact, unique line and the rest were cleanly blocked."""
        ctx = mp.get_context("fork")
        p = os.path.join(self.root, "log.txt")
        b = ctx.Barrier(8)
        q = ctx.Queue()
        ps = [ctx.Process(target=_app_worker, args=(b, q, p, self.root, "w%d" % i, 0.2)) for i in range(8)]
        [x.start() for x in ps]
        res = dict(q.get(timeout=20) for _ in ps)
        [x.join() for x in ps]
        ok = sorted(k for k, v in res.items() if v == "OK")
        self.assertTrue(all(v in ("OK", "BLOCKED") for v in res.values()), res)
        self.assertGreaterEqual(len(ok), 1)
        lines = _read(p).splitlines()
        self.assertEqual(sorted(lines), sorted("line-from-" + k for k in ok))
        self.assertEqual(len(lines), len(set(lines)))


if __name__ == "__main__":
    unittest.main()
