#!/usr/bin/env python3
"""Real-process checks for the shared STOP latch (no models, services or network).

Why: a latch is only trustworthy if a real separate process is seen to refuse to start, to stop when the file appears, and to
be force-stopped when it ignores SIGTERM, so most tests spawn child interpreters. Each test uses its own temporary STOP path.
Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stop_latch  # noqa: E402


def child(stop_path, body):
    """Start a Python child that imports stop_latch and then runs `body` (source text, indented 8 spaces); return the Popen."""
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(HERE)!r})
        import stop_latch
        {body}
    """)
    return subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


class StopLatchTests(unittest.TestCase):
    """Behaviour of stop_latch in real child processes and in-process."""

    def setUp(self):
        """Create a temporary directory and the path of a STOP file inside it (not yet created)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.stop = Path(tmp.name) / "STOP"

    def spawn(self, body):
        """Start a child running `body` and register cleanup that kills it if still running."""
        proc = child(self.stop, body)

        def cleanup():
            """Kill the child if needed and drain its pipes."""
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
        self.addCleanup(cleanup)
        return proc

    def test_default_path_is_root_stop(self):
        """Proves: with no env the STOP path is <parent of scripts>/STOP, and STOP_LATCH_ROOT relocates it."""
        env = {k: v for k, v in os.environ.items() if k not in ("STOP_LATCH_ROOT", "STOP_LATCH_FILE", "PYTHONPATH")}
        code = "import stop_latch; print(stop_latch.STOP_FILE)"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            out = subprocess.run([sys.executable, "-B", "-c", code], env={**env, "PYTHONPATH": str(HERE)},
                                 capture_output=True, text=True, timeout=10, cwd=tmp)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(Path(out.stdout.strip()), HERE.parent / "STOP")
            out = subprocess.run([sys.executable, "-B", "-c", code],
                                 env={**env, "PYTHONPATH": str(HERE), "STOP_LATCH_ROOT": str(root)},
                                 capture_output=True, text=True, timeout=10, cwd=tmp)
            self.assertEqual(Path(out.stdout.strip()), root / "STOP")

    def test_stop_file_env_overrides_root(self):
        """Proves: STOP_LATCH_FILE beats STOP_LATCH_ROOT, and stop_present() honours an explicit path argument."""
        env = {k: v for k, v in os.environ.items() if k not in ("STOP_LATCH_ROOT", "STOP_LATCH_FILE", "PYTHONPATH")}
        code = ("import json,stop_latch; "
                "print(json.dumps([str(stop_latch.STOP_FILE),stop_latch.stop_present(),"
                "stop_latch.stop_present('explicit-absent-STOP')]))")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            custom = root / "custom" / "latch"
            custom.parent.mkdir()
            custom.write_text("fixture")
            run_env = {**env, "PYTHONPATH": str(HERE), "STOP_LATCH_ROOT": str(root / "other"), "STOP_LATCH_FILE": str(custom)}
            out = subprocess.run([sys.executable, "-B", "-c", code], env=run_env,
                                 capture_output=True, text=True, timeout=10, cwd=tmp)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(json.loads(out.stdout), [str(custom), True, False])

    def test_refuses_to_start_when_stop_present(self):
        """Proves: with STOP already present a worker exits 0 before doing work and says it is not starting."""
        self.stop.write_text("incident")
        proc = self.spawn(f"stop_latch.enforce('fixture', path={str(self.stop)!r}); print('WORKED')")
        out, err = proc.communicate(timeout=20)
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("WORKED", out)
        self.assertIn("not starting", err)

    def test_running_worker_stops_when_stop_appears(self):
        """Proves: a running worker is terminated within seconds after STOP is created."""
        proc = self.spawn(f"stop_latch.enforce('fixture', interval=0.1, path={str(self.stop)!r})\n"
                                "        print('started', flush=True)\n"
                                "        time.sleep(60)")
        self.assertEqual(proc.stdout.readline().strip(), "started")
        started = time.monotonic()
        self.stop.write_text("incident")
        proc.wait(timeout=20)
        self.assertLess(time.monotonic() - started, 15)
        self.assertNotEqual(proc.returncode, None)

    def test_worker_that_ignores_sigterm_is_still_stopped(self):
        """Proves: a worker that ignores SIGTERM is hard-exited (status 0) after the grace period."""
        body = ("import signal\n"
                "        signal.signal(signal.SIGTERM, lambda *a: None)\n"
                "        stop_latch.DEFAULT_GRACE = 0.3\n"
                f"        stop_latch.enforce('fixture', interval=0.1, path={str(self.stop)!r})\n"
                "        print('started', flush=True)\n"
                "        time.sleep(60)")
        proc = self.spawn(body)
        self.assertEqual(proc.stdout.readline().strip(), "started")
        self.stop.write_text("incident")
        proc.wait(timeout=20)
        self.assertEqual(proc.returncode, 0)

    def test_absent_stop_lets_work_run_and_custom_handler_fires(self):
        """Proves: no exit and no callback while STOP is absent; a custom on_stop callback fires once when it appears."""
        fired = []
        stop_latch.refuse_if_stopped("fixture", self.stop)  # no exit
        stop_latch.watch("fixture-custom", interval=0.05, path=self.stop, on_stop=lambda: fired.append(1))
        time.sleep(0.2)
        self.assertEqual(fired, [])
        self.stop.write_text("incident")
        deadline = time.monotonic() + 5
        while not fired and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(fired, [1])

    @unittest.skipIf(os.geteuid() == 0, "root can read any folder, so PermissionError cannot be provoked")
    def test_watcher_survives_unreadable_stop_folder(self):
        """Regression (M8): stat() on a STOP file inside an unreadable folder raises PermissionError. That used to kill the
        daemon watcher thread silently (the latch quietly stopped working). Proves: the thread stays alive while the folder is
        unreadable, and still fires once the folder is readable and STOP appears. The entry check reports the error loudly."""
        folder = self.stop.parent / "locked"
        folder.mkdir()
        stop = folder / "STOP"
        fired = []
        folder.chmod(0o000)
        try:
            with self.assertRaises(PermissionError):
                stop_latch.stop_present(stop)  # entry check fails loudly, not "absent"
            th = stop_latch.watch("fixture-perm", interval=0.05, path=stop, on_stop=lambda: fired.append(1))
            time.sleep(0.4)
            self.assertTrue(th.is_alive(), "watcher thread died on PermissionError")
            self.assertEqual(fired, [])
        finally:
            folder.chmod(0o700)
        stop.write_text("incident")
        deadline = time.monotonic() + 5
        while not fired and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(fired, [1])

    def test_missing_parent_folder_means_absent(self):
        """A STOP path whose parent folder does not exist is simply 'absent' (no exception)."""
        self.assertFalse(stop_latch.stop_present(self.stop.parent / "nope" / "STOP"))

    def test_relative_stop_file_is_resolved_once_at_startup(self):
        """Regression (L7): a relative STOP_LATCH_FILE used to be re-resolved against the CURRENT directory at every check, so after
        os.chdir() the latch silently stopped matching. Proves: the path is made absolute at import and still finds the file after a chdir."""
        env = {k: v for k, v in os.environ.items() if k not in ("STOP_LATCH_ROOT", "STOP_LATCH_FILE", "PYTHONPATH")}
        code = ("import os, stop_latch; open('rel-latch','w').close(); os.mkdir('sub'); os.chdir('sub'); "
                "print(stop_latch.STOP_FILE.is_absolute(), stop_latch.stop_present())")
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run([sys.executable, "-B", "-c", code], cwd=tmp, capture_output=True, text=True, timeout=10,
                                 env={**env, "PYTHONPATH": str(HERE), "STOP_LATCH_FILE": "rel-latch"})
            self.assertEqual(out.stdout.strip(), "True True", out.stderr)

    def test_dangling_symlink_counts_as_present(self):
        """Regression (L7): a symlink at the STOP path whose target is missing used to count as ABSENT (os.stat follows links).
        Documented policy: the link itself is the latch, so it counts as present (the safe side for a stop signal)."""
        os.symlink(self.stop.parent / "no-such-target", self.stop)
        self.assertTrue(stop_latch.stop_present(self.stop))

    def test_raising_on_stop_callback_still_stops_the_worker(self):
        """Regression (L7): an on_stop callback that raised used to kill the watcher thread with only a traceback, leaving the worker
        running although STOP was present. Proves: the failure is reported and the default SIGTERM stop still ends the process."""
        body = ("stop_latch.DEFAULT_GRACE = 0.3\n"
                "        def boom():\n"
                "            raise RuntimeError('callback bug')\n"
                f"        stop_latch.watch('fixture', interval=0.1, path={str(self.stop)!r}, on_stop=boom)\n"
                "        print('started', flush=True)\n"
                "        time.sleep(60)")
        proc = self.spawn(body)
        self.assertEqual(proc.stdout.readline().strip(), "started")
        self.stop.write_text("incident")
        _, err = proc.communicate(timeout=20)
        self.assertIsNotNone(proc.returncode)
        self.assertIn("on_stop callback failed", err)


    def test_dotdot_through_a_symlink_is_not_collapsed(self):
        """Regression (N10): os.path.abspath collapsed "lk/../STOP" textually to "<cwd>/STOP" although "lk" is a symlink, so the latch
        reported absent while the real file the operating system reaches through that spelling (target's parent) was present.
        Proves: with lk -> real/sub and real/STOP present (and <cwd>/STOP absent) the child sees STOP present."""
        env = {k: v for k, v in os.environ.items() if k not in ("STOP_LATCH_ROOT", "STOP_LATCH_FILE", "PYTHONPATH")}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            os.makedirs(os.path.join(tmp, "real", "sub")); open(os.path.join(tmp, "real", "STOP"), "w").close()
            os.makedirs(os.path.join(tmp, "cwd")); os.symlink(os.path.join(tmp, "real", "sub"), os.path.join(tmp, "cwd", "lk"))
            out = subprocess.run([sys.executable, "-B", "-c", "import stop_latch; print(stop_latch.stop_present())"],
                                 cwd=os.path.join(tmp, "cwd"), capture_output=True, text=True, timeout=10,
                                 env={**env, "PYTHONPATH": str(HERE), "STOP_LATCH_FILE": "lk/../STOP"})
            self.assertEqual(out.stdout.strip(), "True", out.stderr)

    def test_tilde_in_stop_latch_root_is_expanded(self):
        """Regression (N11): STOP_LATCH_ROOT='~/x' became '<cwd>/~/x' (only STOP_LATCH_FILE expanded "~"). Proves the root is under HOME."""
        env = {k: v for k, v in os.environ.items() if k not in ("STOP_LATCH_ROOT", "STOP_LATCH_FILE", "PYTHONPATH")}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            os.makedirs(os.path.join(tmp, "home", "x")); os.makedirs(os.path.join(tmp, "cwd"))
            out = subprocess.run([sys.executable, "-B", "-c", "import stop_latch; print(stop_latch.STOP_FILE)"],
                                 cwd=os.path.join(tmp, "cwd"), capture_output=True, text=True, timeout=10,
                                 env={**env, "PYTHONPATH": str(HERE), "HOME": os.path.join(tmp, "home"), "STOP_LATCH_ROOT": "~/x"})
            self.assertEqual(out.stdout.strip(), os.path.join(tmp, "home", "x", "STOP"), out.stderr)


if __name__ == "__main__":
    unittest.main()
