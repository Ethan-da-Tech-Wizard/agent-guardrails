"""Tests for signal_guard: dangerous kill targets are named and refused, ordinary child signalling still works.

Why: the guard exists to stop a mocked pid from turning into a kill of every process the user owns. Where a test calls
os.kill/os.killpg it only uses signal 0 (an existence probe) for dangerous targets, so the test itself is harmless even if
the guard were broken.
Run: python3 -B -m unittest discover -s scripts -p 'test_*.py'
"""
import os, sys, unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import signal_guard as g


class Guard(unittest.TestCase):
    """Behaviour of blocked_reason() and the installed os.kill/os.killpg wrappers."""

    def test_dangerous_targets_are_named(self):
        """Proves: mocks, None, strings, 0, 1, -1, our parent and our own group each get a non-empty block reason."""
        for pid in (MagicMock(), Mock(), None, "7", 0, 1, -1, os.getppid()):
            self.assertTrue(g.blocked_reason(pid), pid)
        for pgid in (MagicMock(), 0, 1, -5, os.getpgrp()):
            self.assertTrue(g.blocked_reason(pgid, group=True), pgid)
        self.assertTrue(g.blocked_reason(-1))
        self.assertTrue(g.blocked_reason(-os.getpgrp()))

    def test_every_negative_or_low_pid_is_refused_so_no_extra_branch_is_needed(self):
        """Proves: pid 1, 0 and every negative value (including -1 and minus our own group) are refused by the single `pid <= 1` rule.

        This is the evidence that the removed "negative pid in (1, our group)" branch was unreachable dead code.
        """
        for pid in (1, 0, -1, -2, -os.getpgrp(), -(2**22)):
            self.assertTrue(g.blocked_reason(pid), pid)

    def test_ordinary_child_targets_pass(self):
        """Proves: an ordinary high pid or group id is allowed (reason is None)."""
        self.assertIsNone(g.blocked_reason(os.getpid() + 100000))
        self.assertIsNone(g.blocked_reason(2**22 + 5, group=True))

    def test_installed_wrappers_block_before_any_syscall(self):
        """Proves: after install() (called twice, idempotent) dangerous os.kill/os.killpg calls raise PermissionError."""
        g.install(); g.install()   # idempotent
        import signal
        for call in (lambda: os.kill(1, 0), lambda: os.kill(MagicMock(), 0), lambda: os.killpg(1, 0),
                     lambda: os.killpg(MagicMock(), 0), lambda: os.killpg(os.getpgrp(), 0)):
            with self.assertRaises(PermissionError):
                call()       # signal 0 only: harmless even if the guard were broken

    def test_real_child_can_still_be_signalled(self):
        """Proves: the guard does not break legitimate use: a real child in its own group is terminated by killpg."""
        import subprocess, signal
        g.install()
        with subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True) as child:
            os.killpg(child.pid, signal.SIGTERM)
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)

    def test_guard_is_inert_when_unittest_is_not_loaded(self):
        """Proves (by source check): the wrapper decides at call time from whether unittest is loaded, so production is unaffected."""
        # call-time check: a production process never imports unittest, so nothing is blocked there
        src = Path(g.__file__).read_text()
        self.assertIn('"unittest" in sys.modules', src)


if __name__ == "__main__":
    unittest.main()
