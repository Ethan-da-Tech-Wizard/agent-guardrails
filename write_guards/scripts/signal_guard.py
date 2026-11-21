"""Process-wide safety net: while a unittest is running, refuse signals that can reach the whole session.

Why: a mock process object's pid (a MagicMock, which converts to 1) can reach os.killpg(1, SIGKILL), which is
kill(-1, SIGKILL) and kills every process you own, ending your whole login session. A sandboxed runner can contain that, but anyone can run a test by hand.
This guard works for every launcher: install() wraps os.kill/os.killpg, and the wrapper checks AT CALL TIME whether
unittest is loaded, so production daemons (which never import unittest) are unaffected.

Blocked while testing: pid 0 / 1 / negative targets for kill, group <= 1 or our own group for killpg, non-integers
(mocks), and our own parent. Everything else (a test killing its own child) passes through unchanged.

Threat model: this prevents accidents, not attacks. Code that saves the original functions
before install(), or calls the syscall through another route, is not stopped.

Usage:
    import signal_guard
    signal_guard.install()          # once, early (for example from a site hook); safe to repeat
    signal_guard.blocked_reason(1)  # -> explanation string; None means the target is allowed
"""
import os
import sys

# Module flag making install() idempotent, so the wrappers are never stacked on top of each other.
_installed = False


def blocked_reason(pid, group=False):
    """Why this signal target is unsafe during a test, or None.

    Args:
        pid: the target given to os.kill (or the group id for killpg). Only a real int is
        accepted: anything else, including mocks, is treated as dangerous.
        group: True when checking a killpg() argument.
    Returns:
        A human-readable reason string if the target must be refused, else None.
    """
    # type() is used (not isinstance) so bool and int subclasses/mocks are rejected too.
    if type(pid) is not int:
        return f"non-integer target {type(pid).__name__} (a mock converts to 1)"
    if group:
        if pid <= 1:
            return f"killpg({pid}) is kill(-{pid}): signals every process you own"
        if pid == os.getpgrp():
            return "killpg of our own process group (the test runner and its launcher)"
        return None
    # Every pid <= 1 is refused here: 0 (our own group), 1 (init), -1 (every process you own) and ANY negative value (kill(-n)
    # signals process group n, which includes our own group -getpgrp()). So no separate negative-pid check is needed.
    if pid <= 1:
        return f"kill({pid}) targets init, our whole group, a process group, or every process you own"
    if pid == os.getppid():
        return "signalling our own parent (the launcher/terminal)"
    return None


def _testing():
    """True while the unittest module is loaded; evaluated on every call so production stays unaffected."""
    return "unittest" in sys.modules


def install():
    """Idempotent. Safe to call from sitecustomize/.pth at interpreter start.

    Replaces os.kill and os.killpg with wrappers that raise PermissionError (before any
    system call) when blocked_reason() objects and unittest is loaded; otherwise they
    delegate to the original functions unchanged.
    """
    global _installed
    if _installed:
        return
    real_kill, real_killpg = os.kill, os.killpg

    def kill(pid, sig, *a, **k):
        """Guarded os.kill: refuse dangerous targets while testing, else call the real one."""
        reason = _testing() and blocked_reason(pid)
        if reason:
            raise PermissionError(f"signal_guard blocked os.kill({pid!r}, {sig}): {reason}")
        return real_kill(pid, sig, *a, **k)

    def killpg(pgid, sig, *a, **k):
        """Guarded os.killpg: refuse dangerous group ids while testing, else call the real one."""
        reason = _testing() and blocked_reason(pgid, group=True)
        if reason:
            raise PermissionError(f"signal_guard blocked os.killpg({pgid!r}, {sig}): {reason}")
        return real_killpg(pgid, sig, *a, **k)

    os.kill, os.killpg = kill, killpg
    _installed = True
