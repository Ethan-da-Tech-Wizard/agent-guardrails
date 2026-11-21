#!/usr/bin/env python3
"""The one shared STOP latch every long-running worker process can use.

The STOP file (default `<STOP_LATCH_ROOT>/STOP`, or the path in `STOP_LATCH_FILE`) stops work except safe shutdown and receipts.
A worker calls ``stop_latch.enforce("<name>")`` once at its entrypoint:

* if STOP is present it refuses to start (exit 0, one stderr line), and
* otherwise a daemon thread checks the file every few seconds (a single ``stat``; near-zero
  CPU) and, when STOP appears, sends the process SIGTERM so its normal shutdown handlers run,
  then hard-exits after a grace period if the process is still alive.

``refuse_if_stopped`` is the entry check alone, for one-shot commands. Nothing here starts a
process, model, service or network request.

Why it exists: when something goes wrong, an operator needs one reliable, dependency-free way to tell every
long-running worker to stop. A file is the simplest signal that survives crashes and needs no running service:
creating it stops work, deleting it allows work again.

Threat model / limits: it is a cooperative, same-machine latch, not a security boundary. Anyone who can create the
file can stop the workers; a process that never calls enforce() is unaffected; polling means a stop takes up to one
interval (default 5 s) to be noticed, plus the grace period (default 30 s) if the process ignores SIGTERM.

Usage:
    import stop_latch
    stop_latch.enforce("my-worker")     # at the top of the worker's main(); exits 0 if STOP already exists
    # shell: touch "$STOP_LATCH_ROOT/STOP"   -> every enforced worker shuts down; rm it to allow starting again
    # python3 stop_latch.py                  -> prints "STOP present" or "STOP absent"
"""
# >>> HOW THIS WORKS
# FLOW:    1 A worker calls enforce("name") at startup. 2 enforce() calls refuse_if_stopped(): if the STOP file exists it
#          prints one line to stderr and raises SystemExit(0). 3 Otherwise watch() starts one daemon thread per name.
#          4 The thread's loop() checks stop_present() every `interval` seconds (default 5, never below 0.05).
#          5 When STOP appears it runs _default_on_stop(): print a line, send SIGTERM to its own process, sleep the
#          grace time (default 30 s), then os._exit(0) if the process is still alive.
# DATA:    Reads only: it checks whether the STOP file exists (STOP_FILE; env STOP_LATCH_FILE, else STOP_LATCH_ROOT/STOP, else <parent of the folder that holds stop_latch.py>/STOP). Writes nothing.
#          Audit tools can read ENTRY_FUNCTIONS to see which names count as entry calls.
#          It calls nothing outside the standard library.
# FAILS:   STOP present at start: clean exit 0, no work. STOP appears later: SIGTERM first, so normal shutdown
#          handlers run; a process that ignores SIGTERM is killed after the grace time. Calling watch() twice with the
#          same name returns the existing live thread (no duplicates). A custom on_stop callback replaces the default; if it raises, the default reaction runs instead.
# EXTEND:  Add new helpers near enforce(). Test: scripts/test_stop_latch.py. Run:
#          PYTHONPATH=scripts python3 -B -m unittest -q scripts.test_stop_latch
# GOTCHAS: Running the file directly only
#          prints "STOP present" or "STOP absent". Watching is a stat poll, not a file event.
# GLOSSARY: STOP latch = the empty-or-not file that tells every worker to stop.
# <<< HOW THIS WORKS
from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

# Directory that holds the STOP file: env STOP_LATCH_ROOT if set, else the PARENT of the folder that contains this file.
# (Copy the file to myproject/stop_latch.py and the default STOP is the parent of myproject/; set STOP_LATCH_FILE to be explicit.)
# N11: "~" in STOP_LATCH_ROOT is expanded (STOP_LATCH_FILE already was), so "~/x" means the home folder and not a folder literally named "~".
REPO_ROOT = Path(os.path.expanduser(os.environ.get("STOP_LATCH_ROOT") or str(Path(__file__).resolve().parent.parent))).resolve()
# The latch file itself: env STOP_LATCH_FILE (a full path, "~" expanded) wins, otherwise <REPO_ROOT>/STOP.
# L7: a relative STOP_LATCH_FILE is made absolute ONCE, here at import, against the working directory of that moment. Without this
# the path would be re-resolved against whatever the current directory is at every poll, so a worker that calls os.chdir() would
# silently stop seeing the latch. Path.resolve is NOT used so a symlink at the STOP path is not followed: the link itself is the
# latch (see stop_present for the dangling-symlink rule).
# N10: os.path.abspath is NOT used either: it collapses ".." textually, so "lk/../STOP" with "lk" a symlink to some/dir became
# "<cwd>/STOP", while the operating system resolves it to "some/STOP" (the parent of the link TARGET). os.path.join keeps the
# text exactly as given, so the kernel does the ".." walk when the path is stat-ed and the latch watches the file that every
# other program sees at that spelling.
def _latch_file_from_env(value):
    """Return the absolute (but not normalised, not link-resolved) latch path for env value `value` ("~" expanded)."""
    return Path(os.path.join(os.getcwd(), os.path.expanduser(value)))  # join: an absolute right-hand side wins, ".." stays as text


STOP_FILE = (_latch_file_from_env(os.environ["STOP_LATCH_FILE"])
             if os.environ.get("STOP_LATCH_FILE") else REPO_ROOT / "STOP")
# Seconds between checks of the STOP file by the watcher thread (one cheap stat per check).
DEFAULT_INTERVAL = 5.0
# Seconds to wait after SIGTERM before hard-exiting a process that is still alive.
DEFAULT_GRACE = 30.0
ENTRY_FUNCTIONS = frozenset({"enforce", "refuse_if_stopped"})  # entry-point names, for audit tools

# Running watcher threads by worker name, so watch() is idempotent per name.
_watchers: dict[str, threading.Thread] = {}


def stop_present(path: Path | None = None) -> bool:
    """True when the STOP file exists.

    Args:
        path: file to check instead of the configured STOP_FILE (used by tests and callers with their own latch).
    Existence only is tested, never content: an empty file counts.
    Raises:
        OSError (for example PermissionError) when the answer cannot be determined because the folder is unreadable.
        "Does not exist" (including a missing parent folder) is a plain False. We call os.lstat directly because
        Path.exists() raises PermissionError on Python 3.9 but quietly returns False on newer versions; this makes the
        behaviour the same everywhere. os.lstat is used, not os.stat, so a DANGLING symlink at the STOP path (a link whose
        target is missing) counts as PRESENT: someone put something at the latch path, and a latch should fail on the safe
        side. (os.stat follows the link and would report such a path as absent.) The entry check lets the error propagate (fail loudly at start); the watcher
        thread catches it and keeps polling, see watch().
    """
    try:
        os.lstat(STOP_FILE if path is None else path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def refuse_if_stopped(name: str, path: Path | None = None) -> None:
    """Exit cleanly before doing any work when STOP is present.

    Args:
        name: worker name used in the message. path: optional alternative STOP file.
    Raises:
        SystemExit(0) after printing one line to stderr; exit status 0 so supervisors do not treat it as a crash.
    """
    if stop_present(path):
        print(f"{name}: STOP latch present ({STOP_FILE if path is None else path}); not starting.", file=sys.stderr)
        raise SystemExit(0)


def _default_on_stop(name: str, grace: float) -> None:
    """Default reaction to STOP: SIGTERM ourselves, wait `grace` seconds, then hard-exit.

    The SIGTERM lets the process's own handlers do an orderly shutdown; os._exit skips cleanup and is only the backstop.
    """
    print(f"{name}: STOP latch appeared; shutting down.", file=sys.stderr, flush=True)
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(grace)
    os._exit(0)  # the process ignored SIGTERM; STOP still wins


def watch(name: str, interval: float = DEFAULT_INTERVAL, path: Path | None = None,
          on_stop=None, grace: float | None = None) -> threading.Thread:
    """Start (once per name) a daemon thread that reacts when STOP appears.

    Args:
        name: worker name (also the thread name suffix and the idempotency key).
        interval: poll period in seconds, clamped to at least 0.05.
        path: optional alternative STOP file.
        on_stop: optional zero-argument callback replacing the default SIGTERM-then-exit behaviour.
        grace: seconds before the hard exit in the default reaction (default DEFAULT_GRACE, read at trigger time).
    Returns:
        The watcher thread (the existing live one if this name is already being watched).
    """
    if name in _watchers and _watchers[name].is_alive():
        return _watchers[name]
    interval = max(0.05, float(interval))

    def loop() -> None:
        """Poll until STOP exists, then run the stop reaction once.

        An unreadable STOP location (PermissionError or any other OSError) must NOT kill this thread: a dead watcher would
        silently disable the latch for a running worker. Policy, stated plainly: the answer is "unknown", so we warn once on
        stderr and keep polling (fail-open for an already-running worker; the entry check at start-up is loud instead).
        """
        warned = False
        while True:
            try:
                if stop_present(path):
                    break
                warned = False
            except OSError as exc:
                if not warned:
                    print(f"{name}: STOP latch location unreadable ({type(exc).__name__}); will keep polling.", file=sys.stderr, flush=True)
                    warned = True
            time.sleep(interval)
        default = lambda: _default_on_stop(name, DEFAULT_GRACE if grace is None else grace)  # noqa: E731
        if on_stop is None:
            default()
            return
        # L7: a custom on_stop that raises must not end this thread with nothing done (the exception would only print a
        # traceback from a daemon thread and the worker would keep running although STOP is present). STOP still wins:
        # report the failure, then fall back to the default SIGTERM-then-hard-exit reaction.
        try:
            on_stop()
        except BaseException as exc:  # noqa: BLE001 - any failure of the callback must still lead to the default stop
            print(f"{name}: on_stop callback failed ({type(exc).__name__}); falling back to the default stop.",
                  file=sys.stderr, flush=True)
            default()

    # daemon=True so the watcher never keeps an otherwise finished process alive.
    thread = threading.Thread(target=loop, name=f"stop-latch-{name}", daemon=True)
    thread.start()
    _watchers[name] = thread
    return thread


def enforce(name: str, interval: float = DEFAULT_INTERVAL, path: Path | None = None) -> threading.Thread:
    """Entry check plus a running watch: the standard call for any daemon or server.

    Exits 0 immediately if STOP is present; otherwise starts the watcher and returns its thread.
    """
    refuse_if_stopped(name, path)
    return watch(name, interval, path)


if __name__ == "__main__":
    try:
        print("STOP present" if stop_present() else "STOP absent")
    except OSError as exc:
        print(f"STOP unknown ({type(exc).__name__}: cannot read {STOP_FILE})")
        sys.exit(2)
