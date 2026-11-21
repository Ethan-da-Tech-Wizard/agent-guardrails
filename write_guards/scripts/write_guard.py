#!/usr/bin/env python3
"""write_guard: single-writer locks and task-root path validation. stdlib only.

Exit codes: 0 ok, 2 REFUSED (outside root, or an OS error such as the path being a directory), 75 BLOCKED-BY-LOCK. No retry loops.

PURPOSE
  Several independent processes (scripts, agents, cron jobs) may want to write the same
  files. This module gives each writer two protections:
    1. Path validation: a write is refused unless the fully resolved target (after
       following symlinks and ".." segments) lies inside a declared task root.
    2. A per-file advisory lock (one small JSON file per target, created with
       O_CREAT|O_EXCL so creation is atomic). A second writer does not wait or retry;
       it fails immediately with a message naming the current holder.

DESIGN NOTES
  * Locks live under <root>/data/locks/ and are named by the SHA-1 of the target's path
    relative to the root (SHA-1 is only a file-name hash here, not a security control).
  * A lock is "stale" when its holder pid is dead or when the lock file has not been
    touched for longer than its ttl_s. Stale locks may be reclaimed; every reclaim is
    appended to reclaim.log.jsonl so nothing is taken silently.
  * Reclaimers are serialised with a short-lived "<lock>.reclaim" guard file, and the
    lock content is re-read under the guard to avoid stealing a lock that was just
    refreshed or re-acquired.
  * Writes go to a temp file in the target directory, are fsync'ed, then os.replace()d
    over the target, so readers see either the old or the new complete content.

THREAT MODEL / LIMITS
  Locks are advisory: they only constrain writers that use this module. The root check
  defends against accidental escapes (".." segments, symlinks pointing outside, sibling
  directories sharing a name prefix); it is not a sandbox against a hostile local user.
  There is a small time-of-check/time-of-use window between validating a path and
  writing it; it is acceptable for cooperating tools on one machine.

USAGE
  Library:
      import write_guard
      write_guard.safe_write("/work/task/out.txt", "hello", task_root="/work/task",
                             agent_id="worker-1", session="s1")
  Command line (data is read from stdin when --data-file is "-"):
      echo hi | python3 write_guard.py write --path /work/task/out.txt \
          --task-root /work/task --agent worker-1
      python3 write_guard.py lock-status --root /work/task
      python3 write_guard.py reclaim-stale --root /work/task
"""
import argparse, errno, hashlib, json, os, socket, sys, tempfile, time
from datetime import datetime, timezone


class BlockedByLock(Exception):
    """Raised when another live writer holds the lock for the target path.

    Attributes:
        path: resolved path of the contended file.
        holder: the holder's lock record (dict; may be empty or marked corrupt).
    """

    def __init__(self, path, holder):
        self.path, self.holder = path, holder
        super().__init__("BLOCKED-BY-LOCK " + _blocked_line(path, holder))


class PathOutsideRoot(Exception):
    """Raised when a target path resolves outside the declared task root.

    Attributes:
        resolved: the fully resolved (symlink-free) target path.
        declared_root: the resolved task root it was checked against.
    """

    def __init__(self, resolved, declared_root):
        self.resolved, self.declared_root = resolved, declared_root
        super().__init__("REFUSED write: resolved=%s declared_root=%s" % (resolved, declared_root))


def _blocked_line(path, h):
    """Format the one-line, key=value description of a lock holder used in BLOCKED messages.

    Args:
        path: contended file path.
        h: holder record dict; missing keys are printed as None.
    Returns:
        A single line such as "path=... holder_pid=... holder_agent=... ttl_s=...".
    """
    return "path=%s holder_pid=%s holder_agent=%s holder_session=%s acquired_at=%s ttl_s=%s" % (
        path, h.get("pid"), h.get("agent_id"), h.get("session"), h.get("acquired_at"), h.get("ttl_s"))


def _iso(ts=None):
    """Return a UTC ISO-8601 timestamp with microseconds and a trailing Z.

    Args:
        ts: POSIX seconds; defaults to the current time (0 is honoured, not replaced).
    """
    return datetime.fromtimestamp(time.time() if ts is None else ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def pid_alive(pid):
    """Return True if a process with this pid appears to exist.

    Uses signal 0 (an existence probe that delivers nothing). Edge cases: a
    non-positive or non-numeric pid is treated as dead; EPERM/PermissionError means the
    process exists but belongs to someone else, so it counts as alive.
    """
    try:
        pid = int(pid)
        if pid <= 0:
            return False
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, ValueError, TypeError) as e:
        return getattr(e, "errno", None) == errno.EPERM
    return True


def _rp(p):
    """Resolve a path fully (symlinks, "..") so comparisons are on real locations."""
    return os.path.realpath(p)


def _locks_dir(root):
    """Directory holding lock files and the reclaim log for a given root."""
    return os.path.join(_rp(root), "data", "locks")


def lock_path_for(path, root):
    """Map a target path to its lock-file path under <root>/data/locks.

    The name is the SHA-1 hex digest of the target's path relative to the resolved root,
    so the same file always maps to the same lock and file names stay short and safe.
    """
    rroot = _rp(root)
    rel = os.path.relpath(_rp(path), rroot)
    return os.path.join(rroot, "data", "locks", hashlib.sha1(rel.encode()).hexdigest() + ".lock")


def _read_lock(lp):
    """Read a lock record.

    Returns:
        The parsed dict; None if the lock file does not exist; or a marker dict
        {"corrupt": True, "pid": -1} if it is unreadable/invalid (pid -1 is "dead", so a
        corrupt lock becomes reclaimable instead of blocking forever).
    """
    try:
        with open(lp) as f:
            rec = json.load(f)
        if not isinstance(rec, dict):  # e.g. a lock file holding [] or 5: treat as corrupt (reclaimable), never crash
            return {"corrupt": True, "pid": -1}
        return rec
    except FileNotFoundError:
        return None
    except (ValueError, OSError):
        return {"corrupt": True, "pid": -1}


def _mtime(lp):
    """Modification time of a lock file (its heartbeat), or None if it cannot be stat'ed."""
    try:
        return os.stat(lp).st_mtime
    except OSError:
        return None


def _stale_reason(holder, lp):
    """Say why a lock may be reclaimed.

    Returns:
        "pid-dead" if the holder process is gone, "ttl" if the lock file has not been
        touched within the holder's ttl_s (default 300 s), otherwise None (lock is live).
    """
    if not pid_alive(holder.get("pid")):
        return "pid-dead"
    mt = _mtime(lp)
    ttl = holder.get("ttl_s", 300)
    if mt is not None and time.time() - mt > float(ttl):
        return "ttl"
    return None


def _create(lp, rec):
    """Atomically create the lock file with record `rec`.

    O_EXCL makes creation fail with FileExistsError if another writer got there first;
    that error is the mutual-exclusion primitive and is handled by the callers.
    """
    fd = os.open(lp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        os.write(fd, json.dumps(rec).encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _log_reclaim(root, reclaimer, holder, reason, heartbeat, lp):
    """Append one JSON line to reclaim.log.jsonl describing a stale-lock takeover.

    Args:
        root: lock root. reclaimer: dict identifying who reclaimed. holder: the old
        holder record. reason: "pid-dead" or "ttl". heartbeat: old lock mtime or None.
        lp: lock file path.
    The append is O_APPEND + fsync so concurrent reclaimers do not interleave lines.
    """
    d = _locks_dir(root)
    os.makedirs(d, exist_ok=True)
    line = {"at": _iso(), "reclaimer": reclaimer, "reason": reason, "holder": holder,
            "holder_last_heartbeat": _iso(heartbeat) if heartbeat else None, "lock": lp}
    fd = os.open(os.path.join(d, "reclaim.log.jsonl"), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o644)
    try:
        os.write(fd, (json.dumps(line) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def acquire(path, agent_id, session, root, ttl_s=300):
    """Acquire the per-file lock for `path`. Returns the lock file path. Raises BlockedByLock. No retries.

    Args:
        path: file to be written (not required to exist). agent_id/session: identity
        recorded in the lock. root: directory under which data/locks lives. ttl_s:
        seconds without a heartbeat after which the lock may be reclaimed.
    Flow: try to create the lock; if it exists and its holder is alive, block; if it is
    stale, take the reclaim guard, re-verify, log the takeover, replace the lock.
    """
    rpath = _rp(path)
    lp = lock_path_for(path, root)
    os.makedirs(os.path.dirname(lp), exist_ok=True)
    rec = {"pid": os.getpid(), "session": session, "agent_id": agent_id, "path": rpath,
           "acquired_at": _iso(), "ttl_s": ttl_s, "host": socket.gethostname()}
    try:
        _create(lp, rec)
        return lp
    except FileExistsError:
        pass
    holder = _read_lock(lp)
    # Lock existed a moment ago but is gone now (released between our calls).
    if holder is None:  # vanished between calls: single attempt to create
        try:
            _create(lp, rec)
            return lp
        except FileExistsError:
            holder = _read_lock(lp) or {}
            raise BlockedByLock(rpath, holder)
    if _stale_reason(holder, lp) is None:
        raise BlockedByLock(rpath, holder)  # live holder: fail fast, never wait
    # stale: serialize reclaimers with a guard file
    guard = lp + ".reclaim"
    try:
        gfd = os.open(guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        try:
            if time.time() - os.stat(guard).st_mtime > 30:
                os.unlink(guard)  # abandoned guard
        except OSError:
            pass
        raise BlockedByLock(rpath, holder)
    os.close(gfd)
    try:
        # Re-read under the guard: the lock may have been released, replaced or
        # refreshed since we judged it stale; if so we must not take it.
        holder2 = _read_lock(lp)
        if holder2 is None or holder2 != holder:
            raise BlockedByLock(rpath, holder2 or holder)
        reason = _stale_reason(holder2, lp)
        if reason is None:
            raise BlockedByLock(rpath, holder2)
        _log_reclaim(root, {"pid": os.getpid(), "agent_id": agent_id, "session": session},
                     holder2, reason, _mtime(lp), lp)
        os.unlink(lp)
        try:
            _create(lp, rec)
        except FileExistsError:  # a third writer slipped in after our unlink
            raise BlockedByLock(rpath, _read_lock(lp) or {})
        return lp
    finally:
        try:  # always drop the reclaim guard, even on failure
            os.unlink(guard)
        except OSError:
            pass


def release(path, agent_id, root):
    """Remove lock only if ours (pid + agent). Returns True if removed.

    A lock held by another pid/agent, or already gone, is left alone (returns False),
    so a slow writer can never delete a lock that was legitimately reclaimed.
    """
    lp = lock_path_for(path, root)
    h = _read_lock(lp)
    if not h or h.get("pid") != os.getpid() or h.get("agent_id") != agent_id:
        return False
    try:
        os.unlink(lp)
        return True
    except FileNotFoundError:
        return False


def touch(path, root):
    """Heartbeat: bump the lock file's mtime so a long write is not judged stale by ttl.

    Returns True on success, False if the lock file does not exist or cannot be touched.
    """
    lp = lock_path_for(path, root)
    try:
        os.utime(lp, None)
        return True
    except OSError:
        return False


def check_in_root(path, task_root):
    """Validate that `path` resolves inside `task_root`; return the resolved path.

    Raises:
        PathOutsideRoot: for ".." escapes, symlinks leading outside, or sibling
        directories that merely share a name prefix (commonpath compares whole path
        components, so "/a/root-evil" is not inside "/a/root").
    """
    resolved, rroot = _rp(path), _rp(task_root)
    try:
        inside = os.path.commonpath([resolved, rroot]) == rroot
    except ValueError:  # e.g. mixed absolute/relative or different drives
        inside = False
    if not inside:
        raise PathOutsideRoot(resolved, rroot)
    return resolved


def _fsync_dir(d):
    """Best-effort fsync of a directory so a rename is durable; errors are ignored."""
    try:
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def safe_write(path, data, task_root, agent_id, session, root=None, ttl_s=300, _hook=None):
    """Atomically replace `path` with `data` while holding its lock.

    Args:
        path: target file; must resolve inside task_root. data: bytes or str (utf-8).
        task_root: allowed directory tree. agent_id/session: lock identity.
        root: where data/locks lives (defaults to task_root). ttl_s: lock staleness limit.
        _hook: test-only callable run while the lock is held (used to widen race windows).
    Known limits (N8, deliberate, also in the README): the replacement is an atomic rename of a new file over the old one, so
    (1) a read-only file (mode 0444 or 0000) is REPLACED without complaint, because the rename needs write permission on the
    folder, not on the file; the read-only mode is kept on the new file, so it still looks protected. (2) A hard link to the old
    file keeps the OLD content (the name is re-pointed to a new inode). (3) Only the permission bits (including setuid/setgid/
    sticky where the OS allows) are preserved, not owner, group or extended attributes.
    Returns:
        The resolved path written.
    Raises:
        PathOutsideRoot, BlockedByLock. The lock is always released, even on error, and
        a partially written temp file is removed.
    """
    resolved = check_in_root(path, task_root)
    root = root or task_root
    if isinstance(data, str):
        data = data.encode()
    acquire(resolved, agent_id, session, root, ttl_s)
    try:
        if _hook:
            _hook()
        d = os.path.dirname(resolved)
        os.makedirs(d, exist_ok=True)  # inside root: validated above
        # Temp file in the same directory so os.replace is an atomic same-filesystem rename.
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".wg-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            # mkstemp creates the temp file 0600; keep an existing file's permission bits (new files get the usual 0644 & ~umask).
            try:
                mode = os.stat(resolved).st_mode & 0o7777
            except OSError:
                um = os.umask(0); os.umask(um)
                mode = 0o666 & ~um
            os.chmod(tmp, mode)
            os.replace(tmp, resolved)
        except BaseException:  # includes KeyboardInterrupt: never leave temp litter behind
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        _fsync_dir(d)
        return resolved
    finally:
        release(resolved, agent_id, root)


def safe_append(path, line, task_root, agent_id, session, root=None, ttl_s=300, _hook=None):
    """Append one line to `path` under its lock (same arguments and errors as safe_write).

    A trailing newline is added if missing, so each call adds exactly one complete line.
    The file is created if absent. Returns the resolved path.
    """
    resolved = check_in_root(path, task_root)
    root = root or task_root
    if isinstance(line, str):
        line = line.encode()
    if not line.endswith(b"\n"):
        line += b"\n"
    acquire(resolved, agent_id, session, root, ttl_s)
    try:
        if _hook:
            _hook()
        os.makedirs(os.path.dirname(resolved), exist_ok=True)
        fd = os.open(resolved, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o644)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return resolved
    finally:
        release(resolved, agent_id, root)


def lock_status(root):
    """List all locks under `root` as dicts (lock path, holder, alive, stale_reason, last_heartbeat).

    Vanished locks are skipped; the result is sorted by lock file name.
    """
    d = _locks_dir(root)
    out = []
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            if n.endswith(".lock"):
                lp = os.path.join(d, n)
                h = _read_lock(lp)
                if h is None:
                    continue
                out.append({"lock": lp, "holder": h, "alive": pid_alive(h.get("pid")),
                            "stale_reason": _stale_reason(h, lp), "last_heartbeat": _iso(_mtime(lp))})
    return out


def reclaim_stale(root, agent_id="reclaim-cli", session=None):
    """Remove every stale lock under `root`, logging each one. Returns a list of {lock, reason}.

    Uses the same reclaim guard as acquire(); locks whose guard is held by someone else
    are skipped (they are being handled) and the stale check is repeated under the guard.
    """
    done = []
    for st in lock_status(root):
        if not st["stale_reason"]:
            continue
        lp = st["lock"]
        guard = lp + ".reclaim"
        try:
            gfd = os.open(guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        os.close(gfd)
        try:
            h = _read_lock(lp)
            reason = _stale_reason(h, lp) if h else None
            if reason:
                _log_reclaim(root, {"pid": os.getpid(), "agent_id": agent_id, "session": session},
                             h, reason, _mtime(lp), lp)
                os.unlink(lp)
                done.append({"lock": lp, "reason": reason})
        finally:
            try:
                os.unlink(guard)
            except OSError:
                pass
    return done


def main(argv=None):
    """Command-line entry point.

    Returns the process exit code: 0 success, 2 path refused or not writable (OSError), 75 blocked by lock.
    Subcommands: write, append, lock-status, reclaim-stale (see module docstring).
    """
    ap = argparse.ArgumentParser(prog="write_guard.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("write", "append"):
        p = sub.add_parser(name)
        p.add_argument("--path", required=True)
        p.add_argument("--task-root", required=True)
        p.add_argument("--agent", required=True)
        p.add_argument("--session", default=None)
        p.add_argument("--root", default=None)
        p.add_argument("--data-file", default="-")
        p.add_argument("--ttl", type=float, default=300)
    for name in ("lock-status", "reclaim-stale"):
        p = sub.add_parser(name)
        p.add_argument("--root", required=True)
        p.add_argument("--agent", default="reclaim-cli")
    a = ap.parse_args(argv)
    try:
        if a.cmd in ("write", "append"):
            if a.data_file == "-":
                data = sys.stdin.buffer.read()
            else:
                with open(a.data_file, "rb") as f:
                    data = f.read()
            # Test/diagnostic knob: hold the lock this many seconds to make races reproducible.
            hold = float(os.environ.get("WRITE_GUARD_HOLD_S", "0") or 0)
            hook = (lambda: time.sleep(hold)) if hold else None
            fn = safe_write if a.cmd == "write" else safe_append
            res = fn(a.path, data, a.task_root, a.agent, a.session, a.root, a.ttl, _hook=hook)
            print("OK %s %s" % (a.cmd, res))
        elif a.cmd == "lock-status":
            print(json.dumps(lock_status(a.root), indent=1))
        else:
            print(json.dumps(reclaim_stale(a.root, a.agent), indent=1))
        return 0
    except PathOutsideRoot as e:
        print("REFUSED write: resolved=%s declared_root=%s" % (e.resolved, e.declared_root), file=sys.stderr)
        return 2
    except BlockedByLock as e:
        print("BLOCKED-BY-LOCK " + _blocked_line(e.path, e.holder), file=sys.stderr)
        return 75
    except OSError as e:
        # L8: a target that cannot be written for an ordinary OS reason (for example --path names an existing directory ->
        # IsADirectoryError, or an unreadable --data-file) used to escape as a traceback with exit 1, outside the documented
        # exit codes. It is now a one-line message and exit 2 ("refused"). Only the error class and the OS message are printed,
        # never file content.
        print("REFUSED write: %s (%s)" % (type(e).__name__, e.strerror or "os error"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
