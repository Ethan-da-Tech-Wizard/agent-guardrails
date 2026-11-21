#!/usr/bin/env python3
"""guarded_write: optimistic locking for shared files (compare-and-swap on the file's SHA-256). Stdlib only, local only.

File claims and lock conventions are advisory: nothing stops another writer. This is the enforcement a writer can opt into:

  guarded_write.py hash PATH                      print the SHA-256 of PATH (record it when you READ the file)
  guarded_write.py write PATH --expect SHA        replace PATH with stdin, but ONLY if PATH still hashes to SHA
  guarded_write.py write PATH --expect-missing    create PATH, but ONLY if it does not exist
  guarded_write.py write PATH --expect missing    same as --expect-missing (so the output of `hash` can be passed straight back)

Exit 0 written | 3 CONCURRENT MODIFICATION (file changed since you read it; nothing written; re-read, re-apply, retry) | 2 bad use, or an unsafe lock folder (message says which).
The compare and the replace happen under one per-file exclusive lock, and the replace is atomic (temp file + os.replace), so of two
writers holding the same expected hash exactly one succeeds. Limit, stated plainly: it only protects writers that call it. An
editor or script that writes the file directly is not stopped; that needs an OS permission or an editor hook.

WHY IT EXISTS
  Two tools editing one shared file can silently overwrite each other (lost update). A compare-and-swap on the content hash turns
  that silent loss into a loud, retryable error.

DESIGN NOTES
  * The lock is an flock() on a small per-target lock file kept in the system temp folder (mode 0700 directory, named by a hash
    of the resolved target path), never next to the target, so file-sync tools do not copy it. Closing the descriptor releases it,
    so a crashed writer cannot leave a stuck lock.
  * The replacement is written to a temp file in the target's own directory, fsync'ed, given the old file's permission bits
    (0644 for a new file), then renamed over the target: readers never see a half-written file.
  * An existing lock folder is NOT trusted: it must be a real directory (not a symlink), owned by the caller, with no group/other
    permission bits, and the lock file must be a regular file owned by the caller, opened with O_NOFOLLOW. Otherwise the tool exits 2
    with an explanatory message (UnsafeLockDirectory) and writes nothing. This matters on shared /tmp (Linux), where another local
    user could pre-create the predictable folder name.
  * Symlink targets are refused so a write cannot be redirected to a different file than the one that was hashed.
  * This program's own docstring is its usage message: it is printed to stderr on bad usage (exit 2).

EXAMPLE (shell)
  h=$(python3 guarded_write.py hash notes.txt)            # remember what you read
  printf 'new text\n' | python3 guarded_write.py write notes.txt --expect "$h"
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import sys
import tempfile
import time
from pathlib import Path


class ConcurrentModification(Exception):
    """The file's content is no longer the content the writer read."""


def sha256_of(path) -> str | None:
    """Return the hex SHA-256 of the file's bytes, or None if the file does not exist.

    Reads the whole file into memory; intended for small shared text/config files.
    """
    p = Path(path)
    if not p.exists():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


class UnsafeLockDirectory(ValueError):
    """The per-user lock folder (or a lock file in it) is not safe to use: wrong owner, group/world accessible, or a symlink.

    Raised loudly instead of silently trusting whatever is at that path. A shared temp folder lets another local user
    pre-create the folder name (or plant a symlink there) so that this process would lock, or create files, somewhere they chose.
    """


def _lock_dir_name() -> str:
    """Return the per-user lock folder path (uid in the name; in the system temp folder, never next to the target so sync tools ignore it)."""
    return os.path.join(tempfile.gettempdir(), "write-guards-locks-%d" % os.getuid())


def _open_lock_fd(path: Path) -> int:
    """Open (creating if needed) the lock file for `path` and return its descriptor, after verifying the lock folder is safe.

    The name is the first 32 hex chars of SHA-256 of the resolved path, so two spellings of the same file share one lock.

    Checks, in this order, on an ALREADY EXISTING lock folder as well as a new one (a pre-existing folder is the attack):
      1. it is opened with O_NOFOLLOW|O_DIRECTORY, so a symlink or a non-directory is refused outright;
      2. fstat of that open descriptor (no check-then-use race): owner uid must be ours, and mode must have no group/other bits;
      3. the lock file is opened relative to that descriptor with O_NOFOLLOW, and must be a regular file owned by us.
    Any failure raises UnsafeLockDirectory with an explanation and the fix; nothing is locked and nothing is written.
    """
    d = _lock_dir_name()
    try:
        os.mkdir(d, 0o700)               # a new folder gets owner-only mode (subject to umask, which can only tighten it)
    except FileExistsError:
        pass                              # already there: it is NOT trusted until the checks below pass
    try:
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise UnsafeLockDirectory("lock folder %s is not a plain directory (symlink or not a folder: %s); refusing to use it. "
                                  "Remove it yourself after checking who created it." % (d, exc.strerror)) from exc
    try:
        st = os.fstat(dfd)
        if st.st_uid != os.getuid():
            raise UnsafeLockDirectory("lock folder %s is owned by uid %d, not by you (uid %d); refusing to use it. "
                                      "Another local user may have created it." % (d, st.st_uid, os.getuid()))
        if st.st_mode & 0o077:
            raise UnsafeLockDirectory("lock folder %s has mode %03o: group/other access is not allowed (need 700); refusing to use it. "
                                      "Fix with: chmod 700 %s" % (d, st.st_mode & 0o777, d))
        name = hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:32] + ".lock"
        # Retry on ENOENT: when two processes create the same new lock file at the same instant, macOS can fail one O_CREAT|O_NOFOLLOW
        # open with ENOENT even though the file now exists (observed: the two-process race test failed ~1 in 3 without this). The
        # retry is bounded and ELOOP (a planted symlink) or any other error is NOT retried.
        for attempt in range(50):
            try:
                fd = os.open(name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
                break
            except FileNotFoundError:
                if attempt == 49:
                    raise UnsafeLockDirectory("cannot create lock file %s/%s (still missing after retries); refusing to continue" % (d, name))
                time.sleep(0.002)
            except OSError as exc:
                raise UnsafeLockDirectory("cannot open lock file %s/%s safely (%s); refusing to continue" % (d, name, exc.strerror)) from exc
        lst = os.fstat(fd)
        if not stat.S_ISREG(lst.st_mode) or lst.st_uid != os.getuid():
            os.close(fd)
            raise UnsafeLockDirectory("lock file %s/%s is not a regular file owned by you; refusing to use it" % (d, name))
        return fd
    finally:
        os.close(dfd)


def write_if_unchanged(path, data: bytes, expected_sha256: str | None) -> str:
    """Write `data` to `path` iff it still hashes to `expected_sha256` (None = must not exist). Returns the new SHA-256."""
    p = Path(path)
    # Refuse symlinks: the hash we compare and the file we replace must be the same object.
    if p.is_symlink():
        raise ValueError("refusing to write through a symlink: %s" % p)
    fd = _open_lock_fd(p)   # verifies the lock folder (owner, mode, not a symlink) first; raises UnsafeLockDirectory
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # blocks until any other guarded writer finishes
        # Compare while holding the lock: no other guarded writer can change the file between this check and the replace.
        current = sha256_of(p)
        if current != expected_sha256:
            raise ConcurrentModification("%s changed since it was read (expected %s, found %s); nothing written"
                                         % (p, (expected_sha256 or "missing")[:12], (current or "missing")[:12]))
        # (Known, harmless race: is_symlink() above and the replace below are not one atomic step. os.replace swaps the directory
        # entry itself, so even if a symlink appeared in between it would be replaced, never followed to another file.)
        # Keep the existing permission bits (NamedTemporaryFile would otherwise use 0600); new files get 0644.
        mode = p.stat().st_mode & 0o7777 if p.exists() else 0o644
        tmp = tempfile.NamedTemporaryFile(dir=p.parent, prefix=".gw-", delete=False)
        try:
            with tmp:
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.chmod(tmp.name, mode)
            os.replace(tmp.name, p)
        except BaseException:  # clean up the temp file on any failure, then re-raise
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
            raise
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(fd)     # closing releases the flock


def main(argv=None) -> int:
    """Command-line entry point. Returns the exit code: 0 ok, 3 concurrent modification, 2 bad use or I/O error.

    Args:
        argv: argument list (defaults to sys.argv[1:]); see the module docstring for the three forms.
    """
    a = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(a) == 2 and a[0] == "hash":
            print(sha256_of(a[1]) or "missing")  # prints "missing" when the file does not exist
            return 0
        if len(a) == 4 and a[0] == "write" and a[2] == "--expect":
            # `hash` prints the word "missing" for a file that does not exist, so accept that word as "must not exist"
            # (None). A real digest is compared case-insensitively (we store lower-case hex), so an upper-case paste works.
            expected = None if a[3].strip().lower() == "missing" else a[3].strip().lower()
        elif len(a) == 3 and a[0] == "write" and a[2] == "--expect-missing":
            expected = None
        else:  # any other shape of arguments: show usage
            print(__doc__, file=sys.stderr)
            return 2
        print(write_if_unchanged(a[1], sys.stdin.buffer.read(), expected))
        return 0
    except ConcurrentModification as exc:
        print("CONCURRENT MODIFICATION: %s" % exc, file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print("guarded_write: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
