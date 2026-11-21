# write_guards

Small, standard-library-only safety tools for programs that write files and send signals.

| file | what it does |
|---|---|
| `scripts/write_guard.py` | single-writer lock files and task-root path validation: refuses writes that resolve outside a declared root, blocks a second writer while a lock is held, reclaims stale locks |
| `scripts/guarded_write.py` | optimistic locking (compare-and-swap on a file's SHA-256) so two writers cannot silently overwrite each other |
| `scripts/host_paths.py` | per-host file names (`LATEST.json` becomes `LATEST.<host>.json`) so two computers never write the same synced file |
| `scripts/signal_guard.py` | while a unittest is running, refuses `os.kill`/`os.killpg` calls that could hit every process you own (pid 0/1/-1, mocks, your own process group or parent) |
| `scripts/install_signal_guard.sh` | optional installer that loads `signal_guard.py` at start-up of one Python installation's user site (read the warning below first) |

## Why this exists
When several programs (or people, or machines) edit the same files, the last writer silently wins and the others' work is
lost; a lock that nobody checks does not help; file-sync tools make "conflict copies" when two computers write the same
file; and a single test that passes a mock process object to `os.kill`/`os.killpg` can turn into `kill(-1, SIGKILL)`, which
ends your whole login session. These small tools turn each of those silent failures into a loud, early, retryable error:
a single-writer lock plus path validation, compare-and-swap writes, per-host file names, and a test-time signal safety net.

## Install
Copy `scripts/` into your project (or put it on `PYTHONPATH`). Python 3.9+, standard library only. POSIX only
(`fcntl`, signals).

## Usage
```sh
python3 scripts/write_guard.py write --path /work/out.txt --task-root /work --agent me < data.txt   # exit 0 ok, 2 outside root, 75 blocked by lock
python3 scripts/write_guard.py lock-status --root /work
python3 scripts/write_guard.py reclaim-stale --root /work
python3 scripts/guarded_write.py hash FILE
python3 scripts/guarded_write.py write FILE --expect <sha256> < new_content     # exit 3 = changed since you read it
python3 scripts/guarded_write.py write NEWFILE --expect missing < content       # new file: `hash` prints "missing"; same as --expect-missing
```
```python
import host_paths; host_paths.per_host("data/x/LATEST.json")      # data/x/LATEST.<host>.json
import signal_guard; signal_guard.install()                       # e.g. from a test runner or sitecustomize
```

## Configuration
| env var | effect |
|---|---|
| `HOST_PATHS_HOST` | overrides the host name used by `host_paths` |
| `WRITE_GUARD_HOLD_S` | test hook: hold the lock for N seconds in the CLI |

`guarded_write.py` keeps its lock files in `<system temp>/write-guards-locks-<uid>`. If that folder already exists it is NOT
trusted: it must be a real directory (not a symlink), owned by you, with mode 700 (no group/other access), and the lock file
must be a regular file owned by you; otherwise the command exits 2 with a message and writes nothing (this protects shared
`/tmp` on Linux, where another user could pre-create the name). `write_guard.py` keeps its locks under `<root>/data/locks`
inside the root you give it; if you omit `--root` that is `<task-root>/data/locks`, i.e. inside the very folder you are protecting.
`write_guard.py` keeps the permission bits of an existing file when it replaces it (a new file gets the usual `0666 & ~umask`),
and treats a lock file whose JSON is not an object as corrupt (reclaimable).

## install_signal_guard.sh: what it installs (opt-in, persistent)
By default it only reports status. `install_signal_guard.sh --install --yes` writes two small files into your user-level
Python site-packages folder: `write_guards_signal_guard_boot.py` and `write_guards_signal_guard.pth`. A `.pth` line that
starts with `import` is executed at start-up of every Python process that reads THAT folder. What that covers exactly: the
user site of the `python3` that is first on your PATH when you run the installer (for example
`~/Library/Python/3.9/lib/python/site-packages`), so only that minor version, for your user. Other Python versions, virtual
environments, and runs with `-S` or `-I` do not read it. Within that scope it is a persistent side effect. It records the
absolute path of your checkout's `signal_guard.py`; if that file moves or is deleted you will see a warning on stderr at every
start of that Python (naming both installed files) until you run `--remove`. `--remove` and `--status` work even when
`signal_guard.py` is gone, and when the script is started through a symlink; if the script itself is gone, delete the two
files named in the warning by hand. The script refuses to run if an unresolved placeholder token
is present, passes paths safely (quotes and backslashes cannot inject code), verifies the guard is active after
installing and rolls back if not. It is not needed to use anything else here.

**Code-execution risk.** Because the `.pth` runs `signal_guard.py` from your checkout at every start of that Python, anyone who can
write to that file, to `scripts/`, or to the checkout folder (another user in a group-writable folder, or anyone if it is
world-writable) can run arbitrary code as you. So the installer refuses unless the guard file, its `scripts/` folder and the
checkout folder are owned by you and not writable by group or others, and the installed boot file re-checks this at every
Python start and declines to load the guard (with a warning) if it stops being true. Keep the checkout owner-only
(for example `chmod -R go-w`), and do not install from a location other people can write to. Remove it with `--remove`.

## Placeholders

None: nothing in this component needs to be filled in; configuration is by environment variables only.

## Run all tests (no CI needed)

```sh
cd write_guards
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

Python 3.9 or newer, standard library only, no network, no packages to install. The command above is all you need.
(The maintainers also run the suites through an optional isolating runner, `hermetic_run.py`, from the release-kit repository at https://github.com/Ethan-da-Tech-Wizard/release-kit; it is not part of this repository and nothing here depends on it.)

## Status and limits
- `write_guard.py write|append` exit codes: 0 ok, 2 refused (path outside the root, or an OS error such as `--path` naming a directory), 75 blocked by a lock.
- `write_guard.py write` replaces a file by renaming a new file over it. So a read-only file (mode 0444 or 0000) IS overwritten
  (the read-only mode is kept on the new file, so it still looks protected), and a hard link to the old file keeps the OLD
  content (the link is no longer the same file). Permission bits are preserved; owner, group and extended attributes are not.
  Use a lock-and-compare-and-swap discipline, not file modes, to protect a file from this tool.
- Locks and compare-and-swap only protect writers that use them; an editor or script that writes directly is not stopped.
- Lock liveness uses pid checks on one machine; it is not a distributed lock and NFS/sync-folder behaviour is unverified.
- The lock-folder checks are tested on macOS only; the Linux shared-`/tmp` scenario they target is simulated (wrong mode, symlink, fake uid), not run on Linux.
- `signal_guard` only acts while `unittest` is imported; it is a safety net, not a sandbox.
- The installer's ownership/permission check covers the guard file, `scripts/` and the checkout folder, not the checkout's parent
  folders or the user site folder itself; keep those owner-only too.
- Status: small, working, used for its purpose; tested on macOS, Python 3.9: 57 tests, all pass. Linux untested here. The
  installer was exercised with a throw-away `PYTHONUSERBASE` (install, verify, remove, remove with the guard missing, run through a symlink, path with a quote, placeholder refusal, refusal of group/world-writable checkouts).
- Licence: MIT, copyright TWU LLC. Notes: `CHANGES_FROM_SOURCE.md`.
