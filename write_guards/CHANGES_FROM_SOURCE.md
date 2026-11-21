# Notes: write_guards

Behaviour and configuration notes for this component.

- `host_paths.py`: the host-name override variable is `HOST_PATHS_HOST`; examples are generic.
- `guarded_write.py`: lock folder is `write-guards-locks-<uid>` in the system temp folder. An existing lock folder is verified (real
  directory, not a symlink, owned by the caller, no group/other bits; lock file regular, caller-owned, opened with `O_NOFOLLOW`) and
  the tool fails loudly (exit 2) otherwise. A bounded retry on `ENOENT` covers a macOS quirk where a concurrent
  `O_CREAT|O_NOFOLLOW` create can fail spuriously. `write --expect missing` (the word `hash` prints for a new file) means "the file
  must not exist yet", like `--expect-missing`; a pasted upper-case digest is accepted.
- `write_guard.py`: `safe_write` keeps the existing file's permission bits; a lock file holding JSON that is not an object is treated as
  corrupt (reclaimable) instead of crashing.
- `signal_guard.py`: explains the technical hazard only (a mock pid converting to 1 and reaching `kill(-1, SIGKILL)`). Every pid <= 1,
  including all negative values, is refused; a test documents it.
- `install_signal_guard.sh`: installs nothing unless you pass `--install --yes`; refuses to run if an unresolved placeholder token is
  present; writes file paths safely (no code injection through odd paths); uses a fixed neutral module name; reports a failure on stderr
  at Python start instead of failing silently (the warning names both installed files); verifies the guard is active after installing
  and rolls back if not; refuses unless the guard file, its folder and the checkout folder are owned by the user and not group/world
  writable (the installed boot file re-checks at every start of that Python). `--remove` and `--status` work when `signal_guard.py`
  is missing and when the script is started through a symlink.
- `write_guard.py write|append`: an OS error such as `--path` naming a directory is a one-line `REFUSED write:` message with exit 2 (no traceback).
- `write_guard.py write` limits documented (and pinned by a test): a read-only file is replaced, a hard link keeps the old content, owner/group/xattrs are not preserved.
- `README.md` and `LICENSE` (MIT, copyright TWU LLC) are included.
