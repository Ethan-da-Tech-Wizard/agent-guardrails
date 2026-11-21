# Notes: stop_latch

Behaviour and configuration notes for this component.

- Default location of the STOP file is `<root>/STOP`, where `<root>` is the parent of the folder that contains `stop_latch.py`
  (the `scripts/` folder in this layout). Two environment variables change it: `STOP_LATCH_ROOT` (folder) and `STOP_LATCH_FILE`
  (exact file path; wins over the folder). The README explains what the default means if you copy the file elsewhere.
- The watcher thread survives an unreadable STOP location (for example `PermissionError`): it warns once on stderr and keeps
  polling. The entry check reports the error loudly instead of treating it as "absent".
- Comments and documentation are written to be self-explanatory; the component has no dependency on other tools.
- Tests cover the default path, the `STOP_LATCH_FILE` override, refusing to start, stopping a running worker, a worker that ignores
  SIGTERM, a custom callback, an unreadable folder and a missing parent folder.
- A relative `STOP_LATCH_FILE` is made absolute once at import; a symlink at the STOP path (even dangling) counts as present; a raising `on_stop` callback falls back to the default stop.
- `..` in `STOP_LATCH_FILE` is no longer collapsed textually (it is resolved by the OS, so it works through symlinks); `~` is expanded in `STOP_LATCH_ROOT`.
- `README.md` and `LICENSE` (MIT, copyright TWU LLC) are included.
