# Release set: stop_latch, write_guards, secret_scan_suite

Three small, independent, standard-library-only Python components (Python 3.9+, POSIX), each in its own folder with its
own README, LICENSE, tests and change notes.

| component | one line |
|---|---|
| `stop_latch/` | one shared STOP file that makes cooperating worker processes refuse to start or shut down |
| `write_guards/` | single-writer locks, compare-and-swap writes, per-host file names, and a test-time signal safety net |
| `secret_scan_suite/` | credential scanner, git pre-commit/pre-push leak prevention, and home-folder scan; never prints secrets |

Each folder is self-contained: `cd <component> && python3 -B -m unittest discover -s scripts -p 'test_*.py'` runs its tests
(no network, nothing to install, no CI). Components do not import each other. Only plain `python3` and `unittest` are needed.

## Files in every component
`README.md` (why it exists, install, usage, config, status and limits) - `LICENSE` (MIT) - `CHANGES_FROM_SOURCE.md` (notes on
behaviour and configuration) - `ANNOTATIONS.json` (an empty machine-readable placeholder list that the release tooling requires; it lists no placeholders) - `scripts/` (code and tests).

## Status
No placeholders are needed: nothing has to be filled in, because every setting is an optional environment variable (see each component's README).
All three pass their tests on macOS with Python 3.9, as shipped (stop_latch 13 tests, write_guards 57, secret_scan_suite 125). Not verified on Linux. Licence: MIT, copyright TWU LLC.

The optional isolating test runner (`hermetic_run.py`) and the annotation helper used by the maintainers live in the release-kit repository at https://github.com/Ethan-da-Tech-Wizard/release-kit; nothing here depends on them.

Contact: ethan@twu.software
https://twu.software
