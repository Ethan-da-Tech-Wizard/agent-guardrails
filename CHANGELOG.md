# Changelog

All notable changes. Dates are commit dates. This project does not use version numbers yet.

## Unreleased

- Rewrote the top-level README as a landing page with a diagram, a quick start run literally on 2026-11-21, a feature table, a configuration reference for every environment variable, test counts and limits.
- Added `docs/` with one page per component and a "How to plug in your own" section on each; the component READMEs are unchanged and still hold the full details and limits.
- Added `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue templates and a pull request template.
- No code changes: the Python and shell files are unchanged and the test suites are unchanged (stop_latch 13, write_guards 57, secret_scan_suite 125).
- Added a GitHub Actions workflow (`.github/workflows/tests.yml`) in a separate commit: stdlib `unittest` for all three components on ubuntu-latest and macos-latest, Python 3.9 and 3.12. It has not run on GitHub yet.

## 2026-11-21

- First public commit (`19ab99e`): `stop_latch`, `write_guards` and `secret_scan_suite`, each with its own README, MIT licence, notes and tests. MIT, copyright TWU LLC.
