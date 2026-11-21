# Notes: secret_scan_suite

Behaviour and configuration notes for this component.

- Environment variables: `SECRET_SCAN_CACHE`, `SECRET_SCAN_DIR`, `SECRET_SCAN_SKIP_DIRS`, `SECRET_HOOK_REDACTIONS_FILE`,
  `SECRET_HOOK_LOCAL_HOST_OK`, `SECRET_HOOK_EXTRA_DISTRO_WORDS`, `SECRET_HOOK_SKIP`. The cache default is `~/.cache/secret_scan/`.
- `secret_scan.py check` / `accept` take an optional `PATH`; with none they scan the CURRENT DIRECTORY. The scan target and state
  folder are printed. The library functions `files`, `scan`, `check`, `accept` have no default tree. A folder that is not a git work
  tree gives a clean error (exit 2 for `accept`, a PROBLEM line and exit 1 for `check`), never a traceback.
- Scanner state (baseline, receipt) lives in a per-user folder: `$SECRET_SCAN_DIR`, else `$XDG_STATE_HOME/secret_scan`, else
  `~/.local/state/secret_scan`; a state folder inside the component folder is refused. The folder is created `0700`, files `0600`,
  written through an exclusive no-symlink temp file.
- Only the scanner's own two files (exact path) are exempt from scanning; a file with the same name elsewhere is scanned.
  `SECRET_SCAN_SKIP_DIRS` entries match whole folders.
- Installed git hooks do not skip scanning when a generic `SKIP` variable is set; the explicit `SECRET_HOOK_SKIP` skips and prints a
  loud warning. If python or the script is missing the hook warns loudly and lets git continue (documented behaviour). The hook's
  temporary file honours `TMPDIR`. Hook files are replaced atomically, never written through a symlink.
- Diff parsing in the hooks is a hunk-count state machine that splits on `\n` only, so file content cannot be mistaken for a diff
  header and exotic line separators cannot hide an added line; pre-push reads file names with `-z` so quoted names still match the
  sensitive-name rules; explicit `a/` `b/` prefixes make the output independent of `diff.noprefix` / `diff.mnemonicPrefix`.
- MAC-address and host-name findings print `-` instead of a fingerprint (a hash of a guessable value can be reversed).
- Host-name rules: the built-in list of distro words is generic; the allowed `*.local` names, extra distro words and optional private
  host-name files (`redactions.json`, `host_roles.json`, `retired_hosts.json`) are configuration, empty by default.
- `home_secret_scan.py`: the MySQL password pattern covers `mysql`, `mysqldump`, `mysqladmin`; a truncated scan is recorded as
  `"complete": false`, reported by the alarm view and makes `check` exit 1; it refuses a state folder inside the component.
- Test fixtures: key-shaped strings are assembled from pieces at runtime; the second AWS-style fixture is an obviously synthetic
  value; the MAC fixture is a locally assigned address; host-name fixtures are generic. One private-key header literal is split.
- `home_secret_scan.py` fingerprints of human-chosen secrets are HMAC-SHA256 under a random per-user key (`homesecrets_fpkey`, mode 0600, in the state folder).
- Hooks: diff/log calls pass `--text --no-textconv --inter-hunk-context=0` and `-c diff.suppressBlankEmpty=false` (and noprefix / mnemonicPrefix off); an empty line inside a hunk is context and a `+` line outside a valid hunk is still scanned; a push to a URL scans the full history; commit messages are scanned at push; the sensitive-file-name list is broader (`SECRET_HOOK_ALLOW_NAMES` exempts a name); install refuses a symlinked `.git/hooks`; `status` reports `INACTIVE` when `core.hooksPath` is set.
- Hooks, later hardening: the diff filter includes type changes (`T`); the push scan passes `--root`; dash/underscore `.env` variants, `*.env`, backup endings of credential files and any-suffix `id_*` key names are blocked; Python attribute/call uses of `.local` are not host names while `*.local.lan` is; `status` says `UNSAFE` for a symlinked hooks folder. `home_secret_scan.py` validates its key file (symlink/directory/owner refused, 0600 enforced, corrupt key needs `--regenerate-key`).
- `secret_scan.py`: every match on a line is judged; `_`-adjacent tokens and `BEGIN ENCRYPTED PRIVATE KEY` are found; the cache file is 0600.
- `README.md` and `LICENSE` (MIT, copyright TWU LLC) are included.
