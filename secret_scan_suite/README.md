# secret_scan_suite

Three cooperating tools that find credentials without ever printing them. Findings are `file:line TYPE fingerprint`,
where, for token-shaped matches (high-entropy: AWS, GitHub, ...), the fingerprint is the first 10 hex characters of a SHA-256 of the match.
(MAC-address and host-name findings print `-` instead: a hash of such a guessable value could be brute-forced back to the value.
In the home scan, findings for human-chosen secrets (passwords in netrc / pypirc / npmrc / git-credentials, `--password` flags,
`mysql -p`, `curl -u`, literal assignments, bearer values, docker auth) use the first 10 hex characters of an HMAC-SHA256 under a random
per-user key stored `0600` in the state folder (`homesecrets_fpkey`), because a plain hash of a short password can be reversed with
a word list. Those fingerprints are stable on your machine only; deleting the key file makes earlier `accept` entries stop matching. The key file must be a regular file you own: a symlink or directory there is refused (exit 2), a group/world-readable key is tightened to `0600` with a warning, and a corrupt key is never replaced silently: `home_secret_scan.py check --regenerate-key` is required, and it invalidates earlier accepts.)

| file | what it does |
|---|---|
| `scripts/secret_scan.py` | scans a git work tree (tracked plus untracked-not-ignored text files under 1 MB) for key-shaped strings (AWS, GitHub, Anthropic, OpenAI, Google, Slack, Stripe, private-key blocks, WireGuard keys); keeps an accepted-fingerprint baseline and a receipt |
| `scripts/git_secret_hook.py` | prevents a leak: installs chained `pre-commit` / `pre-push` hooks that scan only ADDED lines (including lines of files git calls binary: a NUL byte or a `-diff` attribute does not hide them), commit messages (at push),, block sensitive file names (`.env`, `.env-production` / `.env_prod` (a dash or underscore after `.env`), `production.env`, `.envrc`, `.netrc`, `.npmrc`, `.pypirc`, `.pgpass`, `.git-credentials`, `id_rsa*` with any suffix and the other key names except `*.pub`, `secrets.json`, `service-account.json`, `.aws/credentials`, `.kube/config`, `.docker/config.json`, `kubeconfig`, `*.tfstate`, `*.pem`/`*.key`/`*.p12`/`*.pfx`/`*.jks`/`*.kdbx` (also with a backup ending such as `.bak`, `.old`, `.orig`, `~`), and the optional host-name lists below; templates such as `.env.example` / `.env-example` are allowed; the list is short, not exhaustive), MAC addresses and `*.local` / `*.local.lan` host names (Python code such as a call to a threading-local factory, or an import path ending in `.local`, is not a host name), and optional private host names; can lock a repository so every push fails |
| `scripts/home_secret_scan.py` | scans your home folder outside any repository (shell history, rc files, dotfile configs, Downloads/Desktop/Documents, loose key files) |

## Why this exists
Credentials end up in files by accident: pasted into a note, left in a script, exported in a shell rc file. The expensive
mistake is committing or syncing them, because once a secret is pushed it must be treated as public and rotated. Scanning
after the fact is too late, and scanners that print what they find create a second leak in logs and terminals. These tools
check before commit/push, and scan the home folder where git never looks, and report only a file, a line, a rule name and a
short fingerprint: never the secret.

## Install
Copy `scripts/` anywhere. Python 3.9+, standard library plus the `git` command. Nothing to install.
Optional: `python3 scripts/git_secret_hook.py install /path/to/repo` (adds hooks to that repo only; no global git config
is touched; an existing hook is kept as `<name>.pre-secret-hook` and still runs; refuses, with a warning, if `core.hooksPath` is set or `.git/hooks` is a symlink; `status` reports `INACTIVE` for a repository whose `core.hooksPath` was set after install and `UNSAFE` for one whose `.git/hooks` is a symlink).

## Usage
```sh
python3 scripts/secret_scan.py check            # scan the CURRENT DIRECTORY; exit 1 if any NEW finding
python3 scripts/secret_scan.py check /path/repo # or scan an explicit folder (the folder holding scripts/ is never scanned implicitly)
python3 scripts/secret_scan.py accept [PATH]    # record current findings as known (rotate real keys first!)
python3 scripts/git_secret_hook.py install REPO...   |  uninstall REPO...  |  status REPO... | --under DIR
python3 scripts/git_secret_hook.py lock REPO     # every push from REPO fails; reports remotes   (unlock to undo)
python3 scripts/home_secret_scan.py check [--regenerate-key] | report | status | accept FP --reason TEXT
```
A line containing `secret-scan:allow` is skipped (reviewed test fixtures). `git commit --no-verify` always bypasses.

## Configuration (all optional, all environment variables)
| env var | effect |
|---|---|
| `SECRET_HOOK_SKIP` | any non-empty value makes INSTALLED hooks skip the scan for that command, with a loud stderr warning. (A generic `SKIP` variable is deliberately NOT honoured.) |
| `SECRET_HOOK_REDACTIONS_FILE` | JSON `{"hosts": ["name", ...]}` of private host names to block |
| `SECRET_HOOK_LOCAL_HOST_OK` | comma-separated `*.local` names that are allowed in committed text |
| `SECRET_HOOK_ALLOW_NAMES` | comma-separated file BASE names exempt from the sensitive-file-name check (for example a reviewed project `.npmrc` that holds no token) |
| `SECRET_HOOK_EXTRA_DISTRO_WORDS` | comma-separated extra words (Linux distro names) treated as prose unless next to host words |
| `SECRET_SCAN_DIR` | folder for receipts and baselines (default: `$XDG_STATE_HOME/secret_scan`, else `~/.local/state/secret_scan`; a folder inside this component is refused) |
| `SECRET_SCAN_CACHE` | scan cache file (default `~/.cache/secret_scan/secret_scan_cache.json`) |
| `SECRET_SCAN_SKIP_DIRS` | comma-separated repo-relative folder prefixes to skip (default none) |

Optional JSON files (or an absolute path in `SECRET_HOOK_REDACTIONS_FILE`) add private host names. **Those files contain exactly the
names you want to keep private, so keep them OUT of any public repository:** prefer `SECRET_HOOK_REDACTIONS_FILE=~/somewhere-private/redactions.json`;
if you do put them next to the scripts (or in `../data/`), the repository's `.gitignore` already lists `redactions.json`, `host_roles.json`
and `retired_hosts.json`, and the hook also blocks committing files with those names. The formats are: `redactions.json`
`{"hosts": [...]}`, `host_roles.json` `{"hosts": {"name": {"aliases": [...], "nickname": "..."}}}`, `retired_hosts.json`.
Missing files are skipped. Messages and receipts never contain the names, and host-name / MAC findings carry no fingerprint (`-`),
because a hash of a short, guessable name can be reversed. File and line are still shown.

## What it reads and writes
- `secret_scan.py` / `home_secret_scan.py`: read the files described above; write JSON receipts and baselines
  (fingerprints only; the home scan also keeps its random fingerprint key there) to the per-user state folder (`SECRET_SCAN_DIR`, default `~/.local/state/secret_scan`; never inside the
  component folder or the scanned tree unless you point `SECRET_SCAN_DIR` there yourself), and the cache file. Every `check` prints the folder it
  scanned and the state folder it used (the home scan prints the home folder). `home_secret_scan.py`
  reads shell history, `~/.config`-style dotfiles, Downloads/Desktop/Documents and key files, never `~/Library` or the keychain, and never follows symlinks.
- `git_secret_hook.py`: `install`/`uninstall`/`lock`/`unlock` rewrite hook files in the repositories you name; `status`
  with no arguments or `--under` walks the directory tree (default your home folder, depth 6) looking for repositories.

## Placeholders

None: nothing in this component needs to be filled in; configuration is by environment variables only.

## Run all tests (no CI needed)

```sh
cd secret_scan_suite
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

Python 3.9 or newer, standard library only, no network, no packages to install. The command above is all you need.
(The maintainers also run the suites through an optional isolating runner, `hermetic_run.py`, from the release-kit repository at https://github.com/Ethan-da-Tech-Wizard/release-kit; it is not part of this repository and nothing here depends on it.)

## Status and limits
- Regex heuristics: key shapes only; a clean result means "nothing known was found", not "safe". Placeholder-looking
  values (containing `example`, `xxxx`, `<...>`) are ignored by design.
- The hook inspects added lines of staged/pushed commits only; it cannot see secrets in history that was already pushed. A push to a
  URL (rather than a configured remote name) scans the whole pushed history, because what that target already has is unknown.
- UTF-16 / UTF-32 files are NOT detectable (the characters of a token are separated by NUL bytes). Large binary files are scanned as text
  too, which can be slow (measured: a 30 MB random binary file takes about 24 s, a 400,000-line text file about 48 s); a scan that exceeds 120 s blocks (fails closed).
- The hook has no `://user:password@host` content rule (only `home_secret_scan.py` does) and never claims to find every credential file name; the name list is a short list. Type changes (a symlink replaced by a regular file, or the reverse) are scanned like any other change, and a root commit is scanned at push even when `log.showRoot` is false.
- Commit messages are scanned at push, not at commit time, and tag / branch names and annotated-tag messages are not scanned. Content that exists ONLY in a
  merge commit's conflict resolution is not scanned at push (it is seen by pre-commit when the merge is committed with hooks on).
- The MAC-address and host-name rules were tuned on a small sample and can false-positive on prose elsewhere, and a few real host spellings (a `.local` name followed by further domain labels) are missed; use `secret-scan:allow` or the env options. Config file names that carry a `local` part (the dotenv local-override file, local settings JSON or YAML files) are not treated as host names.
- Every match on a line is judged on its own (a placeholder before a real key does not hide it), but lines over 4000 characters are skipped, and a token split over two lines is not seen. Not covered: JWTs, GitLab `glpat-`, Hugging Face `hf_`, SendGrid, AWS secret keys, generic `PASSWORD=` values, and base64/hex/percent-encoded tokens.
- The scan cache is keyed on file size and modification time; a tool that rewrites a file keeping both identical could go unnoticed until the cache file is deleted.
- `home_secret_scan.py check` has a 20 s / 2500-files-per-tree budget; when it is hit the receipt says `"complete": false`, the alarm view reports `homesecrets:scan-truncated` and `check` exits 1.
- State files and the scan cache are created owner-only (a new folder 0700, files 0600); an already existing folder keeps its mode (the files inside are still 0600); point `SECRET_SCAN_DIR` at a private folder.
- The hook does nothing when git does not run it: `git commit --no-verify`, `git -c core.hooksPath=...`, a `core.hooksPath` set after install, `SECRET_HOOK_SKIP`, or no `python3` on the PATH of the process that runs git (some GUI git clients; the installed hook then prints `secret scan SKIPPED` and exits 0). `git_secret_hook.py status` shows `INACTIVE` when `core.hooksPath` is set.
- Fixture credentials in the tests are assembled from pieces at runtime; they are synthetic (one is the public AWS
  documentation example).
- Status: usable, small, regex-based; tested on macOS, Python 3.9: 125 tests, all pass. Linux untested here.
- Licence: MIT, copyright TWU LLC. Notes: `CHANGES_FROM_SOURCE.md`.
