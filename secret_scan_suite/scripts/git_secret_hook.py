#!/usr/bin/env python3
"""git_secret_hook: PREVENT a credential from being committed or pushed (secret_scan.py only detects leaks after the fact).

Why it exists: scanning a repository after a secret is committed is too late once it is pushed. This script runs
as a git hook so the leak is stopped before it leaves the working copy, and it never prints the secret itself.

  git_secret_hook.py pre-commit              scan ADDED lines of the staged diff + staged sensitive file names
  git_secret_hook.py pre-push REMOTE [URL]   (git's pre-push stdin) scan commits about to leave the machine
  git_secret_hook.py install REPO...         write chained .git/hooks/pre-commit + pre-push (existing hook kept as <name>.pre-secret-hook)
  git_secret_hook.py uninstall REPO...       remove our hooks, restore the saved ones
  git_secret_hook.py lock REPO... | unlock   private repo: pre-push ALWAYS fails, and no remote may exist (exit 1 if one does)
  git_secret_hook.py status REPO... | --under DIR   which repos have it (default DIR: ~)

Output is file:line TYPE fingerprint, never the secret. A line containing `secret-scan:allow` is skipped (reviewed fixtures).
Failure policy: git missing -> loud warning, exit 0 (never wedge the user); a real finding -> exit 1; git erroring -> exit 1.
Bypass in an emergency: git commit/push --no-verify, or set SECRET_HOOK_SKIP=1 for one command (installed hooks then print a loud warning).
Optional config (all env, all default off): SECRET_HOOK_REDACTIONS_FILE, SECRET_HOOK_LOCAL_HOST_OK, SECRET_HOOK_EXTRA_DISTRO_WORDS,
SECRET_HOOK_ALLOW_NAMES (comma-separated file BASE names exempt from the sensitive-file-name check, e.g. a reviewed project .npmrc).
Only touches repos explicitly passed to install; no global config.

What is NOT checked (limits, stated plainly):
  * UTF-16 / UTF-32 files: the text is stored as 2 or 4 bytes per character, so a token's characters are separated by NUL bytes
    and no pattern matches. Such files are not detectable by this tool.
  * Commit messages ARE scanned at push (pre-push), but NOT at commit time (no commit-msg hook is installed). Tag names, branch
    names and annotated-tag messages are not scanned.
  * Merge commits are not diffed at push: content that exists ONLY in a merge's conflict resolution is not scanned at push
    (pre-commit does see it when the merge is committed with hooks on, because it diffs against HEAD).
  * Lines longer than 4000 characters are skipped (minified or encoded blobs); a token split across two lines is not seen.
  * The hook silently does nothing when it is not run by git: `git -c core.hooksPath=...`, a core.hooksPath set AFTER install,
    --no-verify, SECRET_HOOK_SKIP=<anything non-empty>, or no python3 on the PATH of the process that runs git (some GUI git
    clients). In the python3-missing case the installed hook prints "secret scan SKIPPED" and exits 0 (never wedges a commit).

Design / threat-model notes:
  * Only ADDED lines are scanned (diff with zero context), so pre-existing content never blocks unrelated work.
  * Detection reuses the rules in the sibling module secret_scan; this file adds identity checks (MAC addresses,
    ".local" host names, and private host names from optional JSON lists) and sensitive file-name checks.
  * Token findings carry a short hash fingerprint, so logs and terminals never hold the secret. MAC and host-name
    findings print "-" instead (a hash of such a guessable value could be reversed).
  * Installing never overwrites a foreign hook (it is renamed and chained) and refuses repos that set a custom
    hooks path. The hook is a guard against accidents, not against a determined user: --no-verify bypasses it.
  * "lock" is for repos that must never be published: every push fails and a configured remote is reported.

Example:
    python3 git_secret_hook.py install ~/code/myrepo     # protect one repository
    python3 git_secret_hook.py status --under ~/code     # see which repos are protected
    python3 git_secret_hook.py pre-commit                # run by hand inside a repo with staged changes
"""
from __future__ import annotations
import json, hashlib, os, re, subprocess, sys
from pathlib import Path

# Make the sibling module importable no matter what directory the hook is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan  # shared RULES / PLACEHOLDER / scan_text

# Absolute path of this script; embedded into generated hooks so they call back into it.
SELF = Path(__file__).resolve()
# First-line tag written into generated hooks so install/uninstall can tell our hooks from foreign ones.
MARKER = "# secret-hook v1"
# A added line containing this text is skipped (for reviewed test fixtures).
ALLOW = "secret-scan:allow"
# The two git hook names this tool manages.
HOOKS = ("pre-commit", "pre-push")
# The all-zero object id git uses in pre-push input for "no such ref" (new branch or deletion).
ZERO = "0" * 40
# File-name endings marking templates (e.g. ".env.example") that may be committed even if the base name is sensitive.
SAFE_SUFFIX = (".example", ".sample", ".template", ".dist", ".tpl")
# Exact (lower-case) file names that normally hold credentials and must not be committed.
SENSITIVE_NAMES = {".env", ".envrc", ".netrc", "_netrc", ".npmrc_auth", ".npmrc", ".pypirc", ".pgpass", ".htpasswd", ".git-credentials",
                   "credentials.json", "secrets.json", "secrets.yml", "secrets.yaml", "service-account.json", "service_account.json",
                   "kubeconfig", "secring.gpg", "terraform.tfstate", "terraform.tfstate.backup",
                   # M5: optional private host-name lists (see _private_hosts) hold exactly the names they exist to hide.
                   "redactions.json", "host_roles.json", "retired_hosts.json"}
# (parent folder, file name) pairs that are credential files only inside that folder: ~/.aws/credentials, ~/.docker/config.json,
# ~/.kube/config. The bare names ("credentials", "config", "config.json") are far too common to block everywhere.
SENSITIVE_IN_DIR = {(".aws", "credentials"), (".docker", "config.json"), (".kube", "config")}
# Private-key file names and their variants: id_rsa, id_rsa.bak, id_rsa_old, id_ed25519-backup ... (a name ending in ".pub" is a
# public key and is exempt, see sensitive_name). Also .git-credentials.* backups.
# N3: for the private-key names ANY suffix counts (id_rsa2, id_ed25519_work, id_rsa~): a key name followed by whatever is still a key.
# ".git-credentials" keeps the separator rule because ".git-credentialsx" is not a known variant.
SENSITIVE_PREFIX = re.compile(r"^(?:id_(?:rsa|dsa|ecdsa|ed25519)|\.git-credentials(?:$|[._-]))")
# N3: dotenv variants written with a dash or underscore (".env-production", ".env_prod"): ".env" followed by "-" or "_".
ENV_DASH = re.compile(r"^\.env[-_]")
# N3: dotenv file named "<something>.env" (production.env, prod.env). Exact ".env" is already in SENSITIVE_NAMES.
# Template spellings of the dash style (".env-example", ".env_sample") are exempt, like ".env.example".
ENV_SAFE = re.compile(r"[-_](?:example|sample|template|dist|tpl)$")
# N3: editor / manual backup endings. A backup of a credential file (x.pem.bak, private.key.old, secrets.json~) is as sensitive as the
# file; the ending is stripped (repeatedly) before the name rules run.
BACKUP_SUFFIX = (".bak", ".old", ".orig", ".save", ".backup", ".back", ".copy", ".tmp", ".swp", "~")
# File extensions of key / certificate stores that must not be committed.
SENSITIVE_SUFFIX = (".pem", ".key", ".p12", ".pfx", ".ppk", ".keystore", ".jks", ".kdbx", ".tfstate", ".tfstate.backup")
# File base names the user exempts on purpose (env SECRET_HOOK_ALLOW_NAMES, comma-separated, case-insensitive). Default empty.
ALLOW_NAMES = {x.strip().lower() for x in os.environ.get("SECRET_HOOK_ALLOW_NAMES", "").split(",") if x.strip()}
# Placeholder shown in the fingerprint column for findings whose value is too guessable to hash (MAC, host names).
NO_FP = "-"
# Remediation advice appended to every BLOCKED message.
HINT = "remove it, rotate the credential if it was real, load it from the environment; reviewed fixture: add 'secret-scan:allow' to that line"


# First-line tag identifying a hook written by the lock command (a pre-push that always fails).
LOCK = "# secret-hook-lock v1"
# Matches a six-byte MAC-address-shaped token with a consistent ":" or "-" separator, not embedded in a longer
# hex/colon run (so IPv6 pieces and long hashes are skipped). Example shape: six hex pairs joined by colons.
MAC_RX = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
# Matches MAC-shaped values that are harmless placeholders: all zeros, all ff, or one repeated byte
# (six identical hex pairs joined by colons or dashes). Matches are NOT reported.
MAC_OK = re.compile(r"(?i)^(?:00[:-]00[:-]00[:-]00[:-]00[:-]00|ff[:-]ff[:-]ff[:-]ff[:-]ff[:-]ff|(?:([0-9a-f]{2})[:-])\1(?:[:-]\1){4})$")
# Matches a "<name>.local" mDNS-style host name (2-41 chars of letters, digits, hyphen before ".local"),
# i.e. a short name followed by the literal suffix. Such names usually identify a private machine.
# L4: config FILE names that carry a "local" part (a local settings JSON, a local application YAML: a dot and more letters follow "local") are not hosts,
# not mDNS hosts, so the match must not be followed by "." + alphanumeric; the bare label "env" (the dotenv local-override file) is exempted in scan_identity.
# N4: Python / JS attribute access and calls are not host names: a name followed by "local" and then a call paren, a subscript
# bracket or a single "=" (a threading-local factory call, a subscripted attribute, an attribute assignment) is skipped by the
# trailing lookahead; an import path ending in "local" is skipped in scan_identity (see _IMPORT_CTX). Real host uses (after
# "ssh user@", before ":22", inside a URL, at the end of a sentence) still match.
# N4 decision: a name ending in "local" followed by "lan" IS blocked (router-assigned LAN names are as identifying as plain mDNS
# names), so an optional "lan" tail is part of the match; the same spelling followed by a file extension stays exempt through
# the "no further dotted part" lookahead.
HOST_RX = re.compile(r"(?i)\b[a-z0-9][a-z0-9-]{1,40}\.local(?:\.lan)?\b(?!\.[a-z0-9])(?!\s*(?:[(\[]|=(?!=)))")
# N4: text before a match that shows it is a Python import path, not a host (a "from X import" or "import X" statement).
_IMPORT_CTX = re.compile(r"(?:^|[\s;])(?:from|import)\s+[\w.]*$")
# *.local names that may appear in committed text without blocking (comma-separated env SECRET_HOOK_LOCAL_HOST_OK).
HOST_OK = {x.strip().lower() for x in os.environ.get("SECRET_HOOK_LOCAL_HOST_OK", "").split(",") if x.strip()}


def _norm(v: str) -> str:
    """Normalise a name for comparison: strip, lower-case, and make "-", "_" and space interchangeable (all become "-")."""
    return re.sub(r"[-_ ]", "-", v.strip().lower())


def _candidates(fname):
    """List places to look for optional config file `fname`: beside this script, then ../data/. For the redactions
    file an env-var path is tried first. Returns a list of Path objects (existence not checked)."""
    out = [SELF.parent / fname, SELF.parent.parent / "data" / fname]
    if fname == "redactions.json" and os.environ.get("SECRET_HOOK_REDACTIONS_FILE"):
        out.insert(0, Path(os.environ["SECRET_HOOK_REDACTIONS_FILE"]).expanduser())
    return out


def _load(fname):
    """Return parsed JSON from the first readable, valid candidate for `fname`, or None if there is none."""
    for c in _candidates(fname):
        try:
            return json.loads(c.read_text())
        except (OSError, ValueError):
            continue  # missing or malformed: try the next location
    return None


def _private_hosts():
    """Private host names (normalised: lowercase, '-', '_', ' ' interchangeable) from optional JSON files that sit next to
    this script (or in ../data/): redactions.json {"hosts": [...]}, host_roles.json {"hosts": {name: {"aliases": [...],
    "nickname": "..."}}} and retired_hosts.json {"hosts": [name | {"host", "aliases", "nickname"}]}. Missing files are skipped."""
    names = set()

    def add(v):
        """Add one candidate name if it is a string of at least 4 characters (shorter ones would false-positive)."""
        if isinstance(v, str) and len(v.strip()) >= 4:
            names.add(_norm(v))
    d = _load("redactions.json")
    if isinstance(d, dict):
        for x in d.get("hosts", []) if isinstance(d.get("hosts"), list) else []:
            add(x)
    d = _load("host_roles.json")
    if isinstance(d, dict) and isinstance(d.get("hosts"), dict):
        for k, v in d["hosts"].items():
            add(k)
            if isinstance(v, dict):
                for a in v.get("aliases", []) if isinstance(v.get("aliases"), list) else []:
                    add(a)
                add(v.get("nickname"))
    d = _load("retired_hosts.json")
    if isinstance(d, dict) and isinstance(d.get("hosts"), list):
        for v in d["hosts"]:
            if isinstance(v, dict):
                add(v.get("host"))
                for a in v.get("aliases", []) if isinstance(v.get("aliases"), list) else []:
                    add(a)
                add(v.get("nickname"))
            else:
                add(v)
    return sorted(names)


def scan_identity(line: str):
    """MAC addresses and private hostnames in one added line -> [(type, fingerprint)]; never the value.

    Types: "mac-address", "local-hostname" (a .local name not in the allow-list) and "private-hostname"
    (a name from the optional JSON host lists).

    Why the fingerprint is always "-" here: a hash of a low-entropy identity value (a MAC address with a known vendor
    prefix, a short host name) can be brute-forced back to the value in seconds, so printing even a truncated hash would
    leak it. Token-shaped secrets (see secret_scan) have enough entropy for a short fingerprint; identity values do not.
    The finding still says WHICH file and line, which is all a person needs to go and look.
    """
    out = []
    for m in MAC_RX.finditer(line):
        if not MAC_OK.match(m.group(0)):
            out.append(("mac-address", NO_FP))
    for m in HOST_RX.finditer(line):
        if _IMPORT_CTX.search(line[:m.start()]):
            continue  # N4: module path in an import statement
        if m.group(0).lower() not in HOST_OK and m.group(0).lower() != "env" + ".local":
            out.append(("local-hostname", NO_FP))
    low = _norm(line)  # normalised so "my_host", "my host" and "My-Host" all match "my-host"
    for h in _private_hosts():
        if h in DISTRO_WORDS:  # ambiguous names need context, see _distro_host_hit
            if _distro_host_hit(line, h):
                out.append(("private-hostname", NO_FP))
        elif h in low:
            out.append(("private-hostname", NO_FP))
    return out


# A Linux distro name that is ALSO used as a machine name. In prose ("Ubuntu 24.04 LTS")
# it is not a host; as a lowercase token, or next to host words (ssh, host, machine, @ ...), it still is.
# Add more words with env SECRET_HOOK_EXTRA_DISTRO_WORDS (comma-separated).
# Distro names that are ambiguous (see comment above); matched with context rules instead of plain substring.
DISTRO_WORDS = {"ubuntu", "debian", "arch", "centos", "rhel", "alpine", "mint", "kali", "nixos",
                "suse", "opensuse", "gentoo", "manjaro", "popos", "rocky", "almalinux"}
DISTRO_WORDS |= {x.strip().lower() for x in os.environ.get("SECRET_HOOK_EXTRA_DISTRO_WORDS", "").split(",") if x.strip()}
# Words/symbols near a distro-looking token that suggest it is a machine name rather than prose, e.g. "ssh",
# "user@", "named ...". Searched in a 24-char window on each side.
_HOST_CONTEXT = re.compile(r"(?i)(ssh|scp|sftp|rsync|ping|host|hostname|machine|\bbox\b|node|server|\bvm\b|laptop|"
                           r"@|\.local|\bnamed\b|\bcalled\b|peer|\bon the\b)")


def _distro_host_hit(line: str, host: str) -> bool:
    """True if `host` (a distro-word) appears in `line` as a probable machine name rather than as prose.

    Whole-word match only (letters on either side disqualify, so "ubuntuproject" is ignored). An all-lowercase
    token counts as a host; a capitalised one counts only with host-like context nearby.
    """
    for m in re.finditer(r"(?<![A-Za-z])" + re.escape(host) + r"(?![A-Za-z])", line, re.I):
        if m.group(0) == m.group(0).lower():
            return True  # bare lowercase token, typical of a host name
        ctx = line[max(0, m.start() - 24):m.start()] + " " + line[m.end():m.end() + 24]
        if _HOST_CONTEXT.search(ctx):
            return True
    return False


class GitUnavailable(RuntimeError):
    """The git executable cannot be run at all (not installed / not permitted). Callers warn and skip."""

    pass


class GitFailed(RuntimeError):
    """git ran but failed, timed out, or returned non-zero. Callers fail closed (block)."""

    pass


def git(args, cwd=None):
    """Run `git <args>` (120 s timeout) and return its stdout decoded as UTF-8 (bad bytes replaced).

    Raises GitUnavailable if git cannot be executed, GitFailed on timeout or non-zero exit.
    """
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=120)
    except (FileNotFoundError, PermissionError) as exc:
        raise GitUnavailable(str(type(exc).__name__)) from exc
    except subprocess.SubprocessError as exc:
        raise GitFailed(f"git {args[0]} did not finish ({type(exc).__name__})") from exc
    if r.returncode != 0:
        raise GitFailed(f"git {args[0]} exited {r.returncode}")
    return r.stdout.decode("utf-8", "replace")


def sensitive_name(path: str) -> bool:
    """True if the file name (last path component) looks like a credential file; template suffixes are exempt."""
    parts = path.lower().split("/")
    low = parts[-1]
    if low.endswith(SAFE_SUFFIX) or low in ALLOW_NAMES:
        return False
    # N3: strip backup endings ("x.pem.bak.old" -> "x.pem") so the base-name rules see through them.
    core = low
    while core.endswith(BACKUP_SUFFIX) and len(core) > 1:
        core = next(core[:-len(s)] for s in BACKUP_SUFFIX if core.endswith(s))
    if low in SENSITIVE_NAMES or low.startswith(".env.") or low.endswith(SENSITIVE_SUFFIX):
        return True
    if core != low and (core in SENSITIVE_NAMES or core.startswith(".env.") or core.endswith(SENSITIVE_SUFFIX)):
        return True
    if (ENV_DASH.match(core) or core.endswith(".env")) and not ENV_SAFE.search(core):
        return True
    # id_rsa variants (but a public key "*.pub" is fine) and .git-credentials backups.
    if SENSITIVE_PREFIX.match(low) and not low.endswith(".pub"):
        return True
    return len(parts) >= 2 and (parts[-2], low) in SENSITIVE_IN_DIR


# Hunk header "@@ -a[,b] +c[,d] @@": b / d are the old / new line counts and default to 1 when omitted.
_HUNK_RX = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# Commit separator emitted by our own `git log --format=` call; the hash is hex so a diff line can never forge it
# (diff body lines start with + - space or backslash, and header lines are only recognised OUTSIDE a hunk).
_COMMIT_RX = re.compile(r"^@@secret-hook-commit ([0-9a-f]{40,64})$")
# Escapes git uses inside a C-style quoted path.
_C_ESC = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}


def unquote_path(p: str) -> str:
    """Decode a path as git prints it in diff headers: a C-quoted string ("tab\\there", "\\303\\251") or a plain name.

    Git quotes a path only when it holds a control character, a double quote, a backslash (or, with core.quotepath on,
    a non-ASCII byte). Plain names (even with spaces) get a trailing TAB in `+++` lines, which is stripped here.
    """
    if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
        body, out, i = p[1:-1], bytearray(), 0
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                if nxt in "01234567":  # up to three octal digits = one raw byte
                    j = i + 1
                    while j < len(body) and j < i + 4 and body[j] in "01234567":
                        j += 1
                    out.append(int(body[i + 1:j], 8) & 0xFF)
                    i = j
                    continue
                out.append(_C_ESC.get(nxt, ord(nxt) & 0xFF))
                i += 2
                continue
            out += ch.encode("utf-8", "replace")
            i += 1
        return out.decode("utf-8", "replace")
    return p.rstrip("\t")


def _new_path(header: str) -> str | None:
    """Path from the text after `+++ ` (None for /dev/null = deleted file). We always ask git for the a/ b/ prefixes, so strip "b/"."""
    p = unquote_path(header)
    if p == "/dev/null":
        return None
    return p[2:] if p[:2] in ("b/", "w/", "i/", "c/") else p


def scan_patch(patch: str, commit: str = ""):
    """Scan a unified diff (-U0): only added lines. Returns a list of dicts {commit, file, line, type, fp}.

    `commit` is a label copied into each finding (empty for staged scans); `@@secret-hook-commit <hash>` lines (written
    by scan_range) switch the label. Lines containing the allow marker are skipped; deleted files are ignored.
    Values are never stored, only fingerprints.

    Parsing is a small state machine that is deliberately NOT fooled by file content (this was a bypass):
      * the patch is split on "\\n" ONLY. str.splitlines() also splits on lone CR, VT, FF, FS/GS/RS, NEL, LS and PS, which
        cut an added line in two so that the fragment no longer began with "+" and was silently dropped;
      * once a hunk header "@@ -a,b +c,d @@" is read, exactly b old-side and d new-side lines belong to the hunk, and
        EVERY line inside it is classified by its first character only ("+" added, "-" removed, " " context). So an added
        line whose text is "++ x" (diff line "+++ x") or "++ /dev/null" can never be mistaken for a file header;
      * "+++ " is treated as a header only OUTSIDE a hunk;
      * if a path is unknown, added lines are still scanned (reported under "(unknown)") rather than skipped.
    """
    out, path, lineno = [], None, 0  # lineno = line number in the new file of the next added line
    old_left = new_left = 0          # lines still to come in the current hunk (old side / new side)
    for raw in patch.split("\n"):
        if old_left > 0 or new_left > 0:
            c = raw[:1]
            if c == "+":
                new_left -= 1
                line = raw[1:]
                if ALLOW not in line:
                    where = path if path is not None else "(unknown)"
                    for _, kind, fp in secret_scan.scan_text(line):
                        out.append({"commit": commit, "file": where, "line": lineno, "type": kind, "fp": fp})
                    for kind, fp in scan_identity(line):
                        out.append({"commit": commit, "file": where, "line": lineno, "type": kind, "fp": fp})
                lineno += 1
                continue
            if c == "-":
                old_left -= 1
                continue
            if c == " " or c == "":
                # M1: an EMPTY line is a context line too. With diff.suppressBlankEmpty=true git prints a blank context line as ""
                # instead of " "; treating it as malformed used to drop hunk state and hide the following "+" lines.
                old_left -= 1
                new_left -= 1
                lineno += 1
                continue
            if c == "\\":  # "\ No newline at end of file": belongs to the previous line, not counted
                continue
            old_left = new_left = 0  # malformed hunk: stop trusting the counts and fall through to header handling
        # M1 (fail closed): after a malformed hunk, or when the counts ran out early, a "+" line that is not a "+++ " header must
        # still be scanned rather than dropped. A valid diff never has such a line outside a hunk, so this costs nothing normally.
        if raw[:1] == "+" and not raw.startswith("+++ "):
            line = raw[1:]
            if ALLOW not in line:
                where = path if path is not None else "(unknown)"
                for _, kind, fp in secret_scan.scan_text(line):
                    out.append({"commit": commit, "file": where, "line": lineno, "type": kind, "fp": fp})
                for kind, fp in scan_identity(line):
                    out.append({"commit": commit, "file": where, "line": lineno, "type": kind, "fp": fp})
            lineno += 1
            continue
        # ---- outside a hunk: only git's own header lines are meaningful here
        m = _COMMIT_RX.match(raw)
        if m:
            commit, path = m.group(1), None
        elif raw.startswith("diff "):
            path = None
        elif raw.startswith("+++ "):
            path = _new_path(raw[4:])
        elif raw.startswith("@@"):
            h = _HUNK_RX.match(raw)
            if h:
                old_left = int(h.group(2)) if h.group(2) is not None else 1
                new_left = int(h.group(4)) if h.group(4) is not None else 1
                lineno = int(h.group(3))
    return out


def name_findings(paths, commit=""):
    """Build "sensitive-file" findings (line 0, no fingerprint) for every path whose name looks like a credential file."""
    return [{"commit": commit, "file": p, "line": 0, "type": "sensitive-file", "fp": "-"} for p in paths if p and sensitive_name(p)]


def report(findings, what):
    """Print de-duplicated findings to stderr as `file:line TYPE fingerprint`, then a BLOCKED line with the fix hint.

    `what` is "commit" or "push". Never prints secret values.
    """
    seen = set()
    for f in findings:
        key = (f["commit"], f["file"], f["line"], f["type"], f["fp"])
        if key in seen:
            continue
        seen.add(key)
        c = f"[{f['commit'][:8]}] " if f["commit"] else ""
        print(f"secret-hook: {c}{f['file']}:{f['line']} {f['type']} {f['fp']}", file=sys.stderr)
    print(f"secret-hook: BLOCKED {what}. Fix: {HINT}. (emergency only: --no-verify)", file=sys.stderr)


def warn_unavailable(exc):
    """Print a loud stderr warning that the scan was skipped because git is missing (fail-open by design)."""
    print(f"secret-hook: WARNING git is unavailable ({exc}); secret scan SKIPPED, nothing was checked.", file=sys.stderr)


# -c settings given to every diff/log call so the user's own diff configuration cannot change the shape of the patch we parse
# (M1): quotepath off (readable names), no noprefix / mnemonicPrefix (we strip "b/"), suppressBlankEmpty off (blank context lines
# stay " "), interHunkContext 0 (hunks are never merged), context 0 and no external diff / textconv programs.
DIFF_CFG = ["-c", "core.quotepath=off", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
            "-c", "diff.suppressBlankEmpty=false", "-c", "diff.interHunkContext=0", "-c", "diff.context=0"]
# Flags for the diff/log calls themselves. H1: --text makes git print the lines of files it classifies as binary (a NUL byte, or a
# `-diff` / `binary` attribute, e.g. lockfiles and generated files) instead of "Binary files differ", so a token in them is scanned;
# --no-textconv stops a repo-configured textconv filter from rewriting what we scan. UTF-16 / UTF-32 text stays undetectable.
DIFF_FLAGS = ["-U0", "--inter-hunk-context=0", "--no-color", "--no-ext-diff", "--text", "--no-textconv",
              "--src-prefix=a/", "--dst-prefix=b/"]


def pre_commit() -> int:
    """Scan the staged diff (added/copied/modified/renamed/TYPE-CHANGED files) plus staged file names. Returns the hook exit
    code: 0 clean or git missing, 1 finding or git error."""
    try:
        # N1: the filter is ACMRT. "T" = type change (a symlink replaced by a regular file, or the reverse). Without T such a
        # change is invisible to both calls below: e.g. replacing a committed symlink named ".env" with a real file skipped the
        # sensitive-name rule and the content scan. Keep T in all three diff-filter strings of this file.
        patch = git([*DIFF_CFG, "diff", "--cached", *DIFF_FLAGS, "--diff-filter=ACMRT"])
        # -z: NUL-separated, never quoted, so any file name survives intact.
        names = git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"]).split("\0")
    except GitUnavailable as exc:
        warn_unavailable(exc)
        return 0
    except GitFailed as exc:
        print(f"secret-hook: BLOCKED, scan could not run ({exc}). Fix git, or use --no-verify if you are sure.", file=sys.stderr)
        return 1
    found = scan_patch(patch) + name_findings(names)
    if found:
        report(found, "commit")
        return 1
    return 0


def push_ranges(stdin_text: str, remote: str):
    """Turn git's pre-push stdin (`<local ref> <local sha> <remote ref> <remote sha>` per line) into scan specs.

    Returns a list of [revision-spec, tip-sha, remote]. Malformed lines and branch deletions yield nothing.
    """
    specs = []
    for ln in stdin_text.split("\n"):  # "\n" only: git terminates these lines with LF
        parts = ln.split()
        if len(parts) < 4:
            continue
        _, lsha, _, rsha = parts[:4]
        if lsha == ZERO:
            continue  # deletion: nothing is sent
        if rsha != ZERO:
            specs.append([f"{rsha}..{lsha}", lsha, remote])
        else:
            specs.append([lsha, lsha, remote])  # new branch: everything not already on a remote
    return specs


def scan_range(rng: str, tip: str, remote: str):
    """Scan the commits in `rng` (an "old..new" range, or a single tip meaning "not yet on any remote") and return findings.

    Falls back to `tip` minus remote-tracking refs when the old remote sha is unknown locally. Both added lines and
    file names are checked, and each finding carries its commit id.
    """
    # Common git-log options; the marker format line separates commits in the combined output. Explicit prefixes keep the
    # diff header shape independent of the user's diff.noprefix / diff.mnemonicPrefix settings.
    # N2: --root makes `git log -p` print the diff of a root commit too. Without it a user's log.showRoot=false hides the first
    # commit of a history (made earlier without the hook) from the push scan.
    base = [*DIFF_CFG, "log", "--root", *DIFF_FLAGS, "--format=@@secret-hook-commit %H"]
    # M2: exclude commits already reachable from the target remote ONLY when the push target is a configured remote NAME. When
    # it is a URL (or anything else), what the target already has is unknown, and a commit that exists on some OTHER remote
    # (maybe a private one) may be new to this one, so nothing is excluded: the full pushed history is scanned.
    cut = [f"--remotes={remote}"] if remote and remote in _remote_names() else []
    not_cut = ["--not", *cut] if cut else []
    try:
        spec = [rng] if ".." in rng else [rng, *not_cut]
        patch = git([*base, "-p", *spec])
        commits = _commit_ids(spec)
    except GitFailed:
        if ".." not in rng:
            raise
        spec = [tip, *not_cut]  # remote sha unknown locally (force push etc.): fall back to unpublished commits
        patch = git([*base, "-p", *spec])
        commits = _commit_ids(spec)
    # Content scan: scan_patch understands the commit separator lines and parses hunks by their counts.
    found = scan_patch(patch)
    # M3: commit messages (cheap: one more git call). Findings are reported under the pseudo file "(commit-message)".
    found.extend(_scan_messages(spec))
    # File-name scan, one commit at a time with -z (NUL-separated, never C-quoted): a name such as "tab<TAB>here/.env" is
    # quoted by plain --name-only even with core.quotepath=off, which used to hide the ".env" from sensitive_name().
    for c in commits:
        # N1: ACMRT, same reason as in pre_commit (type changes must be name-checked at push as well).
        out = git(["diff-tree", "--root", "-r", "--no-commit-id", "--name-only", "-z", "--diff-filter=ACMRT", c])
        found.extend(name_findings(out.split("\0"), c))
    return found


def _remote_names():
    """Names of the remotes configured in this repository (`git remote`)."""
    return set(git(["remote"]).split())


def _scan_messages(spec):
    """Scan the commit messages of the commits selected by `spec` for token shapes and identity values (M3).

    One `git log -z` call; records are NUL-separated "<hash>\n<message>". Only the commit id, a line number inside the message
    and a fingerprint are reported, never the text. Lines with the allow marker are skipped."""
    out, found = git(["log", "-z", "--format=%H%n%B", *spec]), []
    for rec in out.split("\0"):
        cid, _, msg = rec.lstrip("\n").partition("\n")
        if not re.fullmatch(r"[0-9a-f]{40,64}", cid):
            continue
        for n, line in enumerate(msg.split("\n"), 1):
            if ALLOW in line:
                continue
            for _, kind, fp in secret_scan.scan_text(line):
                found.append({"commit": cid, "file": "(commit-message)", "line": n, "type": kind, "fp": fp})
            for kind, fp in scan_identity(line):
                found.append({"commit": cid, "file": "(commit-message)", "line": n, "type": kind, "fp": fp})
    return found


def _commit_ids(spec):
    """Commit hashes selected by the revision `spec` (newest first); only well-formed hex ids are kept."""
    out = git(["log", "--format=%H", *spec])
    return [x for x in out.split("\n") if re.fullmatch(r"[0-9a-f]{40,64}", x)]


def pre_push(remote: str, stdin_text: str) -> int:
    """Scan everything about to be pushed. Returns 0 clean or git missing, 1 on a finding or git error."""
    found = []
    try:
        for rng, tip, rem in push_ranges(stdin_text, remote):
            found += scan_range(rng, tip, rem)
    except GitUnavailable as exc:
        warn_unavailable(exc)
        return 0
    except GitFailed as exc:
        print(f"secret-hook: BLOCKED push, scan could not run ({exc}). Fix git, or use --no-verify if you are sure.", file=sys.stderr)
        return 1
    if found:
        report(found, "push")
        return 1
    return 0


# ---- install / uninstall / status -------------------------------------------------------------------------------------

def hook_text(name: str) -> str:
    """Return the shell source of the installed hook `name` ("pre-commit" or "pre-push").

    The hook runs a previously saved hook first (chained), honours the skip variable with a loud warning, degrades
    to a warning if python3 or this script is missing, and otherwise execs this script. The pre-push variant
    buffers stdin in a temp file so both the old hook and this tool can read it.
    """
    py = str(SELF).replace("'", "'\\''")
    head = f"#!/bin/sh\n{MARKER}\nd=$(dirname \"$0\")\nhook_unavailable=\n"
    guard = (f"if ! command -v python3 >/dev/null 2>&1 || [ ! -f '{py}' ]; then\n"
             "  echo 'secret-hook: WARNING python3 or git_secret_hook.py missing; secret scan SKIPPED' >&2\n"
             "  hook_unavailable=1\nfi\n"
             "if [ -n \"${SECRET_HOOK_SKIP:-}\" ]; then\n"
             "  echo 'secret-hook: WARNING secret scan SKIPPED because SECRET_HOOK_SKIP is set' >&2\n"
             "  hook_unavailable=1\nfi\n")
    if name == "pre-commit":
        return (head + guard + f"if [ -x \"$d/pre-commit.pre-secret-hook\" ]; then \"$d/pre-commit.pre-secret-hook\" \"$@\" || exit $?; fi\n"
                f"[ -n \"${{hook_unavailable:-}}\" ] && exit 0\nexec python3 '{py}' pre-commit \"$@\"\n")
    return (head + guard + "in=$(mktemp \"${TMPDIR:-/tmp}/secret-hook.XXXXXX\") || exit 1\ncat > \"$in\"\n"
            f"if [ -x \"$d/pre-push.pre-secret-hook\" ]; then \"$d/pre-push.pre-secret-hook\" \"$@\" < \"$in\" || {{ rc=$?; rm -f \"$in\"; exit $rc; }}; fi\n"
            f"[ -n \"${{hook_unavailable:-}}\" ] && {{ rm -f \"$in\"; exit 0; }}\npython3 '{py}' pre-push \"$@\" < \"$in\"; rc=$?\nrm -f \"$in\"; exit $rc\n")


def repo_info(repo):
    """-> (hooks_dir, error). error is a refusal message or None.

    Refuses non-directories, non-repositories, and repos with core.hooksPath set (hooks are managed elsewhere).
    Uses the common git dir so worktrees share one hooks directory.
    """
    repo = Path(repo).expanduser()
    if not repo.is_dir():
        return None, f"{repo}: not a directory"
    try:
        gd = git(["rev-parse", "--git-common-dir"], cwd=repo).strip()
    except GitFailed:
        return None, f"{repo}: not a git repository"
    except GitUnavailable:
        return None, "git is unavailable"
    try:
        hp = git(["config", "--get", "core.hooksPath"], cwd=repo).strip()
    except GitFailed:
        hp = ""  # exit 1 = unset
    if hp:
        return None, (f"{repo}: REFUSED, WARNING core.hooksPath is set to '{hp}': git runs the hooks from THERE, so hooks written to "
                      f".git/hooks would never run (and a core.hooksPath set after install switches this protection off); not touching it")
    g = Path(gd)
    g = g if g.is_absolute() else (repo / g)
    hooks = g.resolve() / "hooks"
    # L6: a symlinked hooks folder points somewhere shared (another repo, a template dir); writing or removing hooks through it
    # would change every repo that uses that folder, although the commands promise "this repo only". Refuse, never follow.
    if hooks.is_symlink():
        return None, f"{repo}: REFUSED, .git/hooks is a symlink (to {os.readlink(hooks)}); not writing through it. Replace it with a real folder first"
    return hooks, None


def _hooks_path(repo) -> str:
    """The repository's effective core.hooksPath ("" if unset, git missing or not a repository)."""
    try:
        return git(["config", "--get", "core.hooksPath"], cwd=Path(repo).expanduser()).strip()
    except (GitFailed, GitUnavailable):
        return ""


def _write_hook(h: Path, text: str) -> None:
    """Write hook file `h` atomically with mode 755: temp file in the same folder, chmod, then os.replace. Replacing swaps the
    directory entry itself, so a symlink at `h` is replaced rather than followed (a plain write would modify its target)."""
    tmp = h.with_name("." + h.name + ".secret-hook-tmp")
    tmp.write_text(text)
    tmp.chmod(0o755)
    os.replace(tmp, h)


def is_ours(p: Path) -> bool:
    """True if the file at `p` is readable and carries our marker (so we may overwrite or remove it)."""
    try:
        return MARKER in p.read_text(errors="replace")
    except OSError:
        return False


def install(repos) -> int:
    """Install chained pre-commit and pre-push hooks in each repo. Existing foreign hooks are renamed to
    `<name>.pre-secret-hook` and still run. Idempotent. Returns 0, or 1 if any repo was refused."""
    rc = 0
    for repo in repos:
        hooks, err = repo_info(repo)
        if err:
            print(err, file=sys.stderr); rc = 1; continue
        hooks.mkdir(parents=True, exist_ok=True)
        for name in HOOKS:
            h, bak = hooks / name, hooks / f"{name}.pre-secret-hook"
            if (h.exists() or h.is_symlink()) and not is_ours(h):
                if bak.exists() or bak.is_symlink():
                    print(f"{repo}: REFUSED {name}: existing hook AND {bak.name} both present; resolve by hand", file=sys.stderr); rc = 1; continue
                h.rename(bak)
            _write_hook(h, hook_text(name))
        print(f"{repo}: installed")
    return rc


def uninstall(repos) -> int:
    """Remove our hooks from each repo and restore any saved `<name>.pre-secret-hook` hook. Returns 0, or 1 on refusal."""
    rc = 0
    for repo in repos:
        hooks, err = repo_info(repo)
        if err:
            print(err, file=sys.stderr); rc = 1; continue
        for name in HOOKS:
            h, bak = hooks / name, hooks / f"{name}.pre-secret-hook"
            if h.exists() and is_ours(h):
                h.unlink()
            if (bak.exists() or bak.is_symlink()) and not (h.exists() or h.is_symlink()):
                bak.rename(h)
        print(f"{repo}: uninstalled")
    return rc


def lock_text() -> str:
    """Return the shell source of the lock hook: prints a forbidden message and always exits 1."""
    return (f"#!/bin/sh\n{LOCK}\necho 'secret-hook: PUSH FORBIDDEN: this repository is locked. Remove the lock with: git_secret_hook.py unlock <repo>' >&2\nexit 1\n")


def lock(repo, undo=False) -> int:
    """Make every push from REPO fail (pre-push always exits 1) and require that it has no remote. Refuses if a remote exists."""
    hooks, err = repo_info(repo)
    if err:
        print(err, file=sys.stderr); return 1
    h, bak = hooks / "pre-push", hooks / "pre-push.pre-lock"
    if undo:
        if h.exists() and LOCK in h.read_text(errors="replace"):
            h.unlink()
        if bak.exists() and not h.exists():
            bak.rename(h)
        print(f"{repo}: unlocked"); return 0
    hooks.mkdir(parents=True, exist_ok=True)
    if (h.exists() or h.is_symlink()) and LOCK not in h.read_text(errors="replace"):
        if bak.exists():
            print(f"{repo}: REFUSED, pre-push and {bak.name} both exist", file=sys.stderr); return 1
        h.rename(bak)
    _write_hook(h, lock_text())
    try:
        remotes = git(["remote"], cwd=repo).split()
    except (GitFailed, GitUnavailable) as exc:
        print(f"{repo}: cannot list remotes ({exc})", file=sys.stderr); return 1
    if remotes:
        print(f"{repo}: LOCKED but {len(remotes)} remote(s) are configured; remove them: git remote remove <name>", file=sys.stderr); return 1
    print(f"{repo}: locked, no remotes"); return 0


def locked(repo) -> bool:
    """True only if the lock hook is in place AND the repo has no remotes; any error counts as not locked."""
    hooks, err = repo_info(repo)
    try:
        return not err and LOCK in (hooks / "pre-push").read_text(errors="replace") and not git(["remote"], cwd=repo).split()
    except (OSError, GitFailed, GitUnavailable):
        return False


def installed(repo: Path) -> bool:
    """True if both managed hooks in the repo are ours."""
    hooks, err = repo_info(repo)
    return not err and all(is_ours(hooks / n) for n in HOOKS)


# Directory names skipped while searching for repositories (caches, package dirs, media, OS folders).
PRUNE = {"node_modules", "Library", ".Trash", ".cache", ".venv", "venv", "__pycache__", ".npm", ".cargo", ".rustup", "Applications", "Pictures", "Music", "Movies"}


def find_repos(under: Path, max_depth=6):
    """Yield every directory below `under` (up to `max_depth` levels) that contains a .git entry; skips PRUNE names."""
    base = len(under.parts)
    for cur, dirs, files in os.walk(under):
        if ".git" in dirs or ".git" in files:
            yield Path(cur)
        # Prune in place so os.walk does not descend into skipped or too-deep directories.
        dirs[:] = [d for d in dirs if d != ".git" and d not in PRUNE and len(Path(cur, d).parts) - base < max_depth]


def status(args) -> int:
    """Print "installed" / "NOT installed" / "INACTIVE" / "UNSAFE" (symlinked hooks folder) per repo. Args: nothing (search home), `--under DIR`, or explicit repos."""
    if args and args[0] == "--under":
        repos = list(find_repos(Path(args[1] if len(args) > 1 else "~").expanduser()))
    elif args:
        repos = [Path(a).expanduser() for a in args]
    else:
        repos = list(find_repos(Path("~").expanduser()))
    for r in sorted(repos):
        # L5: a core.hooksPath set after install makes git ignore .git/hooks, so "installed" would be a false comfort.
        if _hooks_path(r):
            print(f"INACTIVE       {r}  (core.hooksPath is set: git does not run .git/hooks; the secret scan is OFF here)")
            continue
        # N7: a symlinked .git/hooks folder is refused by install/lock/uninstall. Reporting it as "NOT installed" would be wrong
        # (hooks inside the shared target DO run) and would invite a fix that writes through the link; say what it is.
        _, err = repo_info(r)
        if err and "is a symlink" in err:
            print(f"UNSAFE         {r}  (.git/hooks is a symlink: refused, not managed; hooks in the shared target may or may not be ours)")
            continue
        print(f"{'installed    ' if installed(r) else 'NOT installed'}  {r}")
    return 0


def main(argv=None) -> int:
    """Command dispatcher. Returns the process exit code: 2 for bad usage (usage text to stderr), else the command's code."""
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0  # help goes to stdout, exit 0
    cmd, rest = a[0], a[1:]
    if cmd == "pre-commit":
        return pre_commit()
    if cmd == "pre-push":
        return pre_push(rest[0] if rest else "", sys.stdin.read())
    if cmd in ("install", "uninstall") and rest:
        return (install if cmd == "install" else uninstall)(rest)
    if cmd in ("lock", "unlock") and rest:
        return max(lock(r, undo=cmd == "unlock") for r in rest)
    if cmd == "status":
        return status(rest)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
