#!/usr/bin/env python3
"""home_secret_scan: find credentials in the home folder OUTSIDE a repository (where git-based scanning never looks).

  home_secret_scan.py check                 scan; write <state dir>/HOMESECRETS.<host>.json; exit 1 if any unaccepted finding
  home_secret_scan.py accept FP --reason T  accept one fingerprint (reason required) in <state dir>/homesecrets_known.json
  home_secret_scan.py report                list findings from the last receipt (file:line type fp)
  home_secret_scan.py status                one-line summary of the last receipt

Covers: shell history and rc files, dotfile configs (~/.config and top-level dotfiles: .env, .netrc, .npmrc, .pypirc,
.git-credentials, .aws, .gcloud, .docker/config.json auth, gh hosts.yml plaintext oauth_token), ~/Downloads, ~/Desktop,
~/Documents (text, <1 MB), and world/group-readable key files (id_*, *.pem, *.key, *.p12, *.kdbx, credentials*).
Never reads ~/Library or the Keychain, never follows symlinks, bounded by file count, size and a time budget.

PRIVACY: a finding is only {file (home-relative), line, type, fp}. The match, the line and any surrounding text are never
stored or printed. For the human-chosen secret classes (netrc / pypirc / npmrc / git-credentials passwords, --password flags,
mysql -p, curl -u, literal assignments, bearer values, docker auth) fp is the first 10 hex of an HMAC-SHA256 of the match under a
random per-user key kept 0600 in the state dir (homesecrets_fpkey): an unkeyed hash of a short, guessable password can be
reversed offline with a dictionary, a keyed one cannot be unless the key file is also stolen. Fingerprints are therefore
stable on THIS machine and user only; deleting the key file makes every earlier "accept" stop matching (findings reappear).
The key file must be a regular file owned by you (a symlink or directory is refused, a group/world-readable one is tightened to 0600 with a warning),
and a corrupt key is never replaced silently: `check --regenerate-key` is required.
Token-shaped secrets (AWS, GitHub, ... see secret_scan.py) are high-entropy, so they keep the plain sha256 fingerprint.

Why it exists: repository scanners only look inside a git work tree, but credentials also end up in shell history,
dotfiles and download folders, where nothing else checks them. This tool covers that gap with the same fingerprint-only
reporting as secret_scan.py (whose rules and placeholder filter it reuses).

Design and threat-model notes:
  * Read-only and bounded: never follows symlinks (files opened with O_NOFOLLOW, directories skipped if links), limits
    file size, files per tree, directory depth and total run time, and reports when a scan was truncated.
  * Fail-soft on unreadable single files (skipped), fail-closed on the receipt: alarm_problems() reports a missing,
    malformed, future-dated or stale (>26h) receipt.
  * Accepting a finding requires a human-readable reason and is stored by fingerprint only.
  * Key files that other users can read (group/world permission bits) are reported even if their content is not scanned.

Usage example:
  python3 scripts/home_secret_scan.py check
  python3 scripts/home_secret_scan.py accept 0123456789 --reason "revoked test token"
  # prints lines such as "~/.zshrc:12 literal-assignment fp=0123456789"
"""
from __future__ import annotations
import argparse, hashlib, hmac, json, os, re, stat, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan
from secret_scan import RULES, PLACEHOLDER, scan_text

DIR = secret_scan.DIR
HOST = secret_scan.HOST
# Largest ordinary file read in full (1 MB); bigger files are skipped.
MAX_BYTES = 1_000_000
# Shell history files can be huge; only the newest 2 MB is read, since recent commands matter most.
HIST_BYTES = 2_000_000
# Upper bound on files examined per walked folder tree; exceeding it marks the scan truncated.
MAX_FILES_PER_TREE = 2500
# Default maximum directory depth for a walk.
MAX_DEPTH = 6
# Wall-clock budget in seconds for the whole scan, so a huge home folder cannot make a scheduled run hang.
BUDGET_S = 20.0
# Shell history files, scanned tail-first with assignment-style rules.
HISTORY = (".zsh_history", ".bash_history")
# Shell start-up files that often hold exported tokens.
RCFILES = (".zshrc", ".zprofile", ".bashrc", ".profile")
# Folder names never entered: dependency trees, caches, VCS internals, media libraries and the OS library folder
# (large, noisy, and not where hand-written credentials live).
SKIP_DIRS = {"node_modules", ".git", "Library", "venv", ".venv", "__pycache__", "site-packages", ".cache", "cache",
             "caches", ".Trash", "Cache", "Caches", "CachedData", "GPUCache", "Code Cache", "Service Worker", ".npm", ".cargo",
             ".rustup", ".pyenv", ".nvm", "Pictures", "Music", "Movies"}
# File extensions skipped because they are binary, media or archive formats that are not scanned as text.
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".heic", ".pdf", ".zip", ".gz", ".tgz", ".dmg", ".pkg", ".iso", ".mp4", ".mov",
            ".mp3", ".m4a", ".wav", ".sqlite", ".db", ".docx", ".xlsx", ".pptx", ".app", ".so", ".dylib", ".pyc", ".woff", ".woff2"}
# File names that look like private-key or credential files: id_rsa, id_ed25519 (but not *.pub), server.pem, tls.key,
# bundle.p12, vault.kdbx, credentials.json. Used only for the permission check in _key_perms.
KEYNAME = re.compile(r"(?i)^(id_[a-z0-9_]+(?<!\.pub)|.+\.(pem|key|p12|pfx|kdbx)|credentials.*)$")
# Dot-folders under the home folder that hold tool credentials; each is walked shallowly.
CONFIG_DIRS = (".aws", ".gcloud", ".docker", ".kube", ".ssh")

# assignment-style patterns for shell/config text: (type, regex, value group)
# Variable-name fragment: any name containing password, passwd, secret, token, api_key/api-key or apikey,
# e.g. MY_API_TOKEN, db.password, client-secret.
NAME = r"[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api[_-]?key|apikey)[A-Za-z0-9_]*"
# Each entry is (type, regex, index of the capture group holding the secret value). Values must be 12+ non-shell characters
# so short words and variable references are not reported.
ASSIGN = [
    # NAME=value or NAME: value, optionally quoted, e.g. export MY_API_TOKEN=abcdEFGH1234zz
    ("literal-assignment", re.compile(r"(?i)\b" + NAME + r"\s*[=:]\s*(['\"]?)([^\s'\"`;&|<>]{12,})"), 2),
    # Secret passed as a command-line flag, e.g. tool --password abcdEFGH1234zz or --token=abcdEFGH1234zz
    ("cli-password-flag", re.compile(r"(?i)--(?:password|passwd|token|secret|api-key|apikey|auth-token)(?:\s+|=)(['\"]?)([^\s'\"`;&|<>-][^\s'\"`;&|<>]{11,})"), 2),
    # curl basic auth user:password, e.g. curl -u bob:abcdEFGH1234zz https://host
    ("curl-basic-auth", re.compile(r"\bcurl\b[^|;\n]*?\s(?:-u|--user)\s+(['\"]?)[^\s:'\"$]+:([^\s'\"`;&|<>]{12,})"), 2),
    # HTTP header, e.g. Authorization: Bearer abcdEFGH1234zz
    ("bearer-token", re.compile(r"(?i)\bAuthorization:\s*Bearer\s+(['\"]?)([A-Za-z0-9._~+/=\-]{12,})"), 2),
    # MySQL family clients with glued -p<password>, e.g. mysql -u root -pabcdEFGH1234zz (empty group 1 keeps the group index uniform)
    ("mysql-password", re.compile(r"\b(?:mysqldump|mysqladmin|mysql)\b[^|;\n]*?\s-p()([^\s'\"`;&|<>-][^\s'\"`;&|<>]{11,})"), 2),
]
# File-specific plaintext credential patterns, keyed by file name: name -> (type, regex, value group).
FILE_RULES = {
    # netrc line: "machine h login u password secretvalue"
    ".netrc": ("netrc-password", re.compile(r"\bpassword\s+(\S+)"), 1),
    # npm auth settings, e.g. //registry/:_authToken=secretvalue
    ".npmrc": ("npmrc-auth", re.compile(r"(?i)(?:_authToken|_auth|_password)\s*=\s*(\S+)"), 1),
    # pypirc line, e.g. "password = secretvalue"
    ".pypirc": ("pypirc-password", re.compile(r"(?i)^\s*password\s*[:=]\s*(\S+)"), 1),
    # URL with embedded password, e.g. https://user:secretvalue@host
    ".git-credentials": ("git-credentials", re.compile(r"://[^/\s:@]+:([^@\s]+)@"), 1),
    # GitHub CLI hosts file, e.g. "oauth_token: secretvalue" (only honoured inside a gh folder, see _scan_file)
    "hosts.yml": ("gh-plaintext-token", re.compile(r"\boauth_token:\s*(\S+)"), 1),
    # Docker config auth entry, e.g. "auth": "base64value" (only honoured inside a .docker folder, see _scan_file)
    "config.json": ("docker-auth", re.compile(r'"auth"\s*:\s*"([^"]+)"'), 1),
}


# Key for the keyed fingerprints of human-chosen secrets (H2). Until check() loads the persistent per-user key from the state
# folder, a random per-process key is used, so a direct scan() call also never prints a dictionary-reversible hash.
_FPKEY = os.urandom(32)
# File name of the persistent key inside the state folder.
KEY_FILE = "homesecrets_fpkey"


class KeyFileError(Exception):
    """The fingerprint key file cannot be used safely (symlink, directory, wrong owner, corrupt). The message is one clear line."""


def _load_key(d, regenerate=False):
    """Return the persistent 32-byte fingerprint key from folder `d`, creating it (random, mode 0600) when absent.

    N5 rules, all fail-closed with KeyFileError (check() turns it into a one-line message and exit status 2):
      * the key path must be a regular file. A symlink or a directory is refused: following a link could read or tighten a file
        somewhere else, and a directory can never hold a key.
      * a key file owned by another user is refused (its content may be known to that user).
      * a key readable by group/other (any of the 0o077 bits) is tightened to 0600 and a warning goes to stderr: that key may
        already be known to other accounts, so the message says to treat earlier fingerprints as exposed.
      * a corrupt or short key is NEVER silently replaced. Replacing it makes every earlier `accept` stop matching (the findings
        come back), so it needs the explicit flag `check --regenerate-key`; with the flag a loud warning says so.
    May raise OSError for other failures (the caller needs the state folder for the receipt anyway)."""
    f = Path(d) / KEY_FILE
    Path(d).mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        st = os.lstat(f)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            raise KeyFileError(f"fingerprint key path {f} is a {'symlink' if stat.S_ISLNK(st.st_mode) else 'directory or special file'}, "
                               "not a regular file; refusing to use it. Remove it yourself (earlier accepts will stop matching) and re-run")
        try:
            fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise KeyFileError(f"fingerprint key {f} cannot be opened safely ({type(exc).__name__}); refusing to use it")
        try:
            fst = os.fstat(fd)
            if fst.st_uid != os.getuid():
                raise KeyFileError(f"fingerprint key {f} is owned by another user; refusing to use it")
            if stat.S_IMODE(fst.st_mode) & 0o077:
                try:
                    os.fchmod(fd, 0o600)
                except OSError as exc:
                    raise KeyFileError(f"fingerprint key {f} is readable by other users and cannot be tightened ({type(exc).__name__}); refusing to use it")
                print(f"home_secret_scan: WARNING key file {f} was readable by other users; changed to 0600. Treat the fingerprints "
                      "it protected as exposed to them.", file=sys.stderr)
            try:
                data = bytes.fromhex(os.read(fd, 200).decode("ascii", "ignore").strip())
            except ValueError:
                data = b""
        finally:
            os.close(fd)
        if len(data) >= 32:
            return data
        if not regenerate:
            raise KeyFileError(f"fingerprint key {f} is corrupt or too short. NOT replacing it: a new key would make every earlier "
                               "'accept' stop matching. Restore the file, or re-run with --regenerate-key to create a new key on purpose")
        print(f"home_secret_scan: WARNING --regenerate-key: replacing the corrupt key {f}; every earlier accept is now INVALID "
              "and accepted findings will be reported again.", file=sys.stderr)
        os.unlink(f)
    key = os.urandom(32)
    secret_scan._write_private(f, key.hex())  # atomic, 0600, no symlink following
    return key


def _fp(s):
    """Return the 10-hex-character KEYED fingerprint (HMAC-SHA256 under _FPKEY) of string s.

    Used for every finding whose matched text is a human-chosen, low-entropy secret (see the module docstring). The matched
    text never leaves this function; the key never leaves the state folder."""
    return hmac.new(_FPKEY, s.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]


def _fp_plain(s):
    """Unkeyed 10-hex sha256 fingerprint, for values that are not secret (a relative path plus a permission mode)."""
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:10]


def _literal(v):
    """True when v looks like a real literal rather than a placeholder or variable reference."""
    # Drop surrounding quotes, then reject obvious non-secrets: empty, variable references ($VAR), template markers,
    # percent/at substitutions, backtick commands and placeholder words.
    v = v.strip("'\"")
    if len(v) < 1 or "$" in v or v.startswith(("{{", "%", "@", "`")) or PLACEHOLDER.search(v):
        return False
    # Common filler values (changeme, todo, null, ...).
    if re.search(r"(?i)(your[_-]|_here|changeme|replace|insert|todo|redacted|password123|\bnone\b|\bnull\b)", v):
        return False
    # Needs more than 3 distinct characters, which rejects runs like 'aaaaaaaaaaaa' or '121212121212'.
    return len(set(v)) > 3


def scan_lines(text, assign=True, filerule=None):
    """[(line, type, fp)] - fingerprints only; the text never leaves this function."""
    # Start with the shared well-known-token rules from secret_scan.
    hits = list(scan_text(text))
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        # File-specific rule first, then (optionally) the generic assignment rules.
        rules = ([filerule] if filerule else []) + (list(ASSIGN) if assign else [])
        got = False  # becomes True once the file-specific rule matched on this line
        for kind, rx, g in rules:
            if got and filerule and kind != filerule[0]:
                continue  # the file-specific rule already covers this line
            for m in rx.finditer(line):
                v = m.group(g)
                # File-specific rules accept any literal; generic rules additionally require a 12+ character value.
                if _literal(v) and (kind in ("netrc-password", "npmrc-auth", "pypirc-password", "git-credentials",
                                             "gh-plaintext-token", "docker-auth") or len(v.strip("'\"")) >= 12):
                    hits.append((n, kind, _fp(m.group(0)))); got = True
    # De-duplicate: several rules can match the same text on a line.
    seen, out = set(), []
    for h in hits:  # one finding per (line, fp)
        if (h[0], h[2]) not in seen:
            seen.add((h[0], h[2])); out.append(h)
    return out


class Ctx:
    """Mutable state for one scan: home folder, time deadline, collected findings, file counter and truncation flag."""

    def __init__(self, home, deadline):
        """home = folder to scan; deadline = time.monotonic() value after which the scan stops."""
        self.home, self.deadline, self.findings, self.files, self.truncated = Path(home), deadline, [], 0, False

    def add(self, p, line, kind, cls, fp):
        """Record a finding with a home-relative path; the matched text is never stored (only its fingerprint)."""
        self.findings.append({"file": str(Path(p).relative_to(self.home)), "line": line, "type": kind, "class": cls, "fp": fp})

    def out_of_time(self):
        """True once the deadline has passed (and sticks: the truncated flag stays set)."""
        if time.monotonic() > self.deadline:
            self.truncated = True
        return self.truncated


def _read(p, limit, tail=False):
    """Read a regular, non-symlink file with O_NOFOLLOW; None if unreadable/binary/too big."""
    # O_NOFOLLOW refuses symlinks; O_NONBLOCK stops a FIFO or device from hanging the open.
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        # Only regular files: no pipes, sockets or devices.
        if not stat.S_ISREG(info.st_mode):
            return None
        # Oversized ordinary files are skipped; oversized history files are read from the end instead.
        if info.st_size > limit and not tail:
            return None
        if tail and info.st_size > limit:
            os.lseek(fd, info.st_size - limit, os.SEEK_SET)
        data = os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)
    # NUL byte early on means binary content.
    if b"\0" in data[:2048]:
        return None
    return data.decode("utf-8", "replace")


def _scan_file(ctx, p, cls, assign, tail=False):
    """Scan one file and add findings to ctx. cls = finding class label; assign = use generic assignment rules; tail = history mode."""
    ctx.files += 1
    name = Path(p).name
    text = _read(p, HIST_BYTES if tail else MAX_BYTES, tail)
    if text is None:
        return
    # Pick a file-name-specific rule; the generic names config.json and hosts.yml only count in their tool's own folder.
    frule = FILE_RULES.get(name)
    if name == "config.json" and Path(p).parent.name != ".docker":
        frule = None
    if name == "hosts.yml" and Path(p).parent.name != "gh":
        frule = None
    for n, kind, fp in scan_lines(text, assign, frule):
        ctx.add(p, n, kind, cls, fp)


def _walk(ctx, top, cls, assign, name_ok=None, depth=MAX_DEPTH):
    """Bounded walk without following symlinks (neither files nor directories)."""
    top = Path(top)
    try:
        if top.is_symlink() or not top.is_dir():
            return
    except OSError:
        return
    # Iterative depth-first walk; stack holds (directory, depth). count enforces the per-tree file cap.
    stack, count = [(str(top), 0)], 0
    while stack:
        cur, d = stack.pop()
        if ctx.out_of_time():
            return
        try:
            with os.scandir(cur) as it:
                # Sorted for deterministic output and truncation behaviour.
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue  # unreadable folder: skip it
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if d < depth and e.name not in SKIP_DIRS:
                        stack.append((e.path, d + 1))
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if count >= MAX_FILES_PER_TREE:
                ctx.truncated = True
                return
            # Skip binary/media extensions and, when given, names rejected by the caller's filter.
            ext = os.path.splitext(e.name)[1].lower()
            if ext in SKIP_EXT or (name_ok and not name_ok(e.name)):
                continue
            count += 1
            _key_perms(ctx, e.path, e)
            _scan_file(ctx, e.path, cls, assign)


def _key_perms(ctx, path, entry=None):
    """Report a key-looking file readable by group or others (mode bits 0o044). Public keys (*.pub) are ignored.

    The fingerprint covers the relative path and mode, so changing permissions produces a new finding. entry is unused.
    """
    name = os.path.basename(path)
    if not KEYNAME.match(name) or name.endswith(".pub"):
        return
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return
    if stat.S_ISREG(mode) and mode & 0o044:
        ctx.add(path, 0, "key-file-permissions", "key-permissions", _fp_plain(f"{os.path.relpath(path, ctx.home)}:{mode & 0o777:o}"))


def scan(home=None, now=None):
    """Scan the home folder and return (sorted unique findings, {"files_scanned": n, "truncated": bool}).

    Order: history files, rc files, top-level dotfiles and *.env files, credential config folders, ~/.config, then
    Downloads, Desktop and Documents. `now` is accepted for call compatibility and unused.
    """
    home = Path(home or Path.home())
    ctx = Ctx(home, time.monotonic() + BUDGET_S)
    for n in HISTORY:
        _scan_file(ctx, home / n, "shell-history", True, tail=True)
    for n in RCFILES:
        _scan_file(ctx, home / n, "shell-rc", True)
    # top-level dotfiles (files only); history/rc files were already handled above
    try:
        with os.scandir(home) as it:
            tops = sorted(it, key=lambda e: e.name)
    except OSError:
        tops = []
    for e in tops:
        try:
            if e.is_symlink():
                continue
            if e.is_file(follow_symlinks=False) and e.name.startswith(".") and e.name not in HISTORY + RCFILES \
                    and os.path.splitext(e.name)[1].lower() not in SKIP_EXT:
                _key_perms(ctx, e.path, e)
                _scan_file(ctx, e.path, "dotfile-config", True)
            elif e.is_file(follow_symlinks=False) and e.name.endswith(".env"):
                _scan_file(ctx, e.path, "dotfile-config", True)
        except OSError:
            continue
    # Credential folders; .ssh is walked without assignment rules (only key patterns and permissions matter there).
    for d in CONFIG_DIRS:
        _walk(ctx, home / d, "dotfile-config", d != ".ssh", depth=3)
    _walk(ctx, home / ".config", "dotfile-config", True, depth=4)
    # User document folders: well-known token shapes only (assignment rules would be too noisy in prose).
    for d in ("Downloads", "Desktop", "Documents"):
        _walk(ctx, home / d, d.lower(), False)
    # Stable ordering, then drop exact duplicates.
    f = sorted(ctx.findings, key=lambda x: (x["file"], x["line"], x["type"], x["fp"]))
    uniq = [x for i, x in enumerate(f) if x not in f[:i]]
    return uniq, {"files_scanned": ctx.files, "truncated": ctx.truncated}


def known(d=None):
    """Return the accepted map {fingerprint: {reason, accepted}}; {} if the file is missing, unreadable or the wrong shape."""
    f = Path(d or DIR) / "homesecrets_known.json"
    try:
        v = json.loads(f.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}
    return v if isinstance(v, dict) else {}


def _counts(findings):
    """Summarise findings as {"by_type": {...}, "by_class": {...}} counts."""
    by_t, by_c = {}, {}
    for x in findings:
        by_t[x["type"]] = by_t.get(x["type"], 0) + 1
        by_c[x["class"]] = by_c.get(x["class"], 0) + 1
    return {"by_type": by_t, "by_class": by_c}


def _problems(findings, k):
    """Build {problem_key: message} for findings whose fingerprint is not in the accepted map k."""
    return {f"homesecrets:{x['fp']}": (f"home secret: {x['type']} at ~/{x['file']}:{x['line']} (fp {x['fp']}) | fix: rotate/remove it, "
                                       f"or home_secret_scan.py accept {x['fp']} --reason TEXT")
            for x in findings if x["fp"] not in k}


def check(home=None, d=None, now=None, regenerate_key=False):
    """Scan, mark accepted findings, write the receipt atomically, and return (receipt_dict, unaccepted_findings).

    Args: home = folder to scan (default: current user home); d = receipt folder; now = epoch seconds override for tests;
    regenerate_key = allow replacing a corrupt fingerprint key (see _load_key). Raises KeyFileError when the key is unusable.
    """
    d = Path(d or DIR)
    secret_scan._refuse_component_dir(d)  # same guard as secret_scan.py: never litter this component's folder
    global _FPKEY
    _FPKEY = _load_key(d, regenerate_key)  # H2: persistent per-user key so fingerprints stay stable between runs (and accept keeps working)
    findings, meta = scan(home, now)
    k = known(d)
    for x in findings:
        x["accepted"] = x["fp"] in k
    new = [x for x in findings if not x["accepted"]]
    r = {"checked": time.time() if now is None else now, "host": HOST, "complete": not meta["truncated"], **meta,
         "findings": findings, "counts": _counts(findings), "new": len(new), "problems": _problems(findings, k)}
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Temp file then rename (a reader never sees a half-written receipt); owner-only, no symlink following.
    secret_scan._write_private(d / f"HOMESECRETS.{HOST}.json", json.dumps(r, indent=1))
    return r, new


def accept(fp, reason, d=None, now=None):
    """Record fingerprint fp as accepted with a mandatory non-blank reason; returns the updated map.

    Raises ValueError if the reason is empty or blank.
    """
    if not reason or not reason.strip():
        raise ValueError("a reason is required")
    d = Path(d or DIR); secret_scan._refuse_component_dir(d); d.mkdir(mode=0o700, parents=True, exist_ok=True)
    k = known(d)
    k[fp] = {"reason": reason.strip(), "accepted": time.time() if now is None else now}
    secret_scan._write_private(d / "homesecrets_known.json", json.dumps(k, indent=1, sort_keys=True))
    return k


def _load(d=None):
    """Read and parse the latest receipt; raises OSError or ValueError if it is missing or malformed."""
    return json.loads((Path(d or DIR) / f"HOMESECRETS.{HOST}.json").read_text())


def alarm_problems(now=None, d=None):
    """Return {problem_key: message} derived from the last receipt; empty means healthy.

    Reports a missing receipt, a malformed or other-host one, a timestamp more than 60 s in the future, unaccepted findings,
    and a receipt older than 26 hours. Never raises.
    """
    try:
        now = time.time() if now is None else now
        f = Path(d or DIR) / f"HOMESECRETS.{HOST}.json"
        if not f.exists():
            return {"homesecrets:quiet": "home secrets: scanner never ran | fix: python3 scripts/home_secret_scan.py check"}
        r = json.loads(f.read_text())
        if not isinstance(r, dict) or r.get("host") != HOST or not isinstance(r.get("findings"), list):
            raise ValueError("wrong host or invalid receipt shape")
        checked = float(r["checked"])
        if checked > now + 60:
            raise ValueError("receipt timestamp is in the future")
        out = _problems(r["findings"], known(d))
        # A truncated scan only looked at part of the home folder: never present it as a clean, complete result.
        if r.get("complete") is not True:
            out["homesecrets:scan-truncated"] = "home secrets: the last scan was truncated (time or file budget); part of the home folder was NOT checked"
        # Stale receipt: the scheduled scan has stopped running.
        if now - checked > 26 * 3600:
            out["homesecrets:quiet"] = "home secrets: scanner silent for 26h | fix: python3 scripts/home_secret_scan.py check"
        return out
    except Exception as exc:
        return {"homesecrets:quiet": f"home secrets: receipt is unreadable or malformed ({type(exc).__name__})"}


def main(argv=None):
    """Command-line entry point. argv = argument list (default sys.argv[1:]).

    Subcommands: check (default), accept FP --reason TEXT, report, status. Returns an exit status:
    0 ok, 1 unaccepted findings or no readable receipt, 2 invalid accept or unusable state/key file.
    """
    ap = argparse.ArgumentParser(prog="home_secret_scan.py", description="Scan the home folder for credentials (fingerprints only, never values).")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="scan, write receipt, exit 1 on unaccepted findings")
    c.add_argument("--regenerate-key", action="store_true", help="replace a corrupt fingerprint key (invalidates every earlier accept)")
    a = sub.add_parser("accept", help="accept a fingerprint")
    a.add_argument("fp"); a.add_argument("--reason", required=True)
    sub.add_parser("report", help="list findings from the last receipt")
    sub.add_parser("status", help="one-line receipt summary")
    # report/status read the stored receipt instead of rescanning.
    args = ap.parse_args(sys.argv[1:] if argv is None else argv)
    if args.cmd in (None, "check"):
        print(f"home_secret_scan: scanning {Path.home()} (state: {DIR})")
        try:
            r, new = check(regenerate_key=getattr(args, "regenerate_key", False))
        except (ValueError, KeyFileError) as exc:  # state folder inside the component folder, or an unusable key file (N5)
            print(f"home_secret_scan: {exc}", file=sys.stderr); return 2
        for x in new:
            print(f"~/{x['file']}:{x['line']} {x['type']} fp={x['fp']}")
        print(f"home_secret_scan: {len(r['findings'])} finding(s), {r['new']} unaccepted, {r['files_scanned']} files"
              + (" (truncated)" if r["truncated"] else ""))
        if r["truncated"]:  # fail closed: a partial scan is not a clean result
            print("home_secret_scan: INCOMPLETE, the scan hit its time or file budget; part of the home folder was not checked (receipt: complete=false)")
        return 1 if (new or r["truncated"]) else 0
    if args.cmd == "accept":
        try:
            accept(args.fp, args.reason)
        except ValueError as exc:
            print(f"error: {exc}"); return 2
        print(f"accepted {args.fp}"); return 0
    try:
        r = _load()
    except (OSError, ValueError):
        print("home_secret_scan: no readable receipt; run check"); return 1
    if args.cmd == "report":
        for x in r["findings"]:
            print(f"~/{x['file']}:{x['line']} {x['type']} fp={x['fp']}{' (accepted)' if x.get('accepted') else ''}")
        print(json.dumps(r["counts"], sort_keys=True))
        return 0
    print(f"home_secret_scan: {len(r['findings'])} finding(s), {r['new']} unaccepted, checked {time.strftime('%F %T', time.localtime(r['checked']))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
