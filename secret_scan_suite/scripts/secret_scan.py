#!/usr/bin/env python3
# >>> HOW THIS WORKS
# FLOW:    1 main() runs check() (default) or accept() on ONE explicit target folder: the PATH argument, or the current directory
#          when none is given (never "the folder this script lives in"). 2 check() calls scan(), which asks files() for the git
#          file list (git ls-files -co --exclude-standard). 3 scan() skips files over 1 MB, binaries and its own files, then
#          scan_text() tests each line (lines over 4000 chars skipped) against the RULES regexes; a match that looks like a
#          placeholder is ignored. 4 Each hit becomes file, line, type and a 10-character sha256 fingerprint (never the secret).
#          5 check() drops fingerprints already listed in secrets_known.json; whatever is left is a NEW finding and main() exits 1.
# DATA:    reads every tracked or untracked-not-ignored file under the target. STATE (the accepted list secrets_known.json and the
#          receipt SECRETS.<host>.json) lives in a per-user state folder: $SECRET_SCAN_DIR if set, else
#          $XDG_STATE_HOME/secret_scan, else ~/.local/state/secret_scan. State is never written inside this component's own folder
#          (check()/accept() refuse that). Also writes ~/.cache/secret_scan/secret_scan_cache.json (a speed-up keyed on file size,
#          mtime and a hash of the rules). git_secret_hook.py and home_secret_scan.py import this module; a monitor can call
#          alarm_problems() to read the receipt back.
# FAILS:   if git or any file read fails, ScanUnavailable is raised and the receipt says complete=false with a
#          secret:scan-unavailable problem, so it fails closed (no clean result is ever recorded). Files deleted mid-scan
#          and dangling symlinks are skipped. A cache write failure is ignored. alarm_problems() reports a missing receipt,
#          a malformed or future-dated one, and one older than 26 hours.
# EXTEND:  add a regex to RULES (changing a rule invalidates the cache automatically). Tests: scripts/test_secret_scan.py.
#          Run: PYTHONPATH=scripts python3 -B -m unittest -q scripts.test_secret_scan
# GOTCHAS: accept() records ALL current findings as known, so rotate the key first. SKIP_DIRS (env SECRET_SCAN_SKIP_DIRS, comma-separated repo-relative prefixes, default none) skips folders of third-party material.
# <<< HOW THIS WORKS
"""secret_scan: find real-looking credentials in a repository or workspace folder. Never prints a secret.

  secret_scan.py check [PATH]    scan PATH (default: the CURRENT DIRECTORY); print file:line TYPE fingerprint; exit 1 if any NEW finding
  secret_scan.py accept [PATH]   record current findings as known (test fixtures, revoked keys), by fingerprint

Files: git-tracked plus untracked-not-ignored, text, <1 MB. A finding is identified by a short sha256 of the match, so the
baseline file (<state dir>/secrets_known.json) holds no secret either. Alarm receipt: <state dir>/SECRETS.<host>.json.

State directory (where the baseline and receipt live): $SECRET_SCAN_DIR if set; otherwise $XDG_STATE_HOME/secret_scan;
otherwise ~/.local/state/secret_scan. It is a per-user folder OUTSIDE the scanned tree and outside this component, so running
the scanner never adds files to a checkout. Passing a state folder inside this component's own folder is refused.

Why it exists: credentials pasted into notes, scripts or config files are easy to commit or sync to other machines by
accident. This scanner gives a cheap, offline, dependency-free check that can run from a scheduler or a git hook.

Design and threat model:
  * Never leak the thing being protected. Output, receipts, the baseline and the cache hold only file, line, rule name
    and a 10-hex-character sha256 prefix of the matched text, never the match itself.
  * Fail closed. If the file inventory or any file read fails, no "clean" result is recorded; the receipt says
    complete=false and alarm_problems() reports it. A missing, malformed, future-dated or stale (>26h) receipt is also
    reported, so a scanner that silently stopped is noticed.
  * Pattern matching is heuristic: well-known token shapes (cloud keys, VCS tokens, private-key headers). Lines that
    look like documentation placeholders are ignored to keep the false-positive rate low. It is not a proof of absence.
  * accept() trusts the operator: it whitelists every current finding by fingerprint, so rotate the key first.

Environment: SECRET_SCAN_DIR (receipt/baseline folder; see above), XDG_STATE_HOME (fallback base), SECRET_SCAN_CACHE (cache file), SECRET_SCAN_SKIP_DIRS
(comma-separated repo-relative prefixes to skip).

Usage example:
  python3 scripts/secret_scan.py check .            # scan the current folder; prints "path:12 github-token fp=0123456789", exit 1 on new findings
  python3 scripts/secret_scan.py check /path/repo   # scan another folder
  python3 scripts/secret_scan.py accept .           # baseline the current findings
  # from Python: receipt, new = secret_scan.check(root, state_dir)
"""
from __future__ import annotations
import hashlib, json, os, re, socket, stat, subprocess, sys, time
from pathlib import Path

# This component's own folder (the parent of scripts/). It is NOT a scan target and NOT a place to keep state: check()/accept()
# refuse a state folder inside it, so a checkout is never littered with receipts.
COMPONENT_DIR = Path(__file__).resolve().parent.parent


def default_state_dir(environ=None):
    """Return the per-user folder for the baseline and receipt (the folder is not created here).

    Order: $SECRET_SCAN_DIR (a leading ~ is expanded), then $XDG_STATE_HOME/secret_scan, then ~/.local/state/secret_scan.
    Args: environ = mapping to read instead of os.environ (testing hook).
    """
    env = os.environ if environ is None else environ
    if env.get("SECRET_SCAN_DIR"):
        return Path(env["SECRET_SCAN_DIR"]).expanduser()
    base = env.get("XDG_STATE_HOME")
    # The XDG spec says a relative XDG_STATE_HOME must be ignored; honouring it would make state land in the current folder.
    if base and os.path.isabs(base):
        return Path(base) / "secret_scan"
    return Path.home() / ".local" / "state" / "secret_scan"


def _refuse_component_dir(d):
    """Raise ValueError if state folder `d` is (or is inside) this component's own folder; guards against littering a checkout."""
    try:
        inside = Path(d).expanduser().resolve().is_relative_to(COMPONENT_DIR) if hasattr(Path, "is_relative_to") else \
            str(Path(d).expanduser().resolve()).startswith(str(COMPONENT_DIR) + os.sep)
    except OSError:
        inside = False
    if inside:
        raise ValueError("refusing to write scanner state inside the component folder (%s); set SECRET_SCAN_DIR to a "
                         "per-user folder" % COMPONENT_DIR)


# Folder for the receipt and baseline, resolved once at import (see default_state_dir). Tests and callers may pass `d=` explicitly.
DIR = default_state_dir()
# Short host name (domain part dropped); keeps receipts from different machines distinct.
HOST = socket.gethostname().split(".")[0]
# Rule name -> compiled regex. Each regex matches one well-known credential shape; the rule name is reported in findings.
# Changing any rule changes _rules_sig(), which discards the on-disk cache.
RULES = {
    # AWS access key id: "AKIA" + 16 upper-case/digits, e.g. AKIA followed by 16 characters such as ABCDEFGHIJKLMNOP.
    # L2: the boundary is "no letter/digit next to it" instead of \b, because \b treats "_" as a word character and so missed
    # "KEY_AKIA..." / "AKIA..._SUFFIX" style names (very common in env files).
    "aws-access-key": re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),
    # GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36 or more alphanumerics, or the fine-grained github_pat_ form (50+ chars).
    "github-token": re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    # Anthropic API key prefix "sk-ant-" followed by 30+ key characters, e.g. sk-ant-api03-<30+ chars>.
    "anthropic-key": re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{30,}"),
    # OpenAI-style key: "sk-" (optionally "sk-proj-") + 40+ key characters; the lookahead excludes the Anthropic prefix handled above.
    "openai-key": re.compile(r"(?<![A-Za-z0-9])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{40,}"),
    # Google API key: "AIza" + exactly 35 URL-safe characters, e.g. AIza followed by 35 characters.
    "google-api-key": re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9])"),
    # Slack token: an "xox" + one of a/b/p/r/s + hyphen prefix followed by 20+ characters.
    "slack-token": re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[0-9A-Za-z\-]{20,}"),
    # Stripe live secret or restricted key: sk_live_ / rk_live_ + 20+ alphanumerics.
    "stripe-live-key": re.compile(r"(?<![A-Za-z0-9])[sr]k_live_[0-9A-Za-z]{20,}"),
    # PEM private-key header, a BEGIN line (optionally with ENCRYPTED (PKCS#8, L3), RSA, EC, DSA, OPENSSH or PGP) for a private key, with five hyphens on each side.
    "private-key-block": re.compile(r"-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    # WireGuard config line "PrivateKey = <43 base64 chars>=" (the 44-character key is captured in group 1).
    "wireguard-private-key": re.compile(r"(?i)(?<![A-Za-z0-9])PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)"),
}
# Words that mark a match as documentation or a dummy value (example, placeholder, your_key, xxxx, <angle brackets>, ..., dummy,
# fake, redacted, 8+ zeros). A match containing one is ignored, e.g. an AWS documentation example id, or a key written with an angle-bracket stand-in.
# Private-key headers are exempt from this filter (see scan_text).
# L1: placeholder words are looked for only in the "core" of a variable-length token (its prefix plus the minimum number of key
# characters). Without this, "ghp_<36 real chars>example" was dropped because the greedy match swallowed the word "example".
# Rule name -> core length (rules not listed are tested whole). github_pat_ tokens use 61 (see _core).
CORE_LEN = {"github-token": 40, "anthropic-key": 37, "openai-key": 43, "slack-token": 25, "stripe-live-key": 28}
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|your[_-]?key|xxxx|<[^>]*>|\.\.\.|dummy|fake|redacted|0{8,})")
# The scanner's own source and test file are never scanned: they necessarily mention key shapes. ONLY these two exact
# resolved paths are skipped. (Skipping by base name would let a file called secret_scan.py in ANY scanned repo escape the
# scan, which is a trivial hiding place for a credential.)
SELF_PATHS = frozenset({Path(__file__).resolve(), Path(__file__).resolve().with_name("test_secret_scan.py")})
# Repo-relative folder prefixes skipped entirely (env SECRET_SCAN_SKIP_DIRS, comma-separated; default none).
# Used for folders of third-party material that legitimately contain public client keys.
SKIP_DIRS = tuple(x.strip() for x in os.environ.get("SECRET_SCAN_SKIP_DIRS", "").split(",") if x.strip())  # e.g. scraped third-party pages whose public client keys are not yours


def _skipped_dir(rel):
    """True if repo-relative path `rel` lies inside one of the SKIP_DIRS folders (folder boundary, so "vendor" does not skip "vendors/x")."""
    return any(rel == d.rstrip("/") or rel.startswith(d.rstrip("/") + "/") for d in SKIP_DIRS)


def _write_private(path, text):
    """Atomically write `text` to `path` (owner-only 0600). The temp file is created with O_EXCL|O_NOFOLLOW after removing any
    stale one, so a pre-planted symlink at the temp name is never followed and receipts are not world-readable."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


class ScanUnavailable(RuntimeError):
    """The credential scan could not inspect its complete input set."""


def files(root):
    """Return the absolute paths of tracked plus untracked-not-ignored files under root, via git.

    Raises ScanUnavailable if git cannot run or exits non-zero, so an inventory failure is never mistaken for an empty repo.
    """
    root = Path(root)
    # -z gives NUL-separated output so odd file names (spaces, newlines) survive intact.
    try:
        result = subprocess.run(["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
                                capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanUnavailable(f"git file inventory could not run ({type(exc).__name__})") from exc
    if result.returncode != 0:
        raise ScanUnavailable(f"git file inventory exited with status {result.returncode}")
    return [root / p for p in result.stdout.decode("utf-8", "replace").split("\0") if p]


def _core(kind, matched):
    """Return the part of `matched` that is checked for placeholder words (see CORE_LEN); the whole match for fixed-length rules."""
    if kind == "github-token" and matched.startswith("github_pat_"):
        return matched[:61]
    n = CORE_LEN.get(kind)
    return matched[:n] if n else matched


def scan_text(text):
    """Scan text line by line and return [(line_number, rule_name, fingerprint)]; the matched text itself is never returned.

    Lines over 4000 characters are skipped (minified blobs). Placeholder-looking matches are ignored, except private-key headers.
    """
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        # Very long lines are almost always minified or encoded data, and slow to regex; skip them.
        if len(line) > 4000:
            continue
        for kind, rx in RULES.items():
            # L1: finditer, not search. With search only the FIRST match on a line was judged, so a placeholder such as the AWS
            # documentation id placed before a real key on the same line hid the real key. Every match is judged on its own.
            for m in rx.finditer(line):
                # Placeholder filter: ignore documentation-like matches (but a PEM header is always a finding).
                if PLACEHOLDER.search(_core(kind, m.group(0))) and kind != "private-key-block":
                    continue
                # WireGuard templates use @NAME@-style substitution markers rather than real keys.
                if kind == "wireguard-private-key" and m.group(1).startswith("@"):
                    continue
                # Fingerprint = first 10 hex chars of sha256(match): stable identity without storing the secret.
                hits.append((n, kind, hashlib.sha256(m.group(0).encode()).hexdigest()[:10]))
    return hits


def _cache_file():
    """Return the cache file path: SECRET_SCAN_CACHE if set, else a file under the per-user cache folder."""
    return Path(os.environ.get("SECRET_SCAN_CACHE") or Path.home() / ".cache" / "secret_scan" / "secret_scan_cache.json")


def _rules_sig():
    """Changes whenever a rule or the placeholder filter changes, which throws the whole cache away."""
    return hashlib.sha256(repr((sorted((k, rx.pattern) for k, rx in RULES.items()), PLACEHOLDER.pattern, 4000, sorted(CORE_LEN.items()))).encode()).hexdigest()[:16]


def _load_cache(path):
    """Return the cached {relative path: {sig, hits}} map, or {} if the file is absent, corrupt or built under different rules."""
    try:
        d = json.loads(Path(path).read_text())
        # A signature mismatch means the rules changed: the old hits are untrustworthy, so discard them all.
        if d.get("sig") == _rules_sig() and isinstance(d.get("files"), dict):
            return d["files"]
    except (OSError, ValueError, AttributeError):
        pass  # unreadable or malformed cache: behave as if there were none
    return {}


def _save_cache(path, files):
    """Atomically write the cache (temp file then rename). Any OSError is swallowed: caching is best-effort."""
    try:
        path = Path(path)
        # M6: the cache holds repo-relative file names and fingerprints, so it is private like the receipts: a NEW folder is
        # created 0700 (mode is only applied to the folder that is created here; an existing folder, which may be shared such
        # as /tmp, is never chmod-ed) and the file itself is always written 0600 through _write_private (atomic, no symlink
        # following), so it is owner-only even inside a pre-existing 0755 folder.
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_private(path, json.dumps({"sig": _rules_sig(), "files": files}))
    except OSError:
        pass          # the cache is only a speed-up: failing to write it must never change what is reported


def scan(root, flist=None, cache=None):
    """Scan the workspace. For the full workspace scan (flist is None) unchanged files are NOT re-read: a file whose size and mtime match the
    last scan, under the same rules, reuses its previous hits. A change to a file's size or mtime, or to a rule, rescans it (a tool that
    rewrites a file while preserving both size and mtime_ns could therefore go unnoticed until the cache is deleted), and read errors still
    fail closed. The cache is one global file keyed by relative path, so scanning repo A then repo B starts B cold. (Re-reading tens of thousands of unchanged files on every run can exceed a scheduler's time limit.)"""
    root = Path(root)  # callers must pass the target explicitly; there is deliberately no default tree
    # Findings as dicts {file, line, type, fp}; paths are made relative to root when possible.
    found = []
    # Default: cache only the full-workspace scan (flist is None); an explicit file list bypasses it unless forced.
    use_cache = (flist is None) if cache is None else bool(cache)
    cpath = _cache_file()
    old = _load_cache(cpath) if use_cache else {}
    new = {}
    for p in (flist if flist is not None else files(root)):
        try:
            # Cache key and report name: root-relative when the file lives under root, else the path as given.
            rel = str(p.relative_to(root)) if root in p.parents else str(p)
            # Skip only the scanner's own two files (exact resolved path) and configured third-party folders.
            if p.name in ("secret_scan.py", "test_secret_scan.py") and p.resolve() in SELF_PATHS:
                continue
            if _skipped_dir(rel):
                continue
            if p.is_symlink() and not p.exists():
                continue  # dangling symlink: no content exists to hold a secret (other read errors still fail closed)
            # stat() errors other than 'not found' propagate to the OSError handler below and fail closed.
            info = p.stat()
            # Only regular files up to 1 MB are scanned (skips sockets, devices and huge blobs).
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1_000_000:
                continue
            # Cache signature: size plus nanosecond mtime; any edit to the file changes it.
            sig = [info.st_size, info.st_mtime_ns]
            hit = old.get(rel)
            if hit is not None and hit.get("sig") == sig:
                hits = [tuple(h) for h in hit["hits"]]
            else:
                data = p.read_bytes()
                # A NUL byte in the first 2 KB marks a binary file: not scanned.
                hits = [] if b"\0" in data[:2048] else scan_text(data.decode("utf-8", "replace"))
            if use_cache:
                new[rel] = {"sig": sig, "hits": [list(h) for h in hits]}
            for n, kind, fp in hits:
                found.append({"file": str(p.relative_to(root)) if root in p.parents else str(p), "line": n, "type": kind, "fp": fp})
        except FileNotFoundError:
            continue  # deleted between the file listing and the read (sync-tool conflict copies come and go): nothing left to scan
        except OSError as exc:
            raise ScanUnavailable(f"could not read scan input {p.name} ({type(exc).__name__})") from exc
    if use_cache:
        _save_cache(cpath, new)
    return found


def known(d=None):
    """Load the accepted-fingerprint baseline as a set; a missing file is an empty set.

    Raises ScanUnavailable if the file is unreadable, not JSON, or not a list of strings (fail closed).
    """
    f = Path(d or DIR) / "secrets_known.json"
    try:
        value = json.loads(f.read_text())
    except FileNotFoundError:
        return set()
    except (OSError, ValueError) as exc:
        raise ScanUnavailable(f"known-fingerprint baseline is unreadable ({type(exc).__name__})") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScanUnavailable("known-fingerprint baseline has an invalid format")
    return set(value)


def check(root, d=None, flist=None):
    """Scan, subtract the baseline, write the receipt, and return (receipt_dict, new_findings).

    Args: root = tree to scan; d = receipt/baseline folder; flist = optional explicit file list.
    If the scan cannot complete, the receipt records complete=false and a scan-unavailable problem instead of a clean result.
    At most 20 problems are listed in the receipt.
    """
    d = Path(d or DIR)
    _refuse_component_dir(d)  # fail loudly before touching the disk
    try:
        found = scan(root, flist)
        k = known(d)
        # New = findings whose fingerprint is not in the accepted baseline.
        new = [x for x in found if x["fp"] not in k]
        problems = {f"secret:{x['fp']}": (f"secret: {x['type']} at {x['file']}:{x['line']} (fp {x['fp']}) | fix: rotate it at the provider, remove it from the file "
                                          f"(a sync tool may have copied it to other machines), then secret_scan.py accept") for x in new[:20]}
        complete = True
    except ScanUnavailable as exc:
        found, new = [], []
        problems = {"secret:scan-unavailable": f"secret_scan: required scan failed ({exc}); no clean result was recorded"}
        complete = False
    # Receipt: timestamp, host, completeness flag, problem messages and counts (None counts when incomplete).
    r = {"checked": time.time(), "host": HOST, "complete": complete, "problems": problems,
         "findings": len(found) if complete else None, "new": len(new) if complete else None}
    d.mkdir(mode=0o700, parents=True, exist_ok=True)  # owner-only state folder
    _write_private(d / f"SECRETS.{HOST}.json", json.dumps(r, indent=1))  # atomic: a reader never sees a half-written receipt
    return r, new


def accept(root, d=None, flist=None):
    """Add every current finding's fingerprint to the baseline file and return the sorted list.

    Existing baseline entries are kept. Rotate the credential first: this silences the finding permanently.
    """
    d = Path(d or DIR); _refuse_component_dir(d); d.mkdir(mode=0o700, parents=True, exist_ok=True)
    fps = sorted({x["fp"] for x in scan(root, flist)} | known(d))
    _write_private(d / "secrets_known.json", json.dumps(fps))
    return fps


def alarm_problems(now=None, d=None):
    """Read the receipt back and return {problem_key: message}; an empty dict means healthy.

    Reports: no receipt, receipt for another host or of invalid shape, incomplete scan, timestamp more than 60 s in the future,
    and a receipt older than 26 hours. Any parse failure is reported as an alarm rather than raised.
    Args: now = epoch seconds (testing hook); d = receipt folder.
    """
    try:
        now = time.time() if now is None else now
        f = Path(d or DIR) / f"SECRETS.{HOST}.json"
        if not f.exists():
            return {"secret:quiet": "secrets: scanner never ran | fix: schedule `secret_scan.py check` to run regularly"}
        r = json.loads(f.read_text())
        # A receipt written by another host (e.g. a synced folder) says nothing about this one.
        if not isinstance(r, dict) or r.get("host") != HOST or not isinstance(r.get("problems"), dict):
            raise ValueError("wrong host or invalid receipt shape")
        out = dict(r["problems"])
        if r.get("complete") is not True:
            out.setdefault("secret:scan-unavailable", "secret_scan: latest scan receipt is incomplete; no clean credential result is trusted")
        checked = float(r["checked"])
        if checked > now + 60:
            raise ValueError("receipt timestamp is in the future")
        # 26 h = a daily schedule plus slack; older means the scheduled run stopped.
        if now - checked > 26 * 3600:
            out["secret:quiet"] = "secrets: scanner silent for 26h | fix: check that the scheduled `secret_scan.py check` still runs"
        return out
    except Exception as exc:
        return {"secret:receipt-unavailable": f"secret_scan: receipt is unreadable or malformed ({type(exc).__name__})"}


def main(a=None):
    """Command-line entry point. Args: a = argument list (default sys.argv[1:]).

    Forms: `check [PATH]` (the default when no command is given) and `accept [PATH]`. PATH defaults to the CURRENT DIRECTORY, never
    to the folder this script lives in. The receipt and baseline go to the per-user state folder (see default_state_dir), and the
    scanned target and state folder are printed so the run is never ambiguous.
    Returns the exit status: 0 clean, 1 new findings or incomplete scan, 2 usage error or refused state folder (prints the docstring).
    """
    a = (a if a is not None else sys.argv[1:]) or ["check"]
    if a[0] not in ("check", "accept") or len(a) > 2:
        print(__doc__); return 2
    root = Path(a[1] if len(a) == 2 else ".").expanduser().resolve()
    if not root.is_dir():
        print(f"secret_scan: not a folder: {root}", file=sys.stderr); return 2
    try:
        if a[0] == "check":
            print(f"secret_scan: scanning {root} (state: {DIR})")
            r, new = check(root)
            if not r["complete"]:
                for key, message in r["problems"].items():
                    print(f"PROBLEM {key}: {message}")
                return 1
            for x in new:
                print(f"{x['file']}:{x['line']} {x['type']} fp={x['fp']}")
            print(f"secret_scan: {r['findings']} finding(s), {r['new']} new")
            return 1 if new else 0
        print(f"accepted {len(accept(root))} fingerprint(s) from {root} (state: {DIR})"); return 0
    except ValueError as exc:  # refused state folder
        print(f"secret_scan: {exc}", file=sys.stderr); return 2
    except ScanUnavailable as exc:  # not a git work tree, git missing, unreadable file or baseline: a clean message, not a traceback
        print(f"secret_scan: cannot scan {root}: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
