#!/usr/bin/env bash
# install_signal_guard.sh: optional, opt-in installer for the test-time signal guard (signal_guard.py).
#
#   scripts/install_signal_guard.sh --status           show state (this is the default; nothing is changed)
#   scripts/install_signal_guard.sh --install --yes    install
#   scripts/install_signal_guard.sh --remove           uninstall
#
# WHAT IT INSTALLS (read this first): two small files in YOUR user-level Python site-packages folder
# (the folder printed by: python3 -c 'import site; print(site.getusersitepackages())'):
#   write_guards_signal_guard_boot.py   loads signal_guard.py from this checkout and calls install()
#   write_guards_signal_guard.pth       one line, "import write_guards_signal_guard_boot"
# A .pth line that starts with "import" is EXECUTED at start-up by the Python that reads THAT site-packages folder: the python3 found
# first on PATH when you ran this script (one minor version), not every Python of the user; other versions, virtualenvs and
# `python -S` / `python -I` runs do not read it.
# The guard only acts while the unittest module is loaded: then os.kill/os.killpg refuse pid 0/1/-1,
# mock objects, and our own process group/parent. Normal programs are unaffected.
# If signal_guard.py cannot be loaded, a warning is printed to stderr at Python start (it never fails silently).
# The boot file records the absolute path of this checkout's signal_guard.py: if you move or delete the
# checkout, run --remove (or you will see that warning).
#
# SECURITY WARNING (code execution): the .pth makes every start of that Python run signal_guard.py from this checkout.
# Anyone who can write to signal_guard.py, to the scripts/ folder, or to the checkout folder that holds it (that is: the file's
# owner, other users in a group-writable folder, or anyone if it is world-writable) can replace that file and thereby run
# arbitrary code as YOU every time you start Python. So this installer REFUSES (exit 2) unless the guard file, its scripts/
# folder and the checkout folder above it are all (a) owned by the current user and (b) not writable by group or others, and the
# installed boot file re-checks the same two conditions at every Python start and refuses to load the guard if they stop
# holding (it prints a warning instead). Keep the checkout owner-only (for example chmod -R go-w) and do not install from a
# shared or downloaded-by-someone-else location. Symlinks are resolved before checking.
#
# WHY: a plain test run can be made safe against a stray os.kill on a mock pid only if the guard is loaded in the interpreter, including ones
# started by other tools; a user-level .pth hook is the standard stdlib mechanism for that.
# SAFETY PROPERTIES: ownership and writability checks (above); opt-in (default is read-only status); --install needs an explicit --yes; the install is verified
# with a fresh interpreter and rolled back if the guard is not active; --remove deletes exactly the two files it made.
# EXIT CODES: 0 success | 1 install verification failed (rolled back) | 2 bad usage, missing prerequisite or refusal.
# --remove / --status work even if signal_guard.py is gone, and when this script is started through a symlink.
# REQUIRES: bash, python3. Touches nothing outside the user site-packages folder.
# Exit on any error, unset variable, or failed pipeline stage.
set -euo pipefail

# Refuse to run if this script still contains an unfilled double-brace placeholder token (never run a half-scrubbed copy).
# Build the two-character placeholder opener from pieces so this very file does not contain it literally.
open='{''{'
if grep -q -- "$open[A-Z]" "${BASH_SOURCE[0]}" 2>/dev/null; then
  echo "install_signal_guard.sh: refusing to run: an unresolved placeholder token is present in this script." >&2
  exit 2
fi

# Prerequisite: python3 (used for the real path and the user site folder). Needed by every mode, including --remove.
command -v python3 >/dev/null 2>&1 || { echo "install_signal_guard.sh: python3 not found" >&2; exit 2; }
# Absolute folder of the REAL script file, and the guard module that sits beside it. If this script was started through a symlink
# (for example ~/bin/install_signal_guard.sh -> <checkout>/scripts/install_signal_guard.sh) the guard sits next to the TARGET, so
# resolve links with Python's realpath (readlink -f is not portable to macOS).
here="$(python3 -c 'import os,sys; print(os.path.dirname(os.path.realpath(sys.argv[1])))' "${BASH_SOURCE[0]}")" || { echo "install_signal_guard.sh: cannot resolve own path" >&2; exit 2; }
guard="$here/signal_guard.py"
# NOTE: the guard file is only required for --install (below). --remove and --status must work even when signal_guard.py is gone,
# because that is exactly the situation in which the start-up warning tells you to run --remove.
case "$guard" in
  *"$open"*) echo "install_signal_guard.sh: refusing to run: path contains an unresolved placeholder token." >&2; exit 2 ;;
esac
site="$(python3 -c 'import site;print(site.getusersitepackages())')" || { echo "install_signal_guard.sh: cannot find the user site folder" >&2; exit 2; }
[ -n "$site" ] || { echo "install_signal_guard.sh: empty user site folder" >&2; exit 2; }
# The two files this installer owns: the boot module and the .pth line that imports it.
boot="$site/write_guards_signal_guard_boot.py"
pth="$site/write_guards_signal_guard.pth"

# Arguments: first is the mode (default: status), second must be --yes to confirm an install.
mode="${1:---status}"
yes="${2:-}"
case "$mode" in
  --remove)
    # Idempotent: -f means removing something already absent is not an error.
    rm -f -- "$boot" "$pth"
    echo "removed from $site" ;;
  --status|status)
    # Installed means both files exist; nothing is modified.
    if [ -f "$pth" ] && [ -f "$boot" ]; then echo "installed in $site"; else echo "not installed ($site)"; fi ;;
  --install|install)
    # The guard file must exist to install it (not needed for --remove / --status).
    [ -f "$guard" ] || { echo "install_signal_guard.sh: missing $guard" >&2; exit 2; }
    # Consent gate: without --yes only describe what would happen.
    if [ "$yes" != "--yes" ]; then
      echo "Would install $boot and $pth (the Python that reads $site then loads $guard at start)." >&2
      echo "Re-run with: $0 --install --yes" >&2
      exit 2
    fi
    # Code-execution guard: refuse unless the guard, its folder and the checkout folder are ours and not group/world writable.
    # Done in Python (stat is not portable between macOS and Linux shells). Paths are passed as arguments, never interpolated.
    python3 - "$guard" <<'PY' || exit 2
import os, sys
guard = os.path.realpath(sys.argv[1])
bad = []
for label, p in (("signal_guard.py", guard), ("its scripts folder", os.path.dirname(guard)),
                 ("the checkout folder above it", os.path.dirname(os.path.dirname(guard)))):
    st = os.stat(p)
    if st.st_uid != os.getuid():
        bad.append("%s (%s) is owned by uid %d, not by you" % (label, p, st.st_uid))
    if st.st_mode & 0o022:
        bad.append("%s (%s) is writable by group or others (mode %03o)" % (label, p, st.st_mode & 0o777))
if bad:
    print("install_signal_guard.sh: refusing to install: this would let someone else run code as you at every start of that Python.", file=sys.stderr)
    for b in bad:
        print("  - " + b, file=sys.stderr)
    print("Fix the ownership/permissions (for example: chmod -R go-w <checkout>) or copy the checkout somewhere only you control.", file=sys.stderr)
    sys.exit(2)
PY
    # Create the user site folder if Python has not yet; then write the boot module via a quoted heredoc (no shell expansion).
    mkdir -p -- "$site"
    # The path is passed as an argument and written with repr(), so quotes/backslashes in it cannot break or inject code.
    python3 - "$guard" "$boot" <<'PY'
import sys
guard, boot = sys.argv[1], sys.argv[2]
text = '''# Installed by write_guards/scripts/install_signal_guard.sh. Remove it with: install_signal_guard.sh --remove
import sys as _sys
try:
    import importlib.util as _u, os as _os
    _p = %s
    if not _os.path.isfile(_p):
        raise FileNotFoundError(_p)
    # Re-check at every start: the guard file, its folder and the checkout folder must still be ours and not group/world writable,
    # otherwise someone could have swapped in code since install time. Refuse to load it if not.
    _q = _os.path.realpath(_p)
    for _d in (_q, _os.path.dirname(_q), _os.path.dirname(_os.path.dirname(_q))):
        _st = _os.stat(_d)
        if _st.st_uid != _os.getuid() or (_st.st_mode & 0o022):
            raise PermissionError("not owned by you or writable by others: " + _d)
    _s = _u.spec_from_file_location("write_guards_signal_guard", _p)
    _m = _u.module_from_spec(_s)
    _s.loader.exec_module(_m)
    _m.install()
except Exception as _e:
    # Say where the two installed files are, so they can be deleted by hand even if the installer script is gone.
    _f = globals().get("__file__", "write_guards_signal_guard_boot.py")
    print("write_guards signal guard NOT active: %%s: %%s (run install_signal_guard.sh --remove, or delete these two files by hand: %%s and %%s)"
          %% (type(_e).__name__, _e, _f, _f[:-len("_boot.py")] + ".pth"), file=_sys.stderr)
''' % repr(guard)
with open(boot, "w", encoding="utf-8") as fh:
    fh.write(text)
PY
    # The .pth file: a line starting with "import" is executed at every interpreter start.
    printf 'import write_guards_signal_guard_boot\n' > "$pth"
    # Verify: a fresh interpreter must start cleanly and the guard must be active; otherwise roll back.
    # "|| true" because the probe is expected to fail with the guard's PermissionError; we inspect its message instead.
    out="$(python3 -c 'import os, unittest; os.kill(1, 0)' 2>&1 || true)"
    case "$out" in
      # guard is live: success
      *"signal_guard blocked"*) ;;
      *)
        rm -f -- "$boot" "$pth"
        echo "install_signal_guard.sh: verification FAILED, rolled back. Output was:" >&2
        printf '%s\n' "$out" >&2
        exit 1 ;;
    esac
    echo "installed in $site" ;;
  # Unknown mode.
  *) echo "usage: $0 [--status | --install --yes | --remove]" >&2; exit 2 ;;
esac
