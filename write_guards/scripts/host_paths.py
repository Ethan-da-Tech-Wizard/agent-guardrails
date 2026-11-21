#!/usr/bin/env python3
"""
host_paths.py: one place that gives every writer a PER-HOST file name, so two computers never write the
same synced file (a file-sync tool would otherwise make a conflict copy on every cycle).

THE PATTERN:
  data/x/LATEST.json        ->  data/x/LATEST.<host>.json
  per_host("a/b/name.ext")  ->  "a/b/name.<host>.ext"
  Writers call per_host(); readers call resolve(), which returns the per-host file if it exists and
  otherwise the legacy shared file (read-only fallback, so nothing breaks before the first new write).

HOST NAME: env HOST_PATHS_HOST if set (tests and overrides), else the short hostname, lower-cased
  (for example "laptop", "desktop", "server").  Never empty.

WHY: when two computers share a folder through a sync tool, both writing one file creates
  a conflict copy every cycle; one file per host removes the conflict by construction.
THREAT MODEL: none; this is naming only. It does not validate or sanitise the host string
  or the relative path, so callers must not feed it untrusted input.
EXAMPLE:
  >>> per_host("data/x/LATEST.json", "box").as_posix()
  'data/x/LATEST.box.json'
"""
# >>> HOW THIS WORKS
# FLOW:    1 host_name() returns env HOST_PATHS_HOST if set, else the short hostname, lower-cased, never empty ("unknown-host").
#          2 per_host("a/LATEST.json") puts the host before the last suffix: a/LATEST.<host>.json (no suffix: name.<host>).
#          3 resolve(root, rel) returns root/per_host(rel) if that file exists, else the old shared root/rel.
# DATA:    Pure path maths. resolve() only calls Path.exists(); nothing is read, written or created.
# FAILS:   No errors are raised or handled on purpose. A missing per-host file simply falls back to the legacy
#          shared path, which may itself not exist (the caller then sees the usual missing-file result).
# EXTEND:  Add new naming helpers here, keep them pure. Test: scripts/test_host_paths.py. Run:
#          PYTHONPATH=scripts python3 -B -m unittest -q scripts.test_host_paths
# GOTCHAS: Writers must use per_host() and readers resolve(); mixing them brings back the sync conflict copies.
#          A host argument is not cleaned: per_host() uses it exactly as given.
# GLOSSARY: a sync tool copies files between computers; a *.sync-conflict-* file is its copy when two hosts edit one file.
# <<< HOW THIS WORKS
from __future__ import annotations

import os
import socket
from pathlib import Path


def host_name() -> str:
    """Short, lower-case name of this computer; HOST_PATHS_HOST overrides (used by tests)."""
    # Prefer the explicit override; otherwise drop any domain part of the hostname ("box.example" -> "box").
    raw = os.environ.get("HOST_PATHS_HOST") or socket.gethostname().split(".")[0]
    return (raw.strip().lower() or "unknown-host")  # never return an empty name


def per_host(rel, host: str | None = None) -> Path:
    """Insert the host name before the final suffix: a/LATEST.json -> a/LATEST.<host>.json.

    Args:
        rel: relative path (str or Path). host: explicit host name; default host_name().
    Returns:
        A Path. A name with no suffix gets ".<host>" appended; only the LAST suffix counts,
        so "x.tar.gz" becomes "x.tar.<host>.gz". The host string is used exactly as given.
    """
    p = Path(rel)
    h = host or host_name()
    if p.suffix:
        return p.with_name(f"{p.stem}.{h}{p.suffix}")
    return p.with_name(f"{p.name}.{h}")


def resolve(root, rel, host: str | None = None) -> Path:
    """Path to READ: this host's file if present, else the legacy shared file (read-only fallback).

    Args:
        root: base directory. rel: the legacy (shared) relative path. host: optional override.
    Returns:
        root/per_host(rel) if it exists, otherwise root/rel (which may not exist either).
    """
    root = Path(root)
    mine = root / per_host(rel, host)
    return mine if mine.exists() else root / rel
