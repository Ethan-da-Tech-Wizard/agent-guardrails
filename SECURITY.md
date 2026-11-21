# Security policy

This is a prototype-stage project maintained by one person (Ethan Kilmer, TWU LLC). There is no bounty and no response-time promise; I will reply when I can.

## How to report a vulnerability

Private vulnerability reporting is enabled on this repository.

1. Open the repository's **Security** tab, choose **Report a vulnerability**, and fill in the form. Only you and the maintainer can see it.
2. Or email **ethan@twu.software** with steps to reproduce.

Please do not open a public issue or pull request with exploit details. Do not include real secrets in a report; use made-up values with the same shape (and build them from pieces so a scanner does not flag your message).

## Scope

In scope: the code in this repository, in particular a scanner or hook that prints a secret, a credential shape it claims to cover but misses, a way to make `write_guard.py` or `guarded_write.py` write outside its declared root or lose an update without an error, a lock-folder trust check that can be bypassed, the `install_signal_guard.sh` installer running code from a location other users can write, and a STOP latch that is ignored when the file exists.

Out of scope: your environment, other tools, and anything listed under "Status and limits" in each component README.

## What is not a boundary

- `stop_latch` is cooperative. Only code that calls it is stopped, and anyone who can create the file can stop the workers. It is not access control.
- Locks and compare-and-swap only protect writers that use them. An editor or script that writes directly is not stopped. They are not distributed locks.
- `secret_scan_suite` is regex based. A clean result means nothing known was found. The git hook is bypassed by `git commit --no-verify`, a later `core.hooksPath`, or `SECRET_HOOK_SKIP`; it is a guard against accidents, not against a determined user.
- `signal_guard` only acts while `unittest` is imported; it is a safety net, not a sandbox.
- Linux is untested here; Windows is not supported.

Supported version: the latest commit on the default branch.
