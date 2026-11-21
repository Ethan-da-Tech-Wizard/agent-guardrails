# stop_latch

A single shared "STOP" file that tells long-running worker processes to stop, plus a tiny library any worker can call.

## Why this exists
Programs that run unattended (schedulers, daemons, agents, batch jobs) sometimes have to be halted everywhere at once, for
example when they are doing something wrong faster than you can find and kill each process. Hunting down every process by
hand is slow and error-prone, and a "stop" that needs a running service fails exactly when things are broken. A plain file
is the simplest signal that survives crashes and needs nothing running: when the STOP file exists, workers that call this
library refuse to start, and running workers get SIGTERM (so their own shutdown handlers run) and are hard-exited after a
grace period if they ignore it. Delete the file to allow work again.

## Install
Copy `scripts/stop_latch.py` into your project (or put `scripts/` on `PYTHONPATH`). Nothing else to install.

**Where the STOP file lives (read this).** By default it is `STOP` in the PARENT of the folder that contains `stop_latch.py`.
Keeping the original layout (`<root>/scripts/stop_latch.py`) that is `<root>/STOP`. If you copy the file to
`myproject/stop_latch.py`, the default STOP file is `<parent of myproject>/STOP` (and `/STOP` if you put it in a top-level folder),
which is rarely what you want. To avoid surprises, always set one of the two variables below in the environment of every
worker and of the person who creates the file; `python3 stop_latch.py` prints `STOP present` / `STOP absent` for the path in force.

## Usage
```python
import stop_latch
stop_latch.enforce("my-worker")          # at the top of a long-running worker
stop_latch.refuse_if_stopped("my-job")   # entry check only, for one-shot commands
```
Running the file directly prints `STOP present` or `STOP absent`. Create the latch with `touch <root>/STOP`; remove it
to allow work again. `stop_latch.stop_present()` is a plain `stat` check. Watching is a poll every 5 s by default.

## Configuration
| env var | effect |
|---|---|
| `STOP_LATCH_ROOT` | folder that holds `STOP` (default: the parent of the folder that contains `stop_latch.py`) |
| `STOP_LATCH_FILE` | exact path of the STOP file; overrides `STOP_LATCH_ROOT` |

## Side effects
Reads only (existence of the STOP file). `enforce()` starts one daemon thread per name; on STOP it prints one line,
sends SIGTERM to its own process and, after the grace time (30 s), calls `os._exit(0)` if still alive.

## Placeholders

None: nothing in this component needs to be filled in; configuration is by environment variables only.

## Run all tests (no CI needed)

```sh
cd stop_latch
python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

Python 3.9 or newer, standard library only, no network, no packages to install. The command above is all you need.
(The maintainers also run the suites through an optional isolating runner, `hermetic_run.py`, from the release-kit repository at https://github.com/Ethan-da-Tech-Wizard/release-kit; it is not part of this repository and nothing here depends on it.)

## Status and limits
- Cooperative: only code that calls `enforce`/`refuse_if_stopped` is stopped. Nothing here kills other processes.
- It is a same-machine latch, not a security boundary: anyone who can create the file can stop the workers, and a process that never calls `enforce` ignores it.
- A relative `STOP_LATCH_FILE` is made absolute once, when the module is imported (against the working directory of that moment),
  so a later `os.chdir()` in the worker does not change which file is watched.
- `STOP_LATCH_FILE` and `STOP_LATCH_ROOT` both expand `~`. A `..` in `STOP_LATCH_FILE` is NOT collapsed in text (it is resolved by the operating system when the file is checked), so `link/../STOP` with `link` a symlink means the parent of the link's target, as it does for every other program.
- A symlink at the STOP path counts as present even when its target is missing (the link itself is the latch).
- If a custom `on_stop` callback raises, the failure is printed and the default reaction (SIGTERM, then hard exit after the grace
  period) runs instead; the watcher never ends with nothing done.
- Polling, not file events; a stopped worker can run for up to one interval (plus the grace period).
- If the STOP location becomes unreadable (for example `PermissionError` on its folder) the answer is "unknown": starting a worker
  fails loudly with the error, and an already-running watcher prints one warning to stderr and keeps polling (it does not die and
  does not stop the worker). Fix the permission or set `STOP_LATCH_FILE` to a readable place.
- Status: small and finished for its purpose; tested on macOS with Python 3.9 (13 tests, all pass). POSIX signals are
  used; Windows is not supported and Linux is untested here.
- Licence: MIT, copyright TWU LLC. Notes: `CHANGES_FROM_SOURCE.md`.
