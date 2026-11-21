# Documentation

One page per component. Each page says what the component does, shows its public Python API and command line, and ends with **How to plug in your own**, a short, runnable recipe for adapting it to your project.

| Page | Component | Plug in your own |
|---|---|---|
| [stop_latch.md](stop_latch.md) | one shared STOP file for workers | a custom `on_stop` callback, a custom STOP location |
| [write_guards.md](write_guards.md) | locks, compare-and-swap, per-host names, signal safety net | wrap your own writer, per-host naming, signal guard in your test runner |
| [secret_scan_suite.md](secret_scan_suite.md) | credential scanner and git hooks | your own rule, your own private host list, your own exemptions |

The component READMEs ([stop_latch](../stop_latch/README.md), [write_guards](../write_guards/README.md), [secret_scan_suite](../secret_scan_suite/README.md)) remain the reference for every limit and side effect. Start at the [top-level README](../README.md).
