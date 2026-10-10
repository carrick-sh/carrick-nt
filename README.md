# carrick-nt

The NT (Windows) personality for [Carrick](https://github.com/carrick-sh/carrick).
It runs unmodified Windows binaries on Carrick's shared guest kernel.

**Status: not started.** This repository holds governance only. It contains no
NT implementation yet.

- Dependencies point one way, NT -> Carrick. Nothing in `carrick` names this
  repository. Carrick keeps the personality-neutral core, the seams and the
  registration hooks (see `docs/superpowers/specs/2026-10-04-personality-core-split.md`
  in carrick).
- First target: x86_64 guests and console programs.
- Experimental. Not production-ready. Not a security boundary.

Work is tracked on the org project board "Carrick shared kernel".

Licensed under either of Apache License, Version 2.0 or MIT license, at your option.
