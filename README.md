# carrick-nt

The NT (Windows) personality for [Carrick](https://github.com/carrick-sh/carrick).
It runs unmodified Windows binaries on Carrick's shared guest kernel.

**Status: early bring-up.** The PE loader, NT call decoder and dispatch,
guest `ntdll`/`kernel32` stubs, the import census and console fixtures exist.
Next milestones: M2 (a console hello world on Carrick through the carrier
library), then M3 (file I/O and process creation).

- Dependencies point one way, NT -> Carrick. Nothing in `carrick` names this
  repository. Carrick keeps the personality-neutral core, the seams and the
  registration hooks (see `docs/superpowers/specs/2026-10-04-personality-core-split.md`
  in carrick).
- First target: x86_64 guests and console programs.
- Experimental. Not production-ready. Not a security boundary.

Work is tracked on the org project board "Carrick shared kernel"; rules for
contributors and agents are in [AGENTS.md](AGENTS.md).

Licensed under either of Apache License, Version 2.0 or MIT license, at your option.
