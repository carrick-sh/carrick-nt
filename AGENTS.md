# AGENTS.md: carrick-nt

Rules for agents and humans working in this repository. Carrick's AGENTS.md
supplies the shared engineering standards (typed domains, red-first, no
shortcuts, commit style). Its build, codesign and conformance commands do not
apply here; this repository's gate is below. Where the two differ, this file
wins.

## Clean room: hard rules
- **No Wine, ReactOS or other reimplementation source, design or tests**, in
  any form: no code, no structure, no test reuse. Never cite them as prior art.
- **No leaked, decompiled or disassembled Microsoft code**, and no GPL or LGPL
  sources.
- **Never reverse engineer Microsoft binaries.** No disassembly, no
  decompilation, no debugging or tracing inside Microsoft code, and no PDB or
  symbol-server inspection.
- **Reading PE metadata is allowed**: our own loader may read the PE headers
  and import/export directories of real Windows binaries (for example the
  import census). Results are names, ordinals and counts, never code.
- **No Microsoft bytes in the repository or any build input**: no DLLs, no
  SDK headers, no `.lib` import libraries, no copied tables.
- **No third-party tables of undocumented NT internals** (syscall-number
  tables, structure dumps, undocumented-API wikis).
- Behaviour is learned only from public documentation (Microsoft Learn,
  published specs) and from black-box observation of real Windows. Every
  structure or behaviour cites a Learn URL or an oracle receipt, and each PR
  lists its sources under "Verified".
- **The oracle is real Windows**: Windows containers, or the owner's Windows VM.
  Conformance is differential, as in Carrick's Linux Docker oracle.

## Gating
- Before review, run and post on the PR:
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo xtask all`, plus an oracle receipt for any
  guest-visible behaviour.
- The similarity scan of AI-generated NT code and the IP counsel review were
  deferred by the owner on 2026-10-10. They do not gate implementation work.
  The clean-room rules above still apply in full.

## Depending on Carrick
- Dependencies point NT -> Carrick only. Nothing in Carrick may name NT.
- Pin every Carrick git dependency to ONE commit on Carrick `main`'s
  first-parent history (`rev =`), never a PR branch head. Repin all of them
  together in a dedicated bump PR.
- Depend on Carrick's personality-facing API (`carrick-personality-api`) rather
  than Carrick internals. Until it is on a pinned `main` commit, depend only on
  `carrick-core` and `carrick-guest-arch`.
- A missing or wrong Carrick capability is a **seam request**: open a
  carrick-sh/carrick issue in personality-neutral vocabulary (no NT names),
  labelled `seam`, and link it from the NT issue. Never patch Carrick from
  this repo, and never build a local stand-in.
- No fake backends: do not build simulated or in-memory versions of Carrick
  subsystems to test against. Test-only doubles stay behind `cfg(test)` or a
  `test-support` feature, and behavioural witnesses run against the real
  Carrick path once it exists.

## Workflow
GitHub is the system of record for plans, status, decisions and evidence;
chat, mailboxes and agent memory are not.
- **Issue first, then work.** Every unit of work starts as an issue
  (NT-0xx work packages, defects, seam follow-ups) with the plan and an
  acceptance criterion. Briefs cite it; the PR closes it.
- **Draft PR from the first commit**, linked to its issue. PRs land by squash
  merge after review.
- **Board status follows every transition** on the org project "Carrick
  shared kernel" (project 1, spanning carrick and carrick-nt): Todo →
  In progress → In review → Done. Blocked names its blocker.
- **Decisions** go in Carrick's decision-log issue (carrick#231) and on the
  affected issue when they are made.
- **Progress, blockers, oracle receipts and gate evidence are PR comments**;
  facts and defects are labelled issues.
- **Workers:** codex for personality, loader and seam design; Gemini for
  precisely specified mechanical work. Commits carry the worker's
  `Co-Authored-By:` trailer.
- Commits use `type(scope): subject` with a Why, What and Verified body,
  matching Carrick.
