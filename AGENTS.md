# AGENTS.md: carrick-nt

Rules for agents and humans working in this repository. Carrick's own
AGENTS.md also applies, except where this file is stricter.

## Clean room: hard rules
- **No Wine, ReactOS or other reimplementation source, design or tests**, in
  any form: no code, no structure, no test reuse. Never cite them as prior art.
- **No leaked, decompiled or disassembled Microsoft code**, and no GPL or LGPL
  sources.
- Behavior is learned only from public documentation (Microsoft Learn,
  published specs) and from black-box observation of real Windows.
- **The oracle is real Windows**: Windows containers, or the owner's Windows VM.
  Conformance is differential, as in Carrick's Linux Docker oracle.

## Gating
- The similarity scan of AI-generated NT code and the IP counsel review were
  deferred by the owner on 2026-10-10. They do not gate implementation work.
  The clean-room rules above still apply in full.
- Dependencies point NT -> Carrick only.

## Workflow
- GitHub-first: every change is a draft PR from its first commit, linked to an
  issue on the org board; progress goes in PR comments; facts and defects are
  labelled issues.
- Commits use `type(scope): subject` with a Why, What and Verified body,
  matching Carrick.
