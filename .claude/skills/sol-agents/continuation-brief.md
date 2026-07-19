# Continuation-agent brief (fix round / resume on an existing PR)

You are working an EXISTING PR: either resuming one whose previous agent died mid-loop
(model-capacity outage) or running a fix round on findings handed to you by the orchestrator.
All rules of `agent-brief.md` — the file sitting NEXT TO this one in the same skill directory
(the orchestrator's prompt gives you its absolute path) — apply: no local builds/tests
(`cargo fmt --all` only), one `@codex review` per round, never merge, final report. Do NOT
create a new worktree or branch — work in the existing worktree given in your prompt (the
branch is checked out there).

## YOU are the implementer (do not sub-dispatch)

Implement, commit, and push the changes YOURSELF, in this session. Do NOT invoke any
agent-dispatch skill or script available in your environment (e.g. `opus-agents`, `fable-agents`,
`grok-agents`, `.agents/skills/*/scripts/dispatch-agent.sh`, `claude` CLI workers) and do NOT
spawn nested
workers — the orchestrator chose this session's model and reasoning effort deliberately, and
delegating the implementation silently substitutes different hands at a different effort. If a
skill index entry fails to load (stale path), ignore it and continue; you need nothing beyond
this brief, `agent-brief.md`, and your prompt.

Resume procedure, in order:
1. `git status` + `git log --oneline -5` in the worktree. If there is uncommitted WIP, read it,
   decide finish-or-discard on its merits, and fold it into a proper commit if kept.
2. `git fetch origin` and check whether origin/main moved; merge it only if GitHub reports a
   conflict on the PR (check `mergeable` via `gh pr view`).
3. Reconstruct review state: fetch ALL codex review threads
   (`gh api graphql` reviewThreads query from the main brief) and the PR comment timeline.
   Identify unresolved findings and whether the last `@codex review` trigger predates the
   latest push (if so, a re-trigger is needed AFTER you finish fixes).
4. Triage CI: `gh pr checks <PR>`. For each failure, read the log
   (`gh run view <id> --log-failed` or the jobs API). Failures whose log shows
   "cargo fetch failed ... likely a crates.io/registry outage" are stale outage artifacts —
   rerun them (`gh run rerun <id> --failed`). Known-flake list is in the main brief. Anything
   else: fix for real.
5. Then continue the normal loop: verify each unresolved codex finding in code, fix or rebut
   with evidence, fmt, commit, push, post exactly ONE `@codex review` summarizing dispositions,
   wait/poll, repeat until codex is clean AND CI is green. Report final state.
