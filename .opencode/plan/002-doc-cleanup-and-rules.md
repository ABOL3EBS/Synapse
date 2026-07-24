# Plan: Documentation Cleanup + Agent Structural Rules

## Problem

The documentation is well-written but bloated. 16 markdown files with massive redundancy. The agent produces structurally bad code (838-line monoliths, copy-paste blocks, leaked threads) because the agent rules enforce naming conventions and security invariants but have zero rules about code structure.

## Part 1: Delete Redundant Files

**Delete 8 files:**

| File | Why |
|---|---|
| `VALIDATION_REPORT.md` | One-time artifact from 07-24. All info now in STATUS.md. Stale commit hash. |
| `doc/report.md` (876 lines) | Day-by-day diary. Architecture details duplicate `Synapse-IPS-Architecture.md`. Bug history duplicates `STATUS.md`. Test results are just a list. Agent never needs this. |
| `doc/intern-presentation-prompt.md` | Slide deck content. Stale (says enforcement wiring is TODO — it's done). Not agent context. |
| `doc/components/anchor-fix/context.md` | Historical bug postmortem. Already in commit history. Not actionable for future agents. |
| `crates/common/context.md` | Duplicates `doc/components/types/context.md` word-for-word. |
| `crates/platform-macos/context.md` | Duplicates `doc/components/{enforcement,ipc,capture}/context.md` combined. |
| `crates/agent/src/flow/README.md` | Duplicates `doc/components/agent-engine/context.md` flow section. Has stale line count (574 vs 975). |

**After cleanup: 8 files remain:**

```
opencode.md                        — Agent rules (structural + conventions + status)
README.md                          — Human-facing GitHub overview
doc/STATUS.md                      — Ground-truth ledger
doc/Synapse-IPS-Architecture.md    — Design blueprint + rejected alternatives
doc/components/capture/context.md  — BPF setup (ioctl ordering, gotchas)
doc/components/enforcement/context.md — pfctl execution (anchor lifecycle, methods)
doc/components/ipc/context.md      — SCM_RIGHTS + bincode protocol
doc/components/types/context.md    — Shared types, Detector trait, Verdict, DecisionConfig
doc/components/agent-engine/context.md — Capture loop, flow tracker, detectors, decision engine
```

## Part 2: Update Remaining Component Context Files

Fix stale information in the 6 component context files:

- `agent-engine/context.md`: says "No catch_unwind yet" and "No circuit breaker" — both are done. Fix.
- `agent-engine/context.md`: stale line counts (819 vs actual, 574 vs 975 for flow). Fix.
- All files: verify line counts match actual source.

## Part 3: Rewrite opencode.md — Add Structural Quality Rules

Add a new section to `opencode.md` that enforces code structure. This is the core fix.

### New section: "Structural Rules"

```markdown
## Structural Rules — Code Quality (non-negotiable)

These rules exist because the agent has a pattern of making code that compiles and passes tests but is structurally bad. Follow them literally.

### Function size
- **No function body may exceed 80 lines.** If a function hits 60+ lines, start planning extraction. At 80, stop and refactor before adding more.
- **`main()` must be under 100 lines.** It orchestrates — it does not implement. Extract the capture loop body into a struct and its methods.

### Module size
- **`main.rs` must stay under 500 lines.** If it exceeds 400, the next feature must go in a new module file, not appended to main.
- **Any file over 600 lines needs justification.** Add a comment explaining why it can't be split.

### No copy-paste
- **If you write two similar code blocks (same structure, different variable names), you have already made a mistake.** Stop. Extract the common logic into a function with parameters. The copy-pasted enforcement blocks in the capture loop (expired vs re-evaluate) are the canonical example of what NOT to do.
- **Rule of three:** If the same pattern appears twice, note it. Three times, extract immediately. Don't wait for the refactor trigger.

### One responsibility per function
- **A function does one thing.** If a function name contains "and" (e.g., "parse_and_store"), split it.
- **A function's control flow should be readable top-to-bottom.** Deeply nested match/if chains inside a function that also does I/O means the function has too many responsibilities.

### Extraction discipline
- **Before writing a new for-loop body, check if a similar loop already exists.** Read the surrounding code. If there's a loop that does detector→decision→enforcement, reuse or extend it — don't write a new one.
- **The capture loop body (inside `loop {}`) is the highest-risk area for copy-paste.** Every new feature added to the capture loop must be reviewed against existing loop bodies before writing.

### Refactor triggers (if you see these, fix before proceeding)
- Two for-loops with >70% identical code
- A function that takes 5+ parameters (consider a struct)
- A function that does I/O AND computation AND logging (split)
- `main.rs` over 500 lines
- Any `.rs` file over 800 lines

### Verification
After making structural changes, run:
```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
```
All four must pass. If structural refactoring breaks tests, fix the tests — don't revert the refactoring.
```

### Update existing conventions section

Add to the existing "Coding Conventions" section:

```markdown
8. **Extract, don't duplicate.** Before writing a second similar block, extract the first into a reusable function.
9. **Functions under 80 lines.** main() under 100. main.rs under 500.
```

### Update "Agent workflow" section

Add after the existing workflow rules:

```markdown
- **Before adding code to the capture loop, read the entire loop body.** Identify existing patterns. Reuse or extend — never duplicate.
- **After completing a step, check file sizes.** If main.rs is over 500 lines, the next step must include extracting a module.
```

## Part 4: Fix STATUS.md Socket Permission Claim

`doc/STATUS.md` line says socket permissions are `0o660` — but the code is `0o666`. Either:
- Fix the code to `0o660`, or
- Fix the doc to say `0o666`

The audit found `0o666` is the current state. Update STATUS.md to match reality.

## Execution Order

1. Delete 8 files (Part 1)
2. Update 6 component context files (Part 2)
3. Rewrite opencode.md with structural rules (Part 3)
4. Fix STATUS.md socket permission claim (Part 4)
5. Verify: `cargo build`, `cargo clippy`, `cargo fmt`, `cargo test`

## Files Modified

- **DELETE:** 8 files listed in Part 1
- **EDIT:** `opencode.md` — add structural rules section
- **EDIT:** `doc/STATUS.md` — fix socket permission claim
- **EDIT:** `doc/components/agent-engine/context.md` — fix stale claims (catch_unwind, circuit breaker, line counts)
- **EDIT:** `doc/components/capture/context.md` — verify line counts
- **EDIT:** `doc/components/enforcement/context.md` — verify line counts
- **EDIT:** `doc/components/ipc/context.md` — verify line counts
- **EDIT:** `doc/components/types/context.md` — verify line counts
