# AGENTS.md — Synapse IPS

This file is operational guidance for any AI coding agent (OpenCode or otherwise) working in this repo. It does not restate the architecture — that lives in `doc/Synapse-IPS-Architecture.md`, which is the source of truth for *design*. `doc/STATUS.md` is the separate source of truth for *what's actually built* — read both, and don't confuse one for the other (see Hard Rule 0). This file exists to (a) point you at the right sections of the architecture doc for a given task, (b) give commands/conventions neither doc covers, and (c) put a hard stop on a few mistakes that are easy to make if you only skim.

## Before you do anything structural

Read `Synapse-IPS-Architecture.md` §1b ("Reviewed & Rejected Alternatives") **before** proposing or making any of the following changes. They have already been considered and explicitly declined for v1, with reasoning:

- Adding Linux or Windows support (capture, enforcement, or crate scaffolding for either)
- Adding `tokio` anywhere in the `agent` or `platform-macos` crates
- Adding a backend/control-plane service (API server, Postgres, ClickHouse, fleet management, auth)
- Pre-creating multi-platform crate directories "for later"

If you think one of these is actually necessary, say so and argue it explicitly against the reasoning already in §1b — don't just add it because it seems like reasonable engineering. A prior correct decision is not an invitation to re-litigate it by default.

## Where to look for context, by task

- Adding or changing a detector → §4b (`DetectorFinding`, latency budgets) and `crates/agent/src/detectors/`
- Touching anything that calls `pfctl` or talks to the helper → §4c (`EnforcementBackend` trait) and §1 (typed-values-only, no strings, no shell interpolation — this is non-negotiable, not a style preference)
- Touching capture, the BPF fd, or the helper/agent split → §2 (diagram) and §1a (threat model — explains *why* the privilege split exists)
- Touching enrichment (DNS/geo/reputation/process attribution) → §4 (it's async, it must never block the hot path — see the open policy question about missing enrichment at decision time, which is still unresolved and worth flagging if you hit it)
- Anything about `pf` reload/anchor behavior → §4a
- Repo/crate layout questions → §5, and note the explicit principle: don't build cross-platform abstractions before a second platform is real

## Hard rules (violating these is a bug, not a style nit)

0. **`Synapse-IPS-Architecture.md` describes the target design, not what's currently built.** Nothing in it — trait names, structs, pipeline stages, whole components — exists until `doc/STATUS.md` says it does. Before answering any question about what the code currently does, or writing code that assumes something exists, open and read the actual source file. Do not infer implementation status from the architecture doc's tense or phrasing (it's written in present tense throughout, which describes the design, not a claim that it's running), and never describe planned/spec'd behavior as if it's already working. `doc/STATUS.md` is the ground-truth ledger — check it first, then verify against the real file before relying on it further.
1. **Only `platform-macos/src/helper/` runs privileged, and only it calls `pfctl`.** If you're writing code in `crates/agent/` and you find yourself wanting to shell out to `pfctl` or touch the BPF device directly, stop — that's a sign the code belongs in the helper, not the agent.
2. **`pfctl` is invoked via `Command::new("pfctl").arg(...).arg(...)` — never via a shell, never via string formatting into a command line.** This applies even to values that are already typed (`IpAddr`, etc.) — see §4c for why typed data alone doesn't make this safe. This also means: don't assume a `.args([...])` call is *functionally* correct just because it's shell-injection-safe — verify the actual flag syntax against the real tool's docs (e.g. `pfctl -k` takes two separate `-k host`/`-k network` flags, not one formatted "proto from X to Y" sentence — that mistake shipped once already, see `doc/STATUS.md`).
3. **No `tokio` in `agent` or `platform-macos`.** `std::thread` + `crossbeam` only. If a piece of code seems to need an async runtime, that's a signal to re-check whether it belongs in this project at all right now (see §1b).
4. **Every detector implementation returns a `DetectorFinding`, not a raw score**, and must respect its configured timeout — don't write a detector that can block indefinitely.
5. **Enrichment code must never be awaited inline in the hot path** (capture → feature extraction → detection → decision → enforcement). If you're adding an enrichment source, it goes through the async worker pool in `crates/agent/src/enrichment/`.
6. **PID attribution must carry process start-time alongside the PID**, not PID alone (avoids PID-reuse misattribution — see §5 changelog for why).

## Naming conventions

- Crates/packages: `synapse-*`
- Rust modules: `snake_case`
- Types: `PascalCase`
- SQLite tables: `snake_case`
- Enforcement functions: verb-first, e.g. `apply_block()`, `remove_block()`
- Event/log names: `snake_case`, past-tense-ish nouns, e.g. `flow_observed`, `decision_created`
- Any measurement field name carries its unit explicitly: `latency_us`, `ttl_ms`, `duration_ns` — never a bare `latency` or `duration` with the unit left implicit

## Build, lint, test

This is a Cargo workspace (see §5 for crate layout). Standard commands apply:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Recommended additional tooling (adopted from review — these are dev-quality tools, not scope changes, so they're fine to bring in early):

```bash
cargo deny check        # dependency license/advisory policy
cargo audit              # known-vulnerability scan
cargo nextest run        # faster/better test runner than `cargo test`
cargo fuzz               # for parsers touching untrusted input (packet parsing, protocol.rs)
```

`criterion` (benchmarking) and `proptest` (property-based testing) are worth reaching for specifically around the capture/parsing path and the `Detector`/`EnforcementBackend` trait boundaries, since that's where malformed or adversarial input actually lands.

## Order of work

Follow §6 (First Build Milestone) literally: capture → typed IPC to helper → `pfctl` block, end to end, before anything ML- or UI-related. Don't start the ONNX detector, the dashboard, or enrichment sources until that milestone works. If asked to build something from a later stage before the milestone is proven, flag that explicitly rather than silently complying — the sequencing is intentional (see §6's reasoning), not arbitrary.

## When you're unsure

If a task seems to require a decision this file and the architecture doc don't cover — e.g., the open enrichment-timing policy question in §4, or how `EnforcementBackend::reconcile()` should handle a specific `pf` conflict — don't guess silently. State the ambiguity and the option you're leaning toward, then proceed with that assumption explicitly noted, so it's visible and revisable rather than buried in an implementation choice.
