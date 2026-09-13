# Synapse IPS — Database Architecture

Ground-truth ledger for Synapse's persistent storage: two SQLite databases, all
tables with their columns, and the relationships between them.

**Source of truth:** `crates/agent/src/storage/schema.rs` (DDL constants
`V1_DDL`/`V4_DDL`/`V6_MIGRATION` + `apply_schema()`), `crates/agent/src/storage/spool.rs`,
`crates/agent/src/storage/mod.rs` (write paths, retention, replay),
`crates/platform-macos/src/helper/reconcile_db.rs` (helper read path).

If this file and the schema code disagree, the code wins.

---

## 1. Database inventory

| | Main audit DB | Crash-safe spool |
|---|---|---|
| **Path** | `$HOME/.synapse/synapse.db` (or `$SYNAPSE_DB_PATH` env var) | `<main-db-path>` with extension replaced → `$HOME/.synapse/synapse.spool` (`db_path.with_extension("spool")`) |
| **Writer** | Agent `StorageWorker`; Tauri `WriteDbState` (unblock only) | Agent `StorageWorker` (`CriticalSpool`) |
| **Readers** | Helper `reconcile_db.rs` (read-only), Tauri read conn, agent `StorageReader` | Agent `StorageWorker` (startup replay) |
| **journal_mode** | `WAL` | `DELETE` |
| **synchronous** | default (WAL) | `FULL` — every append fsync'd before returning |
| **foreign_keys** | `ON` | `OFF` |
| **Other PRAGMAs** | `trusted_schema=OFF`, `secure_delete=ON` | — |
| **Schema version** | `PRAGMA user_version = 6` | one table; `payload_version` column (currently 1) |
| **Purpose** | Decision + enforcement audit trail, dashboard queries, reconcile source | At-least-once delivery of Critical (enforcement lifecycle) events across agent crashes |

### Why the spool exists

Critical events (enforcement lifecycle) are written to the spool **before** the
main DB commit. If the agent crashes between the IPC send and the database
commit, the spool entries survive and are replayed into `enforcement_log` on
next startup via `INSERT OR IGNORE` on the stable `event_id` column —
idempotent at-least-once delivery.

---

## 2. Tables and columns

### 2.1 `spool` (crash-safe spool DB)

One table, no WAL, `synchronous=FULL`.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK AUTOINCREMENT | |
| `event_id` | TEXT | NOT NULL UNIQUE | Stable ID from `boot_id:seq`; dedup key for replay |
| `ts_ms` | INTEGER | NOT NULL | Wall-clock event timestamp |
| `kind` | TEXT | NOT NULL | Operator visibility only — written but never read back (e.g. `EnforcementRequested`) |
| `payload_version` | INTEGER | NOT NULL DEFAULT 1 | **V6** — payload JSON shape version. Replay refuses unrecognised versions (logs + skips, entry stays unconfirmed) rather than misparsing. Pre-V6 spools get the column via `ALTER TABLE ... DEFAULT 1` — old payloads are version 1 and remain replayable. |
| `payload` | TEXT | NOT NULL | JSON of the Critical event (`ip_text`, `ip_blob_hex`, `ttl_ms`, `reason`, `detector`, `score`, `send_error`) |
| `done` | INTEGER | NOT NULL DEFAULT 0 | 0 = unconfirmed (replay on startup), 1 = committed to main DB |

**Lifecycle:** `append()` (synchronous=FULL) → main-DB commit → `confirm()`
sets `done=1` → `prune_done()` deletes `done=1 AND ts_ms < now-7d` on the
hourly retention tick.

### 2.2 `enforcement_log` (main DB, Critical)

Enforcement lifecycle — one row per Block/Unblock action.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK AUTOINCREMENT | |
| `event_id` | TEXT | NOT NULL UNIQUE | Stable ID; replay uses `INSERT OR IGNORE` on this |
| `ts_ms` | INTEGER | NOT NULL | Wall-clock event timestamp |
| `action` | TEXT | NOT NULL CHECK (`'Block'` \| `'Unblock'`) | **V6** — CHECK constraint enforces the enum at the DB level |
| `ip_blob` | BLOB | NOT NULL | 16-byte IPv4-mapped IPv6 canonical binary form |
| `ip_text` | TEXT | NOT NULL | Human-readable (denormalised for queries/UI) |
| `ttl_ms` | INTEGER | nullable | Block TTL; NULL/0 for Unblock |
| `reason` | TEXT | NOT NULL | Decision reason; `'dashboard-requested'` for manual unblocks |
| `detector` | TEXT | nullable | Top-scoring detector that caused the Block |
| `score` | REAL | nullable CHECK (`score IS NULL OR score BETWEEN 0 AND 1`) | **V6** — composite score at decision time, range-checked |
| `error` | TEXT | nullable | IPC send error if send failed |

**V6 note:** the legacy `requested` (IPC-send-attempted) and `confirmed` (helper
ACK) columns were **dropped**. They were written-but-never-read: `confirmed` was
always 0 (no ACK in the protocol) or 1 for dashboard/block-test unblocks, and
nothing filtered on it as a real acknowledgement. The send-failed case is fully
represented by `error IS NOT NULL`.

**Indexes:** `enf_ts (ts_ms DESC)`, `enf_ip (ip_text, ts_ms DESC)`.

**Retention:** 90 days.

**Writers:** agent `StorageWorker` (Block, `INSERT OR IGNORE`); Tauri
`request_unblock` (Unblock, `INSERT` with `event_id = dashboard-<ts_ms>`).

**Readers:** helper reconcile (desired firewall state); Tauri (`get_active_blocks`,
`get_threat_stats` blocked_addresses); `StorageReader` (`recent_enforcement`,
`kpi_since`).

### 2.3 `verdicts` (main DB, Important)

One row per Alert/Block decision. Allow verdicts are NOT stored.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK AUTOINCREMENT | FK target of `detector_findings.verdict_id` |
| `ts_ms` | INTEGER | NOT NULL | Wall-clock verdict timestamp |
| `flow_id` | INTEGER | NOT NULL | Session-scoped flow ID (resets to 1 on agent restart — not a stable key) |
| `a_ip_blob` / `b_ip_blob` | BLOB | NOT NULL | Canonical endpoint blobs (smaller/larger IP — NOT src/dst) |
| `a_ip_text` / `b_ip_text` | TEXT | NOT NULL | Canonical endpoint text (smaller/larger IP) |
| `a_port` / `b_port` | INTEGER | NOT NULL | Canonical endpoint ports (NOT local/remote) |
| `protocol` | INTEGER | NOT NULL | IP protocol number (6=TCP, 17=UDP) |
| `pid` | INTEGER | nullable | Process ID at flow creation |
| `process_path` | TEXT | nullable | Full process path (used for dashboard app icons) |
| `process_start` | REAL | nullable | Float seconds (libproc) — detects PID reuse |
| `dns_name` | TEXT | nullable | Enrichment: reverse DNS |
| `country_code` | TEXT | nullable | Enrichment: GeoIP ISO-2 |
| `asn` | INTEGER | nullable | Enrichment: ASN |
| `reputation_score` | REAL | nullable | Enrichment: reputation (stub for v1) |
| `verdict` | TEXT | NOT NULL CHECK (`'Alert'` \| `'Block'`) | **V6** — CHECK constraint enforces the enum |
| `reason` | TEXT | NOT NULL | Decision reason string |
| `composite_score` | REAL | NOT NULL CHECK (`0 <= composite_score <= 1`) | **V6** — decision-engine composite (capped at 1.0), range-checked |
| `ttl_ms` | INTEGER | nullable | Block TTL only |
| `flow_age_ms` | INTEGER | NOT NULL | Flow age at verdict time |
| `pkt_count` | INTEGER | NOT NULL DEFAULT 0 | Packets seen |
| `byte_count` | INTEGER | NOT NULL DEFAULT 0 | Bytes seen |
| `local_ip_text` | TEXT | nullable | **V3** — agent local IP at verdict time |
| `remote_ip_text` | TEXT | nullable | **V5** — remote endpoint, persisted verbatim from `resolved.remote_ip` |

**Indexes:** `v_ts (ts_ms DESC)`, `v_ip (a_ip_text, b_ip_text)`,
`v_type (verdict, ts_ms DESC)`, and the V4 `v_5tuple_verdict`
`UNIQUE (a_ip_text, a_port, b_ip_text, b_port, protocol, verdict)`.

**Write path (V4+):** re-evaluation of a still-active flow UPSERTs, never
INSERTs — `ON CONFLICT(a_ip_text, a_port, b_ip_text, b_port, protocol, verdict)
DO UPDATE` refreshes ts_ms/score/reason/evidence columns and `RETURNING id`.
Distinct verdict values on the same 5-tuple (Alert escalating to Block) produce
two rows. Deduplication is enforced at the DB level, not by application code.

**Retention:** 7 days, `DELETE FROM verdicts WHERE ts_ms < cutoff` — cascades to
`detector_findings` (FK `ON DELETE CASCADE`, `foreign_keys=ON` enforced on the
worker connection).

### 2.4 `detector_findings` (main DB, Important)

One row per detector finding per verdict — the verified per-verdict evidence.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK AUTOINCREMENT | |
| `verdict_id` | INTEGER | NOT NULL REFERENCES `verdicts(id)` ON DELETE CASCADE | Parent verdict |
| `detector_id` | TEXT | NOT NULL | e.g. `CrossFlow`, `DnsAnalyzer` (Rust `Debug` of `DetectorId`) |
| `detector_version` | TEXT | NOT NULL | e.g. `1.0.0` |
| `score` | REAL | NOT NULL CHECK (`score >= 0 AND score <= 1`) | **V6** — 0.0–1.0, range-checked |
| `confidence` | REAL | NOT NULL CHECK (`confidence >= 0 AND confidence <= 1`) | **V6** — 0.0–1.0, range-checked |
| `severity` | TEXT | NOT NULL | `Low` \| `Medium` \| `High` \| `Critical` |
| `status` | TEXT | NOT NULL | `Completed` \| `TimedOut` \| `Errored` |
| `latency_us` | INTEGER | NOT NULL | Detector latency |
| `evidence_json` | TEXT | nullable | JSON array of `{description, detail?}` objects |

**Indexes:** `df_verdict (verdict_id)`, `df_detector (detector_id)`.

On every verdict upsert (including re-evaluation), the previous findings for
that verdict_id are DELETEd and re-INSERTed so evidence stays current.

### 2.5 `circuit_breaker_events` (main DB, Important)

Detector health history — circuit-breaker state transitions.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | INTEGER | PK AUTOINCREMENT | |
| `ts_ms` | INTEGER | NOT NULL | Transition timestamp |
| `detector_id` | TEXT | NOT NULL | |
| `from_state` | TEXT | NOT NULL | `Closed` \| `Open` \| `HalfOpen` |
| `to_state` | TEXT | NOT NULL | |
| `consecutive_failures` | INTEGER | NOT NULL | Failure count at transition |

**Indexes:** `cb_ts (ts_ms DESC)`, `cb_detector (detector_id, ts_ms DESC)`.

**Retention:** 7 days.

### 2.6 `metadata` (main DB, V2)

Durable key/value worker state — survives agent restarts.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `key` | TEXT | PK | |
| `value` | TEXT | NOT NULL | |

Seeded on schema apply with `('last_retention_run_ms', '0')`; updated in place
by the storage worker after each hourly retention pass. This persistence is
what makes retention fire on a long-lived run's next tick even after frequent
short-lived restarts.

---

## 3. Relationships

### 3.1 Diagram

```
                        ┌─────────────────────────────┐
                        │  agent capture pipeline     │
                        └─────────────┬───────────────┘
                          Critical    │   Important (no spool)
                          events      ▼
             ┌──────────────┐   ┌─────────────────────┐   ┌───────────────────┐
             │  spool (DB)  │──▶│  enforcement_log    │◀──│  Tauri unblock    │
             │  (pre-write) │replay on startup,       │   │  (WriteDbState)   │
             └──────────────┘ INSERT OR IGNORE       │   └───────────────────┘
                                   │ action Block/    │
                                   │ Unblock per ip   │
                                   └─────────┬────────┘
                                             │ read-only (helper reconcile,
                                             │ dashboard get_active_blocks)
                                             ▼
                       ┌─────────────────────────────────┐
                       │  verdicts (1)                   │
                       └──────────────┬──────────────────┘
                                      │ FK ON DELETE CASCADE
                                      ▼
                       ┌─────────────────────────────────┐
                       │  detector_findings (N)          │
                       └─────────────────────────────────┘

         circuit_breaker_events  ·  metadata   (standalone, no FKs)
```

### 3.2 Prose

- **`verdicts` → `detector_findings`** — 1-to-N foreign key
  (`verdict_id REFERENCES verdicts(id) ON DELETE CASCADE`). Retention pruning
  of `verdicts` propagates automatically to findings when `foreign_keys=ON`.
  **V6 status (verified live 2026-09-13):** a clean V6 run on a live-DB copy
  ends with `foreign_key_check` returning **0 rows** and **0 orphaned findings**
  — there were no pre-existing orphans at migration time. (An early buggy run's
  output was initially misread as pre-existing orphans; it was 100 % the
  `verdicts.id`-drop defect — see the V6 safety note below.) The CHECKs +
  `foreign_key_check` in the V6 dance prevent *new* orphans.
- **`enforcement_log` self-relationship (per `ip_text`)** — the *current
  desired state* for an IP is derived from the latest action: the most recent
  `ts_ms` among `action IN ('Block','Unblock')` decides; an `Unblock` after a
  `Block` supersedes it. Implemented as a `MAX(ts_ms)` correlated subquery in
  both the helper reconcile query and the dashboard's `get_active_blocks`.
  No FK enforces this — it is a query-level invariant over an append-only log.
- **`spool` → `enforcement_log`** — write-ahead relationship. Append order:
  spool first (fsync'd), then main DB in the same commit lifecycle, then
  `done=1` confirm, then prune. On startup any `done=0` entry is replayed into
  `enforcement_log` with `INSERT OR IGNORE` (idempotent on `event_id`).
- **`metadata`** is standalone; `circuit_breaker_events` is standalone.

---

## 4. Connections and access boundaries

The boundary matters: only the helper (root) and the agent can enforce; the DB
is shared but each process has a deliberately narrow surface.

| Process | Privilege | Connection | Tables touched | Direction |
|---|---|---|---|---|
| Agent `StorageWorker` | unprivileged | read-write (WAL, hardened) | `enforcement_log`, `verdicts`, `detector_findings`, `circuit_breaker_events`, `metadata` + spool | writer |
| Helper `reconcile_db.rs` | root | read-only (`READ_ONLY \| NO_MUTEX`) | `enforcement_log` only | reader |
| Tauri `DbState` | unprivileged (UI) | read-only (`READ_ONLY \| NO_MUTEX`, `query_only=ON`, WAL, `busy_timeout=5000`) | `verdicts`, `detector_findings`, `enforcement_log` | reader |
| Tauri `WriteDbState` | unprivileged (UI) | read-write (WAL, `busy_timeout=5000`) | `enforcement_log` (Unblock insert only) | writer |

**Reconcile trigger:** the dashboard's `request_unblock` writes an `Unblock`
row, then touches `~/.synapse/reconcile-now`. The helper (root) watches this
file plus its 60 s periodic pass; its reconcile loop queries
`query_desired_state()` and re-derives the real firewall state. The helper
never writes the agent's DB.

**Retention:** checked on every 250 ms tick against a 1-hour wall-clock
threshold persisted in `metadata`; deletes enforcement_log > 90 d, verdicts >
7 d (cascade), circuit_breaker_events > 7 d, spool `done=1` > 7 d.

---

## 5. Schema migration history

Tracked via `PRAGMA user_version` (currently `6`). `apply_schema()` is
idempotent — safe on every startup.

| Version | What changed |
|---|---|
| V1 | Base: `enforcement_log`, `verdicts`, `detector_findings`, `circuit_breaker_events`. Pre-v1 databases had an `enforcement_log` with a different column set (`timestamp/ip/success/message`) — it is dropped so V1 DDL can recreate it correctly. |
| V2 | `metadata` table (seeded `last_retention_run_ms`) — durable retention state across restarts. |
| V3 | `ALTER TABLE verdicts ADD COLUMN local_ip_text` — fixes dashboard showing the user's own IP as the remote endpoint for flows where local IP > remote IP. |
| V4 | Historical dedup (`DELETE` keeps `MAX(id)` per 5-tuple+verdict) + `CREATE UNIQUE INDEX v_5tuple_verdict` — re-evaluation now UPSERTs, so verdict rows count distinct detections, not re-fires. 98.2% of existing rows at the time were redundant re-fires. |
| V5 | `ALTER TABLE verdicts ADD COLUMN remote_ip_text` — remote endpoint persisted verbatim at verdict time; dashboard no longer re-derives direction from canonical a/b ordering (fallback `pick_remote()` for NULL pre-V5 rows). |
| V6 | Recreates `enforcement_log`, `verdicts`, `detector_findings` via rename dance. **Drops** `enforcement_log.requested`/`confirmed` (dead columns — written but never read; send failures already captured by `error`). **Adds CHECK constraints** — `action IN ('Block','Unblock')`, `verdict IN ('Alert','Block')`, score/confidence/composite_score ∈ [0,1] (NULL allowed only for nullable score). `verdicts.id` is copied verbatim (not re-assigned) so `detector_findings.verdict_id` FKs survive — production ids reach the 200k range (V4 dedup keeps `MAX(id)`; retention deletes old rows). All indexes recreated. `PRAGMA foreign_keys=OFF`/`BEGIN`/`COMMIT`/`foreign_key_check`/`ON` around the dance. |

**V6 safety note — the id-preservation mistake:** the first formulation of the
V6 `verdicts` INSERT omitted the `id` column, so the recreated table re-assigned
ids from 1, orphaning **all 5388** `detector_findings` rows in the live-migration
demo (every `verdict_id` was a real 200k-range id). Caught by `PRAGMA
foreign_key_check` output showing one violation per finding row, confirmed by
ground-truth (`verdicts` ids 210308–225774, `detector_findings.verdict_id`
210308–225774). Fixed by copying `id` explicitly. The unit test now seeds a
realistic high id (210308) and asserts zero orphans + a join back to the parent,
so this bug class is caught in CI. **Post-fix clean-run reconciliation:** the
migrated live copy ended with `foreign_key_check` returning **0 rows** and **0
orphaned findings** — no pre-existing orphans existed at migration time, so every
violation in the earlier demo was the `id`-drop bug; see §3.2.**

**IP storage:** every IP is stored twice — a 16-byte BLOB (IPv4-mapped IPv6,
canonical binary form for exact-match lookups) and a TEXT column (human-readable
for queries and UI). Both are always populated.