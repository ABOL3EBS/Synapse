# Synapse Dashboard — Design Brief (v1)

Read this BEFORE writing any UI code. It defines the vision, the plain-language
rules, and the hard "never show" list. This file is the contract between the
product owner and every Claude session that touches the dashboard.

## Audience

A non-technical person on a family Mac. They open the app to answer one question:
**"Am I safe right now?"** They want reassurance, not data.

## Tone

Calm, confident, reassuring. Consumer antivirus energy (McAfee/Norton/1Password) —
never a security-operations console. No jargon, no alarm unless something genuinely
needs action. The product quietly does its job; the UI does not parade machinery.

## Design principles

1. **One glance, one answer.** The hero answers "Am I safe?" in under 2 seconds.
2. **Plain language over data.** "Brave tried to reach a known-bad address" — NOT
   "BLOCK 185.220.101.34:443 score=0.92".
3. **Color = meaning, calm by default.** Green = protected, amber = investigate,
   red = needs attention. Red used sparingly.
4. **Immaculate minimalism.** Generous whitespace, soft shadows, rounded-2xl cards
   (16–20px), one accent color. No KPI walls, no dense tables.
5. **Technical truth available, never required.** IPs, scores, detector names live
   behind a "Why did this happen?" disclosure — never on the surface.

## Visual language (generated from scratch — no external reference)

- **Palette:** ink navy `#0F172A`, off-white canvas `#F8FAFC`, protected emerald
  `#10B981`, warning amber `#F59E0B`, alert red `#EF4444` (sparingly), emerald-teal
  gradient for the shield accent.
- **Type:** system stack (`-apple-system`/SF Pro), friendly headline weights,
  relaxed leading.
- **Shape:** soft layered shadows, subtle 1px borders.
- **Mood:** Apple-meets-consumer-AV. No cyberpunk, no dark-scanline motifs, no
  matrix green.

## Screens

### 1. Protection (home)

- Large shield hero: "You're protected" in emerald.
- Sub-line: "Synapse has blocked N threats this week."
- Reassurance row: "Monitoring your network • Protection is on".
- Nothing else on the primary screen. No charts, no counter grid.

### 2. Activity

- Chronological plain-language feed, newest first:
  - "Brave tried to reach a known-bad address — blocked."
  - "A program tried to connect to many servers in a short time — blocked."
  - "Spotify connected to servers in Sweden. Looks normal — allowed."
- Each row: friendly app name (basename of process_path), plain-language verdict,
  relative time.
- Tapping a row opens a "Why?" panel: one plain sentence + an optional "Technical
  details" disclosure (IP, score, detector names) — hidden by default.

### 3. Threat counters (minimal)

- One calm row: "Threats stopped today • this week • blocked addresses".
- Large friendly numerals, no sparklines, no ratios. Never a KPI wall.

### 4. Settings (v2 — control channel; design now, stub in v1)

- Protection on/off toggle, "Pause protection for 10 minutes", notification
  preferences. Rendered in v1 as disabled/planned.

### 5. "Explain it to me" (milestone 12 — AI, UI-layer only)

- Weekly plain-prose summary. Marked "Coming soon" in v1.

## Plain-language translation rules (the most important part)

Map stored data → human sentences. Never surface raw fields on primary screens.

- Scan/connection-count finding → "tried to connect to many servers in a short time"
- Reputation finding → "a known-bad address"
- Beaconing finding → "kept reaching out on a repeating schedule"
- DNS-tunnel/entropy finding → "looked like it was hiding data in web requests"
- GeoIP country/ASN → "in Russia" / "hosted by Amazon"
- Verdict → "— blocked." / "— allowed." / "— flagged for review."
- NEVER show: composite_score, confidence, detector_id, latency_us, severity enum,
  or a raw IP as the headline.

## Hard "never show" list

- composite_score, confidence, detector_id, latency_us on any primary screen.
- A table/grid of IPs + ports + scores (the old project's KPI wall — do not repeat).
- Technical terms as surface nouns ("the CrossFlow detector fired").

## Technical constraints (v1)

- Read-only. Opens `~/.synapse/synapse.db` (or `SYNAPSE_DB_PATH`) via read-only WAL
  connection. Never writes, never touches the spool, never sends enforcement commands.
- Stack: Tauri v2 + React + TypeScript + Vite + Tailwind + shadcn/ui.
- "You're protected" liveness derived from DB freshness (recent verdicts/enforcement),
  no agent IPC in v1.
- v2: settings control channel. Milestone 12: AI panel (UI-layer only).

## Do not

- Add a KPI wall, dense tables, or dashboards-of-dashboards.
- Invent features outside this brief. When in doubt: fewer elements, more whitespace.
