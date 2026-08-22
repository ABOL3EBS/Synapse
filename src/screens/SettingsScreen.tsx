import { useEffect, useState } from "react";
import {
  getActiveBlocks,
  getConfigValues,
  requestUnblock,
  type ActiveBlock,
  type ConfigValues,
  type UnblockResult,
} from "../lib/db";
import { useNow } from "../hooks/useNow";

const REFRESH_MS = 10_000;

type UnblockState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "fast" }
  | { kind: "slow"; message: string }
  | { kind: "error"; message: string };

export default function SettingsScreen() {
  const [blocks, setBlocks] = useState<ActiveBlock[]>([]);
  const [fetchedAt, setFetchedAt] = useState(() => Date.now());
  const [config, setConfig] = useState<ConfigValues | null>(null);
  const [unblockState, setUnblockState] = useState<Record<string, UnblockState>>({});

  useEffect(() => {
    const load = () => {
      getActiveBlocks().then((data) => { setBlocks(data); setFetchedAt(Date.now()); }).catch(() => {});
      getConfigValues().then(setConfig).catch(() => {});
    };
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  const handleUnblock = async (ip: string) => {
    setUnblockState((prev) => ({ ...prev, [ip]: { kind: "loading" } }));
    let result: UnblockResult;
    try {
      result = await requestUnblock(ip);
    } catch {
      setUnblockState((prev) => ({
        ...prev,
        [ip]: { kind: "error", message: "IPC error" },
      }));
      return;
    }
    if (!result.queued) {
      setUnblockState((prev) => ({
        ...prev,
        [ip]: { kind: "error", message: result.message },
      }));
    } else if (result.fast_path) {
      setUnblockState((prev) => ({ ...prev, [ip]: { kind: "fast" } }));
      // Remove from list after brief confirmation
      setTimeout(() => setBlocks((prev) => prev.filter((b) => b.ip_text !== ip)), 1200);
    } else {
      setUnblockState((prev) => ({
        ...prev,
        [ip]: { kind: "slow", message: result.message },
      }));
    }
  };

  return (
    <div className="h-full overflow-y-auto scroll-area">
      <div className="max-w-4xl xl:max-w-6xl 2xl:max-w-7xl mx-auto px-6 py-5 flex flex-col gap-6">
      {/* Active Blocks — sized to content; caps at max-h and scrolls internally once it exceeds that. */}
      <section>
        <SectionHeader icon={<ActiveBlocksIcon />} title="Active Blocks" accent="red" />
        <div className="rounded-2xl border border-black/[0.04] bg-white divide-y divide-black/[0.04] overflow-y-auto overflow-x-hidden max-h-[440px]">
          {blocks.length === 0 ? (
            <div className="py-7 px-5 text-center text-sm text-navy/40">No active blocks</div>
          ) : (
            blocks.map((block) => (
              <BlockRow
                key={block.ip_text}
                block={block}
                fetchedAt={fetchedAt}
                state={unblockState[block.ip_text] ?? { kind: "idle" }}
                onUnblock={() => handleUnblock(block.ip_text)}
              />
            ))
          )}
        </div>
      </section>

      {/* Detection Thresholds */}
      <section>
        <SectionHeader icon={<ThresholdsIcon />} title="Detection Thresholds" accent="navy" />
        <div className="rounded-2xl border border-black/[0.04] bg-white overflow-hidden">
          <ThresholdRow
            label="Block threshold"
            value={config?.block_threshold ?? 0.7}
            accent="crimson"
          />
          <ThresholdRow
            label="Alert threshold"
            value={config?.alert_threshold ?? 0.3}
            accent="amber"
          />
          <ThresholdRangeBar
            alert={config?.alert_threshold ?? 0.3}
            block={config?.block_threshold ?? 0.7}
          />
        </div>
        <p className="text-[10px] text-navy/30 mt-2 px-1">
          Takes effect on agent restart
        </p>
      </section>

      {/* CrossFlow Exclusions */}
      <section>
        <SectionHeader icon={<ExclusionsIcon />} title="CrossFlow Exclusions" accent="navy" />
        <div className="rounded-2xl border border-black/[0.04] bg-white divide-y divide-black/[0.04] overflow-hidden">
          {!config || config.cf_exclusions.length === 0 ? (
            <div className="px-4 py-4 text-sm text-navy/40 text-center">
              No exclusions configured
            </div>
          ) : (
            config.cf_exclusions.map((ip) => (
              <div key={ip} className="px-4 py-3 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-navy/20 shrink-0" />
                <span className="text-sm font-mono text-navy">{ip}</span>
              </div>
            ))
          )}
        </div>
        <p className="text-[10px] text-navy/30 mt-2 px-1">
          Own IPs and default gateway are also always excluded (dynamic — not shown here).
          Additional exclusions can be added via <code className="font-mono">synapse.toml</code>.
        </p>
      </section>
      </div>
    </div>
  );
}

function BlockRow({
  block,
  fetchedAt,
  state,
  onUnblock,
}: {
  block: ActiveBlock;
  fetchedAt: number;
  state: UnblockState;
  onUnblock: () => void;
}) {
  const now = useNow();
  const liveRemaining = Math.max(0, block.remaining_ms - (now - fetchedAt));

  // Strip the boilerplate prefix so only the detector findings are shown.
  const shortReason = block.reason
    .replace(/^score [0-9.]+ exceeds block threshold: /, "")
    .replace(/^score [0-9.]+ exceeds alert threshold: /, "");

  return (
    <div className="px-4 py-3 flex items-start gap-3">
      <div className="flex-1 min-w-0">
        <span className="text-sm font-mono text-navy block">{block.ip_text}</span>
        {shortReason && (
          <span
            className="text-[11px] text-navy/40 font-mono truncate block mt-0.5"
            title={block.reason}
          >
            {shortReason}
          </span>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0 mt-0.5">
        <span className="text-[11px] text-navy/40 tabular-nums">
          {formatRemaining(liveRemaining)}
        </span>
        <UnblockButton state={state} onUnblock={onUnblock} />
      </div>
    </div>
  );
}

function UnblockButton({
  state,
  onUnblock,
}: {
  state: UnblockState;
  onUnblock: () => void;
}) {
  if (state.kind === "loading") {
    return (
      <span className="w-16 flex items-center justify-center">
        <SpinnerIcon />
      </span>
    );
  }
  if (state.kind === "fast") {
    return (
      <span className="text-[11px] font-semibold text-emerald w-16 text-center">
        Removed
      </span>
    );
  }
  if (state.kind === "slow") {
    return (
      <span
        className="text-[11px] font-semibold text-amber-600 w-16 text-center"
        title={state.message}
      >
        Queued ~60s
      </span>
    );
  }
  if (state.kind === "error") {
    return (
      <span
        className="text-[11px] font-semibold text-red-500 w-16 text-center cursor-default"
        title={state.message}
      >
        Failed
      </span>
    );
  }
  return (
    <button
      onClick={onUnblock}
      className="text-[11px] font-semibold text-navy/50 hover:text-navy border border-black/10
                 hover:border-black/20 rounded-lg px-3 py-1 transition-colors duration-100"
    >
      Unblock
    </button>
  );
}

const THRESHOLD_VALUE_COLOR: Record<"crimson" | "amber", string> = {
  crimson: "text-crimson",
  amber: "text-amber-700",
};

function ThresholdRow({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: "crimson" | "amber";
}) {
  return (
    <div className="px-4 py-3 flex items-center border-b border-black/[0.04]">
      <span className="text-sm text-navy flex-1">{label}</span>
      <span className={`text-sm font-semibold tabular-nums ${THRESHOLD_VALUE_COLOR[accent]}`}>
        {value.toFixed(2)}
      </span>
    </div>
  );
}

// Read-only visualization of where the Alert/Block thresholds sit on the 0–1 scale.
// No drag/input interaction — display only.
function ThresholdRangeBar({ alert, block }: { alert: number; block: number }) {
  const alertPct = Math.min(Math.max(alert, 0), 1) * 100;
  const blockPct = Math.min(Math.max(block, 0), 1) * 100;
  return (
    <div className="px-4 pt-1.5 pb-4">
      <div className="relative h-1.5 rounded-full bg-navy/5">
        <div className="absolute inset-y-0 left-0 rounded-full bg-amber/25" style={{ width: `${alertPct}%` }} />
        <div className="absolute inset-y-0 left-0 rounded-full bg-crimson/15" style={{ width: `${blockPct}%` }} />
        <div
          className="absolute -top-[3px] w-3 h-3 rounded-full bg-amber border-2 border-white shadow-[0_0_0_1px_rgba(0,0,0,0.06)] -translate-x-1/2"
          style={{ left: `${alertPct}%` }}
        />
        <div
          className="absolute -top-[3px] w-3 h-3 rounded-full bg-crimson border-2 border-white shadow-[0_0_0_1px_rgba(0,0,0,0.06)] -translate-x-1/2"
          style={{ left: `${blockPct}%` }}
        />
      </div>
    </div>
  );
}

function SectionHeader({
  icon,
  title,
  accent,
}: {
  icon: React.ReactNode;
  title: string;
  accent: "red" | "navy";
}) {
  const border = accent === "red" ? "border-crimson" : "border-navy";
  const color = accent === "red" ? "text-crimson" : "text-navy";
  return (
    <div className={`flex items-center gap-2 mb-2.5 pl-2.5 border-l-[3px] ${border}`}>
      <span className={color}>{icon}</span>
      <p className="text-[10px] font-semibold uppercase tracking-widest text-navy/30">{title}</p>
    </div>
  );
}

function ActiveBlocksIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function ThresholdsIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 21v-7M4 10V3M12 21v-11M12 6V3M20 21v-5M20 12V3" />
      <circle cx="4" cy="12" r="2" />
      <circle cx="12" cy="9" r="2" />
      <circle cx="20" cy="14" r="2" />
    </svg>
  );
}

function ExclusionsIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12h4l3 8 4-16 3 8h6" />
    </svg>
  );
}

function SpinnerIcon() {
  return (
    <svg
      className="animate-spin text-navy/30"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
    >
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
    </svg>
  );
}

function formatRemaining(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const remM = m % 60;
  return remM > 0 ? `${h}h ${remM}m` : `${h}h`;
}
