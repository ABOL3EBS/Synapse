import type { DetectorStat } from "../lib/db";

interface Props {
  stats: DetectorStat[];
}

// Strip version suffixes and format for display
function friendlyName(raw: string): string {
  const names: Record<string, string> = {
    CrossFlow: "Scan / Beacon",
    DnsAnalyzer: "DNS Analysis",
    DnsTunnelDetector: "DNS Tunnel",
    FlowBehavior: "Traffic Pattern",
    IpReputation: "IP Reputation",
    ProcessCorrelator: "Process Behavior",
  };
  return names[raw] ?? raw;
}

export default function DetectorChart({ stats }: Props) {
  if (stats.length === 0) return null;
  const max = Math.max(...stats.map((s) => s.count), 1);

  const active = stats.filter((s) => s.count > 0);
  const silent = stats.filter((s) => s.count === 0 && s.has_runs);

  return (
    <div className="space-y-2.5 chart-fade">
      {active.map((stat, i) => {
        const pct = (stat.count / max) * 100;
        return (
          <div key={stat.name} className="flex items-center gap-3">
            <span className="text-xs text-navy/50 w-32 shrink-0 truncate">
              {friendlyName(stat.name)}
            </span>
            <div className="flex-1 h-2 bg-navy/5 rounded-full overflow-hidden">
              <div
                className="h-full bg-crimson rounded-full bar-grow"
                style={{ width: `${pct}%`, animationDelay: `${i * 80}ms` }}
              />
            </div>
            <span className="text-xs font-semibold text-navy/40 w-10 text-right tabular-nums">
              {stat.count.toLocaleString()}
            </span>
          </div>
        );
      })}

      {silent.length > 0 && (
        <div className="pt-1 border-t border-black/[0.04] space-y-2">
          {silent.map((stat) => (
            <div key={stat.name} className="flex items-center gap-3">
              <span className="text-xs text-navy/25 w-32 shrink-0 truncate">
                {friendlyName(stat.name)}
              </span>
              <span className="text-[10px] text-navy/20 italic">no findings yet</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
