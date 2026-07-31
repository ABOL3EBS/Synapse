import { useEffect, useState } from "react";
import { getThreatStats, type ThreatStats } from "../lib/db";

export default function StatsScreen() {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    getThreatStats()
      .then(setStats)
      .catch(() => setError(true));
  }, []);

  return (
    <div className="h-full flex flex-col px-8 pt-8 pb-6">
      <header className="mb-6">
        <h2 className="text-xl font-bold text-navy tracking-tight">Threat Report</h2>
        <p className="text-xs text-navy/40 mt-0.5">What Synapse has stopped for you</p>
      </header>

      {error && (
        <div className="flex-1 flex items-center justify-center">
          <p className="text-sm text-navy/30">Couldn't load stats — Synapse may be starting up.</p>
        </div>
      )}

      {!error && (
        <div className="flex-1 flex flex-col justify-between">
          {/* Stat cards — horizontal row */}
          <div className="grid grid-cols-3 gap-4">
            <StatCard label="Threats stopped today" value={stats?.blocks_today ?? null} accent="emerald" />
            <StatCard label="This week" value={stats?.blocks_week ?? null} accent="emerald" />
            <StatCard label="Blocked addresses" value={stats?.blocked_addresses ?? null} accent="navy" />
          </div>

          {/* Coming soon */}
          <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-5 py-4
            flex items-start gap-3">
            <span className="text-xl mt-0.5">✨</span>
            <div>
              <p className="text-sm font-semibold text-navy">Explain it to me</p>
              <p className="text-xs text-navy/40 mt-0.5 leading-relaxed">
                A weekly plain-English summary of what Synapse found and why it matters. Coming soon.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, accent }: {
  label: string;
  value: number | null;
  accent: "emerald" | "navy";
}) {
  const numColor = accent === "emerald" ? "text-emerald-dark" : "text-navy";
  return (
    <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-5 py-5
      flex flex-col gap-2">
      <span className="text-xs text-navy/40 font-medium leading-snug">{label}</span>
      <span className={`text-4xl font-bold tabular-nums ${numColor}`}>
        {value === null ? <span className="text-navy/20 text-3xl">—</span> : value.toLocaleString()}
      </span>
    </div>
  );
}
