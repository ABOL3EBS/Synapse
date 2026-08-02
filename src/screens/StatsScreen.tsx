import { useEffect, useState } from "react";
import {
  getThreatStats,
  getActivityChart,
  getDetectorBreakdown,
  getTopApps,
  type ThreatStats,
  type ChartPoint,
  type DetectorStat,
  type TopApp,
} from "../lib/db";
import { useCountUp } from "../hooks/useCountUp";
import Sparkline from "../components/Sparkline";
import DetectorChart from "../components/DetectorChart";
import TopApps from "../components/TopApps";

const REFRESH_MS = 30_000;

export default function StatsScreen() {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [chart, setChart] = useState<ChartPoint[]>([]);
  const [detectors, setDetectors] = useState<DetectorStat[]>([]);
  const [topApps, setTopApps] = useState<TopApp[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    const load = () =>
      Promise.all([
        getThreatStats(),
        getActivityChart(),
        getDetectorBreakdown(),
        getTopApps(),
      ])
        .then(([s, c, d, a]) => {
          setStats(s); setChart(c); setDetectors(d); setTopApps(a);
          setLoading(false);
        })
        .catch(() => { setError(true); setLoading(false); });

    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  if (error) {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-sm text-navy/30">Couldn't load stats — Synapse may be starting up.</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col px-7 pt-7 pb-5 overflow-y-auto scroll-area">
      <header className="shrink-0 mb-5">
        <h2 className="text-xl font-bold text-navy tracking-tight">Threat Report</h2>
        <p className="text-xs text-navy/40 mt-0.5">What Synapse has stopped for you</p>
      </header>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-3 shrink-0">
        {loading ? (
          <>
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </>
        ) : (
          <>
            <StatCard
              label={
                stats?.blocks_today === 0 && (stats?.blocks_week ?? 0) > 0
                  ? "All quiet today"
                  : "Stopped today"
              }
              value={stats?.blocks_today ?? 0}
              accent="emerald"
            />
            <StatCard label="This week" value={stats?.blocks_week ?? 0} accent="emerald" />
            <StatCard label="Blocked IPs" value={stats?.blocked_addresses ?? 0} accent="navy" />
          </>
        )}
      </div>

      {/* Activity timeline */}
      <Section title="Activity · last 24 h">
        <Sparkline points={chart} />
      </Section>

      {/* Two-column lower section */}
      <div className="flex gap-4 mt-4 flex-1 min-h-0">
        <Panel title="Detection breakdown" className="flex-1">
          <DetectorChart stats={detectors} />
          {detectors.length === 0 && <Empty text="No findings yet" />}
        </Panel>
        <Panel title="Flagged apps" className="flex-1">
          <TopApps apps={topApps} />
          {topApps.length === 0 && <Empty text="No apps flagged yet" />}
        </Panel>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SkeletonCard() {
  return (
    <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-4 animate-pulse">
      <div className="h-2.5 bg-navy/10 rounded w-20 mb-3" />
      <div className="h-8 bg-navy/10 rounded w-12" />
    </div>
  );
}

function StatCard({ label, value, accent }: {
  label: string;
  value: number;
  accent: "emerald" | "navy";
}) {
  const animated = useCountUp(value);
  const numColor = accent === "emerald" ? "text-emerald-dark" : "text-navy";
  return (
    <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-4 flex flex-col gap-1">
      <span className="text-[10px] text-navy/40 font-medium leading-snug">{label}</span>
      <span className={`text-3xl font-bold tabular-nums ${numColor}`}>
        {animated.toLocaleString()}
      </span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-4 shrink-0">
      <p className="text-[10px] font-semibold text-navy/30 uppercase tracking-widest mb-2">{title}</p>
      {children}
    </div>
  );
}

function Panel({ title, children, className = "" }: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-3 flex flex-col ${className}`}>
      <p className="text-[10px] font-semibold text-navy/30 uppercase tracking-widest mb-3">{title}</p>
      {children}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex-1 flex items-center justify-center">
      <p className="text-xs text-navy/25">{text}</p>
    </div>
  );
}
