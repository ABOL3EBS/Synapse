import { useEffect, useState } from "react";
import {
  getThreatStats,
  getActivityChart,
  getDetectorBreakdown,
  getTopApps,
  getThreatCountries,
  getWeeklyBlocks,
  type ThreatStats,
  type ChartPoint,
  type DetectorStat,
  type TopApp,
  type CountryStat,
  type DayStat,
} from "../lib/db";
import { useCountUp } from "../hooks/useCountUp";
import Sparkline from "../components/Sparkline";
import DetectorChart from "../components/DetectorChart";
import TopApps from "../components/TopApps";
import TopThreatSources from "../components/TopThreatSources";

const REFRESH_MS = 30_000;

// Day abbreviation from offset (0 = today, 6 = 6 days ago)
function dayLabel(offset: number): string {
  const d = new Date();
  d.setDate(d.getDate() - offset);
  return d.toLocaleDateString("en", { weekday: "short" });
}

export default function StatsScreen() {
  const [stats,    setStats]    = useState<ThreatStats | null>(null);
  const [chart,    setChart]    = useState<ChartPoint[]>([]);
  const [detectors,setDetectors]= useState<DetectorStat[]>([]);
  const [topApps,  setTopApps]  = useState<TopApp[]>([]);
  const [countries,setCountries]= useState<CountryStat[]>([]);
  const [weekDays, setWeekDays] = useState<DayStat[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(false);

  useEffect(() => {
    const load = () =>
      Promise.all([
        getThreatStats(),
        getActivityChart(),
        getDetectorBreakdown(),
        getTopApps(),
        getThreatCountries(),
        getWeeklyBlocks(),
      ])
        .then(([s, c, d, a, ct, wd]) => {
          setStats(s); setChart(c); setDetectors(d);
          setTopApps(a); setCountries(ct); setWeekDays(wd);
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
    <div className="h-full overflow-y-auto scroll-area">
      <div className="px-7 pt-7 pb-5 flex flex-col min-h-full">
        <header className="shrink-0 mb-5">
          <h2 className="text-xl font-bold text-navy tracking-tight">Threat Report</h2>
          <p className="text-xs text-navy/40 mt-0.5">What Synapse has stopped for you</p>
        </header>

        {/* KPI cards — full width */}
        <div className="grid grid-cols-3 gap-3 shrink-0">
          {loading ? (<><SkeletonCard /><SkeletonCard /><SkeletonCard /></>) : (
            <>
              <StatCard
                label={stats?.blocks_today === 0 && (stats?.blocks_week ?? 0) > 0
                  ? "All quiet today" : "Stopped today"}
                value={stats?.blocks_today ?? 0} accent="emerald"
              />
              <StatCard label="This week"    value={stats?.blocks_week       ?? 0} accent="emerald" />
              <StatCard label="Blocked IPs"  value={stats?.blocked_addresses ?? 0} accent="navy"    />
            </>
          )}
        </div>

        {/* Sparkline — Y-axis gridlines + labels + hourly dots */}
        <Section title="Activity · last 24 h">
          <Sparkline points={chart} />
        </Section>

        {/* 7-day bar strip */}
        <Section title="Blocked · per day · last 7 days">
          <WeeklyBars days={weekDays} />
        </Section>

        {/* Three-panel row: capped + centered; stacks to 1-col below md (768px) */}
        <div className="flex-1 mt-4">
          <div className="max-w-4xl xl:max-w-6xl 2xl:max-w-7xl mx-auto">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Panel title="Detection breakdown" style={{ minHeight: PANEL_H }}>
                <DetectorChart stats={detectors} />
                {detectors.length === 0 && <Empty text="No findings yet" />}
              </Panel>
              <Panel title="Flagged apps" style={{ minHeight: PANEL_H }}>
                <TopApps apps={topApps} />
                {topApps.length === 0 && <Empty text="No apps flagged yet" />}
              </Panel>
              <Panel title="Top threat sources" style={{ minHeight: PANEL_H }}>
                <TopThreatSources sources={countries} />
                {countries.length === 0 && <Empty text="No threat sources yet" />}
              </Panel>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CARD_H  = "clamp(80px, 10vh, 130px)";
const PANEL_H = "clamp(200px, 28vh, 420px)";

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SkeletonCard() {
  return (
    <div
      className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-4 animate-pulse"
      style={{ minHeight: CARD_H }}
    >
      <div className="h-2.5 bg-navy/10 rounded w-20 mb-3" />
      <div className="h-8 bg-navy/10 rounded w-12" />
    </div>
  );
}

function StatCard({ label, value, accent }: {
  label: string; value: number; accent: "emerald" | "navy";
}) {
  const animated = useCountUp(value);
  const numColor = "text-navy";
  return (
    <div
      className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-4 flex flex-col gap-1"
      style={{ minHeight: CARD_H }}
    >
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

function Panel({ title, children, style }: {
  title: string; children: React.ReactNode; style?: React.CSSProperties;
}) {
  return (
    <div
      className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-3 flex flex-col"
      style={style}
    >
      <p className="text-[10px] font-semibold text-navy/30 uppercase tracking-widest mb-3">{title}</p>
      {children}
    </div>
  );
}

function WeeklyBars({ days }: { days: DayStat[] }) {
  if (days.length === 0) return (
    <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-5 py-4">
      <p className="text-xs text-navy/25 text-center">No data yet</p>
    </div>
  );

  const maxCount = Math.max(...days.map((d) => d.count), 1);

  return (
    <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-5 py-4">
      <div className="flex gap-2 items-end" style={{ height: "clamp(56px, 8vh, 96px)" }}>
        {days.map((d) => {
          const pct = (d.count / maxCount) * 100;
          return (
            <div key={d.day_offset} className="flex-1 flex flex-col items-center gap-[3px] justify-end h-full">
              <span className="text-[9px] font-semibold text-navy/40 leading-none">{d.count}</span>
              <div className="w-full rounded-t-[3px] overflow-hidden flex-1 relative bg-crimson/10">
                <div
                  className="absolute bottom-0 left-0 right-0 rounded-t-[3px] bg-crimson bar-grow"
                  style={{ height: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
      <div className="flex gap-2 mt-[5px]">
        {days.map((d) => (
          <div key={d.day_offset} className="flex-1 text-center text-[9px] text-navy/30 font-medium">
            {dayLabel(d.day_offset)}
          </div>
        ))}
      </div>
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
