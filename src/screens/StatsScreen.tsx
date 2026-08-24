import { useEffect, useState } from "react";
import {
  getThreatStats,
  getActivityChart,
  getActivityChartForDay,
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
import type { ActivityFilter } from "../lib/db";

const REFRESH_MS = 30_000;

// Day abbreviation from offset (0 = today, 6 = 6 days ago)
function dayLabel(offset: number): string {
  const d = new Date();
  d.setDate(d.getDate() - offset);
  return d.toLocaleDateString("en", { weekday: "short" });
}

// Full "Mon DD" label for a selected day's sparkline title / empty state
function dayFullLabel(offset: number): string {
  const d = new Date();
  d.setDate(d.getDate() - offset);
  return d.toLocaleDateString("en", { month: "short", day: "numeric" });
}

const DEFAULT_SPARKLINE_LABELS = ["24h ago", "18h ago", "12h ago", "6h ago", "Now"];

function formatHourLabel(hour: number): string {
  const period = hour < 12 ? "AM" : "PM";
  const displayHour = hour % 12 === 0 ? 12 : hour % 12;
  return `${displayHour} ${period}`;
}

// 5 evenly-spaced clock-time labels drawn from the points actually rendered
// (so a truncated "today" chart never labels an hour that hasn't happened).
function buildSelectedDayLabels(points: ChartPoint[]): string[] {
  const n = points.length;
  if (n === 0) return DEFAULT_SPARKLINE_LABELS;
  return [0, 1, 2, 3, 4].map((i) => {
    const idx = Math.min(n - 1, Math.round((i * (n - 1)) / 4));
    return formatHourLabel(points[idx].hour);
  });
}

interface Props {
  onNavigateActivity: (filter: ActivityFilter) => void;
  onNavigateGlobe: (countryCode: string) => void;
}

export default function StatsScreen({ onNavigateActivity, onNavigateGlobe }: Props) {
  const [stats,    setStats]    = useState<ThreatStats | null>(null);
  const [chart,    setChart]    = useState<ChartPoint[]>([]);
  const [detectors,setDetectors]= useState<DetectorStat[]>([]);
  const [topApps,  setTopApps]  = useState<TopApp[]>([]);
  const [countries,setCountries]= useState<CountryStat[]>([]);
  const [weekDays, setWeekDays] = useState<DayStat[]>([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(false);
  // null = default rolling last-24h view; 0..6 = a selected day's bar (0 = today)
  const [selectedDay, setSelectedDay] = useState<number | null>(null);

  useEffect(() => {
    const load = () => {
      const chartPromise = selectedDay === null
        ? getActivityChart()
        : getActivityChartForDay(selectedDay);

      return Promise.all([
        getThreatStats(),
        chartPromise,
        getDetectorBreakdown(),
        getTopApps(),
        getThreatCountries(),
        getWeeklyBlocks(),
      ])
        .then(([s, c, d, a, ct, wd]) => {
          setStats(s); setChart(c); setDetectors(d);
          setTopApps(a); setCountries(ct); setWeekDays(wd);
          setError(false);
          setLoading(false);
        })
        .catch(() => { setError(true); setLoading(false); });
    };

    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [selectedDay]);

  const handleSelectDay = (offset: number) =>
    setSelectedDay((prev) => (prev === offset ? null : offset));

  // Today's bar uses the same query as any other day, but future hours
  // (past the current UTC hour) don't exist yet — trim the fake flat tail.
  const displayedChart = selectedDay === 0
    ? chart.slice(0, new Date().getUTCHours() + 1)
    : chart;

  const chartTotal = displayedChart.reduce((sum, p) => sum + p.count, 0);
  const showEmptyChart = selectedDay !== null && chartTotal === 0;

  const sparklineLabels = selectedDay === null
    ? DEFAULT_SPARKLINE_LABELS
    : buildSelectedDayLabels(displayedChart);

  const sparklineTitle = selectedDay === null
    ? "Activity · last 24 h"
    : selectedDay === 0
      ? "Activity · today"
      : `Activity · ${dayFullLabel(selectedDay)}`;

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
        <Section title={sparklineTitle}>
          {showEmptyChart ? (
            <div
              className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-5 py-4 flex items-center justify-center"
              style={{ height: "clamp(80px, 14vh, 180px)" }}
            >
              <p className="text-xs text-navy/25">
                {selectedDay === 0 ? "No activity today" : `No activity on ${dayFullLabel(selectedDay ?? 0)}`}
              </p>
            </div>
          ) : (
            <Sparkline points={displayedChart} labels={sparklineLabels} />
          )}
        </Section>

        {/* 7-day bar strip */}
        <Section title="Blocked · per day · last 7 days">
          <WeeklyBars days={weekDays} selectedDay={selectedDay} onSelectDay={handleSelectDay} />
        </Section>

        {/* Three-panel row: capped + centered; stacks to 1-col below md (768px) */}
        <div className="flex-1 mt-4">
          <div className="max-w-4xl xl:max-w-6xl 2xl:max-w-7xl mx-auto">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Panel title="Detection breakdown" style={{ minHeight: PANEL_H }}>
                <DetectorChart
                  stats={detectors}
                  onSelect={(id, label) => onNavigateActivity({ kind: "detector", id, label })}
                />
                {detectors.length === 0 && <Empty text="No findings yet" />}
              </Panel>
              <Panel title="Flagged apps" style={{ minHeight: PANEL_H }}>
                <TopApps
                  apps={topApps}
                  onSelect={(appName) => onNavigateActivity({ kind: "app", appName })}
                />
                {topApps.length === 0 && <Empty text="No apps flagged yet" />}
              </Panel>
              <Panel title="Top threat sources" style={{ minHeight: PANEL_H }}>
                <TopThreatSources
                  sources={countries}
                  onSelect={(countryCode) => onNavigateGlobe(countryCode)}
                />
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

function WeeklyBars({ days, selectedDay, onSelectDay }: {
  days: DayStat[];
  selectedDay: number | null;
  onSelectDay: (offset: number) => void;
}) {
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
          const isSelected = d.day_offset === selectedDay;
          return (
            <button
              key={d.day_offset}
              type="button"
              onClick={() => onSelectDay(d.day_offset)}
              className="flex-1 flex flex-col items-center gap-[3px] justify-end h-full bg-transparent border-0 p-0 cursor-pointer hover:opacity-80 transition-opacity"
            >
              <span className="text-[9px] font-semibold text-navy/40 leading-none">{d.count}</span>
              <div
                className={`w-full rounded-t-[3px] overflow-hidden flex-1 relative bg-crimson/10 ${
                  isSelected ? "ring-2 ring-navy" : ""
                }`}
              >
                <div
                  className="absolute bottom-0 left-0 right-0 rounded-t-[3px] bg-crimson bar-grow"
                  style={{ height: `${pct}%` }}
                />
              </div>
            </button>
          );
        })}
      </div>
      <div className="flex gap-2 mt-[5px]">
        {days.map((d) => (
          <div key={d.day_offset} className="flex-1 text-center text-[9px] font-medium">
            <span className={d.day_offset === selectedDay ? "text-navy font-semibold" : "text-navy/30"}>
              {dayLabel(d.day_offset)}
            </span>
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
