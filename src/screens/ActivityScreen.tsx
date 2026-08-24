import { useEffect, useRef, useState } from "react";
import ActivityRow from "../components/ActivityRow";
import {
  getActivityFeed,
  getActivityFeedFiltered,
  isTauri,
  type ActivityItem,
  type ActivityFilter,
} from "../lib/db";

const REFRESH_MS = 5_000;

interface Props {
  filter: ActivityFilter;
  onClearFilter: () => void;
}

export default function ActivityScreen({ filter, onClearFilter }: Props) {
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [flashIds, setFlashIds] = useState<ReadonlySet<number>>(new Set());
  const seenIds = useRef<Set<number>>(new Set());
  const isFirstLoad = useRef(true);

  useEffect(() => {
    // Switching filters is a fresh view, not an incremental update —
    // reset new-item tracking so the whole result doesn't flash green.
    isFirstLoad.current = true;
    seenIds.current = new Set();
    setLoading(true);

    const load = () => {
      const fetch = filter
        ? getActivityFeedFiltered(
            50,
            filter.kind === "detector"
              ? { detectorId: filter.id }
              : { appName: filter.appName }
          )
        : getActivityFeed(50);

      return fetch
        .then((data) => {
          if (isFirstLoad.current) {
            isFirstLoad.current = false;
            data.forEach((i) => seenIds.current.add(i.id));
          } else {
            const fresh = new Set(
              data.filter((i) => !seenIds.current.has(i.id)).map((i) => i.id)
            );
            data.forEach((i) => seenIds.current.add(i.id));
            if (fresh.size > 0) {
              setFlashIds(fresh);
              setTimeout(() => setFlashIds(new Set()), 1000);
            }
          }
          setItems(data);
          setLoading(false);
        })
        .catch(() => { setError(true); setLoading(false); });
    };

    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [filter]);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <header className="shrink-0 px-5 pt-10 pb-4">
        <h2 className="text-xl font-bold text-navy tracking-tight">Recent Activity</h2>
        <p className="text-xs text-navy/40 mt-0.5">
          What Synapse has seen on your network
        </p>
        {filter && <FilterBanner filter={filter} onClear={onClearFilter} />}
      </header>

      {/* Feed */}
      <div className="flex-1 scroll-area px-4 xl:px-6 pb-4 xl:pb-6 space-y-2.5 xl:space-y-3">
        {loading && <SkeletonFeed />}

        {error && (
          <EmptyState
            icon="⚠️"
            headline={isTauri() ? "Couldn't load activity" : "Open in the Synapse app"}
            sub={isTauri() ? "Synapse may still be starting up." : "The browser preview has no database access. Run via tauri dev."}
          />
        )}

        {!loading && !error && items.length === 0 && (
          <EmptyState
            icon="✓"
            headline="All quiet"
            sub="No suspicious activity found. Synapse is watching."
          />
        )}

        {items.map((item, i) => (
          <div
            key={item.id}
            className="activity-row"
            style={{ animationDelay: `${Math.min(i * 40, 400)}ms` }}
          >
            <ActivityRow item={item} isNew={flashIds.has(item.id)} />
          </div>
        ))}
      </div>
    </div>
  );
}

function FilterBanner({ filter, onClear }: { filter: NonNullable<ActivityFilter>; onClear: () => void }) {
  const source = filter.kind === "detector" ? "Detection Breakdown" : "Flagged Apps";
  const value = filter.kind === "detector" ? filter.label : filter.appName;

  return (
    <div className="mt-3 inline-flex items-center gap-2 text-[10px] xl:text-xs font-semibold
      px-2 py-0.5 xl:px-2.5 xl:py-1 rounded-full text-navy/60 bg-navy/5">
      <span>
        Filtered from Report → {source} → <span className="text-navy">{value}</span>
      </span>
      <button
        type="button"
        onClick={onClear}
        aria-label="Clear filter"
        className="text-navy/40 hover:text-navy/70 leading-none"
      >
        ×
      </button>
    </div>
  );
}

function SkeletonFeed() {
  return (
    <div className="space-y-2.5">
      {[72, 56, 64].map((w) => (
        <div key={w} className="bg-white rounded-2xl shadow-card border border-black/[0.04] px-4 py-3.5 flex items-start gap-3 animate-pulse">
          <div className="mt-1.5 w-2 h-2 rounded-full bg-navy/10 shrink-0" />
          <div className="flex-1 space-y-2 min-w-0">
            <div className={`h-3 bg-navy/10 rounded w-${w}/100`} style={{ width: `${w}%` }} />
            <div className="h-2.5 bg-navy/[0.06] rounded w-24" />
          </div>
          <div className="h-5 w-14 bg-navy/10 rounded-full shrink-0" />
        </div>
      ))}
    </div>
  );
}

function EmptyState({
  icon,
  headline,
  sub,
}: {
  icon: string;
  headline: string;
  sub: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-center gap-2">
      <span className="text-3xl">{icon}</span>
      <p className="text-sm font-semibold text-navy/60">{headline}</p>
      <p className="text-xs text-navy/35 max-w-[200px]">{sub}</p>
    </div>
  );
}
