import { useEffect, useState } from "react";
import ActivityRow from "../components/ActivityRow";
import { getActivityFeed, isTauri, type ActivityItem } from "../lib/db";

export default function ActivityScreen() {
  const [items, setItems] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    getActivityFeed(50)
      .then((data) => {
        setItems(data);
        setLoading(false);
      })
      .catch(() => {
        setError(true);
        setLoading(false);
      });
  }, []);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <header className="shrink-0 px-5 pt-10 pb-4">
        <h2 className="text-xl font-bold text-navy tracking-tight">Recent Activity</h2>
        <p className="text-xs text-navy/40 mt-0.5">
          What Synapse has seen on your network
        </p>
      </header>

      {/* Feed */}
      <div className="flex-1 scroll-area px-4 pb-4 space-y-2.5">
        {loading && (
          <div className="flex justify-center items-center h-32">
            <span className="text-sm text-navy/30">Loading…</span>
          </div>
        )}

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
            <ActivityRow item={item} />
          </div>
        ))}
      </div>
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
