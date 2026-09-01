import type { TopApp } from "../lib/db";
import ChevronRight from "./ChevronRight";
import AppIcon, { appHue } from "./AppIcon";

interface Props {
  apps: TopApp[];
  onSelect?: (appName: string) => void;
}

export default function TopApps({ apps, onSelect }: Props) {
  if (apps.length === 0) return null;
  const maxTotal = Math.max(...apps.map((a) => a.blocks + a.alerts), 1);

  return (
    <div className="space-y-2.5 chart-fade">
      {apps.map((app, i) => {
        const total = app.blocks + app.alerts;
        const pct = (total / maxTotal) * 100;
        const hue = appHue(app.app_name);

        return (
          <button
            key={app.app_name + i}
            type="button"
            onClick={() => onSelect?.(app.app_name)}
            className="group w-full flex items-center gap-3 -mx-2 px-2 py-0.5 rounded-lg
              text-left bg-transparent border-0 cursor-pointer
              hover:bg-navy/[0.03] transition-colors"
          >
            {/* Real app icon (40px, same as Activity); letter-circle fallback */}
            <AppIcon processPath={app.process_path} size={40} />

            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-navy/70 truncate">{app.app_name}</p>
              <div className="mt-1 h-1.5 bg-navy/5 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bar-grow"
                  style={{
                    width: `${pct}%`,
                    background: `hsl(${hue}, 55%, 48%)`,
                    animationDelay: `${i * 80}ms`,
                  }}
                />
              </div>
            </div>

            <div className="flex gap-1.5 shrink-0">
              {app.blocks > 0 && (
                <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full
                  bg-crimson-light text-crimson-dark">
                  {app.blocks}B
                </span>
              )}
              {app.alerts > 0 && (
                <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full
                  bg-amber-light text-amber-700">
                  {app.alerts}A
                </span>
              )}
            </div>
            <ChevronRight />
          </button>
        );
      })}
      <div className="mt-3 pt-2 border-t border-black/[0.04] flex gap-3">
        <span className="text-[9px] text-navy/30">
          <span className="font-semibold text-crimson-dark">B</span> = blocked
        </span>
        <span className="text-[9px] text-navy/30">
          <span className="font-semibold text-amber-700">A</span> = flagged
        </span>
      </div>
    </div>
  );
}
