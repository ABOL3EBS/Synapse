import type { TopApp } from "../lib/db";

interface Props {
  apps: TopApp[];
}

function initial(name: string): string {
  return name.charAt(0).toUpperCase();
}

// Hue from app name — consistent colour per app
function appHue(name: string): number {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xffff;
  return h % 360;
}

export default function TopApps({ apps }: Props) {
  if (apps.length === 0) return null;
  const maxTotal = Math.max(...apps.map((a) => a.blocks + a.alerts), 1);

  return (
    <div className="space-y-2.5 chart-fade">
      {apps.map((app, i) => {
        const total = app.blocks + app.alerts;
        const pct = (total / maxTotal) * 100;
        const hue = appHue(app.app_name);

        return (
          <div key={app.app_name + i} className="flex items-center gap-3">
            {/* App initial circle */}
            <div
              className="w-6 h-6 rounded-full shrink-0 flex items-center justify-center
                         text-[10px] font-bold text-white"
              style={{ background: `hsl(${hue}, 55%, 48%)` }}
            >
              {initial(app.app_name)}
            </div>

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
                  bg-emerald-light text-emerald-dark">
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
          </div>
        );
      })}
      <div className="mt-3 pt-2 border-t border-black/[0.04] flex gap-3">
        <span className="text-[9px] text-navy/30">
          <span className="font-semibold text-emerald-dark">B</span> = blocked
        </span>
        <span className="text-[9px] text-navy/30">
          <span className="font-semibold text-amber-700">A</span> = flagged
        </span>
      </div>
    </div>
  );
}
