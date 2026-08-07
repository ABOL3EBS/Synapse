import { useEffect, useState } from "react";
import { getProtectionStatus, type ProtectionStatus } from "../lib/db";

const REFRESH_MS = 30_000;

export default function ProtectionScreen() {
  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    const load = () =>
      getProtectionStatus()
        .then((s) => { setStatus(s); setLoading(false); })
        .catch(() => { setError(true); setLoading(false); });

    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  const shieldState = error ? "inactive" : status?.is_protected ? "protected" : "warning";

  const headline =
    error || !status
      ? "Synapse is starting up"
      : status.is_protected
      ? "You're protected"
      : "Monitoring your network";

  const headlineColor =
    shieldState === "protected" ? "text-navy"
    : shieldState === "warning" ? "text-amber-700"
    : "text-navy/40";

  const subline =
    !status || error
      ? "Getting things ready…"
      : status.blocks_week > 0
      ? `Synapse has stopped ${status.blocks_week} ${status.blocks_week === 1 ? "threat" : "threats"} this week.`
      : "No threats found this week. All clear.";

  return (
    /* Outer centres the constrained inner panel horizontally and vertically. */
    <div className="h-full flex items-center justify-center">
      {/* Responsive max-width: wider at large windows so the two-column layout doesn't look narrow. */}
      <div className="w-full max-w-4xl xl:max-w-5xl 2xl:max-w-6xl flex">
      {/* Left — shield hero */}
      <div className="flex-1 flex flex-col items-center justify-center gap-6 px-10">
        <div className={`transition-opacity duration-300 ${shieldState === "inactive" ? "opacity-30 grayscale" : shieldState === "warning" ? "opacity-70" : "opacity-100"}`}>
          <img
            src="/icon.png"
            alt="Synapse"
            className={`w-28 h-28 drop-shadow-xl${shieldState === "protected" ? " shield-pulse" : ""}`}
          />
        </div>
        <div className="text-center space-y-2">
          <h1 className={`text-2xl font-bold tracking-tight ${headlineColor}`}>{headline}</h1>
          <p className="text-sm text-navy/50 leading-relaxed">{subline}</p>
        </div>
      </div>

      {/* Divider */}
      <div className="w-px bg-black/[0.05] my-8" />

      {/* Right — reassurance panel */}
      <div className="flex-1 flex flex-col justify-center gap-4 px-10">
        <p className="text-xs font-semibold text-navy/30 uppercase tracking-widest mb-2">
          Status
        </p>
        {loading ? (
          <div className="space-y-4 animate-pulse">
            {[48, 40, 44].map((w) => (
              <div key={w} className="flex items-center gap-3">
                <div className="w-4 h-4 rounded bg-navy/10 shrink-0" />
                <div className="h-3 bg-navy/10 rounded" style={{ width: `${w}%` }} />
              </div>
            ))}
          </div>
        ) : (
          <>
            <StatusRow icon={<MonitorIcon />} label="Monitoring your network" active={!error} />
            <StatusRow icon={<ShieldSmallIcon />} label="Protection is on" active={!error} />
            <StatusRow icon={<LockIcon />} label="pf firewall active" active={!error} />
          </>
        )}

        {/* Threat count callout */}
        {status && status.blocks_week > 0 && (
          <div className="mt-4 bg-emerald-light rounded-2xl px-4 py-3">
            <p className="text-sm font-semibold text-emerald-dark">
              {status.blocks_week} {status.blocks_week === 1 ? "threat" : "threats"} stopped this week
            </p>
            <p className="text-xs text-emerald-dark/70 mt-0.5">
              Synapse blocked these automatically.
            </p>
          </div>
        )}
      </div>
      </div>
    </div>
  );
}

function StatusRow({ icon, label, active }: { icon: JSX.Element; label: string; active: boolean }) {
  return (
    <div className={`flex items-center gap-3 ${active ? "text-navy" : "text-navy/30"}`}>
      <span className={`shrink-0 ${active ? "text-emerald" : "text-navy/20"}`}>{icon}</span>
      <span className="text-sm font-medium">{label}</span>
      {active && (
        <span className="ml-auto text-[10px] font-semibold text-emerald bg-emerald-light px-2 py-0.5 rounded-full">
          ON
        </span>
      )}
    </div>
  );
}

function MonitorIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  );
}

function ShieldSmallIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0110 0v4" />
    </svg>
  );
}
