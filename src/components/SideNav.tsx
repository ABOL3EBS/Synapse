import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import type { AgentStatus } from "../lib/db";

export type Tab = "protection" | "activity" | "stats" | "globe" | "settings";

interface Props {
  active: Tab;
  onChange: (tab: Tab) => void;
  agentStatus: AgentStatus | null;
}

const TABS: { id: Tab; label: string; icon: (active: boolean) => JSX.Element }[] = [
  {
    id: "protection",
    label: "Protection",
    icon: (active) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth={active ? 2.2 : 1.8} strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
        {active && <path d="M9 12l2 2 4-4" strokeWidth={2.2} />}
      </svg>
    ),
  },
  {
    id: "activity",
    label: "Activity",
    icon: (active) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth={active ? 2.2 : 1.8} strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" />
        <rect x="9" y="3" width="6" height="4" rx="1" />
        <line x1="9" y1="12" x2="15" y2="12" />
        <line x1="9" y1="16" x2="13" y2="16" />
      </svg>
    ),
  },
  {
    id: "stats",
    label: "Report",
    icon: (active) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth={active ? 2.2 : 1.8} strokeLinecap="round" strokeLinejoin="round">
        <rect x="18" y="3" width="3" height="18" rx="1" />
        <rect x="10.5" y="9" width="3" height="12" rx="1" />
        <rect x="3" y="13" width="3" height="8" rx="1" />
      </svg>
    ),
  },
  {
    id: "globe",
    label: "Threat Map",
    icon: (active) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth={active ? 2.2 : 1.8} strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
      </svg>
    ),
  },
  {
    id: "settings",
    label: "Settings",
    icon: (active) => (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth={active ? 2.2 : 1.8} strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06
                 a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09
                 A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06
                 A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09
                 A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06
                 A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09
                 a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06
                 A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09
                 a1.65 1.65 0 00-1.51 1z" />
      </svg>
    ),
  },
];

function startDrag() {
  getCurrentWebviewWindow().startDragging().catch(() => {});
}

function statusInfo(s: AgentStatus | null): { dot: string; label: string } {
  if (s === null) return { dot: "bg-white/20", label: "Connecting…" };
  if (s.agent_ok && s.helper_ok) return { dot: "bg-emerald", label: "Live" };
  if (!s.agent_ok && !s.helper_ok) return { dot: "bg-red-400", label: "Offline" };
  if (!s.helper_ok) return { dot: "bg-amber-400", label: "Helper offline" };
  return { dot: "bg-amber-400", label: "Agent offline" };
}

export default function SideNav({ active, onChange, agentStatus }: Props) {
  const { dot, label } = statusInfo(agentStatus);

  return (
    <nav className="w-44 shrink-0 flex flex-col bg-navy h-full">
      {/* Wordmark — mousedown starts window drag. */}
      <div
        className="pl-4 pr-4 pt-[52px] pb-5 flex items-center gap-2.5 cursor-default"
        onMouseDown={startDrag}
      >
        <img src="/icon.png" alt="" className="w-7 h-7 rounded-md shrink-0" />
        <span className="text-white text-base font-bold tracking-tight">Synapse</span>
      </div>

      {/* Nav items */}
      <div className="flex-1 px-3 space-y-1">
        {TABS.map(({ id, label: tabLabel, icon }) => {
          const isActive = active === id;
          return (
            <button
              key={id}
              onClick={() => onChange(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left
                transition-colors duration-150
                ${isActive
                  ? "bg-emerald/15 text-emerald"
                  : "text-white/40 hover:text-white/70 hover:bg-white/5"
                }`}
            >
              {icon(isActive)}
              <span className={`text-sm font-medium ${isActive ? "text-emerald" : ""}`}>
                {tabLabel}
              </span>
            </button>
          );
        })}
      </div>

      {/* Connection status + version */}
      <div className="px-4 pb-5 cursor-default" onMouseDown={startDrag}>
        <div className="flex items-center gap-2 mb-1">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
          <span className="text-[10px] font-medium text-white/40 truncate">{label}</span>
        </div>
        <span className="text-white/15 text-[10px] font-medium">v0.1</span>
      </div>
    </nav>
  );
}
