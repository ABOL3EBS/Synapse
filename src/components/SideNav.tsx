import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

export type Tab = "protection" | "activity" | "stats" | "globe";

interface Props {
  active: Tab;
  onChange: (tab: Tab) => void;
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
];

function startDrag() {
  getCurrentWebviewWindow().startDragging().catch(() => {});
}

export default function SideNav({ active, onChange }: Props) {
  return (
    <nav className="w-44 shrink-0 flex flex-col bg-navy h-full">
      {/* Wordmark — mousedown starts window drag */}
      <div
        className="pl-4 pr-4 pt-8 pb-5 flex items-center gap-2.5 cursor-default"
        onMouseDown={startDrag}
      >
        <img src="/icon.png" alt="" className="w-7 h-7 rounded-md shrink-0" />
        <span className="text-white text-base font-bold tracking-tight">Synapse</span>
      </div>

      {/* Nav items */}
      <div className="flex-1 px-3 space-y-1">
        {TABS.map(({ id, label, icon }) => {
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
                {label}
              </span>
            </button>
          );
        })}
      </div>

      {/* Bottom — also draggable dead space */}
      <div className="px-5 pb-5 cursor-default" onMouseDown={startDrag}>
        <span className="text-white/20 text-[10px] font-medium">v0.1</span>
      </div>
    </nav>
  );
}
