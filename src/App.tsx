import { useEffect, useState } from "react";
import SideNav, { Tab } from "./components/SideNav";
import ProtectionScreen from "./screens/ProtectionScreen";
import ActivityScreen from "./screens/ActivityScreen";
import StatsScreen from "./screens/StatsScreen";
import GlobeScreen from "./screens/GlobeScreen";
import SettingsScreen from "./screens/SettingsScreen";
import { getAgentStatus, type AgentStatus } from "./lib/db";

const STATUS_POLL_MS = 10_000;

export default function App() {
  const [tab, setTab] = useState<Tab>("protection");
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);

  useEffect(() => {
    const poll = () =>
      getAgentStatus()
        .then(setAgentStatus)
        .catch(() => {});
    poll();
    const id = setInterval(poll, STATUS_POLL_MS);
    return () => clearInterval(id);
  }, []);

  const showBanner = agentStatus !== null && !agentStatus.agent_ok;

  return (
    <div className="flex h-screen bg-canvas select-none overflow-hidden">
      <SideNav active={tab} onChange={setTab} agentStatus={agentStatus} />
      <main className="flex-1 overflow-hidden flex flex-col">
        {showBanner && (
          <div className="shrink-0 bg-amber-50 border-b border-amber-200 px-4 py-1.5
                          text-[11px] font-medium text-amber-700">
            Agent offline — displayed data may be stale
          </div>
        )}
        <div className="flex-1 overflow-hidden">
          {tab === "protection" && <ProtectionScreen />}
          {tab === "activity" && <ActivityScreen />}
          {tab === "stats" && <StatsScreen />}
          {tab === "globe" && <GlobeScreen />}
          {tab === "settings" && <SettingsScreen />}
        </div>
      </main>
    </div>
  );
}
