import { useEffect, useState } from "react";
import SideNav, { Tab } from "./components/SideNav";
import ProtectionScreen from "./screens/ProtectionScreen";
import ActivityScreen from "./screens/ActivityScreen";
import StatsScreen from "./screens/StatsScreen";
import GlobeScreen from "./screens/GlobeScreen";
import SettingsScreen from "./screens/SettingsScreen";
import { getAgentStatus, type AgentStatus, type ActivityFilter } from "./lib/db";

const STATUS_POLL_MS = 10_000;

export default function App() {
  const [tab, setTab] = useState<Tab>("protection");
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>(null);
  const [globeFocusCountry, setGlobeFocusCountry] = useState<string | null>(null);

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

  // Normal sidebar navigation always resets any drill-down filter — nothing
  // else in the app persists state across a tab switch, so filters shouldn't
  // either (every screen fully unmounts on tab change).
  const handleTabChange = (t: Tab) => {
    setTab(t);
    setActivityFilter(null);
    setGlobeFocusCountry(null);
  };

  const navigateToActivity = (filter: ActivityFilter) => {
    setActivityFilter(filter);
    setTab("activity");
  };

  const navigateToGlobe = (countryCode: string) => {
    setGlobeFocusCountry(countryCode);
    setTab("globe");
  };

  return (
    <div className="flex h-screen bg-canvas select-none overflow-hidden">
      <SideNav active={tab} onChange={handleTabChange} agentStatus={agentStatus} />
      <main className="flex-1 overflow-hidden flex flex-col">
        {showBanner && (
          <div className="shrink-0 bg-amber-50 border-b border-amber-200 px-4 py-1.5
                          text-[11px] font-medium text-amber-700">
            Agent offline — displayed data may be stale
          </div>
        )}
        <div className="flex-1 overflow-hidden">
          {tab === "protection" && <ProtectionScreen />}
          {tab === "activity" && (
            <ActivityScreen
              filter={activityFilter}
              onClearFilter={() => setActivityFilter(null)}
            />
          )}
          {tab === "stats" && (
            <StatsScreen
              onNavigateActivity={navigateToActivity}
              onNavigateGlobe={navigateToGlobe}
            />
          )}
          {tab === "globe" && <GlobeScreen focusCountry={globeFocusCountry} />}
          {tab === "settings" && <SettingsScreen />}
        </div>
      </main>
    </div>
  );
}
