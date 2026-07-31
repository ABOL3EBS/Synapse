import { useState } from "react";
import SideNav, { Tab } from "./components/SideNav";
import ProtectionScreen from "./screens/ProtectionScreen";
import ActivityScreen from "./screens/ActivityScreen";
import StatsScreen from "./screens/StatsScreen";

export default function App() {
  const [tab, setTab] = useState<Tab>("protection");

  return (
    <div className="flex h-screen bg-canvas select-none overflow-hidden">
      <SideNav active={tab} onChange={setTab} />
      <main className="flex-1 overflow-hidden">
        {tab === "protection" && <ProtectionScreen />}
        {tab === "activity" && <ActivityScreen />}
        {tab === "stats" && <StatsScreen />}
      </main>
    </div>
  );
}
