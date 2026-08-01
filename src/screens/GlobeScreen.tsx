import { useEffect, useRef, useState } from "react";
import Globe, { GlobeMethods } from "react-globe.gl";
import { getThreatCountries, type CountryStat } from "../lib/db";
import { COUNTRY_COORDS } from "../lib/countries";
import { countryName } from "../lib/translate";

const REFRESH_MS = 30_000;

interface RingPoint {
  lat: number;
  lng: number;
  maxR: number;
  color: string;
  country: string;
  count: number;
}

interface DotPoint {
  lat: number;
  lng: number;
  size: number;
  color: string;
  country: string;
  count: number;
}

function buildPoints(stats: CountryStat[]): { rings: RingPoint[]; dots: DotPoint[] } {
  const rings: RingPoint[] = [];
  const dots: DotPoint[] = [];

  for (const s of stats) {
    const coords = COUNTRY_COORDS[s.country_code.toUpperCase()];
    if (!coords) continue;

    // Log-scale ring radius so a country with 1 event and one with 10,000
    // both show up — neither dwarfs the other.
    const maxR = Math.log2(s.count + 1) * 3.5;

    rings.push({
      lat: coords.lat,
      lng: coords.lng,
      maxR,
      color: "rgba(220, 38, 38, 0.8)",
      country: coords.name,
      count: s.count,
    });
    dots.push({
      lat: coords.lat,
      lng: coords.lng,
      size: 0.4,
      color: "#dc2626",
      country: coords.name,
      count: s.count,
    });
  }

  return { rings, dots };
}

export default function GlobeScreen() {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const [stats, setStats] = useState<CountryStat[]>([]);
  const [tooltip, setTooltip] = useState<{ country: string; count: number } | null>(null);
  const [error, setError] = useState(false);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const load = () =>
      getThreatCountries()
        .then(setStats)
        .catch(() => setError(true));

    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  // Auto-rotate; stop on user interaction
  useEffect(() => {
    if (!globeRef.current) return;
    const controls = globeRef.current.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.4;
    controls.enableZoom = false;
  }, [ready]);

  const { rings, dots } = buildPoints(stats);

  // Ranked list for the sidebar panel
  const ranked = [...stats]
    .filter((s) => COUNTRY_COORDS[s.country_code.toUpperCase()])
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return (
    <div className="h-full flex" style={{ background: "#0a0f1e" }}>
      {/* Globe */}
      <div className="flex-1 flex items-center justify-center relative">
        <Globe
          ref={globeRef}
          width={420}
          height={420}
          backgroundColor="#0a0f1e"
          globeImageUrl="/earth-day.jpg"
          atmosphereColor="#1e3a5f"
          atmosphereAltitude={0.12}
          // Pulsing rings
          ringsData={rings}
          ringColor={() => "rgba(220,38,38,0.7)"}
          ringMaxRadius="maxR"
          ringPropagationSpeed={1.8}
          ringRepeatPeriod={900}
          // Solid dots
          pointsData={dots}
          pointColor="color"
          pointRadius="size"
          pointAltitude={0.01}
          onPointHover={(pt) => {
            if (pt) setTooltip({ country: (pt as DotPoint).country, count: (pt as DotPoint).count });
            else setTooltip(null);
          }}
          onGlobeReady={() => setReady(true)}
        />

        {/* Tooltip */}
        {tooltip && (
          <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-white/10 backdrop-blur
            rounded-xl px-3 py-2 text-white text-sm font-medium pointer-events-none">
            {tooltip.country} — {tooltip.count.toLocaleString()} {tooltip.count === 1 ? "event" : "events"}
          </div>
        )}
      </div>

      {/* Right panel */}
      <div className="w-48 flex flex-col justify-center px-4 py-6 gap-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-white/30 mb-3">
            Threat Origins
          </p>

          {error && (
            <p className="text-xs text-white/30">Couldn't load data.</p>
          )}

          {!error && ranked.length === 0 && (
            <p className="text-xs text-white/30 leading-relaxed">
              No geo-tagged threats yet. Country data appears once Synapse flags traffic to public IPs.
            </p>
          )}

          {ranked.map((s, i) => {
            const max = ranked[0]?.count ?? 1;
            const pct = (s.count / max) * 100;
            const name = COUNTRY_COORDS[s.country_code]?.name ?? countryName(s.country_code);
            return (
              <div key={s.country_code} className="mb-3">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs text-white/70 font-medium truncate mr-2">{name}</span>
                  <span className="text-[10px] text-white/40 tabular-nums shrink-0">{s.count}</span>
                </div>
                <div className="h-1 rounded-full bg-white/10 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-red-500 bar-grow"
                    style={{ width: `${pct}%`, animationDelay: `${i * 80}ms` }}
                  />
                </div>
              </div>
            );
          })}
        </div>

        {ranked.length > 0 && (
          <p className="text-[9px] text-white/20 leading-relaxed mt-auto">
            Showing countries where Synapse blocked or flagged traffic
          </p>
        )}
      </div>
    </div>
  );
}
