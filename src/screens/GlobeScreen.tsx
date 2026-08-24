import { useEffect, useRef, useState } from "react";
import Globe, { GlobeMethods } from "react-globe.gl";
import { getThreatCountries, type CountryStat } from "../lib/db";
import { COUNTRY_COORDS } from "../lib/countries";
import { countryName } from "../lib/translate";

const REFRESH_MS = 30_000;

const HOME_LAT = 53.35;
const HOME_LNG = -6.26; // Dublin, Ireland — update to match your actual location

interface ArcPoint {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  country: string;
  count: number;
}

const HOME_DOT = [{ lat: HOME_LAT, lng: HOME_LNG, size: 0.6, color: "#60a5fa" }];

function buildArcs(stats: CountryStat[]): ArcPoint[] {
  const arcs: ArcPoint[] = [];
  for (const s of stats) {
    const coords = COUNTRY_COORDS[s.country_code.toUpperCase()];
    if (!coords) continue;
    arcs.push({
      startLat: HOME_LAT,
      startLng: HOME_LNG,
      endLat: coords.lat,
      endLng: coords.lng,
      country: coords.name,
      count: s.count,
    });
  }
  return arcs;
}

interface Props {
  focusCountry?: string | null;
}

export default function GlobeScreen({ focusCountry }: Props) {
  const globeRef = useRef<GlobeMethods | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [stats, setStats] = useState<CountryStat[]>([]);
  const [tooltip, setTooltip] = useState<{ country: string; count: number } | null>(null);
  const [error, setError] = useState(false);
  const [ready, setReady] = useState(false);
  // Default matches previous fixed size until ResizeObserver fires on mount.
  const [globeSize, setGlobeSize] = useState(420);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      // Keep globe square, sized to the smaller container dimension.
      setGlobeSize(Math.floor(Math.min(width, height)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const load = () =>
      getThreatCountries()
        .then(setStats)
        .catch(() => setError(true));
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!globeRef.current) return;
    const controls = globeRef.current.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.4;
    controls.enableZoom = false;
  }, [ready]);

  // Drill-down from Report → Top Threat Sources: fly the camera to the
  // requested country. No-op if the code isn't in our coords table — the
  // globe still opens normally, just without a focus.
  useEffect(() => {
    if (!ready || !focusCountry || !globeRef.current) return;
    const coords = COUNTRY_COORDS[focusCountry.toUpperCase()];
    if (!coords) return;
    globeRef.current.controls().autoRotate = false;
    globeRef.current.pointOfView({ lat: coords.lat, lng: coords.lng, altitude: 1.8 }, 1000);
  }, [ready, focusCountry]);

  const arcs = buildArcs(stats);

  const ranked = [...stats]
    .filter((s) => COUNTRY_COORDS[s.country_code.toUpperCase()])
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return (
    <div className="h-full flex bg-canvas">
      {/* Globe container — ResizeObserver measures this element so the canvas
          tracks its actual pixel size rather than a hard-coded 420×420. The
          bg-[#0a0f1e] must match the Globe backgroundColor prop so the area
          outside the square canvas blends with the space scene. */}
      <div
        ref={containerRef}
        className="flex-1 flex items-center justify-center relative bg-[#0a0f1e]"
      >
        <Globe
          ref={globeRef}
          width={globeSize}
          height={globeSize}
          backgroundColor="#0a0f1e"
          globeImageUrl="/earth-day.jpg"
          atmosphereColor="#1e3a5f"
          atmosphereAltitude={0.12}
          arcsData={arcs}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor={() => ["rgba(255,255,255,0.5)", "rgba(220,38,38,0.95)"]}
          arcDashLength={0.35}
          arcDashGap={1.8}
          arcDashAnimateTime={1400}
          arcStroke={0.8}
          onArcHover={(arc) => {
            if (arc)
              setTooltip({ country: (arc as ArcPoint).country, count: (arc as ArcPoint).count });
            else setTooltip(null);
          }}
          pointsData={HOME_DOT}
          pointColor="color"
          pointRadius="size"
          pointAltitude={0.01}
          onGlobeReady={() => setReady(true)}
        />

        {tooltip && (
          <div
            className="absolute top-4 left-1/2 -translate-x-1/2
            bg-white shadow-card border border-black/[0.04]
            rounded-xl px-3 py-2 text-navy text-sm font-medium pointer-events-none"
          >
            {tooltip.country} — {tooltip.count.toLocaleString()}{" "}
            {tooltip.count === 1 ? "event" : "events"}
          </div>
        )}
      </div>

      {/* Right panel */}
      <div className="w-52 xl:w-64 2xl:w-72 flex flex-col justify-center px-4 xl:px-6 2xl:px-8 py-6 xl:py-8 gap-4 xl:gap-6 border-l border-black/[0.04]">
        <div>
          <p className="text-[10px] xl:text-xs font-semibold uppercase tracking-widest text-navy/30 mb-3 xl:mb-4">
            Threat Origins
          </p>

          {error && <p className="text-xs xl:text-sm text-navy/30">Couldn't load data.</p>}

          {!error && ranked.length === 0 && (
            <p className="text-xs xl:text-sm text-navy/30 leading-relaxed">
              No geo-tagged threats yet. Country data appears once Synapse flags traffic to public
              IPs.
            </p>
          )}

          {ranked.map((s, i) => {
            const max = ranked[0]?.count ?? 1;
            const pct = (s.count / max) * 100;
            const name = COUNTRY_COORDS[s.country_code]?.name ?? countryName(s.country_code);
            return (
              <div key={s.country_code} className="mb-3 xl:mb-4">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs xl:text-sm text-navy/70 font-medium truncate mr-2">{name}</span>
                  <span className="text-[10px] xl:text-xs text-navy/40 tabular-nums shrink-0">{s.count}</span>
                </div>
                <div className="h-1 xl:h-1.5 rounded-full bg-navy/8 overflow-hidden">
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
          <p className="text-[9px] xl:text-[11px] text-navy/25 leading-relaxed mt-auto">
            Countries where Synapse blocked or flagged traffic
          </p>
        )}
      </div>
    </div>
  );
}
