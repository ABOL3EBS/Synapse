import { useEffect, useState } from "react";
import type { ChartPoint } from "../lib/db";

interface Props {
  points: ChartPoint[];
}

const W     = 100;
const H     = 24;
const PAD_X = 2;
const PAD_Y = 2;

export default function Sparkline({ points }: Props) {
  const [visible, setVisible] = useState(false);
  useEffect(() => { setVisible(true); }, []);

  if (points.length === 0) return null;

  const max = Math.max(...points.map((p) => p.count), 1);
  const xs  = points.map((_, i) => PAD_X + (i / (points.length - 1)) * (W - PAD_X * 2));
  const ys  = points.map((p)    => H - PAD_Y - (p.count / max) * (H - PAD_Y * 2));

  const linePath = points.map((_, i) => `${i === 0 ? "M" : "L"}${xs[i]},${ys[i]}`).join(" ");
  const areaPath = `${linePath} L${xs[points.length - 1]},${H} L${xs[0]},${H} Z`;

  const peakIdx = points.reduce((best, p, i) => (p.count > points[best].count ? i : best), 0);

  // 3 Y-axis levels: 0, mid, max
  const gridVals = [0, Math.round(max / 2), max];
  const gridYVB  = gridVals.map((v) => H - PAD_Y - (v / max) * (H - PAD_Y * 2));

  return (
    <div className={`transition-opacity duration-700 ${visible ? "opacity-100" : "opacity-0"}`}>
      {/* padding-left carves room for Y-axis labels outside the SVG */}
      <div style={{ position: "relative", paddingLeft: 38 }}>
        <div className="relative" style={{ height: "clamp(80px, 14vh, 180px)" }}>
          <svg
            viewBox="0 0 100 24"
            className="w-full h-full"
            preserveAspectRatio="none"
          >
            <defs>
              <linearGradient id="sparkline-area" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10B981" stopOpacity="0.18" />
                <stop offset="100%" stopColor="#10B981" stopOpacity="0" />
              </linearGradient>
            </defs>

            {/* Dashed gridlines — horizontal lines have no viewBox distortion */}
            {gridYVB.map((y, i) => (
              <line
                key={i}
                x1={0} y1={y} x2={W} y2={y}
                stroke="#0F172A" strokeOpacity="0.07" strokeWidth="0.5"
                strokeDasharray="2.5 3"
                vectorEffect="non-scaling-stroke"
              />
            ))}

            <path d={areaPath} fill="url(#sparkline-area)" />
            <path
              d={linePath} fill="none" stroke="#10B981" strokeWidth="1.8"
              strokeLinejoin="round" strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          </svg>

          {/* Y-axis labels: HTML elements in the padding zone left of the SVG.
               Never draw these inside the SVG — the non-uniform viewBox scale
               would shift their apparent vertical position. */}
          {gridVals.map((val, i) => (
            <span
              key={i}
              style={{
                position: "absolute",
                left: -38,
                width: 34,
                top: `${(gridYVB[i] / H) * 100}%`,
                transform: "translateY(-50%)",
                textAlign: "right",
                fontSize: 9,
                fontWeight: 500,
                color: "rgba(15,23,42,0.30)",
                lineHeight: 1,
                pointerEvents: "none",
              }}
            >
              {val}
            </span>
          ))}

          {/* Hourly dots + peak marker: ALL rendered as HTML divs, never SVG circles.
               SVG <circle r="N"> inside a 100×24 viewBox gets non-uniformly scaled
               (x-scale ≫ y-scale at typical card widths) → oval. HTML divs with
               border-radius:50% are always true circles regardless of parent SVG scale. */}
          {points.map((_, i) => {
            const isPeak = i === peakIdx;
            const sz = isPeak ? 7 : 4;
            return (
              <div
                key={i}
                style={{
                  position: "absolute",
                  left: `${(xs[i] / W) * 100}%`,
                  top: `${(ys[i] / H) * 100}%`,
                  width: sz,
                  height: sz,
                  borderRadius: "50%",
                  backgroundColor: "#10B981",
                  border: isPeak ? "2px solid white" : "1.5px solid white",
                  boxShadow: isPeak ? "0 0 0 3px rgba(16,185,129,0.2)" : "none",
                  transform: "translate(-50%, -50%)",
                  pointerEvents: "none",
                }}
              />
            );
          })}
        </div>

        {/* X-axis labels: every 6h */}
        <div className="flex justify-between mt-1 px-0.5">
          {["24h ago", "18h ago", "12h ago", "6h ago", "Now"].map((label) => (
            <span key={label} className="text-[9px] text-navy/25 font-medium">{label}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
