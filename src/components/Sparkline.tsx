import { useEffect, useState } from "react";
import type { ChartPoint } from "../lib/db";

interface Props {
  points: ChartPoint[];
}

const W = 500;
const H = 64;
const PAD_X = 2;
const PAD_Y = 6;

export default function Sparkline({ points }: Props) {
  const [visible, setVisible] = useState(false);
  useEffect(() => { setVisible(true); }, []);

  if (points.length === 0) return null;

  const max = Math.max(...points.map((p) => p.count), 1);
  const xs = points.map((_, i) => PAD_X + (i / (points.length - 1)) * (W - PAD_X * 2));
  const ys = points.map((p) => H - PAD_Y - (p.count / max) * (H - PAD_Y * 2));

  const linePath = points.map((_, i) => `${i === 0 ? "M" : "L"}${xs[i]},${ys[i]}`).join(" ");
  const areaPath = `${linePath} L${xs[points.length - 1]},${H} L${xs[0]},${H} Z`;

  // Find peak hour label
  const peakIdx = points.reduce((best, p, i) => (p.count > points[best].count ? i : best), 0);

  return (
    <div className={`transition-opacity duration-700 ${visible ? "opacity-100" : "opacity-0"}`}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="w-full"
        style={{ height: 64 }}
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="sparkline-area" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10B981" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#10B981" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={areaPath} fill="url(#sparkline-area)" />
        <path d={linePath} fill="none" stroke="#10B981" strokeWidth="1.8"
          strokeLinejoin="round" strokeLinecap="round" />
        {/* Peak dot */}
        <circle cx={xs[peakIdx]} cy={ys[peakIdx]} r="3" fill="#10B981" />
      </svg>

      {/* X-axis labels: every 6h */}
      <div className="flex justify-between mt-1 px-0.5">
        {["24h ago", "18h ago", "12h ago", "6h ago", "Now"].map((label) => (
          <span key={label} className="text-[9px] text-navy/25 font-medium">{label}</span>
        ))}
      </div>
    </div>
  );
}
