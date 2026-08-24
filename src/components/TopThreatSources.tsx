import type { CountryStat } from "../lib/db";
import ChevronRight from "./ChevronRight";

interface Props {
  sources: CountryStat[];
  onSelect?: (countryCode: string) => void;
}

// CLDR flag from country code (e.g. "CN" → 🇨🇳)
function flag(code: string): string {
  return code
    .toUpperCase()
    .split("")
    .map((c) => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join("");
}

// Country name from ISO 3166-1 alpha-2. Falls back to raw code.
function countryName(code: string): string {
  try {
    const fmt = new Intl.DisplayNames(["en"], { type: "region" });
    return fmt.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

export default function TopThreatSources({ sources, onSelect }: Props) {
  if (sources.length === 0) return null;

  const top = sources.slice(0, 4);
  const maxCount = Math.max(...top.map((s) => s.count), 1);

  return (
    <div className="space-y-2.5 chart-fade">
      {top.map((s, i) => {
        const pct = (s.count / maxCount) * 100;
        return (
          <button
            key={s.country_code}
            type="button"
            onClick={() => onSelect?.(s.country_code)}
            className="group w-full flex items-center gap-3 -mx-2 px-2 py-0.5 rounded-lg
              text-left bg-transparent border-0 cursor-pointer
              hover:bg-navy/[0.03] transition-colors"
          >
            <span className="text-[17px] leading-none shrink-0">
              {flag(s.country_code)}
            </span>

            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-navy/70 truncate mb-[3px]">
                {countryName(s.country_code)}
              </p>
              <div className="h-1.5 bg-navy/5 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bar-grow"
                  style={{
                    width: `${pct}%`,
                    background: "rgba(179,54,74,0.65)",
                    animationDelay: `${i * 80}ms`,
                  }}
                />
              </div>
            </div>

            <span className="text-xs font-semibold text-navy/40 w-8 text-right tabular-nums shrink-0">
              {s.count}
            </span>
            <ChevronRight />
          </button>
        );
      })}

      <p className="mt-3 pt-2 border-t border-black/[0.04] text-[9px] text-navy/25">
        Same feed as Threat Map
      </p>
    </div>
  );
}
