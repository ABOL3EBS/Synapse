interface Props {
  state: "protected" | "warning" | "inactive";
  size?: number;
}

const GRADIENT_IDS = {
  protected: "shield-green",
  warning: "shield-amber",
  inactive: "shield-grey",
} as const;

const COLORS = {
  protected: ["#10B981", "#059669"],
  warning: ["#F59E0B", "#D97706"],
  inactive: ["#94A3B8", "#64748B"],
} as const;

export default function ShieldIcon({ state, size = 120 }: Props) {
  const id = GRADIENT_IDS[state];
  const [c1, c2] = COLORS[state];

  return (
    <svg
      width={size}
      height={size * 1.18}
      viewBox="0 0 100 118"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <defs>
        <linearGradient id={id} x1="20%" y1="0%" x2="80%" y2="100%">
          <stop offset="0%" stopColor={c1} />
          <stop offset="100%" stopColor={c2} />
        </linearGradient>
        <filter id="shield-shadow" x="-20%" y="-10%" width="140%" height="130%">
          <feDropShadow dx="0" dy="6" stdDeviation="10"
            floodColor={c1} floodOpacity="0.35" />
        </filter>
      </defs>

      {/* Shield body */}
      <path
        d="M50 4 L90 20 L90 58 C90 86 72 106 50 114 C28 106 10 86 10 58 L10 20 Z"
        fill={`url(#${id})`}
        filter="url(#shield-shadow)"
      />

      {/* Inner highlight — subtle sheen */}
      <path
        d="M50 12 L82 26 L82 58 C82 82 66 100 50 107 C34 100 18 82 18 58 L18 26 Z"
        fill="white"
        opacity="0.08"
      />

      {state === "protected" && (
        <path
          d="M34 59 L46 71 L68 49"
          stroke="white"
          strokeWidth="6"
          strokeLinecap="round"
          strokeLinejoin="round"
          fill="none"
        />
      )}

      {state === "warning" && (
        <>
          <line x1="50" y1="44" x2="50" y2="68" stroke="white" strokeWidth="6" strokeLinecap="round" />
          <circle cx="50" cy="78" r="3.5" fill="white" />
        </>
      )}

      {state === "inactive" && (
        <circle cx="50" cy="59" r="10" stroke="white" strokeWidth="5" fill="none" opacity="0.7" />
      )}
    </svg>
  );
}
