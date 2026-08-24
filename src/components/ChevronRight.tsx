// Fading-in "this row drills down" affordance for Report screen panels.
// Shared by DetectorChart, TopApps, TopThreatSources.
export default function ChevronRight() {
  return (
    <svg
      width="14" height="14" viewBox="0 0 16 16" fill="none"
      className="shrink-0 text-navy/25 opacity-0 group-hover:opacity-100 transition-opacity"
    >
      <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
