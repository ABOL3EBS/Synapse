interface Props {
  /** ISO 3166-1 alpha-2 country code (e.g. "US"). Empty/null → muted "?" fallback. */
  code: string | null;
  className?: string;
}

// Real flag sprite from flag-icons, keyed by ISO 3166-1 alpha-2. The class
// name is validated by flag-icons' own CSS — unknown codes simply render
// nothing, so the fallback keeps the layout slot occupied.
export default function FlagIcon({ code, className }: Props) {
  const c = (code ?? "").trim();
  if (!c) {
    return (
      <span
        className={`inline-block text-navy/30 text-[10px] font-mono leading-none shrink-0 ${className ?? ""}`}
      >
        ?
      </span>
    );
  }
  return (
    <span
      className={`fi fi-${c.toLowerCase()} leading-none shrink-0 ${className ?? ""}`}
    />
  );
}