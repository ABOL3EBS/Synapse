import { useState } from "react";
import type { ActivityItem } from "../lib/db";
import { toPlainEnglish, toWhySentence } from "../lib/translate";
import { relativeTime } from "../lib/time";

const DETECTOR_LABEL: Record<string, string> = {
  CrossFlow:          "Connection pattern analysis",
  DnsAnalyzer:        "DNS behaviour analysis",
  FlowBehavior:       "Traffic shape analysis",
  IpReputation:       "IP reputation check",
  ProcessCorrelator:  "Process behaviour analysis",
  DnsTunnelDetector:  "DNS tunnel detection",
};

interface Props {
  item: ActivityItem;
}

const VERDICT_DOT: Record<ActivityItem["verdict"], string> = {
  Block: "bg-emerald",
  Alert: "bg-amber",
  Allow: "bg-navy/20",
};

const VERDICT_LABEL: Record<ActivityItem["verdict"], string> = {
  Block: "Blocked",
  Alert: "Flagged",
  Allow: "Allowed",
};

const VERDICT_LABEL_CLASS: Record<ActivityItem["verdict"], string> = {
  Block: "text-emerald-dark bg-emerald-light",
  Alert: "text-amber-700 bg-amber-light",
  Allow: "text-navy/40 bg-navy/5",
};

export default function ActivityRow({ item }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [techOpen, setTechOpen] = useState(false);

  const sentence = toPlainEnglish(item);
  const whySentence = toWhySentence(item);
  const remoteIp = item.dns_name ?? item.remote_ip_text;

  return (
    <div className="bg-white rounded-2xl shadow-card border border-black/[0.04] overflow-hidden">
      {/* Main row */}
      <button
        className="w-full text-left px-4 py-3.5 flex items-start gap-3"
        onClick={() => setExpanded((e) => !e)}
      >
        {/* Verdict dot */}
        <span className={`mt-1.5 shrink-0 w-2 h-2 rounded-full ${VERDICT_DOT[item.verdict]}`} />

        {/* Content */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-navy leading-snug">{sentence}</p>
          <p className="text-xs text-navy/40 mt-0.5">{relativeTime(item.ts_ms)}</p>
        </div>

        {/* Verdict badge + chevron */}
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${VERDICT_LABEL_CLASS[item.verdict]}`}>
            {VERDICT_LABEL[item.verdict]}
          </span>
          <ChevronIcon open={expanded} />
        </div>
      </button>

      {/* Expanded "Why?" panel */}
      {expanded && (
        <div className="border-t border-black/[0.04] px-4 py-4 space-y-3">
          <p className="text-sm text-navy/70 leading-relaxed">{whySentence}</p>

          {/* Technical details accordion */}
          <button
            className="text-xs font-medium text-navy/40 underline underline-offset-2 hover:text-navy/60"
            onClick={() => setTechOpen((o) => !o)}
          >
            {techOpen ? "Hide technical details" : "Show technical details"}
          </button>

          {techOpen && (
            <div className="bg-canvas rounded-xl px-3 py-2.5 space-y-1.5 text-xs font-mono text-navy/50">
              <DetailRow label="Address" value={remoteIp} />
              {item.country_code && <DetailRow label="Location" value={item.country_code} />}
              {item.detector_ids.length > 0 && (
                <DetailRow
                  label="Detectors"
                  value={item.detector_ids
                    .map((id) => DETECTOR_LABEL[id] ?? id)
                    .join(", ")}
                />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-navy/30 w-20 shrink-0">{label}</span>
      <span className="text-navy/60 break-all">{value}</span>
    </div>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="16" height="16" viewBox="0 0 16 16" fill="none"
      className={`text-navy/30 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
    >
      <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
