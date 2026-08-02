import type { ActivityItem } from "./db";

// ---------------------------------------------------------------------------
// Detector ID → plain-language finding phrase
// These IDs come from Rust's Debug fmt of the DetectorId enum variants.
// ---------------------------------------------------------------------------

const FINDING_PHRASE: Record<string, string> = {
  IpReputation: "reach a known-bad address",
  CrossFlow: "make an unusually high number of connections",
  DnsAnalyzer: "reach a suspicious domain",
  DnsTunnelDetector: "hide data in DNS requests",
  FlowBehavior: "send an unusual pattern of traffic",
  ProcessCorrelator: "behave like suspicious software",
};

// CrossFlow has sub-types (scan, DNS burst, beaconing, diversity) that share
// the same detector_id. Refine the phrase using the evidence description text.
function crossFlowPhrase(evidenceDesc: string): string {
  const d = evidenceDesc.toLowerCase();
  if (d.includes("beacon") || d.includes("cv="))
    return "make repeated automated connections at regular intervals";
  if (d.includes("distinct ip") || d.includes("diversity"))
    return "connect to an unusually wide variety of servers";
  if (d.includes("dns query") || d.includes("dns burst"))
    return "make an unusually high number of DNS lookups";
  return "make an unusually high number of connections";
}

// Parse the first evidence description from a raw evidence_json string.
// evidence_json is an array of {description, detail?} objects.
function firstEvidenceDesc(json: string | null): string | null {
  if (!json) return null;
  try {
    const arr = JSON.parse(json) as { description?: string }[];
    return arr[0]?.description ?? null;
  } catch {
    return null;
  }
}

// Country code → human-readable name (subset; falls back to code)
const COUNTRY_NAMES: Record<string, string> = {
  US: "the United States", GB: "the United Kingdom", DE: "Germany",
  FR: "France", NL: "the Netherlands", SE: "Sweden", NO: "Norway",
  CN: "China", RU: "Russia", JP: "Japan", KR: "South Korea",
  AU: "Australia", CA: "Canada", BR: "Brazil", IN: "India",
  SG: "Singapore", HK: "Hong Kong", UA: "Ukraine",
};

export function countryName(code: string): string {
  return COUNTRY_NAMES[code.toUpperCase()] ?? code;
}

export function toPlainEnglish(item: ActivityItem): string {
  const app = item.app_name || "Unknown app";
  const remote = item.dns_name ?? item.remote_ip_text;
  const topDetector = item.detector_ids[0];

  // For CrossFlow, refine the generic phrase using the evidence description.
  let phrase: string;
  if (topDetector === "CrossFlow") {
    const desc = firstEvidenceDesc(item.top_evidence);
    phrase = desc ? crossFlowPhrase(desc) : FINDING_PHRASE.CrossFlow;
  } else {
    phrase = (topDetector && FINDING_PHRASE[topDetector]) ?? "do something suspicious";
  }

  if (item.verdict === "Allow") {
    const loc = item.country_code
      ? ` in ${countryName(item.country_code)}`
      : "";
    return `${app} connected to ${remote}${loc}. Looks normal — allowed.`;
  }

  const suffix =
    item.verdict === "Block" ? "— blocked." : "— flagged for review.";
  return `${app} tried to ${phrase} (${remote}) ${suffix}`;
}

// Brief "Why?" sentence — one step more specific than toPlainEnglish
export function toWhySentence(item: ActivityItem): string {
  if (item.verdict === "Allow") {
    return "This connection looks normal. Synapse is watching it but has no reason to block it.";
  }
  const phrases = item.detector_ids
    .map((id) => FINDING_PHRASE[id])
    .filter(Boolean);
  if (phrases.length === 0) {
    return "Synapse detected unusual behaviour and took action to protect you.";
  }
  const joined =
    phrases.length === 1
      ? phrases[0]
      : `${phrases.slice(0, -1).join(", ")} and ${phrases[phrases.length - 1]}`;
  const action =
    item.verdict === "Block"
      ? "Synapse blocked it to protect you."
      : "Synapse flagged it so you can review it.";
  return `${item.app_name || "This app"} tried to ${joined}. ${action}`;
}
