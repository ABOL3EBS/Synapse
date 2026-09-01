import { useEffect, useState } from "react";
import { getAppIcon } from "../lib/db";

// Module-level cache: one IPC call per unique process path, cached for the
// session. Icons don't change while the app is running. (Rust also caches by
// resolved .app bundle, so helper variants of one app share a single lookup.)
const iconCache = new Map<string, Promise<string | null>>();

function fetchIcon(processPath: string): Promise<string | null> {
  const cached = iconCache.get(processPath);
  if (cached) return cached;
  const p = getAppIcon(processPath).catch(() => null);
  iconCache.set(processPath, p);
  return p;
}

/** First letter of the app name, uppercase — used for the fallback badge. */
export function appInitial(name: string): string {
  return name.charAt(0).toUpperCase();
}

/** Stable hue from the app name — consistent colour per app. */
export function appHue(name: string): number {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xffff;
  return h % 360;
}

interface Props {
  /** Full process path from the verdicts table. Null → fallback glyph. */
  processPath: string | null;
  size?: number;
}

export default function AppIcon({ processPath, size = 24 }: Props) {
  const [src, setSrc] = useState<string | null>(null);
  const name = processPath ? processPath.split("/").pop() ?? "?" : "?";

  useEffect(() => {
    if (!processPath) return;
    let alive = true;
    fetchIcon(processPath).then((b64) => {
      if (alive) setSrc(b64);
    });
    return () => {
      alive = false;
    };
  }, [processPath]);

  if (src) {
    return (
      <img
        src={`data:image/png;base64,${src}`}
        alt={name}
        className="shrink-0 rounded-md object-cover"
        style={{ width: size, height: size }}
      />
    );
  }

  // Fallback — coloured letter circle, same pattern as before the real icons.
  return (
    <div
      className="shrink-0 rounded-full flex items-center justify-center text-white font-bold"
      style={{
        width: size,
        height: size,
        background: `hsl(${appHue(name)}, 55%, 48%)`,
        fontSize: size * 0.4,
      }}
    >
      {appInitial(name)}
    </div>
  );
}