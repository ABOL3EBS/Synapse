#!/bin/bash
# extract-app-icons.sh — Synapse IPS developer utility.
#
# Extracts 64x64 PNG app icons from /Applications/*.app bundles for manual
# preview/debugging. NOT used at runtime — production icon resolution goes
# through the Tauri `get_app_icon` command (NSWorkspace + IconCache in
# src-tauri/src/lib.rs). This script exists so the icon-extraction pipeline
# is a repeatable, committed step rather than word-of-mouth knowledge.
#
# Usage: scripts/extract-app-icons.sh [output_dir]
#   Default output: public/apps/
#
# Pipeline per app: sips -z 64 64 ASSET.icns --out OUT.png
# sips decodes .icns directly. The main app icon is the largest .icns in
# Contents/Resources/.
#
# NOTE: written for macOS's stock bash 3.2 — no associative arrays.
set -euo pipefail

OUTPUT_DIR="${1:-public/apps}"
mkdir -p "$OUTPUT_DIR"

# name → /Applications/App.app. Add entries as new apps appear in the feed.
extract() {
  local name="$1" app="$2"
  [ -d "$app" ] || { echo "skip $name — $app not installed"; return 0; }

  # Largest .icns in Contents/Resources = the main app icon.
  local icns
  icns=$(find "$app/Contents/Resources" -maxdepth 1 -name '*.icns' -exec ls -S {} + 2>/dev/null | head -1)
  [ -n "$icns" ] && [ -f "$icns" ] || { echo "skip $name — no .icns in $app"; return 0; }

  local out="$OUTPUT_DIR/$name.png"
  sips -z 64 64 "$icns" --out "$out" >/dev/null 2>&1
  echo "ok  $name → $out"
}

extract "brave-browser-helper" "/Applications/Brave Browser.app"
extract "cursor-helper"        "/Applications/Cursor.app"
extract "claude-helper"        "/Applications/Claude.app"
extract "granola-helper"       "/Applications/Granola.app"
extract "whatsapp"             "/Applications/WhatsApp.app"

echo "done — $OUTPUT_DIR"