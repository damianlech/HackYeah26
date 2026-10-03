#!/usr/bin/env bash
# Re-render diagrams/src/*.mmd into diagrams/svg/ and diagrams/png/.
#
#   diagrams/render.sh                    # every source
#   diagrams/render.sh slide-cascade ...  # only the named sources (no .mmd suffix)
#
# Env:
#   MMDC    mermaid-cli command   (default: npx -y -p @mermaid-js/mermaid-cli@11 mmdc)
#   CHROME  Chrome/Chromium binary for puppeteer, optional (CI containers, sandboxes);
#           when set, the browser also runs with --no-sandbox
#
# Output:
#   svg/<name>.svg  neutral theme, white background, labels as native SVG <text>
#                   (no <foreignObject>), so the files import into Keynote, PowerPoint and Figma
#   png/<name>.png  neutral theme, white background, 1600 px wide (narrow diagrams are
#                   scaled up as vectors before the screenshot, so they stay crisp)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
MMDC="${MMDC:-npx -y -p @mermaid-js/mermaid-cli@11 mmdc}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# handDrawnSeed pins the random jitter Mermaid uses for some shapes (e.g. stadium nodes),
# so re-rendering an unchanged source gives byte-identical files and clean git diffs.
printf '{"handDrawnSeed": 1}\n' > "$tmp/png-config.json"
# SVG: plain SVG text labels for portability into slide tools.
printf '{"handDrawnSeed": 1, "htmlLabels": false, "flowchart": {"htmlLabels": false}}\n' > "$tmp/svg-config.json"
# PNG: let the diagram fill the 1600 px page instead of stopping at its natural width.
printf '#my-svg { max-width: none !important; }\n' > "$tmp/fill.css"

pp=""
if [ -n "${CHROME:-}" ]; then
  printf '{"executablePath": "%s", "args": ["--no-sandbox"]}\n' "$CHROME" > "$tmp/puppeteer.json"
  pp="-p $tmp/puppeteer.json"
fi

if [ "$#" -gt 0 ]; then
  names="$*"
else
  names="$(cd "$here/src" && ls -1 *.mmd | sed 's/\.mmd$//')"
fi

mkdir -p "$here/svg" "$here/png"
fail=0
for n in $names; do
  src="$here/src/$n.mmd"
  # shellcheck disable=SC2086  # $MMDC and $pp are intentionally word-split
  if $MMDC $pp -q -t neutral -b white -c "$tmp/svg-config.json" -i "$src" -o "$here/svg/$n.svg" &&
     $MMDC $pp -q -t neutral -b white -c "$tmp/png-config.json" -w 1616 -C "$tmp/fill.css" -i "$src" -o "$here/png/$n.png"; then
    echo "ok    $n"
  else
    echo "FAIL  $n" >&2
    fail=1
  fi
done
exit "$fail"
