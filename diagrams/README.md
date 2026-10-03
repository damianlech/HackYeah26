# Diagrams

These are the Mermaid sources and rendered images for the pitch deck, the README and the docs. Each diagram has three files, all named after it:

- `src/<name>.mmd` is the Mermaid source;
- `svg/<name>.svg` is a vector render (neutral theme, white background, labels as plain SVG text so it imports cleanly into Keynote, PowerPoint and Figma);
- `png/<name>.png` is a 1600 px wide raster render (neutral theme, white background).

## Slide diagrams (new, simplified, ≤ 12 nodes, sized for 1280×720)

| Diagram | What it shows | Based on | Files |
|---|---|---|---|
| `slide-architecture` | The product on one slide. Agents sit on a fenced network and reach only `lb`. Behind it, 2 stateless gateway replicas run an LLM edge and an MCP edge that share one policy brain (`policy.yaml`, hot reload). Upstreams are Ollama on the Mac (Metal) and `mock-llm` (simulated commercial); MCP servers are sandboxed. Side services: guard (semantic), feed (signed threat intel), valkey (budgets, runs, taint) and control (console, self-test, audit checkpoints) | VISION-SPEC §3.2, §3.3 | [src](src/slide-architecture.mmd) · [svg](svg/slide-architecture.svg) · [png](png/slide-architecture.png) |
| `slide-cascade` | The hybrid cascade with its p95 targets: T0 policy ≤ 2 ms → T1 deterministic ≤ 5 ms → T2 semantic encoders ≤ 120 ms → T3 guard LLM (P1, alongside the upstream call, ≤ 1.5 s) → OUT stream holdback ≤ 150 ms added TTFT. Also shows the early reject with zero upstream calls, and two rules: "most restrictive wins" and "detectors only add restrictions" | VISION-SPEC §5.1, §5.2 | [src](src/slide-cascade.mmd) · [svg](svg/slide-cascade.svg) · [png](png/slide-cascade.png) |
| `slide-guarantee` | The C24 guarantee. A sink call such as `mail_send_email(to=…)` is decided by where its destination came from: the user task (`/v1/runs`), the policy allowlist or a `trusted_source` tool lead to allow; untrusted content such as a web page leads to deny. Detectors switched off can only add taint, so they never lift that deny | VISION-SPEC §5.6, §2.1 pillar 1 | [src](src/slide-guarantee.mmd) · [svg](svg/slide-guarantee.svg) · [png](png/slide-guarantee.png) |
| `slide-original-idea` | Before → after. The forked Squid and budget service on one side; Mandate on the other. Kept: the chokepoint (now a fenced network), SSO/LDAP groups → models & budgets, and managed settings. Moved: inspection to the LLM and MCP edges. Demoted: stock Squid, now an optional egress sensor | VISION-SPEC §2.3, docs/01 | [src](src/slide-original-idea.mmd) · [svg](svg/slide-original-idea.svg) · [png](png/slide-original-idea.png) |

## Spec diagrams (copied from `design/VISION-SPEC.md`)

| Diagram | What it shows | Spec section | Files |
|---|---|---|---|
| `container-c4` | C4-style container view: every container, its Docker network (trust zone) and the routes between them, including the fence-probe's must-fail targets | §3.3 | [src](src/container-c4.mmd) · [svg](svg/container-c4.svg) · [png](png/container-c4.png) |
| `llm-request-stream` | Sequence (a): an agent → LLM chat request with T0/T1/T2, budget reserve/settle, streaming holdback, tool-call mediation and the audit event | §3.5 (a) | [src](src/llm-request-stream.mmd) · [svg](svg/llm-request-stream.svg) · [png](png/llm-request-stream.png) |
| `mcp-taint-provenance` | Sequence (b): `/v1/runs` → MCP `tools/list` and `tools/call`, taint from a poisoned web page, the C24 deny for `audit@evil.test`, and the allow or ask for the customer reply | §3.5 (b) | [src](src/mcp-taint-provenance.mmd) · [svg](svg/mcp-taint-provenance.svg) · [png](png/mcp-taint-provenance.png) |
| `policy-hot-reload` | Sequence (c): a judge edits `policy.yaml`. Shows the rejected edit (last-known-good stays) and the applied edit (v18 on 2/2 replicas, posture recomputed, canary self-test) | §3.5 (c) | [src](src/policy-hot-reload.mmd) · [svg](svg/policy-hot-reload.svg) · [png](png/policy-hot-reload.png) |
| `feed-update` | Sequence (d): a signed feed publish, the gateway poll and verification, anti-rollback serial, and the tampered/rolled-back/expired branch | §3.5 (d) | [src](src/feed-update.mmd) · [svg](svg/feed-update.svg) · [png](png/feed-update.png) |
| `timeline-gantt` | The 24 h build plan by lane, with checkpoints CF, IC1-IC4, freeze, clean room and submit | §13.4 | [src](src/timeline-gantt.mmd) · [svg](svg/timeline-gantt.svg) · [png](png/timeline-gantt.png) |

These copies are meant to match the spec word for word. `timeline-gantt` needs `todayMarker off` (the spec block has it since v1.1); without it, Mermaid draws a red "now" line at whatever time of day the diagram is rendered, because the chart uses `HH:mm` dates. When the spec changes, copy the block into `src/` again and re-render.

> **Stale since spec v1.1:** `timeline-gantt` still has the pre-v1.1 plan (title "H0 = official start", L's 21:30 sleep instead of the 18:00 nap, no B6 C07 slot, old B5/B7 timings), and `container-c4` lacks "(P1)" on the mock's Ollama-native endpoint. Until they are re-copied from spec §13.4 and §3.3 and re-rendered (`diagrams/render.sh timeline-gantt container-c4`), use the spec's blocks, not these files. The other four spec copies match.

## Re-render

You need Node ≥ 18. The first run downloads `@mermaid-js/mermaid-cli@11` and its headless Chrome through `npx`.

```bash
diagrams/render.sh                                   # everything in src/
diagrams/render.sh slide-cascade slide-guarantee     # only these
```

As a Makefile target:

```make
diagrams:
	diagrams/render.sh
```

Environment knobs:

| Variable | Default | Use |
|---|---|---|
| `MMDC` | `npx -y -p @mermaid-js/mermaid-cli@11 mmdc` | Point it at a local install, e.g. `MMDC=node_modules/.bin/mmdc` |
| `CHROME` | unset (puppeteer's own Chrome) | Use an existing Chrome/Chromium, e.g. in a container: `CHROME=/opt/pw-browsers/chromium-1194/chrome-linux/chrome` (also adds `--no-sandbox`) |

What the script runs for each diagram:

```bash
# SVG: native SVG text labels (no <foreignObject>), so slide tools render the text
#   svg-config.json: {"handDrawnSeed": 1, "htmlLabels": false, "flowchart": {"htmlLabels": false}}
mmdc -t neutral -b white -c svg-config.json -i src/X.mmd -o svg/X.svg
# PNG: 1600 px wide; fill.css scales narrow diagrams up to 1600 px as vectors instead of
# leaving them at their natural width
#   png-config.json: {"handDrawnSeed": 1}
#   fill.css:        #my-svg { max-width: none !important; }
mmdc -t neutral -b white -c png-config.json -w 1616 -C fill.css -i src/X.mmd -o png/X.png
```

`handDrawnSeed: 1` pins the random jitter Mermaid applies to some shapes, such as the rounded `request`/`response` nodes. Without it, every render of an unchanged source produces a different file and a noisy git diff.

**Why mermaid-cli 11 (Mermaid 11.17) rather than 12.** Every source here also parses in Mermaid 12.1, but 12 lays out flowcharts very differently, and the container diagram and the slides come out much harder to read.

## Editing tips for slide diagrams

- Keep a slide to ≤ 12 nodes and ≤ 3 short lines per label. The `wrappingWidth: 400` front matter keeps labels from wrapping at 200 px.
- A subgraph's `direction` only applies when none of its nodes link outside it. Link the subgraph itself instead (`PIPE --> RULES`).
- Inside a nested subgraph, Mermaid flips the default direction (TB inside LR, and the reverse). Set `direction` explicitly.
- Colours come from `classDef`: blue for deterministic authority, amber for detectors or the agent zone, green for kept or trusted, red for denied, dropped or untrusted, dashed grey for off or demoted.
