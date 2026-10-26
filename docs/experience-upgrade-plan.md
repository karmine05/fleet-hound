# Fleet Hound — Experience Upgrade Plan

**Status:** implemented (Phases 0–5 shipped 2026-10-25). Screenshots of the shipped UI are in `assets/`.
**Scope:** visual system, motion, hero diagrams, new Overview, Graph, Blast Radius, Shadow IT, Extensions, Changes, and all loading/empty/error states.
**Runtime constraint:** Flask serves one static `webviz/static/index.html`; D3 v7 is vendored locally. There is no build step. The shipped implementation keeps that architecture.

---

## 0. Design read

> Reading this as: a security-operations console for analysts and IT operators, with a precise, instrument-grade visual language, leaning toward a dark-first **signal cartography** system — closer to Linear, Anduril Lattice, and Palantir Gotham than to a marketing site.

**Dials**

| Dial | Value | Meaning |
|---|---:|---|
| Variance | 5/10 | Structured 12-column grid, one asymmetric hero, no decorative chaos. |
| Motion | 6/10 | One meaningful hero moment per view; everything else is feedback and continuity. |
| Density | 8/10 | Cockpit-dense, but scannable. Mono numerals, hairlines, quiet surfaces. |

The platform's core promise is *reachability*: what does a compromise touch? The interface should make that visible in 30 seconds. Today the capability is there, but the graph is a hairball, the metrics are flat, and there is no front door.

---

## 1. Executive summary

Five moves, in impact order:

1. **Add an Overview / Command Deck as the front door.** A live fleet constellation, four headline counts, three risk cards, and an OODA pulse. This is the single biggest "wow" and the fastest way to explain the product.
2. **Make the graph legible before making it move.** Add a legend, zoom/pan, degree-based sizing, label decluttering, semantic type colors, risk halos, and a focus mode. Motion comes after the hairball is tamed.
3. **Replace the four-axis radar with an Impact Cascade.** Blast Radius becomes a radial burst: seed → impacted hosts → impacted users → platform arcs, with the numbers driving the geometry. Keep the radar as an optional toggle.
4. **Turn tables into triage.** Shadow IT gets a severity donut + detection-mix ribbon; Extensions gets a risk matrix (prevalence × severity). The table remains the workhorse below.
5. **Install a product-wide motion and feedback layer.** Count-ups, skeletons, toasts, modal transitions, a theme crossfade, a short boot screen, and reduced-motion parity. One system, not one-off effects.

**Non-goals:** Three.js/WebGL, particle starfields, glassmorphism on every surface, confetti, invented risk scores, a new chart library, a React rewrite.

**Effort:** ~38 focused hours for the full plan; ~26 hours for the recommended MVP (Phases 0–3). Five visible phases, each independently shippable.

---

## 2. Current state audit

### What already works

- Dark and light token systems, Inter, a consistent spacing scale, focus-visible rings.
- D3 force graph, pathfinder, clusters, hover correlation, 800-node render budget.
- `prefers-reduced-motion` coverage for the marching path and pulse ring.
- Cross-view label scope, keyboard arrow navigation for tabs, `sr-only` live regions.
- Rich data: `/api/graph/full`, `/api/blast-radius`, `/api/shadow-it`, `/api/extensions`, `/api/snapshots`, `/api/diff`, `/api/ooda/*`.

### What makes it feel like a prototype

| Area | Current state | User impact | Fix |
|---|---|---|---|
| Front door | App opens on a full-screen force graph (`index.html:6362`). | First-time users see a hairball with no explanation. | New Overview + first-visit default. |
| Graph legibility | Every node gets a label; all hosts are red; edges at 0.5 opacity (`renderGraph`, line 3042). | Labels overlap, risk color is meaningless, edges dominate. | Degree sizing, label decluttering, type/risk split, edge dimming. |
| Graph navigation | No `d3.zoom` or pan, despite the README claiming it. | Large graphs cannot be inspected. | Zoom/pan, fit, +/−, keyboard controls. |
| Blast Radius | Four-axis radar with four abstract scores (`drawRadarChart`, line 4702). | The diagram does not show what was actually reached. | Impact Cascade. |
| Metrics | `textContent` assignment (`updateBlastMetrics`, line 4610). | Numbers appear; changes are not felt. | Count-ups + proportional bars. |
| Shadow IT | Six equal metric cards, then a table. | No visual hierarchy; triage starts with reading. | Severity donut + detection-mix ribbon. |
| Extensions | Six equal metric cards, then a table. | Risk is only visible row by row. | Prevalence × severity matrix. |
| Changes | Two selects + Compute diff. | Snapshots feel like a file picker, not a timeline. | Snapshot timeline + delta ribbon. |
| Feedback | One top-left status div (`showStatus`, line 3525). | Errors and successes share the same treatment; no stack. | Toast system with severity, icon, progress. |
| Loading | "Loading..." text. | Layout jumps when data arrives. | Skeletons that match final shapes. |
| Modals | `display` toggle + `.visible` class (line 5029), no focus trap. | Abrupt, and keyboard focus escapes. | Fade/scale, focus trap, focus restore. |
| Brand | Text-only "Fleet Hound" (`index.html:2118`), no favicon. | Reads as an internal prototype. | Mark, favicon, boot screen, consistent wordmark. |
| Tab routing | `switchView` knows three views; extensions/changes are monkey-patched wrappers at the bottom of the file. | Adding a tab is brittle. | One data-driven `switchView` with `onEnter` hooks. |
| Responsive | Only touch targets are bumped at ≤900px. Fixed 280–340px sidebars, `100vh` layouts. | Unusable on tablets/phones. | Responsive layout pass + `100dvh`. |

The upgrade is not "add more animation". It is **make the existing intelligence visible, then add motion that explains it**.

---

## 3. Design direction: Signal Cartography

### 3.1 Principles

1. **The graph is the instrument, not the wallpaper.** No decorative background competes with data.
2. **Risk is the only thing allowed to shout.** Type colors are quiet; red/amber are reserved for risk and change.
3. **One hero per view.** Overview has the constellation; Blast Radius has the cascade; Extensions has the matrix. Everything else supports.
4. **Motion must explain hierarchy, feedback, or continuity.** If it only decorates, delete it.
5. **Truth over spectacle.** Sampled data is labeled as sampled; stale data says stale; no fake scores.
6. **Dark first, light fully supported.** Both themes are first-class, not an afterthought.

### 3.2 Visual language

**Palette (dark, proposed adjustments)**

| Role | Token | Value | Use |
|---|---|---|---|
| Canvas | `--bg-primary` | `#08090d` | App background, graph canvas |
| Surface | `--bg-secondary` | `#0e1016` | Panels, cards |
| Raised | `--bg-tertiary` | `#151822` | Controls, table head |
| Floating | `--bg-elevated` | `#1b1f2b` | Popovers, modals |
| Hairline | `--border` | `#242834` | Default dividers |
| Strong line | `--border-strong` | `#343a4b` | Hover, focus support |
| Text | `--text-primary` | `#eceef5` | Body, values |
| Muted | `--text-secondary` | `#9aa2b5` | Labels |
| Faint | `--text-tertiary` | `#646b7d` | Captions |
| Signal | `--accent` | `#6c7bf5` | Primary action, live data |
| Live | `--signal` | `#5eead4` | Only for "live/running" indicators |
| Danger | `--danger` | `#ff5c62` | High risk |
| Warning | `--warning` | `#ffb020` | Medium risk |
| Caution | `--caution` | `#e6c84a` | Low risk |
| Success | `--success` | `#4cc38a` | Resolved / healthy |

**Semantic chart colors**

| Type | Color | Shape / weight |
|---|---|---|
| Host | `#8b9cff` (indigo) | Large node, 18px base |
| User | `#6ee7d8` (teal) | Medium node, 14px base |
| Software | `#9aa3b8` (slate) | Small node, 10px base |
| High risk | `#ff5c62` | Ring/halo, not fill |
| Medium risk | `#ffb020` | Ring/halo |
| Low risk | `#e6c84a` | Ring/halo |

This is a deliberate change: today hosts are red, which implies every host is dangerous. Type should be identity; risk should be a halo. Users still get red/amber where it matters.

**Light theme adjustments:** keep the existing structure but replace pure white cards with `#ffffff` on `#f6f7fa`, strengthen borders to `#dfe3ec`, and use darker risk text tokens (`#c92a32`, `#a35b00`, `#8a6d00`) so small labels pass 4.5:1. Re-run contrast on every badge.

**Typography**

- Keep **Inter** for UI. It is already loaded and appropriate for a dense product.
- Add **JetBrains Mono** (400/500, `display=swap`) for IDs, micro-labels, axis ticks, timestamps, and graph labels. Fall back to the existing mono stack. One extra font family is justified by the instrument feel; no display serif.
- Add a hero size: `--text-hero: clamp(2rem, 3.4vw, 3.25rem)`, line-height `1.05`, tracking `-0.035em`.
- Use `font-variant-numeric: tabular-nums` on every metric and table number.
- Use `text-wrap: balance` on headlines, `text-wrap: pretty` on paragraphs.

**Surfaces**

- 12-column grid, 8px spacing base, 24px page gutters.
- Radius scale: 6px controls, 8px cards, 12px hero, 999px status pills. No mixed-radius confusion.
- Cards only where elevation means hierarchy. Tables and metric strips use hairlines, not boxes inside boxes.
- Deep surfaces get an inset top highlight: `box-shadow: inset 0 1px 0 rgba(255,255,255,.04)`.
- Hero container gets a 1px gradient border (indigo → transparent) and a soft radial glow behind the diagram. No glass everywhere; reserve `backdrop-filter` for floating HUD/popovers over the graph.
- Optional 24px dot grid at 2.5% opacity on the Overview hero and Graph canvas only. Never behind tables.

**Iconography**

- Replace emoji/unicode glyphs (`←`, `!`, `×`) with a small inline SVG sprite: search, graph, shield, pulse, clock, alert, chevron, sun/moon, play, pause, download, x.
- 16px viewBox, 1.5px stroke, `currentColor`. One family only.
- Status is always icon + text, never color alone.

**Brand mark**

A geometric hound head built from graph parts, not a cartoon:

- Five nodes and four edges form a shield-like head silhouette.
- Two upper nodes become ears; one lower node is the muzzle; one small accent node is the scanning eye.
- 22px in the topbar, 48px on the boot screen, same path as favicon.
- Wordmark: "FLEET HOUND" in 12–13px, 600 weight, 0.08em tracking, with "Fleet" in primary and "Hound" in muted — or all primary; decide in implementation.

The mark must read at 16px. If it does not, simplify to a monogram "H" with node terminals rather than forcing a dog illustration.

**Voice**

Operational, specific, calm. No marketing adjectives. Examples:

- Hero: **"See the whole fleet. Find the blast radius."**
- Sub: **"Hosts, identities, and software in one risk graph — so you can trace exposure before it spreads."**
- Empty state: **"No detections in this scope."** + "Clear filters" action.
- Stale: **"Snapshot from 17:24Z · 2h old"** — never "Live" when it is not.

---

## 4. Motion system

### 4.1 Goals

| Motion job | Where |
|---|---|
| Explain hierarchy | Overview hero: diagram first, then headline, then stats. |
| Confirm action | Toasts, count-ups, row flashes, export feedback. |
| Maintain continuity | Tab transitions, graph position carryover, modal open/close. |
| Guide attention | Risk pulses, path packet, changed values. |
| Add craft | Theme transition, boot mark, hover physics. |

If an animation does none of these, it is cut.

### 4.2 Tokens

```css
:root {
  --ease-out: cubic-bezier(0.16, 1, 0.30, 1);   /* entrances, expansions */
  --ease-in: cubic-bezier(0.70, 0, 0.84, 0);    /* exits */
  --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);

  --dur-instant: 90ms;   /* press */
  --dur-fast: 140ms;     /* hover */
  --dur-base: 200ms;     /* state change */
  --dur-slow: 280ms;     /* popover, toast */
  --dur-enter: 420ms;    /* card/section entrance */
  --dur-hero: 700ms;     /* hero beats */
  --dur-trace: 1200ms;   /* path packet */

  --stagger: 60ms;
}
```

**Rules**

- Animate `transform` and `opacity` only. SVG attributes via D3 interpolation are allowed; never animate `width`, `height`, `top`, `left`, or `box-shadow` on large surfaces.
- Exit is faster than entrance: use `--dur-fast` for close, `--dur-base` for open.
- Max one infinite animation per view (live status dot, or hero drift — not both). Pause everything when `document.hidden` or the view is inactive.
- Stagger caps: 5 items for metrics, 12 rows for tables. Do not stagger 200 diff rows.
- Interruptible: a second click/tab switch must not queue a timeline. Every animated component exposes `cancel()` or is replaced on re-render.
- No bounce/elastic except a 1.5% overshoot on toasts and popovers. No overshoot on dense tables.

### 4.3 Choreography

**Boot (only if data takes >250ms)**

1. 0ms: background + centered mark (line draw 600ms).
2. 200ms: wordmark fade/rise 8px.
3. 500ms: status line "Connecting to graph…".
4. On ready: content fades in 300ms; overlay fades out 300ms, then `display:none`.

Fast loads never see it. Under reduced motion: static mark, no line draw, 100ms fade.

**Overview**

1. 0ms: hero shell visible; constellation rings draw from center (600ms).
2. 100ms: eyebrow + headline rise 12px (500ms).
3. 180ms: sub + CTAs rise 8px (400ms).
4. 250ms: three node waves (software → users → hosts) fade/scale in, 60ms apart.
5. 700ms: stat counts run 500ms.
6. 1200ms: ambient drift starts (0.5° amplitude, 30s loop), only if visible and motion allowed.

**Tab switch**

- Outgoing view: opacity 1→0, translateY 0→-4px, 120ms `--ease-in`.
- Incoming: opacity 0→1, translateY 8px→0, 200ms `--ease-out`.
- The tab underline moves with `transform` over 240ms. The graph simulation pauses on exit and resumes on enter.

**Metric update**

- Count from previous value to next over 500ms with ease-out cubic.
- One 600ms background flash on the card border, then settle. No flashing number color.
- `aria-live` is set once to the final value; the animated digits are `aria-hidden` to avoid screen-reader chatter.

**Modal**

- Backdrop: opacity 0→1, 180ms; `backdrop-filter: blur(6px)`.
- Panel: opacity 0→1, translateY 8px→0, scale 0.98→1, 240ms `--ease-out`.
- Close: reverse 140ms.
- Focus trap, Esc, click-outside, restore focus to the trigger.

**Toast**

- Enter: translateY 12px→0 + opacity, 280ms.
- Exit: 160ms, then remove.
- 4s duration, progress line; pause on hover/focus; max 3 stacked; `aria-live="polite"`.

**Reduced motion**

- All ambient/infinite motion off.
- Chart draws and count-ups snap to final state.
- View switches become a 120ms opacity fade.
- Path animation is a static highlighted route.
- No smooth scrolling. The layout and all information remain identical.

---

## 5. Overview / Command Deck

### 5.1 Purpose

Answer three questions before the user clicks anything:

1. What does my fleet look like? (constellation + counts)
2. What is exposed right now? (risk cards)
3. Is the system fresh and working? (OODA pulse + timestamps)

It is a summary and a launcher, not a second Graph view. No entity filters here; deep-link to the real views.

### 5.2 Wireframe (desktop ≥1280px)

```text
┌────────────────────────────────────────────────────────────────────────────┐
│  [mark] FLEET HOUND   Overview  Graph  Blast Radius  Shadow IT  Extensions  Changes   [live] [meta] [theme] │
├────────────────────────────────────────────────────────────────────────────┤
│ ┌─ HERO ────────────────────────────────────────────────────────────────┐  │
│ │ LIVE FLEET GRAPH                           ·  constellation  ·       │  │
│ │ See the whole fleet.                                                 │  │
│ │ Find the blast radius.            hosts orbit · users · software     │  │
│ │                                                                      │  │
│ │ Hosts, identities, and software in one risk graph —                  │  │
│ │ so you can trace exposure before it spreads.                         │  │
│ │                                                                      │  │
│ │ [ Explore the graph ]  [ Triage findings ]     sample 120 of 3,432   │  │
│ │                                                                      │  │
│ │  32 HOSTS      126 IDENTITIES     3,432 SOFTWARE     182 FINDINGS    │  │
│ └──────────────────────────────────────────────────────────────────────┘  │
│ ┌─ Shadow IT ─────────┐ ┌─ Extensions ────────┐ ┌─ Fleet delta ─────────┐  │
│ │ 182   ◔ severity    │ │ 161   critical 2    │ │ +0 hosts  +1 user     │  │
│ │ high 18 · med 44    │ │ high 6 · affected 9 │ │ +12 software          │  │
│ │ [Triage →]          │ │ [Review →]          │ │ [Open changes →]      │  │
│ └─────────────────────┘ └─────────────────────┘ └───────────────────────┘  │
│ ┌─ AUTONOMY PULSE ─────────────────────────────────────────────────────┐  │
│ │ Observe ✓ 37s ─ Orient ✓ 0.1s ─ Decide ✓ 0.01s ─ Act ✓             │  │
│ │ cycle #6,478 · next in 28:12 · [Run now]                             │  │
│ └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

At 1440×900: topbar 52px + hero 380px + cards 180px + pulse 112px + gaps = ~800px, fits without scrolling. At 1024px the hero stacks; cards become 1 column at <768px.

### 5.3 Hero constellation spec

**Not** a generic particle field. It is a radial topology of the real sampled graph.

- **Orbits:** software inner (r=0.34R), users middle (r=0.56R), hosts outer (r=0.78R). Thin rings with mono labels and tick marks.
- **Nodes:** cap at 120 total: top 40 hosts by degree, top 40 users, top 40 software. Node radius `d3.scaleSqrt` by degree, clamped 3–10px.
- **Edges:** only edges between sampled nodes; curved quadratic paths bowed toward the center. Host→software install edges at 0.10 opacity; user→host edges at 0.22. Risk edges get 0.55 and a warm color.
- **Risk:** nodes present in the Shadow IT set get a 2px amber/red halo and one expanding ring every 4s (paused offscreen; static under reduced motion). This is the only pulse in the hero.
- **Labels:** only the 8 highest-degree nodes, plus hover/selected. Mono 9px with a background-colored stroke (`paint-order: stroke`).
- **Entrance:** rings draw, then three node waves, then edges, then labels. 900–1200ms total.
- **Idle:** ±0.5° orbit drift over 30s. No full rotation, no sparkles. Stop when hidden.
- **Interaction:** hover highlights connected edges and shows a floating tooltip (type, name, team/platform, degree, risk). Click jumps to Graph with the node focused; keyboard focus + Enter does the same.
- **Truth:** top-right caption "Sample · 120 of 3,432 nodes · scope: all teams". If the graph is capped, say so.

**Why not use the force simulation?** It is unstable, expensive, and produces the same hairball. A deterministic radial layout is legible, calm, and cheap (no simulation ticks). It also visually distinguishes the Overview hero from the working Graph view.

**Accessibility:** SVG is `role="img"` with a text summary; interactive nodes are `tabindex="0"`, `role="button"`, `aria-label="Host …"`. The counts and risk cards provide the same information in text.

### 5.4 Risk cards

Each card is a deep link, not a filter duplicate.

**Shadow IT**
- Big total + severity donut (high/medium/low) + "affected hosts/users".
- Top 3 detections by risk, truncated with ellipsis.
- CTA: "Triage →" switches to Shadow IT with no filters (or the current scope).
- Data: `/api/shadow-it?team=all` (client cache 60s).

**Extensions**
- Big total + critical/high counts + affected hosts.
- Risk band mini-bar.
- CTA: "Review →" switches to Extensions.
- Data: `/api/extensions` (client cache 60s).

**Fleet delta**
- Latest snapshot vs previous snapshot: `+hosts / +users / +software` from snapshot meta.
- A tiny 7-point sparkline of software count is allowed because it is real metadata.
- CTA: "Open changes →" sets Changes' From/To to the latest pair and runs the diff.
- Data: `/api/snapshots?limit=8` (add limit param; see §8.2).

**Card motion:** 420ms entrance, 40ms stagger, count-ups. Hover lifts 2px and brightens the border. Entire card is a link; the CTA is a visual affordance, not a nested button that traps keyboard focus.

### 5.5 OODA pulse

- Horizontal 4-step rail: Observe → Orient → Decide → Act.
- Current/last phase has a live dot; completed phases are check-marked; failed phase is red with the error summary.
- Show last cycle duration, next cycle countdown, cycle count, failure count.
- "Run now" posts `/api/ooda/trigger`; optimistically sets "Queued", then refreshes status. Handle 429 with a toast: "Retry in Ns."
- If disabled: "Autonomy off — enable OODA_ENABLED to run cycles" with docs link; no fake progress.
- Data: `/api/ooda/status`; poll every 30s only while Overview is active and visible.
- Add a small "pause live updates" control for reduced-distraction use; remembered for the session.

### 5.6 Overview states

| State | Treatment |
|---|---|
| Loading | Skeleton hero (rings + blocks) after 150ms; risk cards skeleton; no spinner. |
| DB down | Hero becomes a "No signal" panel with the last known snapshot if available + Retry. |
| Zero hosts | "Connect Fleet to populate the graph" + docs action. |
| No risk data | Card shows "Unavailable" with Retry; never a misleading zero. |
| Stale | Amber "Snapshot · 2h old" pill; no green live dot. |
| Partial failure | Cards load independently; one failure does not blank the page. |

---

## 6. View-by-view upgrades

### 6.1 Graph

**Goal:** go from hairball to an instrument, then add cinematic interaction.

**Legibility (do first)**

1. **Type colors + shapes:** host indigo large, user teal medium, software slate small. Red/amber only for risk halos. Update the tooltip and add a legend HUD.
2. **Degree sizing:** `r = clamp(5, 4 + sqrt(degree) * 2.2, 22)`. Hosts get +2.
3. **Labels:** show top 12 by degree at overview zoom; show more as zoom increases; always on hover/selection. Truncate to 18 chars with an ellipsis. Add a dark halo.
4. **Edges:** install edges 0.10 opacity and 1px; user→host 0.22 and 1.5px. On node hover, connected edges go 0.75; everything else dims to 0.04. No global edge glow.
5. **Legend:** bottom-left floating chip row: Host / User / Software / Risk. Collapsible; persists state.

**Navigation**

- Add `d3.zoom` on the SVG: scaleExtent `[0.15, 4]`, wheel zoom, drag pan, double-click zoom.
- Toolbar controls: `+`, `−`, `Fit`, and a zoom-level readout. Keyboard: `+`/`−`, `0` to fit, arrows to pan when the canvas is focused.
- Apply zoom to a root `<g>`; keep node drag working by stopping propagation on node drag start.
- Fit computes the graph bounds with 40px padding.

**Focus mode**

- Click a node: do **not** replace the graph. Select it, show a right-side selection card (type, name, team/platform, degree, risk, actions: Focus, Blast radius, Path from, Path to).
- Focus: dim non-neighbors to 0.12, keep positions, animate opacity 200ms. `Esc` clears.
- Double-click: load ego network (existing behavior) with a 220ms crossfade; preserve positions of nodes that survive by id.
- Add "Copy ID" and "Open in Blast Radius" actions.

**Entrance + continuity**

- First load: nodes scale 0→1 with a 6ms stagger capped at 600ms; links fade in after 250ms; labels fade last.
- Re-renders (search, expand, filter): do not replay the full entrance. Crossfade old/new over 180ms; carry `x/y/fx/fy` by id so the layout does not explode.
- Simulation: `alphaDecay(0.035)`, `velocityDecay(0.65)`, `distanceMax(500)`, link strength 0.2. Stop on `alpha < 0.02`.
- Pause the simulation when the Graph tab is hidden.

**Pathfinder**

- Keep the marching dashes, add a **signal packet**: a glowing dot travels the full route over 1.2s; hop badges appear in sequence.
- HUD: "3 hops · Host → Software → Host", with Replay, Step, and Clear.
- Start/end nodes pulse once (not forever). `Esc` cancels.
- Reduced motion: static route + hop badges, no packet.

**Clusters**

- Preserve positions; animate hulls via `attrTween` (or fade/scale if morphing is unstable). Cluster labels count up.
- Toggling off returns to the force layout with a 400ms transition, not a re-render flash.

**Performance**

- Keep the 800-node cap. Budget: 60fps drag at ≤400 nodes, ≥30fps at 800.
- If the budget fails, move links to a `<canvas>` layer behind the SVG nodes. This is a fallback, not the first implementation.
- Add `?debug=1` FPS/JS-heap HUD for QA; remove from normal UI.

### 6.2 Blast Radius

**Goal:** show what was reached, not an abstract score shape.

**New default: Impact Cascade**

```text
                 platform arcs (windows / darwin / linux)
              ╭──────────────────────────────────╮
           ╭──┤        impacted users (ring 2)    ├──╮
        ╭──┤   │      impacted hosts (ring 1)      │   ├──╮
        │  │   │            ● seed                │   │  │
        │  │   │       (software / user)          │   │  │
        │  ╰───┤                                  ├───╯  │
        ╰──────╰──────────────────────────────────╯──────╯
                 dashed halo: 2nd-degree count
```

- **Center:** the seed (software or user) with a type icon and name.
- **Ring 1:** directly impacted hosts, up to 24 nodes; `+N more` chip. Spokes from seed; draw-in via dashoffset.
- **Ring 2:** impacted users, up to 24; spokes from seed to users (the API gives both sets, not the host↔user mapping, so do not invent host→user edges).
- **Outer arcs:** platform spread as labeled arc segments; count = distinct platforms. Do not draw fake proportions; segment count maps to platforms.
- **Dashed halo:** lateral movement (2nd-degree hosts) shown as a numeric halo + label, because the API returns a count, not names. Truthful and still dramatic.
- **Details panel:** right side, not an overlay on top of the chart. Hosts/users/teams/platforms lists, truncated to 50 with "+N more". Keep the existing info block and recommendation.
- **Metrics:** four cards above, count-up + a thin proportion bar (`value / denominator`) under each. Denominators come from `scope.totals`; platform diversity caps at 3.
- **Motion:** on seed select — center scales in 200ms, rings expand 600ms, ring 1 nodes 30ms stagger, ring 2 nodes 25ms, arcs draw 500ms, counts 500ms. On re-select, crossfade 120ms and rebuild; do not leave stale nodes.
- **Radar:** keep behind a small toggle "Cascade / Radar" for analysts who prefer the shape. Default cascade.
- **Empty/zero:** ghost rings + "No reach in this scope" if all counts are zero. Never an empty white card.

**Responsive:** at <1100px, details move below the chart; at <768px, the cascade becomes a compact 320px chart and the lists are accordions.

### 6.3 Shadow IT

**Goal:** triage in one glance, then work the table.

**Triage header (replaces the six equal cards)**

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ 182                    ◔ severity donut           Detection mix           │
│ detections             high 18 · med 44 · low 120  outlier 96 · high 18 · sprawl 68 │
│ 2 hosts · 9 users                                  ███████████░░░░░      │
└──────────────────────────────────────────────────────────────────────────┘
```

- Donut: SVG, 3 segments, 160px, animated `stroke-dashoffset` 700ms; center total; legend with counts.
- Detection mix: horizontal stacked bar; widths animate from 0; hover shows exact counts; labels remain visible for accessibility.
- Keep affected hosts/users as compact stat blocks, not two more equal cards.
- If zero detections: shield/hound illustration + "Clean sweep in this scope" + Clear filters.

**Table**

- Keep the filter row and sticky header.
- Add a 2px left border on rows by risk; keep the text badge as the primary signal.
- Row entrance: first 12 rows fade/translate 4px with 12ms stagger on load/filter; no stagger for 182 rows.
- Hover: background change 120ms; no lift on rows.
- Row click → modal; `Enter` on a focused row opens it.
- Add a "Sort: Risk / Hosts / Name" control above the table. Default risk.
- Export remains; success toast instead of the status div.

**Modal**

- Backdrop blur + panel rise; focus trap; restore focus; scroll lock.
- Risk section uses the same donut colors; recommendation box stays.
- "Authorize Software" gets a confirmation toast and refreshes the table with a row exit animation.

### 6.4 Extensions

**Goal:** make extension risk spatial, not just a list.

**Risk matrix**

- X axis: prevalence bins (1, 2, 3–5, 6–10, 11+ hosts), log-ish spacing.
- Y axis: risk bands (critical, high, medium, low, unassessed).
- Dot size: affected hosts (sqrt scale); dot color: risk band; deterministic jitter inside bins to avoid overlap.
- Hover/focus: tooltip with name, risk score, hosts, top signal.
- Click: opens the existing extension details modal.
- Matrix dots animate in with a 20ms stagger (cap 80 dots); axes draw first.
- Empty: "No extensions in this scope."

**Header**

- Four compact metrics: critical, high, affected hosts, total scored.
- The matrix sits beside/below them in a full-width card 220–280px tall.
- Keep the existing filter sidebar; wire matrix clicks to the risk filter where appropriate (clicking a risk band sets the risk filter; clicking a dot opens details).

**Table/modal**

- Same row/modal polish as Shadow IT.
- Signal chips keep their `good/warn/bad` semantics, but add an icon/dot so color is not the only cue.
- The "Refresh intel" button shows a progress state and a toast on completion.

### 6.5 Changes

**Goal:** make snapshots a timeline, not a file picker.

**Snapshot timeline**

- Full-width card above the diff: last 30 snapshots on a time x-axis.
- Line/area of total nodes (hosts + users + software) from snapshot meta; `+`/`−` ticks.
- Latest point highlighted; hover tooltip: timestamp, hosts/users/software/edges.
- Click a point sets **To**; Shift+click sets **From**. The two selects remain for accessibility and precision. A hint line explains the shortcut.
- Selected range is shaded between handles.
- If fewer than 2 snapshots: "Snapshots appear after the next ETL run."

**Delta ribbon**

- After computing a diff: `+ added`, `− removed`, `~ changed` in three large cells, each with a sparkline of counts by type (hosts/users/software/edges).
- Count-ups 500ms; sections stagger 60ms.
- Keep the existing filter bar and grouped lists.
- Add "Swap" and "Latest pair" buttons.
- Long lists: keep the 200-item cap; add "Load more" rather than dumping thousands of rows.

**Empty/error**

- No snapshots: illustration + explanation.
- Diff failed: inline error card with the HTTP status and Retry; no silent "Diff failed."

---

## 7. Component and micro-interaction specs

### Topbar

- Height 52px desktop, 48px mobile. Mark + wordmark left; tabs center-left; actions right.
- Sticky; backdrop blur only when the graph scrolls beneath it (optional). At rest, solid `--bg-secondary`.
- Tabs: 13px, 500 weight, 8px horizontal padding; active underline is a 2px indigo bar that slides 240ms. Focus ring 2px offset.
- Wordmark click → Overview.
- Add `theme-color` meta for dark/light.

### Theme toggle

- Sun/moon icon crossfade + 180° rotation over 240ms.
- 220ms background crossfade. If `document.startViewTransition` exists, use a 360ms circle reveal from the button; progressive enhancement only. Reduced motion: instant.
- Persist in `localStorage`; apply **before first paint** with an inline head script to prevent a light-theme flash.

### Buttons

- Height 30px default, 26px small, 44px touch.
- Hover: background/border 140ms; no glow on secondary buttons.
- Active: `translateY(1px) scale(0.99)` 90ms.
- Primary: solid accent; text white; contrast checked in both themes.
- Ghost: text secondary → primary on hover; used for toolbar actions.
- Loading: inline 12px spinner or label "Running…"; disable + `aria-busy`.

### Inputs/selects

- 32px height; 6px radius; 1px border; focus ring `0 0 0 3px var(--accent-soft)`.
- Search gets a `/` shortcut to focus; show a subtle `⌘K` hint only if a command palette is added later.
- No placeholder-as-label for forms; dashboard filters may keep placeholders because their column headers label them.

### Metric cards

- Label 10px mono uppercase, value 30–40px tabular, subtitle 12px muted.
- Animated count-up; one border flash on update.
- Hover lift only if the card is clickable. Static metrics stay still.
- No card shadow; use hairline + inset highlight.

### Tables

- 13px body; 11px uppercase header; sticky header; 40px row height.
- Hover background 120ms. Selected row gets an accent left border.
- Risk stripe: 2px left border, color by risk; text badge still present.
- Skeleton rows: 5 rows of pulsing bars, not "Loading...".
- Horizontal scroll container at <900px; first column sticky.

### Modals

- Overlay `rgba(0,0,0,.62)` + `backdrop-filter: blur(6px)`; panel max-width 640px (or 720 for details), 90vw, max-height 84dvh.
- Header sticky within the panel; close button 32px; Esc; click outside; focus trap; `aria-modal="true"`; restore focus.
- Motion as §4.3. Content sections stagger 40ms on open (cap 6).

### Toasts

- Bottom-right stack; 320–400px wide; surface elevated; 1px border; severity icon; message; optional action; progress line.
- Max 3; auto-dismiss 4s (errors 8s or manual); pause on hover/focus; `aria-live="polite"`.
- Replace `showStatus` calls over time; keep a compatibility shim during migration.

### Skeletons

- Show after 150ms to avoid flash.
- Shapes match the final layout: metric bars, table rows, chart rings.
- Shimmer 1.4s linear; reduced motion → static 0.4 opacity pulse or no pulse.
- Never replace a chart with a spinner.

### Empty states

- Geometric SVG (hound/shield/radar) in accent-muted linework, 96–140px.
- Title + one sentence + one action. No emoji. No dead ends.
- Examples: no detections, no extensions, no snapshots, no search results, DB disconnected.

### Tooltips

- One floating HTML tooltip layer for graph/hero/matrix, not `<title>` (slow, inaccessible).
- 120ms open delay, 80ms close; follow pointer with 12px offset; flip at viewport edges.
- Keyboard focus shows the tooltip anchored to the element.
- `role="tooltip"`; trigger has `aria-describedby`.

### Boot screen

- Only after 250ms of loading. Mark line-draw, wordmark, three status dots (auth → graph → meta).
- Fade out when graph + meta resolve; do not block interaction if only a secondary request is pending.
- If a request fails, show a clear error + Retry instead of spinning forever.

---

## 8. Technical implementation plan

### 8.1 Dependency decision

**No new libraries.** Use:

- D3 v7 (already loaded) for the constellation, cascade, timeline, matrix, zoom.
- CSS transitions/keyframes for UI feedback.
- `requestAnimationFrame` only for the path packet and any canvas fallback.
- Native `Intl.NumberFormat`, `ResizeObserver`, `IntersectionObserver`, `matchMedia`.

No GSAP, no Three.js, no chart library. A dashboard does not need a 3D scene; the graph is already the hero.

### 8.2 Backend changes (small and isolated)

**A. `GET /api/graph/full?sample=<n>`**

- Validate `sample` as an integer 20–300.
- After building nodes/links, rank nodes by degree and keep the top `n`; filter links to surviving nodes.
- Return `sample: true`, `total_nodes`, `total_links` so the UI can label the sample.
- This trims the payload; the Cypher remains unchanged for v1. If p95 >800ms, add a dedicated sample query.

**B. `GET /api/snapshots?limit=<n>`**

- Optional `limit`, default 100, cap 500. Slice newest-first.
- Overview requests 8; Changes requests 60.
- Existing callers without `limit` keep working.

**C. No new overview endpoint in v1**

- The Overview fans out to `/api/meta`, `/api/ooda/status`, `/api/shadow-it`, `/api/extensions`, `/api/snapshots?limit=8`, and `/api/graph/full?sample=120`.
- Cache responses client-side for 60s in `sessionStorage` (except graph), so tab switching is instant.
- If p95 for the fan-out exceeds 1.5s on real fleets, add `/api/overview` with a 30s server cache. Do not build it speculatively.

**D. Tests**

- Add a pure-Python test for the sample trimmer (degree ranking, link filtering, caps).
- Add a test for `limit` validation (0, negative, >500, non-int).
- Run `python3 -m unittest discover -s tests -v`.

### 8.3 File layout

Keep the single-file architecture for v1 to preserve zero-build deploy and no-cache behavior. Add clear section banners:

```text
webviz/static/index.html
  <style>
    /* === TOKENS === */
    /* === MOTION === */
    /* === TOPBAR / BRAND === */
    /* === OVERVIEW === */
    /* === GRAPH === */
    /* === BLAST CASCADE === */
    /* === SHADOW TRIAGE === */
    /* === EXTENSIONS MATRIX === */
    /* === CHANGES TIMELINE === */
    /* === COMPONENTS: toast, modal, skeleton, tooltip === */
  </style>
  <body>
    ... existing ...
    <div id="toast-root"></div>
    <div id="boot-screen">...</div>
    <div id="tooltip-root"></div>
  </body>
  <script>
    /* === MOTION / FORMAT HELPERS === */
    /* === TAB ROUTER (single switchView) === */
    /* === OVERVIEW === */
    /* === GRAPH (existing + upgrades) === */
    /* === BLAST CASCADE === */
    /* === SHADOW / EXTENSIONS / CHANGES === */
    /* === COMPONENT WIRING === */
  </script>
```

If the file grows beyond ~9,000 lines, split CSS/JS as a separate mechanical refactor **after** the feature work, not during it. A split adds cache-busting and regression risk for little user value right now.

### 8.4 JavaScript structure

Add a small namespace so new code does not collide with the existing globals:

```js
window.HOUND = {
  motion: { reduce, countUp, reveal, stagger, cancelAll },
  fmt: { int, compact, relativeTime, percent },
  ui: { toast, skeleton, modal, tooltip, focusTrap },
  overview: { load, render, destroy },
  constellation: { render, update, destroy },
  cascade: { render, update },
  extensionsMatrix: { render },
  changesTimeline: { render },
};
```

Key functions:

- `countUp(el, from, to, opts)` — 500ms, ease-out cubic, `Intl.NumberFormat`, reduced-motion snap, `aria-hidden` on the animated span and `sr-only` final value.
- `revealAll(root, {y, stagger, duration})` — uses `IntersectionObserver`, runs once, respects reduced motion.
- `switchView(name)` — single source of truth: tabs, panels, toolbar, `onEnter`/`onExit`, pause/resume graph, load data lazily.
- `loadOverviewData()` — `Promise.allSettled`, 60s cache, per-card state.
- `renderFleetConstellation(svgEl, data, opts)` — deterministic radial layout, 120-node cap, ResizeObserver, cleanup.
- `renderImpactCascade(svgEl, blastData)` — rings, spokes, arcs, counts; crossfade on re-select.
- `renderExtensionsMatrix(svgEl, extensions)` — bins, jitter, tooltip, click.
- `renderChangesTimeline(svgEl, snapshots)` — time scale, area, ticks, from/to selection.
- `showToast(message, {type, action, duration})` — stack manager.
- `openModal(el, trigger)` / `closeModal(el)` — focus trap, scroll lock, restore.
- `applyTheme(theme)` — pre-paint inline script + transition.

**Compatibility:** keep `showStatus` as a shim that calls `showToast` so existing call sites keep working. Migrate the high-traffic ones first (exports, errors, refresh, OODA), then remove the shim in Phase 5.

### 8.5 Data flow (Overview)

```text
DOMContentLoaded
  └─ applyTheme (pre-paint)
  └─ switchView('overview' | saved last tab)
       └─ overview.load()
            ├─ /api/meta
            ├─ /api/ooda/status
            ├─ /api/shadow-it?team=all
            ├─ /api/extensions
            ├─ /api/snapshots?limit=8
            └─ /api/graph/full?sample=120
                 └─ allSettled → per-card skeleton/error
                      └─ constellation.render + counts + cards
```

- Abort in-flight requests when leaving Overview.
- Poll OODA status only while Overview is active and `document.visibilityState === 'visible'`.
- Do not auto-refresh heavy endpoints; offer a manual refresh or 60s cache.

### 8.6 Performance budgets

| Surface | Budget |
|---|---|
| Boot to Overview content | <1.5s p95 (data local) |
| Overview constellation | 120 nodes / 240 links, 60fps entrance, <80ms per frame |
| Graph drag | 60fps at ≤400 nodes, ≥30fps at 800 |
| Chart animation | ≤900ms, no layout thrash |
| Tab switch | <250ms to interactive |
| Memory | No leaked simulations/intervals after 20 tab switches |
| Fonts | One UI family + one mono, `display=swap` |

- Pause all animation when `document.hidden`.
- Use `ResizeObserver`, never window resize polling.
- Add `?debug=1` FPS meter during QA; not shipped visible.

### 8.7 Accessibility requirements

- Tab list: `role="tablist"`, arrow keys, Home/End, `aria-selected`, `tabindex`.
- Charts: `role="img"` + text summary; interactive nodes are focusable buttons with labels; a visible text alternative (cards/lists) always exists.
- Color is never the only encoding: risk has text badges; node types have shape/size; matrix bands have labels.
- Modals: focus trap, Esc, restore focus, `aria-modal`, background `inert` where supported.
- Toasts: `aria-live="polite"`, not assertive; errors persist longer.
- Reduced motion and reduced transparency paths tested.
- Contrast: WCAG AA for all text, 3:1 for large text and graphical objects; check risk colors in both themes.
- Touch targets 44×44 at ≤900px; no hover-only actions.

### 8.8 Responsive requirements

- Replace all `100vh` with `100dvh`.
- Topbar: tabs horizontally scroll; meta pill hides <1100px; brand compresses to mark.
- Overview: hero stacks at <1100px; constellation 280px; cards 1 column at <768px.
- Graph toolbar: wraps into two rows at <1000px; labels/legend collapse.
- Blast: details below chart at <1100px; cascade 320px tall at <768px.
- Shadow/Extensions/Changes: sidebar becomes a top disclosure panel; tables horizontal scroll; first column sticky.
- Test at 375, 768, 1024, 1440, 1920.

---

## 9. Phased delivery plan

Each phase is independently shippable. The recommended MVP is Phases 0–3.

| Phase | Scope | Estimate | Exit criteria |
|---|---|---:|---|
| **0. Foundation** | Tokens, motion helpers, single tab router, brand mark, favicon, pre-paint theme, icons, toast, modal, skeleton primitives | 4–6h | All existing views still work; tabs route through one function; reduced motion and keyboard pass; no console errors. |
| **1. Overview** | New tab, hero constellation, risk cards, OODA pulse, sample API, snapshots limit, boot screen, responsive | 8–10h | Content <1.5s; hero is truthful; cards deep-link; skeleton/error/zero states; 60fps entrance; mobile stacks. |
| **2. Graph** | Legend, type colors, degree sizing, label decluttering, zoom/pan, focus HUD, entrance, path packet, cluster animation | 8–10h | Hairball gone at 400 nodes; zoom/pan works; labels legible; ≤30fps at 800 with fallback plan; reduced motion static. |
| **3. Blast Cascade** | Impact Cascade, metric bars, details layout, animations, radar toggle | 5–7h | Counts match metrics; 0/1/100+; no label overlap; responsive; reduced motion. |
| **4. Triage** | Shadow donut + mix, Extensions matrix, table/modal polish, filter wiring | 5–7h | Charts respond to filters; dots open details; empty states; 60fps. |
| **5. Changes + QA** | Snapshot timeline, delta ribbon, empty states, light-mode pass, cross-browser/a11y/perf audit, docs | 5–7h | Timeline truthful; diff counts animate; all views pass QA; docs updated. |

**Total:** ~35–47h. **MVP (0–3):** ~25–33h.

If only one visible feature can ship, ship **Phase 0 + Phase 1**. The Overview is the front door and the clearest demonstration of value.

### Implementation order inside each phase

1. Markup + static layout.
2. Data wiring with final-state rendering (no animation).
3. Verify truth, responsiveness, and accessibility.
4. Add motion last, behind reduced-motion checks.
5. Screenshot dark/light + reduced motion before moving on.

This order prevents the common failure where animation is built around placeholder data and breaks when real data arrives.

---

## 10. QA and acceptance

### Functional

- [ ] All six tabs switch, deep-link, and remember the last tab.
- [ ] Existing search, filters, labels, pathfinder, clusters, exports, modals, OODA trigger, CSV export still work.
- [ ] New API params reject invalid values and preserve existing behavior.
- [ ] Overview cards handle loading, success, empty, stale, and error independently.
- [ ] Sample label matches the actual node count.

### Visual

- [ ] Dark and light at 1440×900 and 390×844: no overflow, no clipped labels, no contrast failures.
- [ ] One radius scale, one shadow language, one icon family.
- [ ] No emoji; no default spinner; no "Loading..." text where a skeleton fits.
- [ ] Graph legend present; node types distinguishable without color.
- [ ] All charts have titles, units, and an accessible summary.

### Motion

- [ ] `prefers-reduced-motion` produces the same information with no ambient motion.
- [ ] Rapid tab switching / repeated clicks do not queue or stack animations.
- [ ] Hidden tab stops simulations, polling, and drift.
- [ ] No animation longer than 1.2s without a way to skip/complete.
- [ ] 60fps on a 2020-era laptop for the Overview entrance and Graph drag.

### Accessibility

- [ ] Keyboard-only pass through all views, modals, charts, and toolbars.
- [ ] Focus visible and restored after modals/popovers.
- [ ] Screen reader announces async status but not every count-up frame.
- [ ] Contrast AA in both themes; risk colors pass for text.
- [ ] Touch targets ≥44px at ≤900px.

### Performance

- [ ] Overview data p95 <1.5s; skeleton appears after 150ms.
- [ ] Graph 800-node test does not freeze the tab.
- [ ] No memory growth after 20 tab switches (heap snapshot).
- [ ] Fonts do not cause layout shift >0.05.

### Browser

- [ ] Chrome, Safari, Firefox current.
- [ ] `backdrop-filter` fallback is a solid surface.
- [ ] View Transitions (if used) degrade gracefully.
- [ ] Zoom/pan and SVG charts work with trackpad and mouse.

---

## 11. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Overview duplicates Graph and adds maintenance | Summary only; no filters; every card deep-links to the real view. |
| Motion makes a dense tool feel slow | One hero per view; 120–280ms for UI; 420ms max for cards; pause offscreen. |
| Graph performance collapses at 800 nodes | Keep the cap; measure early; canvas link layer fallback. |
| Single-file becomes unmaintainable | Section banners, namespace, phased commits; split only after features ship. |
| Data lies (sample presented as full) | Explicit sample captions; stale timestamps; no fake scores. |
| Charts exclude keyboard/screen-reader users | Text alternatives, focusable marks, aria summaries, tables remain. |
| API fan-out is slow on large fleets | Client cache, skeleton per card, abort on leave; add `/api/overview` only if measured. |
| Scope creep into a full design system rewrite | Phase gates; no React/component-library migration; keep existing tokens and components. |
| Light mode is neglected | Dedicated light-mode QA in every phase exit criteria. |

---

## 12. Decisions and recommended defaults

These are the choices that need a yes/no before implementation. Recommended defaults are listed first.

1. **Default landing:** Overview on first visit, last-used tab on return. *Recommended.* Alternative: keep Graph as the default and make Overview opt-in.
2. **Blast Radius:** Impact Cascade default, radar toggle retained. *Recommended.* Alternative: keep radar and add the cascade as a secondary panel.
3. **Graph type colors:** host indigo, user teal, software slate, risk as halo. *Recommended.* Alternative: keep host red and risk as a separate ring; less semantically clean.
4. **Scope:** MVP Phases 0–3 first, then 4–5. *Recommended.* Alternative: full plan in one pass.
5. **Mono font:** add JetBrains Mono for data labels. *Recommended.* Alternative: use the existing system mono stack, zero extra request.
6. **Architecture:** keep the single-file `index.html` for v1. *Recommended.* Alternative: split CSS/JS first; safer for long-term maintenance, slower to start.

Two choices that are **not** recommended: 3D/WebGL hero, and auto-playing infinite ambient motion across the app. Both add cost and visual noise without improving the analyst's job.

---

## Appendix A — Overview markup sketch

```html
<div id="overview-view" class="view-container" role="tabpanel" aria-labelledby="tab-overview">
  <div class="overview-scroll">
    <section class="overview-hero" aria-labelledby="overview-headline">
      <div class="overview-hero-copy">
        <p class="eyebrow"><span class="live-dot" aria-hidden="true"></span> Live fleet graph</p>
        <h1 id="overview-headline">See the whole fleet.<br>Find the blast radius.</h1>
        <p class="overview-sub">Hosts, identities, and software in one risk graph — so you can trace exposure before it spreads.</p>
        <div class="overview-actions">
          <button class="btn btn-primary" data-jump="graph">Explore the graph</button>
          <button class="btn btn-secondary" data-jump="shadow-it">Triage findings</button>
        </div>
        <dl class="overview-stats" id="overview-stats">
          <div><dt>Hosts</dt><dd data-stat="hosts">—</dd></div>
          <div><dt>Identities</dt><dd data-stat="users">—</dd></div>
          <div><dt>Software</dt><dd data-stat="software">—</dd></div>
          <div><dt>Open findings</dt><dd data-stat="findings">—</dd></div>
        </dl>
      </div>
      <div class="overview-hero-visual">
        <div id="fleet-constellation" role="img" aria-label="Sampled fleet graph"></div>
        <p class="sample-caption" id="constellation-caption">Sample · —</p>
      </div>
    </section>

    <section class="overview-cards" aria-label="Exposure summary">
      <a class="risk-card" data-jump="shadow-it" href="#shadow-it">…</a>
      <a class="risk-card" data-jump="extensions" href="#extensions">…</a>
      <a class="risk-card" data-jump="changes" href="#changes">…</a>
    </section>

    <section class="ooda-pulse" aria-labelledby="ooda-title">…</section>
  </div>
</div>
```

---

## Appendix B — API shapes

**`GET /api/graph/full?sample=120` (additions)**

```json
{
  "nodes": [{ "id": "host_1", "type": "host", "display_name": "dc01.example", "degree": 42 }],
  "links": [{ "source": "user_a", "target": "host_1", "type": "uses" }],
  "sample": true,
  "total_nodes": 3590,
  "total_links": 22046
}
```

**`GET /api/snapshots?limit=8` (addition)**

```json
[
  { "ts": "2026-10-25T17:24:50.545785Z", "slug": "2026-10-25T172450-545785Z", "hosts": 32, "users": 126, "software": 3432, "edges": 22046 }
]
```

**Existing payloads reused**

- `/api/meta`: `{ hosts, users, software, connected }`
- `/api/ooda/status`: cycle, phases, failures, interval, enabled
- `/api/shadow-it`: `{ detections: [{ risk_level, host_count, affected_users, detection_type, … }] }`
- `/api/extensions`: grouped rows with `risk_band`, `risk_score`, `host_count`, `install_users`
- `/api/blast-radius`: `{ metrics, scores, details: {hosts, users, teams, platforms}, scope: { totals } }`
- `/api/diff`: `{ added: {hosts, users, software, edges}, removed: {...}, changed: [{ id, type, props_changed }] }`

---

## Appendix C — Motion recipes

**Count-up**

```js
function countUp(el, to, { duration = 500, format = (n) => n.toLocaleString() } = {}) {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const from = Number(el.dataset.value || 0);
  el.dataset.value = String(to);
  if (reduce || from === to) { el.textContent = format(to); return; }
  const start = performance.now();
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  (function frame(now) {
    const p = Math.min(1, (now - start) / duration);
    el.textContent = format(Math.round(from + (to - from) * ease(p)));
    if (p < 1) requestAnimationFrame(frame);
  })(start);
}
```

**Constellation layout**

```js
const RING = { software: 0.34, user: 0.56, host: 0.78 };
const GOLDEN = Math.PI * (3 - Math.sqrt(5));

function layout(nodes, width, height) {
  const cx = width / 2, cy = height / 2;
  const R = Math.min(width, height) * 0.44;
  const groups = Object.groupBy(nodes, (n) => n.type);
  for (const [type, list] of Object.entries(groups)) {
    list.sort((a, b) => b.degree - a.degree);
    list.forEach((n, i) => {
      const a = i * GOLDEN;
      const r = R * RING[type] + Math.sin(i * 1.7) * 4;
      n.x = cx + Math.cos(a) * r;
      n.y = cy + Math.sin(a) * r;
    });
  }
}
```

(Use a plain `Map` group loop if `Object.groupBy` support is not guaranteed.)

**Reduced-motion check**

```js
const reduceMotion = () =>
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
```

---

## Appendix D — Copy deck

| Context | Copy |
|---|---|
| Overview eyebrow (fresh) | `LIVE FLEET GRAPH` |
| Overview eyebrow (stale) | `FLEET SNAPSHOT · 17:24Z` |
| Overview headline | `See the whole fleet. Find the blast radius.` |
| Overview sub | `Hosts, identities, and software in one risk graph — so you can trace exposure before it spreads.` |
| Primary CTA | `Explore the graph` |
| Secondary CTA | `Triage findings` |
| Shadow card | `Shadow IT` / `Triage →` |
| Extensions card | `Extensions` / `Review →` |
| Changes card | `Fleet delta` / `Open changes →` |
| OODA rail | `Autonomy pulse` |
| OODA disabled | `Autonomy off — enable OODA_ENABLED to run cycles.` |
| Empty Shadow IT | `Clean sweep in this scope.` / `Clear filters` |
| Empty Extensions | `No extensions in this scope.` / `Clear filters` |
| Empty Changes | `Snapshots appear after the next ETL run.` |
| DB down | `No signal from the graph.` / `Retry` |
| Sample caption | `Sample · 120 of 3,432 nodes · scope: all teams` |
| Toast (export) | `Exported 812 rows to CSV.` |
| Toast (OODA limited) | `Cycle already running — retry in 42s.` |

---

## Appendix E — What not to build

- A 3D globe or WebGL particle hero. The data is a graph; 2D is clearer and cheaper.
- Glassmorphism on every card. It destroys hierarchy and contrast in a dense tool.
- Constant rotating/pulsing elements across the page. One live indicator is enough.
- Confetti, emoji, fake "AI-powered" labels, invented risk scores.
- A command palette, custom cursor, or scroll-jacking. Nice in a portfolio; wrong for a security console.
- A full React/design-system migration disguised as an animation task.
