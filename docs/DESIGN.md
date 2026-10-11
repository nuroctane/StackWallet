# StackWallet — Night glass design system

Derived from the StarSleep night glass system and the blackboard material. Quiet, monochrome,
instrument-grade. Money UI should feel like a cockpit at night: legible, calm, nothing thrashes.

## Product feel

- **Stark black, white/gray glass, hairline edges.** Depth comes from material, not color.
- **Red is a signal, not a theme.** `--sw-danger` appears only on destructive actions, policy
  denials, audit-chain breaks and ceremony failures.
- **No blue, indigo or purple chrome.** Chart series use a neutral ramp plus one warm accent for
  the selected series.
- **Numbers are instruments.** Tabular figures, monospace, right-aligned in tables, provenance
  visible on hover.

## Tokens (CSS custom properties, defined in `packages/ui/src/theme.css`)

| Token              | Value                             | Role                                                                |
| ------------------ | --------------------------------- | ------------------------------------------------------------------- |
| `--sw-paper`       | `#050505`                         | Page background                                                     |
| `--sw-surface`     | `#141414`                         | Panels                                                              |
| `--sw-elevated`    | `#1b1b1b`                         | Cards on panels, menus                                              |
| `--sw-ink`         | `#f2f2f2`                         | Primary text                                                        |
| `--sw-muted`       | `#a0a0a0`                         | Secondary text                                                      |
| `--sw-faint`       | `#777777`                         | Labels, tertiary                                                    |
| `--sw-edge`        | `rgb(255 255 255 / 12%)`          | Hairline borders                                                    |
| `--sw-edge-strong` | `rgb(255 255 255 / 30%)`          | Focus ring, selected edge                                           |
| `--sw-sheen`       | `rgb(255 255 255 / 9%)`           | Glass top specular                                                  |
| `--sw-hover`       | `rgb(255 255 255 / 7%)`           | Hover fill                                                          |
| `--sw-danger`      | `#ff453a`                         | Destructive, denial, failure                                        |
| `--sw-danger-soft` | `rgb(255 69 58 / 22%)`            | Danger glass                                                        |
| `--sw-warm`        | `#e2c27b`                         | Single warm accent (selected chart series, pending approvals count) |
| `--sw-ok`          | `#d8d8d8`                         | Success (neutral)                                                   |
| `--sw-radius`      | `12px`                            | Panels and cards                                                    |
| `--sw-radius-sm`   | `6px`                             | Inputs, chips                                                       |
| `--sw-ease`        | `cubic-bezier(0.23, 1, 0.32, 1)`  | Enter, press release, state                                         |
| `--sw-ease-morph`  | `cubic-bezier(0.77, 0, 0.175, 1)` | On-screen morph                                                     |
| `--sw-ease-drawer` | `cubic-bezier(0.32, 0.72, 0, 1)`  | Sheets and drawers                                                  |

## Themes

Night glass is the default and the reference for every rule in this document. The theme engine
(`packages/ui/src/theme`) lets the user replace it:

- **Presets**: night glass plus the 41 NurCLI palettes (evaluated from `nur-cli/src/theme.rs`,
  so chromatic and paper studies match the CLI). Nur roles map onto ours: `bg → paper`,
  `surface → surface`, `surface_2 → elevated`, `fg/muted/faint → ink/muted/faint`,
  `nur_gold → warm` (the accent), `md_h2/md_h3 → accent-2/accent-3`, `success → ok`,
  `error → danger`. Translucent roles (edge, hover, sheen, grid) are derived from the ink at
  night glass strengths; chart and terrain ramps run from the panel colour toward the ink.
- **Tokens**: every colour role in the table above plus `grid`, `accent-2`, `accent-3`,
  `chart-1..4` and `terrain-0..4` is editable with a full-spectrum picker (HSV field, hue and
  opacity rails, hex, platform eyedropper). Stored as canonical `#rrggbb[aa]`.
- **Scope**: one global theme; any layout may carry its own (preset + overrides) or follow the
  global one. The active layout's theme is painted on the document root as both
  `--color-*` and `--sw-*`, and canvases repaint on `useThemeEpoch()`.
- **Guards**: the studio shows live contrast for text (4.5:1) and labels/signals (3:1) and warns
  below the floor. `danger` keeps its meaning whatever hue it is given. Themes export and
  import as `{ stackwalletTheme: 1, name, tokens }` JSON.

## Typography

- Interface: `'JetBrains Mono', ui-monospace, monospace`, 13px / 1.5 base. Bundled locally; no
  remote fonts (D8).
- Display titles: 600 weight, slight negative tracking.
- All numbers: `font-variant-numeric: tabular-nums`.

## Materials

1. **Glass panel**: `--sw-surface` fill, 1px `--sw-edge` border, inset top highlight using
   `--sw-sheen`, `backdrop-filter: blur(18px)` where the platform allows.
2. **Elevated card**: `--sw-elevated`, same edge, no blur.
3. **Reduced transparency** (`prefers-reduced-transparency`): solid fills, no blur.

## Motion

| Interaction           | Duration  |
| --------------------- | --------- |
| Press scale (0.97)    | 100–160ms |
| Chips, small UI       | 125–200ms |
| Cards, sections enter | 150–250ms |
| Sheets, drawers       | 200–400ms |
| Hard cap for UI       | 300ms     |

Rules: every pressable scales to 0.97 on press; never animate from `scale(0)` (enter at 0.95 +
opacity 0); ease-out for UI, never ease-in on controls; only animate `transform` and `opacity`;
respect `prefers-reduced-motion` (keep opacity/color, drop travel); stagger lists 30–80ms; no
animation on high-frequency actions; hover lift only on `(hover: hover) and (pointer: fine)`.

## Workspace

The shell is a terminal workspace, not a page. Chrome is minimal and fixed; content lives in
floating elements on an infinite dark canvas.

- **Top bar (40px)**: wordmark · layout lock · search (`/`) · `elements ▾` · core status.
- **Layout tabs (24px)**: saved layouts as chips, kebab for rename / duplicate / export / delete,
  `+` for a new one. `Ctrl+1..9` switches.
- **Canvas**: `--sw-paper` with a 32px grid at 3% white. Elements are free-floating, draggable by
  their title row, resizable on eight handles, snapping to an 8px grid and to each other's edges
  (6px tolerance). Double-click empty canvas to add an element there. Locked layouts ignore
  gestures. Gestures write transforms directly; the store updates on release.
- **Status bar** stays at the bottom; the **tray** (bottom-right pill) holds approvals and
  activity and persists across layouts.
- Below 800px the canvas becomes a single scrolling column of the same elements.

### Element anatomy

- Title row 28px: `>` glyph · lowercase title · scope chips (`+N` overflow) · optional toolbar ·
  right icons (settings, fullscreen, close). Chips carrying a selection or a total use `--sw-warm`
  at 14% with a warm hairline; everything else is colourless.
- Body hugs the frame: no outer padding, hairline separators, 12px internal padding at most.
- Settings live in an anchored popover of `label ⓘ: [control]` rows (≤ 8 rows). Complex
  elements may use a drawer with vertical tabs.
- Every element is a serialisable `{kind, props}` record; "copy element config" and layout export
  produce JSON that pastes anywhere.

### Density and tables

- Dense tables are virtualised above ~50 rows. Row heights: 21px tight, 24px normal, 32px loose;
  28px sticky header in 10px uppercase tracking `--sw-faint`.
- Address cells: middle-truncated mono, copy on hover, optional filter funnel. Two-line cells
  pair a value with dimmed context.
- Live rows prepend and flash in three tiers (`data-age` 0/1/2 → warm at 18% / 10% / 4%),
  decaying by age bucket, background only. Live tables carry a pause control.
- Loading: KPI cells show `··`; a pane shows the word `loading` with a 10px ring. No shimmer.

### Charts

- Canvas, DPR ≤ 2, redraw only on data or size change. Right-hand y-axis, faint dotted
  vertical gridlines, last value as a pill on the axis.
- Hover: dotted vertical crosshair, timestamp chip grown from the x-axis, dashed horizontal with
  the value pinned to the right axis. No floating tooltip card.
- Series colours: gray ramp (`#d8d8d8 → #555555`), `--sw-warm` for the selected or custom series,
  `--sw-danger` only for a falling or failing series. Up is neutral; down is red.
- The activity terrain is an isometric extrusion (0.9/0.5 projection, three shaded faces) in the
  gray ramp with today and the hovered cell in `--sw-warm`.

## Signing and approval screens

- The decoded intent is the headline, in ink. Asset deltas as a two-column ledger (out / in).
- Destination line shows allowlist status and first-seen date. Unknown destinations carry a
  `--sw-faint` "first seen now" label; denylisted ones carry `--sw-danger`.
- Policy headroom bars are neutral; the only colored element on the screen is the destructive
  confirm when the intent is irreversible and the destination is unknown.
- Ceremony progress is a row of party chips (online, committed, signed), never a spinner alone.
