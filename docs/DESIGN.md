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

## Layout

- Three-column shell on desktop widths: directory tree (280px), main pane (fluid), approval
  rail (320px, collapsible). Below 1100px the rail becomes a sheet; below 800px the tree becomes
  a drawer.
- Screen padding 20px; card gap 12–16px.
- Dense tables for holdings and history; 36px rows; sticky headers.

## Signing and approval screens

- The decoded intent is the headline, in ink. Asset deltas as a two-column ledger (out / in).
- Destination line shows allowlist status and first-seen date. Unknown destinations carry a
  `--sw-faint` "first seen now" label; denylisted ones carry `--sw-danger`.
- Policy headroom bars are neutral; the only colored element on the screen is the destructive
  confirm when the intent is irreversible and the destination is unknown.
- Ceremony progress is a row of party chips (online, committed, signed), never a spinner alone.
