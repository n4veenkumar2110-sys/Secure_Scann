# SecureScan design system

Design rules for the SecureScan interface. Written before the 2026-11 redesign and used as the
acceptance checklist for it.

## Sources

| Skill | Used for |
|---|---|
| [pbakaus/impeccable](https://github.com/pbakaus/impeccable) (Apache-2.0) | Primary rule set: **Operate mode** (dashboards and admin tools), the craft-floor "Refuse" list, typography, color, layout, motion, UX writing and audit checks. Its CLI, hooks and telemetry were not installed; its rules are applied by hand. |
| [anthropics/skills · frontend-design](https://github.com/anthropics/skills/tree/main/skills/frontend-design) (Apache-2.0) | Process: plan palette, type roles and principles before building; spend boldness in one place; critique with screenshots. |
| [nextlevelbuilder/ui-ux-pro-max-skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) (MIT) | One rule only: SVG icons, never emoji. Its cybersecurity preset (neon green on black) was rejected as the stereotype to avoid. |

## The product and the scene

An analyst audits one Windows workstation and investigates what the audit, the packet capture and
the disk analysis found. Sessions are long, at a desk, and the same screens are projected for a
course demonstration. Mode: **Operate**. Scanability, consistency and native expectations
outrank expression.

## Principles

1. **Evidence first.** Every screen leads with the data the analyst acts on. Chrome is quiet.
2. **One severity language everywhere.** Severity is always shape, color *and* word together.
   This is the single signature element of the interface.
3. **Structure from alignment, not boxes.** Hairlines, spacing and type hierarchy group content.
   Borders surround only tables, the graph canvas and forms.
4. **Say what happened and what to do.** Sentence case, specific verbs, no marketing voice.

## Severity marks (signature)

| Severity | Mark | Meaning |
|---|---|---|
| Critical | filled diamond | act now |
| High | filled triangle | investigate today |
| Medium | filled circle | review |
| Low | open circle | note |
| Informational | short bar | context only |

Shapes keep severity readable for color-blind users and in grayscale prints of the report.

## Typography

* **IBM Plex Sans** for the interface. It was drawn for technical enterprise software, has clear
  tabular figures and is not the generic Inter default.
* **IBM Plex Mono** only for data: timestamps, IPs, ports, hashes, paths, command lines,
  evidence references. Never as decoration.
* Fixed role scale (px): 12 meta · 13 table and dense UI · 14 body · 16 section title ·
  20 page title · 32 key figure. Line height 1.45 for text, 1.2 for headings.
* `font-variant-numeric: tabular-nums` on every number column.
* No all-caps labels, no tracked-out eyebrows above headings.

## Color (OKLCH, defined as tokens in `style.css`)

| Role | Light | Dark |
|---|---|---|
| Canvas | `oklch(0.975 0.004 255)` | `oklch(0.17 0.012 260)` |
| Surface | `oklch(0.995 0.002 255)` | `oklch(0.205 0.013 260)` |
| Sunken (table header, code) | `oklch(0.955 0.005 255)` | `oklch(0.235 0.014 260)` |
| Hairline | `oklch(0.905 0.007 255)` | `oklch(0.3 0.014 260)` |
| Ink / secondary / tertiary | `0.23 / 0.42 / 0.55` lightness | `0.94 / 0.76 / 0.62` |
| Accent (action, focus, selection) | `oklch(0.47 0.12 255)` evidence blue | `oklch(0.74 0.11 250)` |
| Critical · High · Medium · Low · Info | red 27° · orange 45° · amber 80° · green 165° · slate | lighter, same hues |

The accent is rare: primary buttons, focus rings, the selected row and the selected nav item.
Light and dark themes are designed separately and follow the operating system unless the user
chooses one in Settings. Contrast is at least 4.5:1 for text and 3:1 for marks and focus rings.

## Layout

* Sidebar 232 px, top bar 56 px, content max 1400 px with 32 px gutters (16 px on phones).
* 4 px spacing base: 4 · 8 · 12 · 16 · 24 · 32 · 48.
* Tables: 36 px rows, sticky header, left-aligned text, right-aligned numbers.
* Event details open in a **side panel** (no interruption needed). Modals only for file import
  and destructive confirmation.

## Motion

150 ms color and border feedback; 200 ms side panel and dialog entrance, faster exit; easing
`cubic-bezier(0.16, 1, 0.3, 1)`. No count-up numbers, scroll reveals, parallax, glows or
pulsing dots. `prefers-reduced-motion` removes movement and keeps the state change.

## Refused (from Impeccable's craft floor and the frontend-design tells)

Emoji or Unicode glyphs as icons · gradient text · glass/blur · glow halos · one-sided colored
stripes on boxes · identical stat-card grids as page structure · eyebrow kickers · all-caps
labels · monospace as costume · decorative charts · count-up animation · modal for reading.

## UX writing

* Buttons are verb + object: "Run audit", "Start capture", "Import Windows log", "Clear demo data".
* Errors say what failed and how to recover. Empty states say why it is empty and offer the action.
* The same thing has the same name on every screen ("evidence", "detection", "event").
