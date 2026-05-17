# Source Prompt: `Ojuri_Architecture_vX.X.docx` Generation

> **Status:** Living document. This file *is* the prompt/procedure used to
> regenerate the polished Word submission deliverable from
> [ARCHITECTURE.md](./ARCHITECTURE.md).
> **Last updated:** 2026-05-17

---

## Purpose

`ARCHITECTURE.md` is the **single source of truth**. The submission artefact is
a polished `.docx` (currently `Ojuri_Architecture_v1.2.docx`, historical
versions preserved alongside it). This document specifies, precisely enough to
be repeatable by a human or an agent, how to convert the markdown into that
`.docx`. The conversion is **mechanical and deterministic**: never hand-edit the
`.docx` for content — fix `ARCHITECTURE.md` and regenerate, or the source of
truth drifts from the deliverable.

The prompt to hand an agent is, verbatim:

> *"Convert `docs/architecture/ARCHITECTURE.md` to
> `docs/architecture/Ojuri_Architecture_v<NEXT>.docx` following the style,
> layout, and workflow specified in `docs/architecture/SOURCE_PROMPT.md`. Do not
> alter technical content. Insert the cover page, revision history (from
> DECISIONS.md), and a generated table of contents. Render a PDF sanity copy
> and report any layout breakage."*

---

## Style guide

- **Cover page:** project title (*Ojuri*), subtitle (*Capability-Constrained
  Forensic Reasoning — Architecture*), document version, submission deadline,
  classification line, author/team.
- **Section numbering:** `§N` for top-level headings, `§N.M` for subsections —
  matching the numbering already present in `ARCHITECTURE.md`.
- **Pseudocode / code blocks:** Consolas 9 pt, light-grey background
  (`#F2F2F2`), no syntax colouring (print-safe), single-cell bordered table or
  styled paragraph.
- **Tables:** header row in a dark fill (`#1F3864`) with white bold text;
  alternating body rows in light grey (`#F2F2F2`) for legibility; thin borders.
- **Backend / aside notes:** italic, ~1 pt smaller than body, grey (`#595959`).
- **Page footer:** `Ojuri Architecture v<version>` (left) · page number
  (right).
- **Page header:** `Ojuri` (left) · current top-level section title (right).
- **ASCII diagram (§4):** keep monospace; render in the code-block style so the
  five-layer box diagram stays aligned. (If a vector redraw is desired later,
  produce it as an image and replace the block — but the markdown stays ASCII.)

---

## Layout specifications

- **Page size:** A4 (210 × 297 mm).
- **Margins:** 25 mm top/bottom, 22 mm left/right.
- **Body font:** Inter (fallback Calibri), 11 pt, 1.15 line spacing.
- **Headings:** Inter Bold — H1 20 pt, H2 16 pt, H3 13 pt.
- **Tables/code:** as in the style guide.
- **TOC:** generated, 2 levels deep, after the cover and revision history.

---

## Workflow

Primary path is **pandoc** (the docx skill is not available on SIFT — confirmed
2026-05-17; if a `/mnt/skills/public/docx` skill exists on another host, it may
substitute for steps 1–2):

1. **Generate the base document:**
   ```bash
   pandoc docs/architecture/ARCHITECTURE.md \
     --from gfm \
     --reference-doc docs/architecture/templates/reference.docx \
     --toc --toc-depth=2 \
     -o docs/architecture/Ojuri_Architecture_v<NEXT>.docx
   ```
   `reference.docx` carries the styles in the style guide (create once; commit
   under `docs/architecture/templates/`).
2. **Apply the reference style template** — handled by `--reference-doc`; verify
   heading, code, and table styles took effect.
3. **Insert the cover page** from `docs/architecture/templates/cover.docx`
   (title, subtitle, version, submission deadline, classification). Prepend, do
   not let pandoc generate it.
4. **Insert the revision history table** built from
   [DECISIONS.md](./DECISIONS.md): one row per dated decision
   (date · title · related commit). Place immediately after the cover.
5. **Insert the generated TOC** (pandoc `--toc`) after the revision history.
6. **Verify in LibreOffice** (`soffice`), then render a PDF sanity copy:
   ```bash
   soffice --headless --convert-to pdf docs/architecture/Ojuri_Architecture_v<NEXT>.docx
   ```
   Check: ASCII §4 diagram alignment, table fills, code-block backgrounds,
   header/footer, no orphaned headings, TOC page numbers correct.
7. **Do not commit** the regenerated `.docx` without review; the human reviews
   layout before it becomes the submission artefact.

---

## Versioning

- `v1.0`, `v1.1`, `v1.2` are **historical** snapshots — preserved as separate
  `.docx` files under `docs/architecture/`, never overwritten.
- Next generations: `v1.3` onward, incrementing per submission-relevant
  regeneration.
- `ARCHITECTURE.md` is the source of truth; each `.docx` is a *snapshot* of it
  at a point in time. The markdown's own header carries `v0.1` for the markdown
  source line — that is independent of the `.docx` version sequence.
- Record each regeneration as a one-line entry in [DECISIONS.md](./DECISIONS.md)
  only if the regeneration accompanied a design change; pure re-renders do not
  need a decision entry.

---

*Living document — keep this procedure in sync with whatever tool actually
produces the submission `.docx`.*
