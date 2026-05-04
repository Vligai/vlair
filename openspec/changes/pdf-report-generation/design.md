## Context

vlair has Markdown and HTML reports already (`core/report_generator.py`). They serve technical users fine. The gap is the artifact compliance and executive audiences expect: a polished PDF with consistent layout, page numbering, headers/footers, and a defensible chain-of-custody trail. Today, customers convert Markdown → PDF themselves with `pandoc` or print-to-PDF in their browser; both are inconsistent and don't carry workspace branding.

## Goals / Non-Goals

**Goals:**
- A single command produces a polished PDF that's ready to attach to an incident ticket or audit packet.
- Three layout types covering executive, technical, and audit needs without per-customer template work.
- Branding (logo, name, accent color) configurable per-workspace so different tenants in a multi-tenant deployment get their own look.
- Every page carries chain-of-custody footer; the report's SHA-256 is recorded in audit log for evidence integrity.
- Server-side rendering only — no browser dependency, no JS toolchain.

**Non-Goals:**
- Editable / fillable PDFs.
- Per-customer template editor.
- PDF-as-input (importing structured data from PDFs).
- Compliance-framework-specific layouts (NIST IR, ISO 27035 IR Annex). Future capability.
- Multi-language. v1 is English-only with centralized copy.

## Decisions

### D1. ReportLab as the rendering engine

`reportlab` is mature, Python-native, has no system dependencies, and produces high-quality PDFs. It supports flowables (paragraphs, tables, images), templates, page numbering via `canvas.beginText`, and SVG embedding via `svglib`. The free version is sufficient for our layouts.

**Alternatives considered:**
- **WeasyPrint** (HTML+CSS → PDF): nicer authoring experience but requires Cairo, Pango, GTK system libraries. On Windows it's a known pain to install, and on Linux containers it bloats the image. Rejected.
- **Headless Chrome via Playwright/Puppeteer**: highest fidelity to HTML, but requires Chromium in the deployment image (~150MB+) and careful resource management for concurrent renders. Rejected for v1.
- **`pandoc` shell-out**: depends on TeX-Live or wkhtmltopdf; system dependencies again. Rejected.
- **`fpdf2`**: lightweight but missing flowables and table layout features we need. Rejected.

### D2. Three templates, fixed layouts

Three fixed templates rather than a templating engine:

1. **incident-summary** (1-2 pages): cover page with verdict callout + risk gauge; one-paragraph executive summary; key findings (3-5 bullets); top IOCs (max 10).
2. **full-investigation** (5-15 pages): cover; TOC; executive summary; verdict + risk + AI summary; full IOC list with source attribution; MITRE ATT&CK heatmap; timeline (Gantt); recommendations.
3. **audit-packet** (15-50+ pages): everything in full-investigation + appendices: full audit log, full connector-call log, chain-of-custody affidavit page, signed metadata.

Branding (logo, name, accent color) is overlay configuration applied to all three.

**Alternatives considered:** Custom template engine (Jinja2-style) (rejected: customers would write fragile templates that break on schema changes; we'd own bug reports). Single template with togglable sections (rejected: doesn't satisfy "1-page executive" cleanly; layout decisions per template are too different).

### D3. Per-workspace branding configuration

Stored in `workspaces` (or for single-tenant, in `~/.vlair/branding.json`). Fields: `organization_name`, `logo_path` (PNG, max 500KB), `accent_color` (hex), `tlp_default`, `watermark_text` (optional). Branding is applied at render time via overlay.

**Alternatives considered:** Per-investigation branding override (rejected: investigations belong to workspaces; branding is a workspace concept). Hard-code vlair branding only (rejected: customers want their own look).

### D4. TLP banner is automatic

Every page renders a colored TLP banner across the top: green/amber/amber+strict/red, derived from the investigation's TLP. The TLP is set automatically from the verdict score (same mapping as the threat-platform-integration TheHive case) but can be overridden per investigation in the SPA.

**Alternatives considered:** Optional TLP banner (rejected: defaults matter; TLP is the right default for security artifacts; can be hidden via `--no-tlp` for non-security audiences).

### D5. Chain-of-custody footer mandatory

Every page footer carries: `Investigation: <id> | Generated: <ISO8601 UTC> | By: <user> | vlair v<x.y.z> | SHA-256 of this PDF (preview): <first 16 hex chars> | Page X of Y`.

The PDF hash is computed after rendering, then a second pass updates the footer with the actual hash. This is a known reportlab pattern (canvas pre-pass for layout, post-pass for metadata).

**Alternatives considered:** Optional chain-of-custody (rejected: the whole point of producing PDFs is evidentiary; footer is non-optional). Append a separate signature page (rejected: footer carries the same info more accessibly; signature page is in the audit-packet template specifically).

### D6. Watermark optional, per-workspace

When `watermark_text` is set, a low-opacity (15%) gray text rotated 45° spans each page diagonally. Not selectable in the resulting PDF (it's a path, not text). Useful for "CONFIDENTIAL", "DRAFT", or customer-specific markers.

**Alternatives considered:** Watermark per-investigation (rejected: scope creep; workspace-level is the right granularity).

### D7. Server-side gauge and chart rendering

Risk score gauge and small distribution charts render with `matplotlib` (already a transitive dep) to PNG, then embed in the PDF as images. Timeline (Gantt) renders to SVG via `svgwrite` and embeds via `svglib + reportlab`. This avoids any JS execution.

The Gantt rendered for PDF is a simplified version of the SPA timeline: same visual language but without interactive elements (no drawer, no filters; the PDF is read-only by nature).

### D8. Generated reports tracked in a table

`generated_reports(id, investigation_id, type, format, generated_at, generated_by, file_size, sha256_hash, file_path)` records every generation. Used for: deduplication (re-generating an unchanged investigation returns the cached PDF), audit (who generated what when), evidence integrity (hash chain).

The PDF binary is not stored in the database. Instead, the file path points to a workspace-scoped storage location (`~/.vlair/reports/<workspace>/<investigation>/<sha256>.pdf` for local; configurable storage backend for cloud deployments — defer to multi-tenant-workspaces).

**Alternatives considered:** Store PDF in DB as BLOB (rejected: bloats the DB; backup/restore complications). Generate fresh every time (rejected: large reports take seconds; caching with hash-based dedup is fast).

### D9. Default report type by entry point

| Command | Default report type |
|---------|---------------------|
| `vlair analyze --format pdf` | incident-summary |
| `vlair workflow --format pdf` | incident-summary |
| `vlair report <id>` (completed investigation) | full-investigation |
| `vlair report <id> --type audit-packet` | audit-packet (explicit) |
| SPA "Export as PDF" button | full-investigation |
| SPA "Export Audit Packet" button | audit-packet |

Operators choose explicitly via `--type` when they want non-default behavior.

### D10. Page size and language

Default page size: US Letter (8.5"×11"). Configurable per-workspace to A4 (210×297mm). All copy is loaded from a centralized `messages.py` module so a future i18n pass is straightforward.

## Risks / Trade-offs

- [Risk] PDF generation is slow for large audit packets. → Mitigation: hash-based caching of generated reports; async generation via webapp's existing background-task queue with notification on completion; UI shows "Generating..." with estimated time.
- [Risk] Embedded images blow up file size. → Mitigation: max logo size 500KB enforced; charts rendered at 150 DPI (sufficient for screen + print); audit log table images compressed.
- [Risk] Logo upload becomes an attack surface (malicious PNG / decompression bombs). → Mitigation: PIL validates the PNG, max dimensions 1000×1000, max file size 500KB; uploaded via authenticated SPA endpoint only.
- [Risk] ReportLab licensing — its Open Source license is GPL with permissive exception for our use; we should confirm. → Mitigation: vendor a copy of the license in `docs/licenses/`; the open-source ReportLab license suits our redistribution model.
- [Risk] PDF accessibility (screen readers). → Mitigation: ReportLab supports tagged PDF (PDF/UA); v1 produces tagged structure for the executive summary and IOC table at minimum.
- [Risk] TLP banner colors may render differently across PDF viewers. → Mitigation: use specific Pantone-equivalent RGB values documented by FIRST; visual regression test against renders from Adobe Reader, Preview, and Chrome PDF viewer.
- [Trade-off] Three fixed templates limit flexibility. We're betting customers want polished defaults more than a customizable template editor; the audit-packet template is the safety valve for "I need everything in one PDF."

## Migration Plan

1. Land `reporting/pdf/renderer.py` core with all three templates rendering against a fixture investigation. No CLI/API hookup yet.
2. Land `generated_reports` table and dedup logic.
3. Land branding configuration (single-tenant defaults; multi-tenant integration deferred to multi-tenant-workspaces follow-up).
4. Hook up CLI: `vlair report <id> --format pdf`, plus `--format pdf` on `analyze` / `workflow`.
5. Hook up webapp endpoint and SPA buttons.
6. Async generation for audit-packet (large), inline for incident-summary (small).
7. Documentation: `docs/REPORTS.md`, `docs/BRANDING.md`, sample PDFs in `docs/samples/`.

**Rollback:** Keep Markdown and HTML formats as primary; PDF is additive. Removing the feature is a no-op for existing reports. The `generated_reports` table can be dropped without affecting investigations.

## Open Questions

- Should we offer optional digital signing (X.509 / PKI) of generated PDFs for legal evidentiary use? (Recommendation: defer; chain-of-custody footer + audit log hash is sufficient for v1; signing is a follow-up gated by customer demand.)
- Should the audit-packet template include the AI summary's input prompt + provider for full reproducibility? (Recommendation: yes — appendix lists AI provider, model, and prompt hash.)
- What happens to PDFs when an investigation is deleted? (Recommendation: cascade-delete generated PDFs and their `generated_reports` rows; add `--keep-reports` flag for legal-hold scenarios where PDFs must outlive the investigation.)
- Should we allow custom cover-page text per investigation (e.g., "Prepared for [stakeholder]")? (Recommendation: yes — single optional `cover_addressee` field; defaults to organization name from branding.)
