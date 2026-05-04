## Why

vlair generates Markdown and HTML reports today. Customers in regulated industries (finance, healthcare, government) need PDF reports with consistent typography, page numbering, headers/footers, and an embedded chain-of-custody footer for incident records. Compliance teams attach these PDFs to audit packets; legal teams need them for evidence preservation; managers want them for monthly readouts. Markdown-to-PDF via `pandoc` works locally but isn't reliable across deployment environments and doesn't produce the polished look executives expect. We need first-class PDF as a vlair output format.

## What Changes

- New `vlair report <investigation_id> --format pdf` (alongside existing `markdown` and `html`).
- New `--format pdf` flag for `vlair analyze` and `vlair workflow` commands.
- Webapp: `GET /api/investigations/{id}/report?format=pdf` and an "Export as PDF" button on the investigation result page (and on the timeline view).
- **Report templates**: three report types — `incident-summary` (1-2 pages, executive), `full-investigation` (5-15 pages, technical), and `audit-packet` (full investigation + appendices: timeline, audit log, connector calls). Default per command varies (executive default for `analyze`; full default for `report` from completed investigation).
- **Visual elements**: cover page with investigation id/verdict/score; table of contents; verdict summary callout; risk score gauge (rendered server-side); IOC table; MITRE ATT&CK techniques; timeline (Gantt-style, rendered to PDF); embedded screenshots from analyst notes (when applicable).
- **Chain-of-custody footer**: every page footer carries `Investigation: <id> | Generated: <ISO8601> | By: <user> | vlair v<x.y.z> | Page X of Y`. The hash of the report PDF is recorded in audit log on generation.
- **TLP banner**: cover page and every-page header show the configured TLP color and label, derived from the investigation's classification or the workspace default.
- **Watermarking (optional)**: per-workspace watermark string (e.g., "CONFIDENTIAL — internal only") rendered diagonally across each page at low opacity. Configurable per-workspace.
- **Branding**: organization name, logo (PNG), and accent color configurable per-workspace; defaults to vlair branding when unset.
- **Multi-language (deferred to follow-up)**: v1 is English-only; copy is centralized so localization is feasible later.
- New CLI: `vlair report <id> [--format pdf] [--type incident-summary|full|audit-packet] [--output FILE]`.

## Capabilities

### New Capabilities
- `pdf-report-generation`: PDF export of investigation reports with templated layouts, branding, TLP banners, watermarks, and chain-of-custody.

### Modified Capabilities
- `operationalize`: `vlair analyze` and `vlair workflow` accept `--format pdf`; SPA result pages gain "Export as PDF" buttons.
- `investigation-automation`: investigation results carry a generated-reports manifest tracking which PDFs have been produced and their hashes.

## Non-goals

- Editable PDFs (form fields, fillable). Output is a flat document.
- PDF to vlair input. We export, don't import.
- Per-section custom templates (e.g., let customers write their own LaTeX). Three fixed templates with branding overlay only.
- HTML→PDF via headless Chrome (rejected: heavyweight, deployment complexity). v1 uses a Python-native renderer.
- Real-time co-editing of report drafts. Reports are generated artifacts.
- Compliance-framework-specific formats (NIST 800-61, ISO 27035 IR templates). Tracked as future capability.
- Multi-language reports in v1.

## Impact

- **Code**: new `src/vlair/reporting/pdf/` package (`renderer.py`, `templates/`, `branding.py`); modifications to `cli/main.py` (new subcommand + flag), `webapp/app.py` (new endpoint + button); `core/report_generator.py` extended with PDF dispatcher.
- **Schema**: new `generated_reports` table tracking each generated PDF (hash, size, generated_at, generated_by, format, type, investigation_id).
- **Dependencies**: `reportlab>=4.0` for PDF rendering (preferred — Python-native, no system dependencies, robust for tabular and structured documents). Alternative: `weasyprint` (uses Cairo + GTK — adds system deps; rejected for the same reason as headless Chrome).
- **Tests**: snapshot tests of generated PDFs (text extraction + layout heuristics); per-template smoke tests; chain-of-custody footer assertion test.
- **Docs**: new `docs/REPORTS.md` covering all three report formats; `docs/BRANDING.md` for workspace customization; sample PDFs checked in to `docs/samples/`.
