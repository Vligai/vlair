## 1. Dependencies and packaging

- [ ] 1.1 Add `reportlab>=4.0` and `svglib>=1.5` to `pyproject.toml` under a new `[pdf]` extra
- [ ] 1.2 Vendor the ReportLab license in `docs/licenses/reportlab-LICENSE`
- [ ] 1.3 Document install path in `docs/REPORTS.md`: `pip install vlair[pdf]`

## 2. Renderer core

- [ ] 2.1 `src/vlair/reporting/pdf/renderer.py` with `PDFRenderer` class wrapping reportlab
- [ ] 2.2 Common header/footer machinery: TLP banner, chain-of-custody footer with two-pass hash
- [ ] 2.3 Branding overlay: logo, org name, accent color, watermark
- [ ] 2.4 Page-size config (US Letter / A4)
- [ ] 2.5 Tagged PDF (PDF/UA) structure for accessibility
- [ ] 2.6 Tests: header/footer rendering; page numbering; hash matches file SHA-256

## 3. Templates

- [ ] 3.1 `templates/incident_summary.py` (1-2 pages)
- [ ] 3.2 `templates/full_investigation.py` (5-15 pages)
- [ ] 3.3 `templates/audit_packet.py` (full + appendices)
- [ ] 3.4 Risk gauge as matplotlib PNG at 150 DPI
- [ ] 3.5 IOC table with source attribution column
- [ ] 3.6 MITRE ATT&CK heatmap rendering
- [ ] 3.7 Timeline (Gantt) rendered to SVG and embedded
- [ ] 3.8 Tests: snapshot per template against fixture investigation

## 4. Branding configuration

- [ ] 4.1 `branding.py` loads from workspace config (single-tenant: `~/.vlair/branding.json`)
- [ ] 4.2 PNG validation: PIL parse, size limits, dimension limits
- [ ] 4.3 SPA settings page section for branding
- [ ] 4.4 Tests: malformed PNG rejected; oversized rejected; default vlair branding when unset

## 5. Schema and dedup

- [ ] 5.1 Migration: create `generated_reports` table with index on `(investigation_id, type, format)`
- [ ] 5.2 Storage layout: `~/.vlair/reports/<workspace>/<investigation>/<sha256>.pdf`
- [ ] 5.3 Dedup logic: skip render when matching row exists and investigation_updated_at < generated_at
- [ ] 5.4 Cascading delete with `--keep-reports` legal-hold path
- [ ] 5.5 Tests: dedup hits cache; investigation update invalidates cache; legal-hold preserves files

## 6. Async generation

- [ ] 6.1 Reuse webapp's existing background-task queue (`webapp/tasks.py`)
- [ ] 6.2 Sync inline for `incident-summary`; async for `full-investigation` and `audit-packet`
- [ ] 6.3 `GET /api/reports/{job_id}` for completion polling
- [ ] 6.4 Per-user notification on completion (in-page toast)
- [ ] 6.5 Tests: sync path returns PDF bytes; async path returns 202 + job_id; polling reaches `done`

## 7. CLI

- [ ] 7.1 New `vlair report <id> --format pdf [--type ...] [--output FILE] [--addressee ...]`
- [ ] 7.2 `--format pdf` flag added to `vlair analyze`
- [ ] 7.3 `--format pdf` flag added to `vlair workflow`
- [ ] 7.4 Multi-format output: `--format pdf,json,markdown`
- [ ] 7.5 Tests: each command produces expected files; exit codes; SHA-256 in audit log

## 8. Webapp endpoints

- [ ] 8.1 `GET /api/investigations/{id}/report?format=pdf&type=...`
- [ ] 8.2 `GET /api/reports/{job_id}` for async retrieval
- [ ] 8.3 `POST /api/branding/logo` for logo upload (admin)
- [ ] 8.4 SPA "Export as PDF" and "Export Audit Packet" buttons on investigation result page
- [ ] 8.5 SPA "Generated reports" list rendered with the investigation result
- [ ] 8.6 Tests: role gating; async polling; logo upload validation

## 9. Investigation engine integration

- [ ] 9.1 Investigation result includes `generated_reports` manifest
- [ ] 9.2 Cascading delete + `--keep-reports` flag in `vlair investigate delete`
- [ ] 9.3 Tests: manifest reflects all generations; delete cascades; legal-hold preserves

## 10. Documentation

- [ ] 10.1 New `docs/REPORTS.md` covering all three templates with screenshots
- [ ] 10.2 New `docs/BRANDING.md` for workspace customization
- [ ] 10.3 Sample PDFs checked in to `docs/samples/incident-summary.pdf`, `full-investigation.pdf`, `audit-packet.pdf`
- [ ] 10.4 Update `docs/INDEX.md` with `vlair report` and `--format pdf` flags
- [ ] 10.5 SOC2 / ISO mapping note in `docs/SECURITY.md` covering chain-of-custody footer and audit hash recording
