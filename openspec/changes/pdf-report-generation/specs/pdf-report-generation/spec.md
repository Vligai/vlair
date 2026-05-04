## ADDED Requirements

### Requirement: Three PDF report templates

The system SHALL provide three PDF report templates: `incident-summary` (1-2 pages, executive audience), `full-investigation` (5-15 pages, technical audience), and `audit-packet` (full investigation plus appendices for compliance/audit). Templates SHALL share a common renderer and overlay system; only the layout and section selection differ.

#### Scenario: Incident-summary single page minimum
- **WHEN** an investigation with verdict "Suspicious" score 65, three IOCs, and a one-paragraph summary is rendered as `incident-summary`
- **THEN** the PDF is one page (or two when content overflows): cover-style header, verdict callout, risk gauge, executive paragraph, top-3 IOCs as a small table

#### Scenario: Audit-packet full appendices
- **WHEN** the same investigation is rendered as `audit-packet`
- **THEN** the PDF includes: cover, TOC, executive summary, full IOC list, MITRE heatmap, timeline, full audit log table, full connector-call log table, AI provider/model/prompt-hash appendix, chain-of-custody affidavit page

### Requirement: Chain-of-custody footer mandatory

Every page footer SHALL render: investigation id, generation timestamp (ISO8601 UTC), generating user, vlair version, first 16 hex characters of the PDF SHA-256, and `Page X of Y`. The hash SHALL be computed after rendering and the footer updated in a second pass so the displayed hash matches the actual file hash.

#### Scenario: Footer present on all pages
- **WHEN** a 10-page report is generated
- **THEN** every page (including cover) carries the chain-of-custody footer; the displayed hash prefix matches the SHA-256 of the resulting PDF file

#### Scenario: Hash recorded in audit log
- **WHEN** any PDF is generated
- **THEN** an audit row is written with `action="report.generated"`, the format, type, investigation_id, the full SHA-256, and the requesting user

### Requirement: TLP banner on every page

Every page SHALL render a colored TLP banner across the top edge with the appropriate label (`TLP:CLEAR` / `TLP:GREEN` / `TLP:AMBER` / `TLP:AMBER+STRICT` / `TLP:RED`) and FIRST-published color. The TLP SHALL derive automatically from the verdict score; a per-investigation override SHALL be respected when set.

#### Scenario: Score-derived TLP
- **WHEN** an investigation with score 85 is rendered as PDF
- **THEN** the TLP banner shows `TLP:AMBER` per the documented mapping; the banner color matches the FIRST-published RGB

#### Scenario: Override via SPA
- **WHEN** an analyst manually sets the investigation's TLP to `TLP:RED` and re-generates
- **THEN** the banner shows `TLP:RED`; the original score-derived TLP is recorded in the audit log

### Requirement: Per-workspace branding

Branding (organization name, logo, accent color, watermark text, page size) SHALL be configurable per-workspace and applied as an overlay to all three templates. The logo SHALL be a PNG (max 500KB, max 1000×1000 pixels). When unset, vlair branding SHALL be used.

#### Scenario: Custom logo on cover
- **WHEN** a workspace configures `logo_path` to a 400×400 PNG
- **THEN** the cover page renders the logo top-right at consistent size; subsequent pages render a smaller version in the header

#### Scenario: Page size configurable
- **WHEN** a workspace configures `page_size: "A4"`
- **THEN** generated PDFs are A4 (210×297mm) instead of the US Letter default; layouts adapt to the page width

### Requirement: Optional watermark

When workspace configuration sets `watermark_text` (non-empty), the rendered PDF SHALL display the text diagonally across each page at low opacity (15%) and 45° rotation. The watermark SHALL be rendered as a path (not selectable text) so it cannot be removed by copying out of the PDF.

#### Scenario: Watermark applied
- **WHEN** `watermark_text="CONFIDENTIAL"` is configured and a report is generated
- **THEN** every page (including cover and appendices) shows "CONFIDENTIAL" rotated 45° at 15% opacity; the watermark is not selectable in any PDF reader

### Requirement: Generated reports tracked and deduplicated

The system SHALL maintain a `generated_reports(id, investigation_id, type, format, generated_at, generated_by, file_size, sha256_hash, file_path)` table. When a re-generation request matches an existing report by `(investigation_id, type, format)` AND the investigation has not been modified since the last generation, the system SHALL return the cached PDF instead of re-rendering.

#### Scenario: Cached PDF on re-generation
- **WHEN** an analyst generates a full-investigation PDF, then immediately requests the same report again
- **THEN** the second request returns the cached PDF (response time < 100ms); no re-rendering occurs; the audit row records `cached: true`

#### Scenario: Cache invalidated by investigation change
- **WHEN** an investigation is updated (e.g., a new note added) after a PDF was generated
- **THEN** a re-generation request renders fresh; the previous cached PDF row remains in `generated_reports` for evidentiary continuity but is not returned for new requests

### Requirement: Async generation for large reports

The webapp SHALL render `incident-summary` synchronously (response is the PDF bytes). For `full-investigation` and `audit-packet`, the response SHALL be 202 Accepted with a generation job id; the SPA SHALL poll for completion and notify the user; the PDF SHALL be retrievable via `GET /api/reports/{job_id}` when ready.

#### Scenario: Sync inline for small report
- **WHEN** an analyst requests `incident-summary` PDF via the SPA
- **THEN** the browser receives the PDF inline within 5 seconds for typical investigations

#### Scenario: Async with progress for large report
- **WHEN** an analyst requests `audit-packet` for a large investigation
- **THEN** the SPA shows a generating-spinner with estimated time; on completion, a download button appears and the user is notified (in-page toast)

### Requirement: CLI report command

The CLI SHALL expose `vlair report <investigation_id> --format pdf [--type incident-summary|full|audit-packet] [--output FILE]`. When `--output` is omitted, the PDF SHALL be written to `<investigation_id>-<type>.pdf` in the current directory.

#### Scenario: CLI generates audit packet
- **WHEN** an analyst runs `vlair report INV-2026-05-04-XXXX --format pdf --type audit-packet --output /tmp/x.pdf`
- **THEN** the audit-packet PDF is written to `/tmp/x.pdf`; the file's SHA-256 is recorded in the audit log; exit code is 0

### Requirement: Format flag on analyze and workflow

`vlair analyze` and `vlair workflow` SHALL accept `--format pdf` to produce an inline incident-summary PDF in addition to the existing console/JSON output. The default report type for these commands SHALL be `incident-summary`; an explicit `--report-type` flag SHALL override.

#### Scenario: analyze produces PDF
- **WHEN** an analyst runs `vlair analyze suspicious.eml --format pdf`
- **THEN** the analysis runs and an `incident-summary.pdf` is produced in the current directory alongside the existing console output

### Requirement: Cover addressee customization

Each PDF generation SHALL accept an optional `cover_addressee` field (string). When set, the cover page SHALL render "Prepared for: <addressee>" beneath the title. When unset, the addressee line is omitted (not blank-padded).

#### Scenario: Addressee shown
- **WHEN** an analyst generates an incident-summary with `--addressee "Acme Corp Security Team"`
- **THEN** the cover page shows "Prepared for: Acme Corp Security Team" beneath the report title

### Requirement: Tagged PDF for accessibility

Generated PDFs SHALL include a tagged structure (PDF/UA) for at minimum the executive summary, IOC tables, and recommendations sections. Screen readers SHALL be able to navigate these sections via the document outline.

#### Scenario: Screen reader navigates structure
- **WHEN** a screen-reader user opens a generated PDF
- **THEN** the document outline announces "Executive Summary", "Indicators of Compromise", "Recommendations" as navigable headings; tables announce row/column structure
