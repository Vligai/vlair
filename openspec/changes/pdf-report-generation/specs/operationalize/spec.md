## ADDED Requirements

### Requirement: SPA Export as PDF buttons

The investigation result page SHALL expose two export buttons: "Export as PDF" (produces full-investigation by default) and "Export Audit Packet" (produces audit-packet). Both SHALL trigger async generation via the webapp endpoint and notify the user on completion.

#### Scenario: Export full PDF from SPA
- **WHEN** an analyst clicks "Export as PDF" on a completed investigation
- **THEN** a generation job is submitted; the page shows "Generating..." with estimated time; on completion, a download dialog opens for the PDF; the audit log records the user-initiated generation

### Requirement: PDF as analyze/workflow output format

`vlair analyze` and `vlair workflow` console outputs SHALL accept `--format pdf` (in addition to existing `console` / `json` / `markdown` formats). The PDF SHALL be the incident-summary template by default; the existing console output SHALL still be printed for shell users.

#### Scenario: Multi-format output
- **WHEN** an analyst runs `vlair analyze x.eml --format pdf,json`
- **THEN** both a PDF and a JSON file are produced; the console also displays the human-readable summary

### Requirement: Branding configuration UI

The SPA admin settings SHALL provide a "Branding" section where admins upload a logo, set the organization name, accent color, watermark text (optional), and page size. Changes SHALL apply to subsequent PDF generations across the workspace.

#### Scenario: Logo upload
- **WHEN** an admin uploads a 600×600 PNG (under 500KB)
- **THEN** the upload succeeds; the next generated PDF uses the new logo on cover and headers

#### Scenario: Logo size limit enforced
- **WHEN** an admin attempts to upload a 2MB PNG
- **THEN** the upload is rejected with `error: logo must be ≤ 500KB`; the previous logo (if any) remains active
