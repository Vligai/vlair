## ADDED Requirements

### Requirement: Investigation result includes generated reports manifest

Investigation results SHALL include a `generated_reports` field listing every PDF/HTML/Markdown report that has been produced for that investigation, with `{type, format, generated_at, generated_by, sha256_hash, file_path_or_url}`. The SPA result page SHALL display the list with download links.

#### Scenario: Manifest visible
- **WHEN** an investigation has had two PDFs (incident-summary and audit-packet) generated
- **THEN** the result page displays "Generated reports (2): incident-summary.pdf | audit-packet.pdf" with download links and timestamps

### Requirement: Cascading delete of reports

When an investigation is deleted, the system SHALL cascade-delete all rows in `generated_reports` for that investigation AND remove the underlying PDF files from storage. A `--keep-reports` flag SHALL be supported on the delete operation for legal-hold scenarios; with this flag, the files persist and the rows are marked `investigation_deleted: true` rather than deleted.

#### Scenario: Default cascade delete
- **WHEN** an admin deletes an investigation that has 3 generated PDFs
- **THEN** all 3 files are removed from storage; the `generated_reports` rows are deleted; an audit row records the cascade

#### Scenario: Legal hold preserves PDFs
- **WHEN** an admin runs `vlair investigate delete INV-... --keep-reports --reason "legal hold ticket #..."`
- **THEN** the investigation row is removed but the 3 PDF files remain on disk; their `generated_reports` rows persist with `investigation_deleted=true`; an audit row records the legal-hold preservation
