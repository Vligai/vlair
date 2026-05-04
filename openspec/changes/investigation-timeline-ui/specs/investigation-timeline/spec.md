## ADDED Requirements

### Requirement: Timeline data endpoint

The webapp SHALL expose `GET /api/investigations/{id}/timeline` returning a structured DTO containing the investigation's steps (with timing and dependencies), connector calls per step, approvals, and analyst notes. The endpoint SHALL require at least the `viewer` role and SHALL respect investigation-level visibility.

#### Scenario: Successful timeline fetch
- **WHEN** an analyst with access to investigation INV-... GETs the timeline endpoint
- **THEN** the response is 200 with `{steps: [...], connector_calls: [...], approvals: [...], notes: [...], dependencies: [{from, to}, ...]}`

#### Scenario: Investigation in progress
- **WHEN** the investigation is still running
- **THEN** the response includes steps with `completed_at: null` and the timeline can be progressively rendered as polling continues

### Requirement: Step timing fields

Every investigation step SHALL carry `started_at`, `completed_at`, `duration_ms`, and `triggered_by` (`automatic` / `approval` / `manual`). The engine SHALL populate `started_at` when execution begins and `completed_at + duration_ms` when execution ends. Steps that paused for approval SHALL have `started_at` from the original execution attempt and `completed_at` from the post-approval re-run; `duration_ms` excludes the pause window.

#### Scenario: Approval pause excluded from duration
- **WHEN** a step starts at T0, pauses for approval, is approved at T0+1h, and completes execution by T0+1h+5s
- **THEN** `started_at=T0`, `completed_at=T0+1h+5s`, `duration_ms=5000` (the active execution time, excluding the 1h pause)

### Requirement: Step dependencies

Each step SHALL declare `depends_on: list[str]` referencing prior step ids. The engine SHALL populate this from playbook definitions. The timeline SHALL render dependencies as arrows from prerequisite to dependent.

#### Scenario: Parallel-eligible steps shown as such
- **WHEN** a playbook declares step B depends on A and step C also depends only on A
- **THEN** the timeline shows B and C with no arrow between them; both have an arrow from A; this visualizes their parallel-eligibility even when executed sequentially

### Requirement: SPA timeline view

The SPA investigation result page SHALL render a Gantt-style timeline as the default view, with: bars for steps colored by status, dependency arrows, approval flags inline on the relevant step, and analyst notes pinned to timestamps. A "List view" toggle SHALL preserve the legacy flat list for users who prefer it.

#### Scenario: Default view is timeline
- **WHEN** an analyst opens an investigation result page
- **THEN** the timeline renders by default with steps, dependencies, and any pinned notes; the "List view" toggle is visible in the upper right

#### Scenario: Status colors accessible
- **WHEN** the timeline renders steps with mixed statuses
- **THEN** colors meet WCAG AA contrast against the bar text; status is also encoded by an icon (not color alone) to satisfy color-blind users

### Requirement: Step detail drawer

Clicking a step in the timeline SHALL open a side drawer showing the full step result, the connector calls made during the step (vendor, operation, latency, outcome), audit log rows scoped to the step, and (when applicable) the related approval id with a link.

#### Scenario: Connector calls visible per step
- **WHEN** the analyst clicks a step that made 3 connector calls
- **THEN** the drawer lists each call with vendor + operation + latency_ms + outcome; the analyst can click each to expand request/response (with credentials redacted)

### Requirement: Connector call sub-timeline

When a step is expanded in the timeline, its bar SHALL split to show child bars for each connector call, indented under the step. Each child bar's width represents the call's latency.

#### Scenario: Slow step diagnosis
- **WHEN** an analyst sees a step that took 45s and clicks expand
- **THEN** the timeline shows three connector-call sub-bars summing to ~44s, with one specific call obviously dominating; the analyst clicks that call to see its details

### Requirement: Analyst notes pinned to timestamps

The system SHALL allow analysts (role: `analyst` and above) to pin notes at any timestamp within an investigation's timeline. Notes SHALL carry `at_timestamp`, `author`, `text` (markdown), and `created_at`. Notes SHALL render as flags on the timeline.

#### Scenario: Pin and render note
- **WHEN** an analyst clicks the timeline at 14:23:45, types "Possible second campaign starting here", and saves
- **THEN** a flag appears at 14:23:45 with the note text; hovering shows the author and creation time

#### Scenario: Note visibility respects role
- **WHEN** a `viewer` opens an investigation with notes
- **THEN** notes are visible read-only; the pin-new-note interaction is hidden

### Requirement: Filters applied client-side

The SPA SHALL provide filters for: step status (success/failure/paused/skipped), connector vendor, approval state (any/pending/approved/denied), and minimum step duration. Filters SHALL apply client-side without re-fetching from the server.

#### Scenario: Filter to slow steps
- **WHEN** an analyst sets the duration filter to "≥ 10s"
- **THEN** only steps with `duration_ms >= 10000` render; the others are hidden but the dependency arrows update to skip past hidden steps where appropriate

### Requirement: PNG export

The SPA SHALL provide a "Export as PNG" button that converts the current timeline view (with active filters) to a PNG image and triggers a download named `<investigation_id>-timeline.png`. Conversion SHALL happen client-side at 2x dimensions for clarity.

#### Scenario: Export button produces image
- **WHEN** an analyst clicks Export as PNG with two notes pinned and a duration filter active
- **THEN** the downloaded PNG matches the on-screen rendering including the notes and the filtered step set

### Requirement: ASCII timeline CLI

The CLI SHALL expose `vlair investigate timeline <id> [--ascii]`. The `--ascii` flag SHALL render a fixed-width-character Gantt to stdout. Without `--ascii`, the command SHALL print a structured summary suitable for further piping to JSON tools.

#### Scenario: ASCII Gantt
- **WHEN** an operator runs `vlair investigate timeline INV-... --ascii`
- **THEN** stdout contains a header line with investigation id and status, a time-scale ruler, and one row per step with a bar showing relative duration

#### Scenario: JSON output
- **WHEN** the operator runs `vlair investigate timeline INV-... --json`
- **THEN** stdout contains the same DTO returned by the timeline API endpoint

### Requirement: Polling cadence

While the investigation is in a non-terminal state, the SPA SHALL poll the timeline endpoint every 5 seconds. Polling SHALL stop when the investigation reaches a terminal state.

#### Scenario: Polling stops on completion
- **WHEN** an in-progress investigation transitions to `COMPLETED`
- **THEN** the SPA detects the terminal state on the next poll, stops further polling, and renders the final timeline
