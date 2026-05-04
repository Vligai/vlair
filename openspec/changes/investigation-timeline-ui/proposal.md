## Why

Investigation results today render as a flat list of step cards in the SPA. As playbooks grow longer (10+ steps for phishing) and once approval pauses introduce non-linear flow, that list stops conveying the investigation's actual shape: when each step started, how long it took, what blocked what, where the analyst's intervention was required. Analysts handing off an investigation to a colleague (shift change, escalation) need to see the timeline at a glance. Auditors reviewing an incident need to reconstruct what happened in what order. A timeline view solves both.

## What Changes

- **Timeline data model**: every investigation step gains `started_at`, `completed_at`, `duration_ms`, `triggered_by` (manual / automatic / approval), and explicit `depends_on` (list of step ids that must complete before this step starts). The engine populates these on existing playbooks.
- **Timeline endpoint**: `GET /api/investigations/{id}/timeline` returns the full timeline as a structured DTO with steps, dependencies, approvals, connector calls, and analyst notes.
- **SPA timeline view**: replaces the current step list with a horizontal Gantt-style timeline. Each step is a bar; bar color reflects step status (success/failure/paused/skipped); bar width reflects duration; arrows show `depends_on` edges; approval pauses are visually distinct.
- **Step detail drawer**: clicking a step opens a side drawer with the full step result, connector calls made during the step, audit log rows, and (when applicable) the related approval.
- **Analyst notes on timeline**: analysts can pin a note at any point on the timeline (with timestamp + author). Notes render as flags on the timeline. This supports handoffs between analysts and post-incident review.
- **Connector call sub-timeline**: each step expands to show the connector calls it made (vendor, operation, latency, outcome). Useful for debugging slow investigations and for SOC2 evidence.
- **Filters**: filter timeline by step status, by connector vendor, by approval state, and by minimum duration (e.g., "show me steps that took > 30s").
- **Comparison view (deferred)**: compare two investigations of the same playbook side-by-side. Tracked as a follow-up; v1 focuses on single-investigation timeline.
- **Export**: PNG export of the timeline view (for incident reports), via SVG-to-PNG client-side. JSON export already exists via the API.
- New CLI command: `vlair investigate timeline <id> [--ascii]` renders the timeline as a console-friendly ASCII Gantt for terminal users.

## Capabilities

### New Capabilities
- `investigation-timeline`: timeline data model, API, SPA visualization, analyst notes, connector sub-timeline, filters, ASCII renderer.

### Modified Capabilities
- `investigation-automation`: steps gain timing fields and explicit dependency declarations; engine populates them.
- `operationalize`: investigation result page in the SPA replaces the flat step list with the timeline view.

## Non-goals

- Real-time live-updating timelines (websocket-driven). v1 polls every 5s when an investigation is in progress.
- Timeline editing (analysts cannot reorder or delete completed steps). Timeline reflects what happened; it is not a planning tool.
- Cross-investigation timeline (showing all of an analyst's investigations on one timeline). Tracked as future capability.
- Custom timeline themes / per-user color preferences. Single accessible color palette.
- Automated post-incident report generation from timeline. Out of scope; PDF report (separate change) consumes the timeline data.

## Impact

- **Code**: modifications to `investigate/models.py` (timing fields), `investigate/engine.py` (populate timing + deps), `webapp/app.py` (new endpoint), `webapp/static/spa/` (timeline component, replaces step list); new `cli/main.py` subcommand.
- **Schema**: `investigation_steps` gains `started_at`, `completed_at`, `duration_ms`, `triggered_by`, `depends_on` columns; new `investigation_notes` table for analyst notes.
- **Dependencies**: `vis-timeline` or `apexcharts` (Gantt-style) for the SPA. Decision in design doc; pre-existing Chart.js does not handle Gantt cleanly.
- **Tests**: timeline endpoint schema test; ASCII renderer test (snapshot-based); SPA component tests for step rendering, drawer behavior, note pinning.
- **Docs**: update `docs/INVESTIGATION.md` with timeline usage; new screenshots in `docs/SCREENSHOTS/` for the timeline view.
