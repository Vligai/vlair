## 1. Schema and model

- [ ] 1.1 Migration adds `started_at`, `completed_at`, `duration_ms`, `triggered_by`, `depends_on` to `investigation_steps`
- [ ] 1.2 Migration creates `investigation_notes` table with `(id, investigation_id, at_timestamp, author, text, created_at)` and index on `investigation_id`
- [ ] 1.3 Audit log gains `step_id` column for connector-call attribution
- [ ] 1.4 Tests: migrations idempotent; backfill leaves existing rows queryable

## 2. Engine timing instrumentation

- [ ] 2.1 Wrap step execution with start/end timestamps; persist on completion
- [ ] 2.2 Active-duration computation excludes approval pause windows
- [ ] 2.3 `triggered_by` set per execution path (`automatic` / `approval` / `manual`)
- [ ] 2.4 Tests: timing fields populated; pause excluded; manual resume tagged

## 3. Playbook dependency declarations

- [ ] 3.1 `BasePlaybook` accepts `depends_on` per step
- [ ] 3.2 Update phishing playbook with explicit dependencies
- [ ] 3.3 Update malware-triage, ioc-hunt, network-forensics, log-investigation playbooks
- [ ] 3.4 Tests: dependencies serialized into step rows; cyclic-dependency detector at playbook load

## 4. Timeline endpoint

- [ ] 4.1 `GET /api/investigations/{id}/timeline` returns the structured DTO
- [ ] 4.2 DTO includes steps, dependencies, connector_calls, approvals, notes
- [ ] 4.3 Role check: at least `viewer`; investigation visibility respected
- [ ] 4.4 Tests: schema; in-progress vs terminal; permission denials

## 5. Notes endpoint

- [ ] 5.1 `POST /api/investigations/{id}/notes` (analyst+); `GET /api/investigations/{id}/notes` (viewer+); `DELETE /api/investigations/{id}/notes/{note_id}` (author or senior_analyst)
- [ ] 5.2 Markdown sanitization (no script tags, no event handlers)
- [ ] 5.3 Tests: role gating; sanitization; ordering by `at_timestamp`

## 6. SPA timeline component

- [ ] 6.1 Add vis-timeline as a vendored dependency (lazy-loaded only on result page)
- [ ] 6.2 Timeline component: bars for steps, status colors, dependency arrows
- [ ] 6.3 Approval flags inline with relevant step
- [ ] 6.4 Note flags pinned to timestamps
- [ ] 6.5 Step detail drawer with connector call list
- [ ] 6.6 Connector call sub-bars on step expand
- [ ] 6.7 Filters (status, vendor, approval state, min duration) — client-side
- [ ] 6.8 Polling at 5s while in-progress
- [ ] 6.9 Tests: component snapshot; filter behavior; drawer interactions

## 7. SPA list view toggle and persistence

- [ ] 7.1 "Timeline / List view" toggle in header
- [ ] 7.2 Persist preference in localStorage; honor on page load
- [ ] 7.3 List view preserves the existing flat-list rendering unchanged
- [ ] 7.4 Tests: toggle persists; cross-session preference respected

## 8. PNG export

- [ ] 8.1 Export button in timeline header
- [ ] 8.2 Client-side SVG-to-canvas-to-PNG at 2x dimensions
- [ ] 8.3 Filename format `<investigation_id>-timeline.png`
- [ ] 8.4 Tests: export produces a non-empty PNG; respects active filters

## 9. CLI timeline command

- [ ] 9.1 `vlair investigate timeline <id> [--ascii] [--json]`
- [ ] 9.2 ASCII Gantt renderer with proportional bars and time-scale ruler
- [ ] 9.3 JSON output mirrors the API DTO
- [ ] 9.4 Tests: snapshot test for ASCII rendering; JSON schema validation

## 10. Investigation list updates

- [ ] 10.1 Show total + active duration in the list rows
- [ ] 10.2 Deep-link to specific step via `?step=<step_id>`
- [ ] 10.3 Tests: durations rendered correctly for paused investigations

## 11. Documentation

- [ ] 11.1 Update `docs/INVESTIGATION.md` with timeline view walkthrough
- [ ] 11.2 Add screenshots in `docs/SCREENSHOTS/timeline-view.png`, `timeline-step-drawer.png`
- [ ] 11.3 Update `docs/INDEX.md` with `vlair investigate timeline` command
- [ ] 11.4 Document accessibility considerations and the color/icon dual encoding
