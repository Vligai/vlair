## Context

The current SPA investigation result page is a flat list of step cards. Each card shows step name, status badge, and a collapsible details section. This works for the small case (5-step ad-hoc analysis) but loses signal for the large case: 10+ step phishing playbook with paused approvals, partial-completion states, and connector calls per step.

The investigation engine in `investigate/engine.py` already records step results with timestamps (`InvestigationStep` dataclass). What's missing is explicit dependency declarations between steps and a UI that uses both timing and dependencies to render a meaningful timeline.

## Goals / Non-Goals

**Goals:**
- A glance at the timeline tells you: where the investigation is, what blocked, what's slow, what waited on a human.
- Analyst handoff: incoming analyst can read the timeline and notes and resume work without losing context.
- Audit reconstruction: months later, someone can replay the timeline and understand who did what when.
- Connector debugging: when a step is slow, the timeline shows which connector call caused it.

**Non-Goals:**
- Real-time push updates (WebSocket / SSE). Polling at 5s is fine; investigations don't run faster than that meaningfully.
- Timeline-as-planning-tool. Read-only view; analysts can pin notes but not move steps.
- Custom themes. One accessible palette.

## Decisions

### D1. Use vis-timeline for the SPA

`vis-timeline` is the established library for Gantt/timeline visualizations in JS. It handles dependency arrows, drag-zoom, and time-scale rendering out of the box. Roughly ~150KB gzipped, acceptable for a feature-rich page. Already used by other security tools (Splunk's incident timeline) so analysts will recognize the pattern.

**Alternatives considered:** `apexcharts` Gantt mode (rejected: Gantt is a recent addition, less mature, awkward for dependency arrows). Custom D3 (rejected: weeks of work for what vis-timeline gives in hours). Plain HTML/CSS rows (rejected: dependency arrows are the core value; CSS doesn't render them well).

### D2. Steps declare `depends_on` explicitly

The engine cannot infer dependencies from execution order alone — some steps run sequentially because the playbook is linear, not because of data dependency. Each playbook step now declares `depends_on` as a list of step ids it requires.

```python
# In a playbook:
steps = [
    Step(id="parse_email", run=...),
    Step(id="extract_iocs", run=..., depends_on=["parse_email"]),
    Step(id="lookup_hashes", run=..., depends_on=["extract_iocs"]),
    Step(id="check_recipients", run=..., depends_on=["parse_email"]),  # parallel-eligible with hash lookup
    ...
]
```

This unlocks future parallel execution (deferred), but in v1 the value is purely visual: the timeline shows that `lookup_hashes` and `check_recipients` could have run in parallel even though they ran sequentially.

**Alternatives considered:** Infer dependencies from step inputs (rejected: requires reflection on every step; brittle). Skip dependency arrows in v1 (rejected: half the value of a timeline view).

### D3. Connector calls are timeline children, not separate timeline

Each step has a sub-row in its expanded view showing connector calls (vendor, operation, latency). When a step is collapsed, the bar shows the step duration; when expanded, the bar splits into the connector calls underneath. This avoids two parallel timelines (steps and calls) which would be visually confusing.

**Alternatives considered:** Two separate timeline tracks (rejected: harder to correlate; doubles cognitive load).

### D4. Analyst notes are pinned to timestamps, not steps

A note carries `at_timestamp`, `author`, `text`, `created_at`. The note renders as a flag on the timeline at the pinned timestamp, NOT attached to a specific step. This way notes can call out cross-step observations ("between 14:23 and 14:27 we saw three failed Okta logins for unrelated users — possibly related campaign?").

Notes can be pinned by clicking on the timeline at any X coordinate; the system maps the click to a timestamp and opens a small editor.

**Alternatives considered:** Notes attached to steps (rejected: too restrictive). Notes as a separate side-panel chronological log (rejected: loses spatial reference).

### D5. ASCII timeline for terminal users

`vlair investigate timeline <id> --ascii` renders a tabular ASCII view:

```
INV-2026-05-04-XXXX | phishing-email | COMPLETED
                     0s  10s 20s 30s 40s 50s 60s 70s 80s
parse_email          [██]
extract_iocs            [████]
check_recipients               [██]
lookup_hashes                  [████████]
auth_check                     [██]
... etc
```

This isn't pretty but it serves CI/log-analysis use cases and gives terminal-only operators something useful.

**Alternatives considered:** Block-text Gantt with terminal escape codes for color (rejected: many CI logs strip colors; plain ASCII is robust). No CLI timeline (rejected: CLI parity is part of vlair's value).

### D6. Filtering happens client-side

The timeline endpoint returns the full investigation timeline (steps + connector calls + approvals + notes). The SPA filters the displayed view client-side. This is fast (timeline data is small — typically <100KB even for big investigations) and avoids a round-trip per filter change.

**Alternatives considered:** Server-side filtering with query params (rejected: tiny benefit; doubles endpoint surface area).

### D7. Polling, not push

When the investigation status is in-progress, the SPA polls the timeline endpoint every 5 seconds. Once status is `COMPLETED`, polling stops. This is simpler than WebSocket plumbing and 5s is fine for human investigations.

**Alternatives considered:** Server-Sent Events (deferred — adds infra; not worth it for v1). WebSocket (rejected: same).

### D8. PNG export client-side via SVG-to-canvas

vis-timeline renders as SVG. Convert to PNG client-side via canvas; download as `<investigation-id>-timeline.png`. No server-side rendering needed. Quality may be lossy on very wide timelines; the export uses 2x dimensions to compensate.

### D9. Timing fields populated by the engine

`investigate/engine.py` already calls `step.run()`. We wrap that call with `time.time()` measurements and persist `started_at`, `completed_at`, `duration_ms` to the step row. `triggered_by` is `automatic` for normal step transitions, `approval` for steps that resumed after an approval, `manual` for steps invoked via `vlair investigate continue`.

## Risks / Trade-offs

- [Risk] vis-timeline adds 150KB to SPA bundle. → Mitigation: lazy-load on the investigation result page only; doesn't affect dashboard or other pages.
- [Risk] Dependency arrows clutter the view for short playbooks. → Mitigation: arrows are visible only on hover by default; toggle to always-visible.
- [Risk] Timeline misleads when investigations are very long-tail (one step takes 99% of duration). → Mitigation: log-scale toggle on the time axis.
- [Risk] Analyst notes leak sensitive content if exported. → Mitigation: notes obey the same role-based viewing as the rest of the investigation; PNG export warns about sensitive content.
- [Trade-off] Replacing the flat step list with the timeline is a larger UX change than incremental. We could keep both views (toggle). Recommendation: ship timeline as default; keep step list available via "List view" toggle for users who prefer it.

## Migration Plan

1. Schema migration: add timing and dependency columns; backfill from existing step data where possible (started_at = step.created_at, completed_at unknown for old steps — leave null).
2. Engine update: populate timing fields on every new step.
3. Playbook update: add `depends_on` declarations to existing playbooks (phishing first, then others).
4. Timeline endpoint and ASCII renderer (no SPA dependency).
5. SPA timeline component behind a feature flag; "List view" remains default.
6. Promote timeline to default view; "List view" becomes the toggle option.
7. Documentation updates with screenshots.

**Rollback:** Feature flag flip returns SPA to list view; endpoint and ASCII renderer remain available; schema migration is additive (rollback no-op).

## Open Questions

- Should the timeline render approvals as their own track (above the step track) or inline as flags on the relevant step? (Recommendation: inline as colored flags; approvers don't have a "track" identity.)
- How do we render very long investigations (running for days)? (Recommendation: time axis auto-zoom on load to fit; default zoom level shows the most active period.)
- Should connector calls have their own row in the expanded view, or share the step's row? (Recommendation: own row, indented under the step; matches familiar IDE call-stack visualization.)
- Should notes be markdown-rendered? (Recommendation: yes — markdown with link autodetect; same library as audit comments.)
