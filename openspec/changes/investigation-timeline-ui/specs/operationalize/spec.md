## ADDED Requirements

### Requirement: Investigation result page renders timeline by default

The SPA investigation result page SHALL render the timeline as the default view. The legacy flat step list SHALL remain available via a "List view" toggle. The view choice SHALL persist per-user (in localStorage) so an analyst's preference is preserved across sessions.

#### Scenario: Returning user preference
- **WHEN** an analyst toggles to "List view", reloads the page, and opens any investigation
- **THEN** the page opens in List view; the toggle to return to Timeline is visible

### Requirement: Investigation list shows duration badges

The investigation list page in the SPA SHALL display total wall-clock duration alongside each completed investigation, and pause-time-excluded active duration as a secondary metric for investigations that involved approval pauses.

#### Scenario: Investigation with approval pause
- **WHEN** an investigation took 1h 5min total, of which 1h was an approval pause
- **THEN** the list row shows "Duration: 1h 5min (active: 5min)"; the active duration is the more useful operational signal

### Requirement: Timeline accessible via deep link

A timeline view SHALL be accessible via `/investigations/{id}/timeline` and `/investigations/{id}` (the latter renders timeline by default per the user's preference). Direct links to a specific step SHALL be supported via `/investigations/{id}/timeline?step=<step_id>`, which opens the page with the step drawer pre-expanded.

#### Scenario: Deep link to step
- **WHEN** an analyst pastes a URL with `?step=lookup_hashes`
- **THEN** the timeline loads and the lookup_hashes step's drawer is open showing its details
