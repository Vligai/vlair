## ADDED Requirements

### Requirement: MISP push and TheHive open are approval-eligible

The threat-platform-integration capability SHALL declare `misp.push` and `thehive.open` as eligible for approval gating. When workspace configuration includes these in the approval list, both operations SHALL submit a pending approval and execute only on approval.

#### Scenario: MISP push approval-required
- **WHEN** workspace config sets `approvals.required = ["misp.push", "thehive.open", "edr.isolate_host", "identity.disable_user"]` and a senior_analyst runs `vlair misp push INV-...`
- **THEN** an approval is submitted, the CLI surfaces the approval id, no MISP API write is made; on approval the push executes idempotently

### Requirement: Auto-publish hooks respect approvals

Investigation post-completion hooks (MISP push, TheHive open) SHALL respect the approval gate. When a hook fires for an approval-required action, the corresponding investigation step is recorded as `paused` rather than `failed`; on approval, the hook re-fires and publishes.

#### Scenario: Auto-publish paused on approval
- **WHEN** an investigation completes with `Malicious` verdict and `misp.push` is approval-required
- **THEN** the publish hook submits an approval; the investigation result shows `published_to: pending`; on approval, the publish executes and `published_to` is updated with the resulting MISP event reference
