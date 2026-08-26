---
name: phase-7-5-code-validation
description: Phase 7.5 Code Validation guide. Use when validating threats and mitigations against actual code or reviewing implementation evidence.
---

# Phase 7.5: Code Validation Analysis

## Objective
Inspect the implementation and record evidence for every current threat and mitigation. This phase runs only when source code is detected in the project recorded with `manage_workflow(action="set_project")`.

## Tool

### manage_code_validation(action, values=None)

| Action | Purpose |
|---|---|
| `describe` | Show the finding payload and accepted outcomes |
| `record` | Atomically store findings and update canonical statuses |
| `get` | Show current findings, missing IDs, and stale records |
| `validate` | Check that every current threat and mitigation has fresh evidence |
| `report` | Render the evidence-based report and finalize the current snapshot |
| `clear` | Remove findings before starting a new validation |

`record` accepts `values.threat_findings` and `values.mitigation_findings`. Each finding requires its record ID, an outcome, and at least one non-empty evidence string. `recommendation` is optional.

Threat outcomes:
- `fully_mitigated`
- `partially_mitigated`
- `not_mitigated`
- `not_applicable`

Mitigation outcomes:
- `implemented`
- `partially_implemented`
- `not_implemented`
- `not_applicable`

## Workflow

1. Call `manage_workflow(action="guidance", phase="7.5")`.
2. Call `manage_code_validation(action="describe")`.
3. Inspect the relevant files and identify concrete file, line, configuration, or test evidence.
4. Call `manage_code_validation(action="record", values=FINDINGS)`. Findings may be submitted incrementally.
5. Call `manage_code_validation(action="validate")`; record every missing or stale item.
6. Call `manage_code_validation(action="report")` to finalize the current snapshot.
7. Call `manage_workflow(action="advance")` to proceed to Phase 8.

Observed code behavior belongs in finding evidence. Use
`manage_assumptions(action="add", values=ASSUMPTION)` only when a statement
remains unverified.

## Completion Criteria
- [ ] Every current threat has a fresh finding
- [ ] Every current mitigation has a fresh finding
- [ ] Each finding contains concrete evidence or a not-applicable rationale
- [ ] Validation reports complete coverage
- [ ] The final report has been generated for the current snapshot
- [ ] `manage_workflow(action="advance")` proceeds to Phase 8
