---
name: phase-8-residual-risk
description: Phase 8 Residual Risk Analysis guide. Use when assessing remaining risk after mitigations and recording explicit risk decisions.
---

# Phase 8: Residual Risk Analysis

## Objective
Assess what risk remains after all mitigations are applied. Make explicit risk acceptance decisions and document justifications.

## Tools Reference

### Review Tools
- `manage_threats(action="list", section="all")` -- Get all threats and mitigations
- `manage_threats(action="get", section="threats", item_id=ID)` -- Threat details and links
- `manage_threats(action="get", section="mitigations", item_id=ID)` -- Mitigation details and links

### Decision Tools
- `manage_threats(action="assess", section="threats", values=ASSESSMENT)` -- Record one decision
- `manage_threats(action="assess", section="threats", items=ASSESSMENTS)` -- Record an atomic batch
- `manage_assumptions(action="add", values=ASSUMPTION)` -- Document risk acceptance

## Risk Assessment Framework

For each threat, consider:

1. **Mitigations in place**: What controls address this threat?
2. **Mitigation effectiveness**: How well do the controls work?
3. **Residual likelihood**: After controls, how likely is the threat?
4. **Residual impact**: If it still occurs, what's the damage?
5. **Business tolerance**: Can the business accept this level of risk?

An assessment contains `threat_id`, `decision`, `residual_severity`,
`residual_likelihood`, and a non-empty `rationale`. Severity and likelihood are
required except for `Not Applicable`.

## Residual Risk Decisions

| Decision | Criteria | Threat Composer status |
|---|---|---|
| `Mitigated` | Controls reduce risk to the required level | `threatResolved` |
| `Accepted` | The business formally accepts the remaining risk | `threatResolved` |
| `Open` | Controls are absent or insufficient | `threatIdentified` |
| `Not Applicable` | The scenario does not apply to this system | `threatResolvedNotUseful` |

## Decision Guide

### Choose `Mitigated` when:
- Preventive controls fully address the threat vector
- Detective + corrective controls provide adequate response
- Code validation confirmed implementation
- Industry-standard controls are in place

### Choose `Not Applicable` when:
- The threat scenario is unrealistic for this system
- The threat is blocked by architectural constraints

### Choose `Accepted` when:
- The remaining severity and likelihood are understood
- The accountable business owner accepts that residual exposure
- The rationale records why no further control is required

### Choose `Open` when:
- Controls are planned but not implemented
- Partial mitigation leaves significant residual risk
- No cost-effective mitigation exists yet

## Workflow

1. **Call `manage_workflow(action="guidance", phase="8")`**
2. **Call `manage_threats(action="list", section="threats")`** to get the full inventory
3. **For each threat**:
   a. Call `manage_threats(action="get", section="threats", item_id=ID)` to see linked mitigations
   b. Assess residual risk considering mitigation effectiveness
   c. Build an assessment with the decision, residual ratings, and rationale
4. **Save decisions atomically** with `manage_threats(action="assess", section="threats", items=ASSESSMENTS)`
5. **Document broader risk assumptions** with `manage_assumptions(action="add", values=ASSUMPTION)`:
   - "Risk of DDoS accepted: CDN and auto-scaling provide adequate protection"
   - "SQL injection risk resolved: all database queries use parameterized statements"
6. **Review summary** with `manage_threats(action="list", section="threats")`; every assessment must show `Assessment State: Current`

## Completion Criteria
- [ ] Every threat reviewed for residual risk
- [ ] Every threat has a current assessment with a decision and rationale
- [ ] Residual severity and likelihood recorded except for Not Applicable threats
- [ ] Risk acceptance assumptions documented with business justification
- [ ] No missing or stale assessments remain
- [ ] Call `manage_workflow(action="advance")` to proceed to Phase 9

## Common Pitfalls
- Marking all threats as resolved without justification
- Not documenting WHY a risk is accepted
- Forgetting to consider combined/cascading risks
- Ignoring threats that lack mitigations
