---
name: phase-8-residual-risk
description: Phase 8 Residual Risk Analysis guide. Use when assessing remaining risk after mitigations, making risk acceptance decisions, or updating final threat statuses.
---

# Phase 8: Residual Risk Analysis

## Objective
Assess what risk remains after all mitigations are applied. Make explicit risk acceptance decisions and document justifications.

## Tools Reference

### Review Tools
- `list_threats()` -- Get all threats with current status
- `list_mitigations()` -- Get all mitigations with status
- `get_threat(id)` -- Detailed view including linked mitigations
- `get_mitigation(id)` -- Detailed view including linked threats

### Decision Tools
- `update_threat(id, status=...)` -- Set final threat status
- `add_assumption(description, category, impact, rationale)` -- Document risk acceptance

## Risk Assessment Framework

For each threat, consider:

1. **Mitigations in place**: What controls address this threat?
2. **Mitigation effectiveness**: How well do the controls work?
3. **Residual likelihood**: After controls, how likely is the threat?
4. **Residual impact**: If it still occurs, what's the damage?
5. **Business tolerance**: Can the business accept this level of risk?

## Final Threat Status Decisions

| Status | Criteria | Action |
|---|---|---|
| `threatResolved` | Threat adequately mitigated by controls | Mark resolved with justification |
| `threatResolvedNotUseful` | Threat not applicable to this system, or risk formally accepted | Mark with business justification |
| `threatIdentified` (keep) | Threat still needs attention, controls insufficient | Document what's still needed |

## Decision Guide

### Mark as `threatResolved` when:
- Preventive controls fully address the threat vector
- Detective + corrective controls provide adequate response
- Code validation confirmed implementation
- Industry-standard controls are in place

### Mark as `threatResolvedNotUseful` when:
- The threat scenario is unrealistic for this system
- Business has formally accepted the risk with justification
- The threat is blocked by architectural constraints

### Keep as `threatIdentified` when:
- Controls are planned but not implemented
- Partial mitigation leaves significant residual risk
- No cost-effective mitigation exists yet

## Workflow

1. **Call `get_phase_8_guidance()`**
2. **Call `list_threats()`** to get the full inventory
3. **For each threat**:
   a. Call `get_threat(id)` to see linked mitigations
   b. Assess residual risk considering mitigation effectiveness
   c. Call `update_threat(id, status=...)` with appropriate status
4. **Document risk acceptance** with `add_assumption()`:
   - "Risk of DDoS accepted: CDN and auto-scaling provide adequate protection"
   - "SQL injection risk resolved: all database queries use parameterized statements"
5. **Review summary** with `list_threats(status="threatIdentified")` to see remaining open risks

## Completion Criteria
- [ ] Every threat reviewed for residual risk
- [ ] Final status set on each threat
- [ ] Risk acceptance assumptions documented with business justification
- [ ] No threats left without a deliberate status decision
- [ ] Call `advance_phase()` to proceed to Phase 9

## Common Pitfalls
- Marking all threats as resolved without justification
- Not documenting WHY a risk is accepted
- Forgetting to consider combined/cascading risks
- Ignoring threats that lack mitigations
