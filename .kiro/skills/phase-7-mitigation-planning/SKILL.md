---
name: phase-7-mitigation-planning
description: Phase 7 Mitigation Planning guide. Use when creating mitigations, linking them to threats, validating coverage, or planning security controls.
---

# Phase 7: Mitigation Planning

## Objective
Define security controls for every identified threat and ensure complete coverage. Every threat needs at least one mitigation; every mitigation must be linked to at least one threat.

## Tools Reference

### manage_threats(action="add", section="mitigations", values=MITIGATION)

Call `manage_threats(action="describe", section="mitigations")` first for the
exact contract.
| Parameter | Required | Values |
|---|---|---|
| content | Yes | Description of the mitigation |
| type | No | Preventive, Detective, Corrective, Deterrent |
| status | No | mitigationIdentified (default), mitigationInProgress, mitigationResolved, mitigationResolvedWillNotAction |
| implementation_details | No | How to implement |
| cost | No | Low, Medium, High |
| effectiveness | No | Low, Medium, High |

### manage_threats(action="link", section="mitigations", values=LINK)
Connect a mitigation to the threat it addresses. A mitigation can address multiple threats.
Use `items=[LINK, ...]` to create multiple links in one call; each item is
reported independently.

### Other Phase 7 Tools
- `manage_threats(action="list", section="mitigations")` -- Review all mitigations
- `manage_threats(action="get", section="mitigations", item_id=ID)` -- Detailed mitigation view
- `manage_threats(action="list", section="threats")` -- Review threats for coverage
- `manage_threats(action="get", section="threats", item_id=ID)` -- Check linked mitigations

## Mitigation Types

| Type | Purpose | Examples |
|---|---|---|
| Preventive | Stop threats from occurring | Input validation, MFA, encryption, least privilege |
| Detective | Detect when threats occur | Logging, monitoring, IDS, alerting |
| Corrective | Respond to and fix threats | Incident response, backup restore, auto-scaling |
| Deterrent | Discourage threat actors | Security notices, legal warnings, monitoring banners |

## STRIDE-to-Mitigation Mapping

| STRIDE Category | Recommended Mitigations |
|---|---|
| Spoofing | MFA, certificate pinning, token validation, session management |
| Tampering | Input validation, parameterized queries, TLS, digital signatures, integrity checks |
| Repudiation | Comprehensive logging, tamper-proof audit trails, digital signatures |
| Information Disclosure | Encryption (TLS + at rest), access controls, data masking, error handling |
| Denial of Service | Rate limiting, auto-scaling, CDN/WAF, circuit breakers, resource quotas |
| Elevation of Privilege | RBAC/ABAC, least privilege, authorization at every layer, secure defaults |

## Coverage Validation Process

After adding mitigations and linking them:

1. **`manage_threats(action="list", section="threats")`** -- Get all threats
2. **`manage_threats(action="get", section="threats", item_id=ID)`** -- Check links
3. **`manage_threats(action="list", section="mitigations")`** -- Get all mitigations
4. **`manage_threats(action="get", section="mitigations", item_id=ID)`** -- Check links
5. **Fix gaps**: Add mitigations for orphaned threats, link orphaned mitigations

**Critical rules**:
- Every threat MUST have at least one linked mitigation
- Every mitigation MUST be linked to at least one threat
- High-severity threats should have both preventive AND detective controls

## Workflow

1. **Call `manage_workflow(action="guidance", phase="7")`** (auto-detects if code exists for Phase 7.5)
2. **For each threat**, create appropriate mitigations
3. **Link every mitigation** to its threats
4. **If AWS**: Validate controls with `search_documentation()` and `read_documentation()`
5. **Run coverage validation** (see process above)
6. **Document assumptions** about mitigation effectiveness

## Completion Criteria
- [ ] Every threat has at least one linked mitigation
- [ ] Every mitigation linked to at least one threat
- [ ] Mitigation types appropriate for threat categories
- [ ] Implementation details provided
- [ ] Coverage validation complete
- [ ] Call `manage_workflow(action="advance")` -- proceeds to Phase 7.5 (if code) or Phase 8
