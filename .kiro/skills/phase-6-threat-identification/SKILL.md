---
name: phase-6-threat-identification
description: Phase 6 Threat Identification guide with STRIDE methodology reference. Use when identifying threats, categorizing security issues, applying STRIDE analysis, or assessing threat severity and likelihood.
---

# Phase 6: Threat Identification (STRIDE)

## Objective
Systematically identify threats using the STRIDE methodology against every component, connection, and asset flow documented in previous phases.

## STRIDE Categories

### S - Spoofing (violates Authentication)
Can identities be faked?
- Authentication bypass, session hijacking, credential theft, certificate forgery
- **Where to look**: Login endpoints, API authentication, service-to-service auth

### T - Tampering (violates Integrity)
Can data or code be modified?
- SQL injection, XSS, man-in-the-middle, config tampering, code injection
- **Where to look**: Input fields, data in transit, stored data, configuration files

### R - Repudiation (violates Non-repudiation)
Can actions be denied?
- Log tampering, missing audit trails, unsigned transactions
- **Where to look**: Logging infrastructure, audit trails, transaction records

### I - Information Disclosure (violates Confidentiality)
Can data leak?
- Data breaches, verbose errors, unencrypted transmission, directory traversal
- **Where to look**: Error handling, API responses, data flows, storage

### D - Denial of Service (violates Availability)
Can availability be impacted?
- DDoS, resource exhaustion, algorithmic complexity, connection pool exhaustion
- **Where to look**: Public endpoints, resource-intensive operations, queues

### E - Elevation of Privilege (violates Authorization)
Can permissions be escalated?
- Privilege escalation, IDOR, missing access controls, role manipulation
- **Where to look**: Authorization checks, role assignments, admin functions

## Per-Element STRIDE Relevance

| Element Type | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| External entities | X | | X | | | |
| Processes/Services | X | X | X | X | X | X |
| Data stores | | X | | X | X | |
| Data flows | | X | | X | X | |
| Trust boundaries | X | X | | | | X |

## Tools Reference

### add_threat(threat_source, prerequisites, threat_action, threat_impact, category, severity, likelihood, affected_components, affected_assets, tags)

**IMPORTANT**: Each text field max 200 characters.

| Parameter | Required | Values |
|---|---|---|
| threat_source | Yes | Who/what (max 200 chars) |
| prerequisites | Yes | Conditions needed (max 200 chars) |
| threat_action | Yes | What they do (max 200 chars) |
| threat_impact | Yes | What happens (max 200 chars) |
| category | No | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |
| severity | No | Low, Medium, High, Critical |
| likelihood | No | Unlikely, Possible, Likely, Very Likely |
| affected_components | No | List of component IDs |
| affected_assets | No | List of asset names |
| tags | No | List of tags (max 30 chars each) |

**Example**:
```
add_threat(
  threat_source="external attacker",
  prerequisites="with access to the login endpoint",
  threat_action="perform credential stuffing attacks",
  threat_impact="unauthorized access to user accounts",
  category="Spoofing",
  severity="High",
  likelihood="Likely",
  affected_components=["C001"],
  affected_assets=["User Credentials"],
  tags=["STRIDE-S", "authentication"]
)
```

### Severity Assessment

| Severity | Criteria |
|---|---|
| Critical | System compromise, regulated data breach, complete auth bypass |
| High | Significant data exposure, privilege escalation, service disruption |
| Medium | Limited data exposure, partial impact, requires specific conditions |
| Low | Minimal impact, difficult to exploit, limited scope |

### Likelihood Assessment

| Likelihood | Criteria |
|---|---|
| Very Likely | Trivially exploitable, public knowledge, no special access |
| Likely | Known vector, moderate skill, some access needed |
| Possible | Specific conditions required, moderate skill and access |
| Unlikely | Significant access/skill needed, rarely seen |

## Workflow

1. **Call `get_phase_6_guidance()`**
2. **For each STRIDE category**, analyze every component and data flow
3. **Add threats** with full parameters (source, prereqs, action, impact, category, severity, likelihood)
4. **Tag threats** with STRIDE category and domain (e.g., "STRIDE-S", "authentication")
5. **Link to components and assets** affected
6. **If AWS**: Use `search_documentation()` to research service-specific threats
7. **Review coverage** with `list_threats()` -- ensure all 6 STRIDE categories represented

## Completion Criteria
- [ ] Threats identified across all 6 STRIDE categories
- [ ] Each threat has category, severity, and likelihood
- [ ] Threats linked to affected components and assets
- [ ] AWS-specific threats included (if applicable)
- [ ] `list_threats()` shows comprehensive inventory
- [ ] Call `advance_phase()` to proceed to Phase 7
