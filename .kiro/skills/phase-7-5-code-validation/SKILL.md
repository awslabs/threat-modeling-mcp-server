---
name: phase-7-5-code-validation
description: Phase 7.5 Code Validation guide. Use when validating threats against actual code, checking which security controls are implemented, or generating remediation reports.
---

# Phase 7.5: Code Validation Analysis

## Objective
Validate which security controls are already implemented in the codebase and update the threat model to reflect actual implementation state. This phase only runs when code is detected in the project.

## Tools Reference

### validate_security_controls(directory, file_patterns)
Scans the codebase for implemented security controls.
- `directory`: Path to scan (default: ".")
- `file_patterns`: Optional list of file patterns (e.g., ["*.py", "*.js"])

### validate_threat_remediation(directory, file_patterns)
Checks which identified threats are already mitigated by code.
- Compares threat model against actual implementation
- Generates remediation status per threat

### generate_remediation_report()
Creates a comprehensive report including:
- Fully remediated threats
- Partially remediated threats
- Unremediated threats
- Detected controls summary
- Security score (0.0 to 1.0)

### Status Update Tools
- `update_threat(id, status=...)` -- Update threat status based on findings
- `update_mitigation(id, status=...)` -- Update mitigation status
- `add_assumption(description, category, impact, rationale)` -- Document code-based assumptions

## Remediation Statuses

### Threat Statuses
| Status | When to Use |
|---|---|
| threatIdentified | Still needs attention (default) |
| threatResolved | Code fully mitigates this threat |
| threatResolvedNotUseful | Threat not applicable given implementation |

### Mitigation Statuses
| Status | When to Use |
|---|---|
| mitigationIdentified | Not yet implemented |
| mitigationInProgress | Partially implemented in code |
| mitigationResolved | Fully implemented in code |
| mitigationResolvedWillNotAction | Decided not to implement |

## What Code Validation Looks For

| Security Control | Code Patterns |
|---|---|
| Input validation | Schema validation, sanitization, regex checks |
| Authentication | Auth middleware, JWT verification, session checks |
| Authorization | RBAC checks, permission decorators, policy enforcement |
| Encryption | TLS config, KMS usage, encryption libraries |
| Logging | Logger calls, audit trail writes, CloudWatch/CloudTrail |
| Error handling | Try/catch, error sanitization, custom error pages |
| Rate limiting | Throttle middleware, API quota configs |
| CSRF protection | CSRF tokens, SameSite cookies |

## Workflow

1. **Call `get_phase_7_5_guidance()`**
2. **Call `validate_security_controls()`** on the project directory
3. **Call `validate_threat_remediation()`** to match threats against code
4. **Call `generate_remediation_report()`** for comprehensive analysis
5. **Update threat statuses** based on findings with `update_threat()`
6. **Update mitigation statuses** with `update_mitigation()`
7. **Document findings** as assumptions: "Code analysis confirms TLS is enforced on all API endpoints"

## Completion Criteria
- [ ] `validate_security_controls()` executed
- [ ] `validate_threat_remediation()` executed
- [ ] `generate_remediation_report()` generated
- [ ] Threat statuses updated for code-mitigated threats
- [ ] Mitigation statuses updated for implemented controls
- [ ] Code-based assumptions documented
- [ ] Call `advance_phase()` to proceed to Phase 8
