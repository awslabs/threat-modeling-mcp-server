---
name: phase-1-business-context
description: Phase 1 Business Context Analysis guide. Use when starting a threat model, setting business context, or configuring business features like industry sector, data sensitivity, and regulatory requirements.
---

# Phase 1: Business Context Analysis

## Objective
Understand what the system does, who it serves, and what's at stake if it's compromised. This phase sets the foundation for all subsequent analysis.

## Tools Reference

### set_business_context (primary tool)
Sets description AND all business features in one call.

**Parameters**:
| Parameter | Required | Values |
|---|---|---|
| description | Yes | Free text describing the system |
| industry_sector | No | Finance, Healthcare, Retail, Technology, Manufacturing, Government, Education, Energy, Transportation, Other |
| data_sensitivity | No | Public, Internal, Confidential, Restricted, Regulated |
| user_base_size | No | Small (<1K), Medium (1K-100K), Large (100K-1M), Enterprise (>1M) |
| geographic_scope | No | Local, Regional, National, Multinational, Global |
| regulatory_requirements | No | GDPR, HIPAA, PCI-DSS, SOX, FISMA, CCPA, None, Multiple (comma-separated) |
| system_criticality | No | Low (down for days), Medium (up within hours), High (up within minutes), Mission-Critical (cannot be down) |
| financial_impact | No | Minimal (<$10K), Low ($10K-$100K), Medium ($100K-$1M), High ($1M-$10M), Severe (>$10M) |
| authentication_requirement | No | None, Basic, MFA, Federated, Biometric |
| deployment_environment | No | On-Premises, Cloud-Public, Cloud-Private, Hybrid, Multi-Cloud |
| integration_complexity | No | Standalone, Limited, Moderate, Complex, Highly Complex |

**Example**:
```
set_business_context(
  description="Payment processing microservice handling credit card transactions for an e-commerce platform",
  industry_sector="Finance",
  data_sensitivity="Restricted",
  user_base_size="Large",
  geographic_scope="Global",
  regulatory_requirements="PCI-DSS,GDPR",
  system_criticality="High",
  financial_impact="High",
  authentication_requirement="MFA",
  deployment_environment="Cloud-Public",
  integration_complexity="Complex"
)
```

### Other Phase 1 Tools
- `validate_business_context_completeness()` -- Checks all 10 features are set. Must return PASSED.
- `get_business_context()` -- Review what's been set
- `get_business_context_features()` -- List all available features and descriptions
- `get_business_context_analysis_plan()` -- Get AI-powered analysis guidance
- `add_assumption(description, category, impact, rationale)` -- Document scope decisions

## Workflow

1. **Read the codebase**: Examine README, config files, package.json/pyproject.toml, infrastructure code
2. **Determine business context**: What does the system do? Who uses it? What data does it handle?
3. **Call `set_business_context()`** with ALL parameters filled
4. **Call `validate_business_context_completeness()`** -- must pass before proceeding
5. **Document assumptions** with `add_assumption()` for any scope decisions:
   - "System only operates in North America" (limits regulatory scope)
   - "Peak load is 10x normal during sales events" (affects availability)

## Completion Criteria
- [ ] `validate_business_context_completeness()` returns PASSED
- [ ] All 10 business features set (not just description)
- [ ] Key assumptions documented
- [ ] Call `advance_phase()` to proceed to Phase 2

## Common Pitfalls
- Setting only the description without the 10 features
- Guessing regulatory requirements without analyzing the data types
- Not documenting assumptions that limit scope
