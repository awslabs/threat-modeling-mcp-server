---
name: phase-1-business-context
description: Phase 1 Business Context Analysis guide. Use when starting a threat model, setting business context, or configuring business features like industry sector, data sensitivity, and regulatory requirements.
---

# Phase 1: Business Context Analysis

## Objective
Understand what the system does, who it serves, and what's at stake if it's compromised. This phase sets the foundation for all subsequent analysis.

## Tools Reference

### manage_system_context (primary tool)
This single tool manages business context plus software, data asset, user persona,
and NFR profiles. Call `action="describe"` for a section before writing it when
you need its exact fields and enum values. Use `action="set", section="all"` to
submit the complete Phase 1 context in one nested payload.

The business fields below live inside `values["business"]`. All are required for
`action="validate", section="all"` to return PASSED for business context.

| Parameter | Required | Values |
|---|---|---|
| description | Yes | Free text describing the system |
| industry_sector | Yes | Finance, Healthcare, Retail, Technology, Manufacturing, Government, Education, Energy, Transportation, Other |
| sensitivity_tier | Yes | Public, Internal, Confidential, Restricted |
| user_base_size | Yes | Nano (<100), Micro (100-1K), Small (1K-100K), Medium (100K-10M), Large (10M-100M), Very Large (100M-1B), Hyper-Scale (>1B) |
| geographic_scope | Yes | Sub-National / Local, National / Single-Country, Regional / Multi-Country Bloc, Continental / Macro-Regional, Multi-Continental / International, Global / Transboundary |
| regulatory_requirements | Yes | GDPR, CCPA / CPRA, HIPAA, PCI-DSS, SOX, FISMA / FedRAMP, None, Multiple / other (comma-separated) |
| system_criticality | Yes | Low (down for days), Medium (up within hours), High (up within minutes), Mission-Critical (cannot be down) |
| financial_impact | Yes | Percent of annual revenue: Negligible (<0.001%), Low (0.001-0.01%), Moderate (0.01-0.1%), High (0.1-1%), Critical (>1%) |
| authentication_requirement | Yes | None, Basic, MFA, Federated, Biometric |
| deployment_model | Yes | On-premises, IaaS, PaaS, SaaS, Serverless / FaaS, Hybrid cloud, Multi-cloud, Edge |
| user_base_metric | Yes | Monthly Active Users, Daily Active Users, Concurrent Users, Seats / licenses, Organizational customers, Installs / downloads, Registered users |
| revenue_band | Yes | Small business, Mid-market, Enterprise |
| data_residency | Yes | Geographic scope level where data is stored (all four facets are required together) |
| compute_location | Yes | Geographic scope level where processing happens |
| user_base_location | Yes | Geographic scope level of the end users |
| organizational_headquarters | Yes | Geographic scope level of the controlling entity |

The 11 scalar features plus the four geographic facets (counted together as
`geographic_profile`) make up the 12 features the completeness check requires.

**Example**:
```python
manage_system_context(
  action="set",
  section="all",
  values={
    "business": {
      "description": "Payment processing service for an e-commerce platform",
      "industry_sector": "Finance",
      "sensitivity_tier": "Restricted",
      "user_base_size": "Large",
      "geographic_scope": "Global / Transboundary",
      "regulatory_requirements": ["PCI-DSS", "GDPR"],
      "system_criticality": "High",
      "financial_impact": "High",
      "authentication_requirement": "MFA",
      "deployment_model": "PaaS",
      "user_base_metric": "Monthly Active Users",
      "revenue_band": "Mid-market",
      "data_residency": "National / Single-Country",
      "compute_location": "Regional / Multi-Country Bloc",
      "user_base_location": "Global / Transboundary",
      "organizational_headquarters": "National / Single-Country"
    },
    "software": {"software_type": "API Service", "deployment_model": "PaaS"},
    "data_assets": [{"name": "Cardholder data", "structural_category": "Structured Data", "sensitivity_tier": "Restricted"}],
    "user_personas": [{"name": "Customer", "persona_type": "Authenticated Standard User"}],
    "nfrs": [{"quality_class": "Availability", "level": "99.9%"}]
  }
)
```

### Other Phase 1 Tools
- `manage_system_context(action="describe", section=SECTION)` -- Exact fields and enum values on demand
- `manage_system_context(action="get", section="all")` -- Review business context and every profile
- `manage_system_context(action="plan", section="business")` -- Get detailed business-analysis guidance
- `manage_system_context(action="validate", section="all")` -- Check the business gate and report profile coverage
- `manage_system_context(action="clear", section=SECTION)` -- Clear one section or all context
- `manage_workflow(action="set_project", directory=PROJECT_DIRECTORY)` -- Record the project path used to decide whether Phase 7.5 applies
- `manage_assumptions(action="add", values=ASSUMPTION)` -- Document scope decisions

The `software`, `data_assets`, `user_personas`, and `nfrs` sections hold the
classification profiles. They are required by the agent workflow, but they are
not inputs to the server's Phase 1 completion gate.

## Workflow

1. **Record the project path** with `manage_workflow(action="set_project", directory=PROJECT_DIRECTORY)`
2. **Read the codebase**: Examine README, config files, package manifests, and infrastructure code
3. **Determine context**: What does the system do, who uses it, and what data does it handle?
4. **Describe sections as needed** with `manage_system_context(action="describe", section=SECTION)`
5. **Set the complete context once** with `action="set", section="all"`
6. **Validate** with `action="validate", section="all"`; business context must pass
7. **Document assumptions** with `manage_assumptions(action="add", values=ASSUMPTION)` for scope decisions such as regional limits or peak-load expectations
   - "Peak load is 10x normal during sales events" (affects availability)

## Completion Criteria
- [ ] `manage_system_context(action="validate", section="all")` returns PASSED for business context
- [ ] All 12 required business features set, including all four geographic facets
- [ ] Project directory recorded
- [ ] Software, known data asset, user persona, and relevant NFR profiles recorded
- [ ] Key assumptions documented
- [ ] Call `manage_workflow(action="advance")` to proceed to Phase 2

## Common Pitfalls
- Setting only the description without the 12 required features
- Guessing regulatory requirements without analyzing the data types
- Not documenting assumptions that limit scope
