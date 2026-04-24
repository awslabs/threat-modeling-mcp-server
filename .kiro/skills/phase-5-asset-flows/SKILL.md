---
name: phase-5-asset-flows
description: Phase 5 Asset Flow Analysis guide. Use when identifying valuable assets, tracking data flows, or analyzing how sensitive data moves through the system.
---

# Phase 5: Asset Flow Analysis

## Objective
Identify every valuable asset in the system and track how it moves between components. This reveals where assets are exposed and what protections exist.

## Tools Reference

### add_asset(name, type, classification, lifecycle_state, description, owner, sensitivity, criticality, metadata)
| Parameter | Required | Values |
|---|---|---|
| name | Yes | e.g., "Credit Card Numbers" |
| type | Yes | Data, Credential, Process, Configuration, Cryptographic Key, Token, Session, Other |
| classification | Yes | Public, Internal, Confidential, Restricted, Regulated, Other |
| lifecycle_state | No | Creation, Storage, Transmission, Processing, Destruction, Archival, Other |
| owner | No | Team or person responsible |
| sensitivity | No | 1-5 scale (5 = most sensitive) |
| criticality | No | 1-5 scale (5 = most critical) |

### add_flow(asset_id, source_id, destination_id, transformation_type, controls, description, protocol, encryption, authenticated, authorized, validated, risk_level)
| Parameter | Required | Values |
|---|---|---|
| asset_id | Yes | Asset ID from add_asset |
| source_id | Yes | Component ID |
| destination_id | Yes | Component ID |
| transformation_type | No | Encryption, Decryption, Processing, Aggregation, Anonymization, Pseudonymization, Tokenization, Hashing, Signing, Verification, Redaction, Other |
| controls | No | List of: Encryption, Access Control, Authentication, Authorization, Audit Logging, Input Validation, Output Encoding, Integrity Check, Rate Limiting, Monitoring, Other |
| encryption | No | true/false |
| authenticated | No | true/false |
| authorized | No | true/false |
| validated | No | true/false |
| risk_level | No | 1-5 scale (5 = highest risk) |

### Other Phase 5 Tools
- `list_assets()`, `list_flows()` -- Review current state
- `get_asset(id)`, `get_flow(id)` -- Detailed view
- `get_asset_flow_analysis_plan()` -- AI-powered analysis
- `reset_asset_flows()` -- Reset to defaults

## Asset Identification Guide

Look for these in the codebase:

| What to Find | Asset Type | Typical Classification |
|---|---|---|
| Passwords, API keys, tokens | Credential | Restricted |
| PII (names, emails, addresses) | Data | Confidential/Regulated |
| Payment data (credit cards) | Data | Regulated |
| Session tokens, JWTs | Token | Confidential |
| Encryption keys, certificates | Cryptographic Key | Restricted |
| Config files, env vars | Configuration | Internal |
| Audit/access logs | Data | Internal |
| Public content, marketing | Data | Public |

## Risk Level Guide for Flows

| Risk Level | Criteria |
|---|---|
| 5 (Critical) | Restricted data, crosses trust boundary, no encryption |
| 4 (High) | Confidential data crossing trust boundary |
| 3 (Medium) | Confidential data within same zone, or internal data crossing boundary |
| 2 (Low) | Internal data within same zone with controls |
| 1 (Minimal) | Public data with standard controls |

## Workflow

1. **Call `get_phase_5_guidance()`**
2. **Identify assets** from code analysis (env vars, database schemas, API payloads)
3. **Add each asset** with classification, sensitivity, and criticality
4. **Map flows** showing how each asset moves between components
5. **Document controls** on each flow (encryption, auth, validation)
6. **Assign risk levels** based on data sensitivity and protection gaps
7. **Call `get_asset_flow_analysis_plan()`** for deeper analysis

## Completion Criteria
- [ ] All valuable assets identified and classified
- [ ] Flows documented for each asset's movement through the system
- [ ] Security controls documented on each flow
- [ ] Risk levels assigned to all flows
- [ ] High-risk flows (unprotected sensitive data) flagged
- [ ] Call `advance_phase()` to proceed to Phase 6
