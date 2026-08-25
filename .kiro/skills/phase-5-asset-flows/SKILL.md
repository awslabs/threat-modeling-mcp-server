---
name: phase-5-asset-flows
description: Phase 5 Asset Flow Analysis guide. Use when identifying valuable assets, tracking data flows, or analyzing how sensitive data moves through the system.
---

# Phase 5: Asset Flow Analysis

## Objective
Identify every valuable asset in the system and track how it moves between components. This reveals where assets are exposed and what protections exist.

## Tools Reference

### add_asset(name, type, classification, lifecycle_state, data_states, description, owner, criticality, metadata)
| Parameter | Required | Values |
|---|---|---|
| name | Yes | e.g., "Credit Card Numbers" |
| type | Yes | Data, Credential, Process, Configuration, Cryptographic Key, Token, Session, Other |
| classification | Yes | Public, Internal, Confidential, Restricted |
| lifecycle_state | No | Active, Archived, Pending deletion, Quarantined |
| data_states | No | At rest, In transit, In use (multiple allowed) |
| owner | No | Team or person responsible |
| criticality | No | 1-5 scale (5 = most critical). Business importance only; data sensitivity is `classification`. |

### manage_system_context(action="update", section="data_assets", item_id=PROFILE_ID, values={"asset_id": ASSET_ID, ...})
Link each data classification profile created in Phase 1 to the matching asset ID.
Complete every applicable Data Classification dimension during this update. Use
`action="add", section="data_assets"` only for data first discovered in this phase.

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
- `update_asset(...)`, `update_flow(...)` -- Atomically update a record
- `delete_asset(id)`, `delete_flow(id)` -- Remove a record
- `clear_asset_flows()` -- Clear all assets and flows
- `manage_system_context(action="list", section="data_assets")` -- Match Phase 1 profiles to asset IDs

To clear nullable values, pass `clear_fields` to an update. Asset fields that can be
cleared are `lifecycle_state`, `description`, `owner`, `criticality`, and `metadata`.
Flow fields are `transformation_type`, `description`, `protocol`, and `risk_level`.

## Asset Identification Guide

Look for these in the codebase:

| What to Find | Asset Type | Typical Classification |
|---|---|---|
| Passwords, API keys, tokens | Credential | Restricted |
| PII (names, emails, addresses) | Data | Confidential |
| Payment data (credit cards) | Data | Restricted |
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
3. **Add each asset** with classification (sensitivity tier), data states, and criticality
4. **Link data profiles** with `manage_system_context(action="update", section="data_assets", item_id=PROFILE_ID, values={"asset_id": ASSET_ID, ...})`; use `action="add"` only when no Phase 1 profile exists
5. **Map flows** showing how each asset moves between components
6. **Document controls** on each flow (encryption, auth, validation)
7. **Assign risk levels** based on the classification tier and protection gaps

## Completion Criteria
- [ ] All valuable assets identified and classified
- [ ] Data asset profiles linked to matching asset IDs without duplicates
- [ ] Flows documented for each asset's movement through the system
- [ ] Security controls documented on each flow
- [ ] Risk levels assigned to all flows
- [ ] High-risk flows (unprotected sensitive data) flagged
- [ ] Call `advance_phase()` to proceed to Phase 6
