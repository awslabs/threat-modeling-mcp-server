---
name: phase-4-trust-boundaries
description: Phase 4 Trust Boundary Analysis guide. Use when defining trust zones, crossing points, and security boundaries between system components.
---

# Phase 4: Trust Boundary Analysis

## Objective
Identify where trust levels change in the system. Every crossing point is a potential attack surface that needs security controls.

## Concepts

- **Trust Zone**: A region where components share the same trust level
- **Crossing Point**: Where data flows between zones (requires authentication/authorization)
- **Trust Boundary**: The security perimeter with specific controls

## Tools Reference

### add_trust_zone(name, trust_level, description)
| Parameter | Values |
|---|---|
| trust_level | Untrusted, Low, Medium, High, Full |

### add_component_to_zone(zone_id, component_id)
Assign a component to exactly one trust zone.

### add_crossing_point(source_zone_id, destination_zone_id, authentication_method, authorization_method, description)
| Parameter | Values |
|---|---|
| authentication_method | Password, Multi-factor, Certificate, Token, Biometric, API Key, IAM Role, OAuth, None, Other |
| authorization_method | Role-based, Attribute-based, Discretionary, Mandatory, Policy-based, Rule-based, None, Other |

### add_conn_to_crossing(crossing_point_id, connection_id)
Map existing connections to crossing points.

### add_trust_boundary(name, type, crossing_point_ids, controls, description)
| Parameter | Values |
|---|---|
| type | Network, Process, Physical, Container, Virtual Machine, Account, Other |
| crossing_point_ids | List of crossing point IDs |
| controls | List of security control names (strings) |

### Other Phase 4 Tools
- `list_trust_zones()`, `list_crossing_points()`, `list_trust_boundaries()`
- `get_trust_boundary_detection_plan()` -- AI-powered boundary detection
- `get_trust_boundary_analysis_plan()` -- Security analysis guidance

## Common Trust Zone Patterns

### Web Application
| Zone | Trust Level | Components |
|---|---|---|
| Internet | Untrusted | End users, external APIs |
| DMZ | Low | Load balancer, CDN, WAF |
| Application | Medium | App servers, API services |
| Data | High | Databases, caches, queues |
| Admin | Full | Admin consoles, CI/CD |

### Microservices
| Zone | Trust Level | Components |
|---|---|---|
| Public | Untrusted | API Gateway, public endpoints |
| Service Mesh | Medium | Internal microservices |
| Data Layer | High | Databases, object stores |
| Secrets | Full | KMS, secret managers |

## Workflow

1. **Call `get_phase_4_guidance()`**
2. **Call `get_trust_boundary_detection_plan()`** for AI-guided detection
3. **Create trust zones** based on security domains
4. **Assign components** to zones with `add_component_to_zone()`
5. **Define crossing points** where data flows between zones
6. **Map connections** to crossing points with `add_conn_to_crossing()`
7. **Create trust boundaries** with security controls

## Completion Criteria
- [ ] All trust zones defined
- [ ] Every component assigned to a zone
- [ ] Crossing points defined for all inter-zone communication
- [ ] Connections mapped to crossing points
- [ ] Trust boundaries created with controls listed
- [ ] Call `advance_phase()` to proceed to Phase 5

## Common Pitfalls
- Putting everything in one trust zone
- Missing the boundary between internal services and external APIs
- Not specifying authentication/authorization at crossing points
- Forgetting admin/management plane boundaries
