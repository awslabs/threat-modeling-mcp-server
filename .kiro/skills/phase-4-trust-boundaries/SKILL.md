---
name: phase-4-trust-boundaries
description: Phase 4 Trust Boundary Analysis guide. Use when defining trust zones, crossing points, and security boundaries between architecture nodes.
---

# Phase 4: Trust Boundary Analysis

## Objective
Identify where trust levels change in the system. Every crossing point is a potential attack surface that needs security controls.

Trust-boundary state starts empty. Define zones, crossing points, and boundaries
for the system under review before advancing.

## Concepts

- **Trust Zone**: A region where components and data stores share the same trust level
- **Crossing Point**: Where data flows between zones (requires authentication/authorization)
- **Trust Boundary**: The security perimeter with specific controls

## Tools Reference

Start with `manage_trust_boundaries(action="describe", section=SECTION)` for the
exact contract.

### manage_trust_boundaries(action="add", section="zones", values=ZONE)
| Parameter | Values |
|---|---|
| trust_level | Untrusted, Low, Medium, High, Full |

### manage_trust_boundaries(action="link", section="zones", values=LINK)
Assign an architecture node to exactly one trust zone. The link fields are
`zone_id` and `node_id`; a node may be either a component or a data store.

### manage_trust_boundaries(action="add", section="crossing_points", values=CROSSING)
| Parameter | Values |
|---|---|
| authentication_method | Password, Multi-factor, Certificate, Token, Biometric, API Key, IAM Role, OAuth, None, Other |
| authorization_method | Role-based, Attribute-based, Discretionary, Mandatory, Policy-based, Rule-based, None, Other |

### manage_trust_boundaries(action="link", section="crossing_points", values=LINK)
Map existing connections to crossing points.

### manage_trust_boundaries(action="add", section="boundaries", values=BOUNDARY)
| Parameter | Values |
|---|---|
| type | Network, Process, Physical, Container, Virtual Machine, Account, Other |
| crossing_point_ids | List of crossing point IDs |
| controls | List of security control names (strings) |

### Other Phase 4 Tools
- `manage_trust_boundaries(action="list", section="all")` -- Review the complete model
- `manage_trust_boundaries(action="detection_plan", section="all")` -- AI-powered boundary detection
- `manage_trust_boundaries(action="analysis_plan", section="all")` -- Security analysis guidance
- CRUD actions accept `values` for one record and `items` for a batch

## Common Trust Zone Patterns

### Web Application
| Zone | Trust Level | Architecture Nodes |
|---|---|---|
| Internet | Untrusted | End users, external APIs |
| DMZ | Low | Load balancer, CDN, WAF |
| Application | Medium | App servers, API services |
| Data | High | Databases, caches, queues |
| Admin | Full | Admin consoles, CI/CD |

### Microservices
| Zone | Trust Level | Architecture Nodes |
|---|---|---|
| Public | Untrusted | API Gateway, public endpoints |
| Service Mesh | Medium | Internal microservices |
| Data Layer | High | Databases, object stores |
| Secrets | Full | KMS, secret managers |

## Workflow

1. **Call `manage_workflow(action="guidance", phase="4")`**
2. **Call `manage_trust_boundaries(action="detection_plan", section="all")`** for AI-guided detection
3. **Create trust zones** based on security domains
4. **Assign every component and data store** to a zone with `action="link", section="zones"`
5. **Define crossing points** where data flows between zones
6. **Map connections** to crossing points with `action="link", section="crossing_points"`
7. **Create trust boundaries** with security controls

## Completion Criteria
- [ ] All trust zones defined
- [ ] Every architecture node assigned to exactly one zone
- [ ] Every inter-zone connection mapped to exactly one matching crossing point
- [ ] Every crossing point assigned to a trust boundary
- [ ] No crossing points created when all communication remains within one zone
- [ ] Call `manage_workflow(action="advance")` to proceed to Phase 5

## Common Pitfalls
- Putting everything in one trust zone
- Missing the boundary between internal services and external APIs
- Not specifying authentication/authorization at crossing points
- Forgetting admin/management plane boundaries
