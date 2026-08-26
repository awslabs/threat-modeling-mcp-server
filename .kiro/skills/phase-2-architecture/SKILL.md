---
name: phase-2-architecture
description: Phase 2 Architecture Analysis guide. Use when documenting system components, connections, data stores, or analyzing technical architecture for threat modeling.
---

# Phase 2: Architecture Analysis

## Objective
Document every component, connection, and data store in the system. This becomes the attack surface map for later phases.

## Tools Reference

Start with `manage_architecture(action="describe", section=SECTION)` to load the
exact fields and accepted enum values for `components`, `connections`, or
`data_stores`.

### manage_architecture(action="add", section="components", values=COMPONENT)
| Parameter | Required | Values |
|---|---|---|
| name | Yes | e.g., "API Gateway", "User Database" |
| type | Yes | Compute, Storage, Network, Security, Database, Messaging, Analytics, Container, Serverless, Other |
| service_provider | No | AWS, Azure, GCP, CNCF, On-Premise, Hybrid, Other |
| specific_service | No | e.g., "Lambda", "RDS", "API Gateway", "EC2" |
| version | No | e.g., "Python 3.9", "PostgreSQL 13" |
| description | No | What this component does |
| configuration | No | Dict of config details |

### manage_architecture(action="add", section="connections", values=CONNECTION)
| Parameter | Required | Values |
|---|---|---|
| source_id | Yes | Component or data-store node ID |
| destination_id | Yes | Component or data-store node ID |
| protocol | No | HTTP, HTTPS, TCP, UDP, SSH, FTP, SMTP, WebSocket, gRPC, MQTT, Other |
| port | No | Integer port number |
| encryption | No | true/false |
| description | No | What flows over this connection |

### manage_architecture(action="add", section="data_stores", values=DATA_STORE)
| Parameter | Required | Values |
|---|---|---|
| name | Yes | e.g., "Customer PII Store" |
| type | Yes | Relational, NoSQL, Object Storage, File System, Cache, Data Warehouse, Graph, Time Series, Ledger, Other |
| classification | Yes | Public, Internal, Confidential, Restricted |
| encryption_at_rest | No | true/false |
| backup_frequency | No | Hourly, Daily, Weekly, Monthly, Continuous, None |
| description | No | What data is stored |

### Other Phase 2 Tools
- `manage_architecture(action="list", section=SECTION)` -- Review one entity type
- `manage_architecture(action="list", section="all")` -- Review the complete architecture
- `manage_architecture(action="plan", section="all")` -- AI-powered analysis guidance
- `manage_architecture(action="clear", section="all")` -- Start over if no asset flows depend on it
- Add and update operations accept `items` for batches; get field details with `describe`

## Workflow

1. **Call `manage_workflow(action="guidance", phase="2")`** for detailed instructions
2. **Scan the codebase** for services, APIs, databases, queues, caches, external integrations
3. **Add components** with `manage_architecture(action="add", section="components", ...)`
4. **Add data stores** with `section="data_stores"` and include classification
5. **After all nodes exist, add connections** with `section="connections"` and include protocol and encryption status; data stores are valid endpoints
6. **If AWS**: Use `search_documentation()` to validate service security configs
7. **Document assumptions** about the architecture

## What to Look For in Code

| Code Pattern | Component Type |
|---|---|
| Dockerfile, ECS/EKS config | Container |
| Lambda handler, serverless.yml | Serverless |
| Database connection strings, ORM config | Database |
| S3 client, blob storage | Storage |
| API routes, REST/gRPC endpoints | Compute/Network |
| Queue/topic publishers/subscribers | Messaging |
| Redis/Memcached clients | Cache (Data Store) |

## Completion Criteria
- [ ] All system components added
- [ ] Every component and data store participates in a connection, unless the architecture has only one node
- [ ] All data stores documented with classification
- [ ] `manage_architecture(action="list", section="all")` shows a comprehensive inventory
- [ ] Call `manage_workflow(action="advance")` to proceed to Phase 3

## Common Pitfalls
- Forgetting external dependencies (third-party APIs, CDNs, DNS)
- Not specifying encryption status on connections
- Missing data stores (logs, caches, temp files are also data stores)
- Not classifying data store sensitivity
- Modeling a data store but omitting its connections
