---
name: phase-2-architecture
description: Phase 2 Architecture Analysis guide. Use when documenting system components, connections, data stores, or analyzing technical architecture for threat modeling.
---

# Phase 2: Architecture Analysis

## Objective
Document every component, connection, and data store in the system. This becomes the attack surface map for later phases.

## Tools Reference

### add_component(name, type, service_provider, specific_service, version, description, configuration)
| Parameter | Required | Values |
|---|---|---|
| name | Yes | e.g., "API Gateway", "User Database" |
| type | Yes | Compute, Storage, Network, Security, Database, Messaging, Analytics, Container, Serverless, Other |
| service_provider | No | AWS, Azure, GCP, CNCF, On-Premise, Hybrid, Other |
| specific_service | No | e.g., "Lambda", "RDS", "API Gateway", "EC2" |
| version | No | e.g., "Python 3.9", "PostgreSQL 13" |
| description | No | What this component does |
| configuration | No | Dict of config details |

### add_connection(source_id, destination_id, protocol, port, encryption, description)
| Parameter | Required | Values |
|---|---|---|
| source_id | Yes | Component ID (from add_component response) |
| destination_id | Yes | Component ID |
| protocol | No | HTTP, HTTPS, TCP, UDP, SSH, FTP, SMTP, WebSocket, gRPC, MQTT, Other |
| port | No | Integer port number |
| encryption | No | true/false |
| description | No | What flows over this connection |

### add_data_store(name, type, classification, encryption_at_rest, backup_frequency, description)
| Parameter | Required | Values |
|---|---|---|
| name | Yes | e.g., "Customer PII Store" |
| type | Yes | Relational, NoSQL, Object Storage, File System, Cache, Data Warehouse, Graph, Time Series, Ledger, Other |
| classification | Yes | Public, Internal, Confidential, Restricted, Regulated |
| encryption_at_rest | No | true/false |
| backup_frequency | No | Hourly, Daily, Weekly, Monthly, Continuous, None |
| description | No | What data is stored |

### Other Phase 2 Tools
- `list_components()` -- Review all components
- `list_connections()` -- Review all connections
- `list_data_stores()` -- Review all data stores
- `get_architecture_analysis_plan()` -- AI-powered analysis guidance
- `clear_architecture()` -- Start over if needed

## Workflow

1. **Call `get_phase_2_guidance()`** for detailed instructions
2. **Scan the codebase** for services, APIs, databases, queues, caches, external integrations
3. **Add components** -- every distinct service, database, CDN, load balancer, etc.
4. **Add connections** -- map all communication paths with protocol and encryption status
5. **Add data stores** -- every place data persists, with classification
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
- [ ] All inter-component connections mapped
- [ ] All data stores documented with classification
- [ ] `list_components()` shows comprehensive inventory
- [ ] Call `advance_phase()` to proceed to Phase 3

## Common Pitfalls
- Forgetting external dependencies (third-party APIs, CDNs, DNS)
- Not specifying encryption status on connections
- Missing data stores (logs, caches, temp files are also data stores)
- Not classifying data store sensitivity
