---
name: phase-3-threat-actors
description: Phase 3 Threat Actor Analysis guide. Use when identifying threat actors, setting relevance and priority, or analyzing who might attack the system.
---

# Phase 3: Threat Actor Analysis

## Objective
Identify who might attack this system, what motivates them, and what they're capable of. This focuses threat identification in Phase 6 on realistic scenarios.

## Default Threat Actors

The system pre-loads 10 default threat actors (TA001-TA010):

| ID | Name | Type | Capability | Motivations |
|---|---|---|---|---|
| TA001 | Insider | Insider | Medium | Financial, Revenge |
| TA002 | External Attacker | External | Medium | Financial |
| TA003 | Nation-state Actor | Nation-state | High | Espionage, Political |
| TA004 | Hacktivist | Hacktivist | Medium | Ideology, Political |
| TA005 | Organized Crime | Organized Crime | High | Financial |
| TA006 | Competitor | Competitor | Medium | Financial, Espionage |
| TA007 | Script Kiddie | Script Kiddie | Low | Curiosity, Reputation |
| TA008 | Disgruntled Employee | Disgruntled Employee | Medium | Revenge |
| TA009 | Privileged User | Privileged User | High | Financial, Accidental |
| TA010 | Third Party | Third Party | Medium | Financial, Accidental |

## Tools Reference

### set_threat_actor_relevance(id, is_relevant)
Mark whether a threat actor applies to this system. Set `is_relevant=false` for actors that don't apply.

### set_threat_actor_priority(id, priority)
Rank from 1 (highest threat) to 10 (lowest). Consider both likelihood and potential impact.

### add_threat_actor(name, type, capability_level, motivations, resources, description)
| Parameter | Values |
|---|---|
| type | Insider, External, Nation-state, Hacktivist, Organized Crime, Competitor, Script Kiddie, Disgruntled Employee, Privileged User, Third Party, Other |
| capability_level | Low, Medium, High |
| motivations | List of: Financial, Political, Espionage, Reputation, Revenge, Ideology, Curiosity, Accidental, Disruption, Other |
| resources | Limited, Moderate, Extensive |

### Other Phase 3 Tools
- `list_threat_actors()` -- Review all actors
- `get_threat_actor(id)` -- Detailed view of one actor
- `analyze_threat_actors()` -- Automated analysis
- `reset_threat_actors()` -- Reset to defaults
- `clear_threat_actors()` -- Remove all

## Relevance Decision Guide

| Business Context | Likely Relevant | Likely Not Relevant |
|---|---|---|
| Internal tool, small team | Insider, Privileged User, Script Kiddie | Nation-state, Organized Crime |
| Financial/healthcare SaaS | All actors relevant | - |
| Public API, no sensitive data | External, Script Kiddie | Nation-state, Organized Crime |
| Government system | Nation-state, Insider, Hacktivist | Competitor |
| E-commerce | External, Organized Crime, Script Kiddie | Nation-state |

## Workflow

1. **Call `get_phase_3_guidance()`**
2. **Call `list_threat_actors()`** to review defaults
3. **Set relevance** for each actor based on business context
4. **Set priority** (1-10) for relevant actors
5. **Add custom actors** if needed (e.g., specific competitors, supply chain actors)
6. **Call `analyze_threat_actors()`** for automated analysis
7. **Document assumptions** about threat actor exclusions

## Completion Criteria
- [ ] All default actors reviewed for relevance
- [ ] Priorities set for all relevant actors
- [ ] Custom actors added if applicable
- [ ] `analyze_threat_actors()` completed
- [ ] Assumptions documented for excluded actors
- [ ] Call `advance_phase()` to proceed to Phase 4
