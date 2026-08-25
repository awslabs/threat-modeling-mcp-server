---
name: phase-3-threat-actors
description: Phase 3 Threat Actor Analysis guide. Use when identifying threat actors, setting relevance and priority, or analyzing who might attack the system.
---

# Phase 3: Threat Actor Analysis

## Objective
Identify who might attack this system, what motivates them, and what they're capable of. This focuses threat identification in Phase 6 on realistic scenarios.

## Default Threat Actors

The system pre-loads 12 default threat actors (TA001-TA012) as a **starting point, not
as findings**. An actor counts toward this phase only once you have assessed it -- set
its relevance, set its priority, or update it. Actors you never touch stay out of the
report's threat actor section and are listed in its "Appendix: Reference Catalogue (Not
Reviewed)" instead, so leaving the catalogue untouched cannot pass for analysis.

| ID | Name | Type | Sophistication Tier | Motivations |
|---|---|---|---|---|
| TA001 | Insider | Insider Threat | Tier 2 - Hacktivist / campaign-driven | Financial gain, Revenge / grievance |
| TA002 | External Attacker | External Attacker | Tier 1 - Opportunistic / script kiddie | Financial gain |
| TA003 | Nation-state Actor | Nation-State / APT | Tier 5 - Nation-state APT / elite | Espionage / intelligence collection |
| TA004 | Hacktivist | Hacktivist | Tier 2 - Hacktivist / campaign-driven | Ideological / hacktivism |
| TA005 | Organized Crime | Financially Motivated Cybercriminal / Organized Crime | Tier 3 - Organized cybercrime | Financial gain |
| TA006 | Competitor | Competitor / Corporate Espionage | Tier 3 - Organized cybercrime | Competitive advantage, Espionage / intelligence collection |
| TA007 | Script Kiddie | Script Kiddie / Novice | Tier 1 - Opportunistic / script kiddie | Thrill-seeking / notoriety |
| TA008 | Disgruntled Employee | Disgruntled Employee | Tier 1 - Opportunistic / script kiddie | Revenge / grievance |
| TA009 | Privileged User | Privileged User | Tier 2 - Hacktivist / campaign-driven | Financial gain |
| TA010 | Third Party | Third Party | Tier 2 - Hacktivist / campaign-driven | Financial gain |
| TA011 | Terrorist Organization | Terrorist Organization | Tier 2 - Hacktivist / campaign-driven | Ideological / hacktivism, Disruption / destruction |
| TA012 | Private Sector Offensive Actor | Private Sector Offensive Actor / Cyber Mercenary | Tier 4 - State-nexus / advanced | Financial gain |

## Tools Reference

### set_threat_actor_relevance(id, is_relevant)
Mark whether a threat actor applies to this system. Set `is_relevant=false` for actors that don't apply.

### set_threat_actor_priority(id, priority)
Rank from 1 (highest threat) to 10 (lowest). Consider both likelihood and potential impact.

### add_threat_actor(name, type, sophistication_tier, motivations, resources, relationship_to_target, state_nexus, targeting_specificity, description)
Use keyword arguments: the taxonomy dimensions sit between `resources` and `description`.
| Parameter | Values |
|---|---|
| type | Nation-State / APT, Financially Motivated Cybercriminal / Organized Crime, Hacktivist, Insider Threat, Terrorist Organization, Private Sector Offensive Actor / Cyber Mercenary, Script Kiddie / Novice, Competitor / Corporate Espionage, External Attacker, Disgruntled Employee, Privileged User, Third Party, Other |
| motivations | List of: Financial gain, Espionage / intelligence collection, Ideological / hacktivism, Disruption / destruction, Competitive advantage, Thrill-seeking / notoriety, Revenge / grievance |
| resources | Individual, Club / small group, Contest / crowd, Team, Organization, Government |
| relationship_to_target | External, Internal, Partner / third-party |
| sophistication_tier | Tier 1 - Opportunistic / script kiddie, Tier 2 - Hacktivist / campaign-driven, Tier 3 - Organized cybercrime, Tier 4 - State-nexus / advanced, Tier 5 - Nation-state APT / elite |
| state_nexus | None, State-aligned, State-sponsored, State-executed |
| targeting_specificity | Opportunistic, Sector-focused, Targeted |

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
- [ ] All default actors reviewed for relevance (the phase gate needs at least one
      assessed actor; anything left untouched shows up in the report's appendix)
- [ ] Priorities set for all relevant actors
- [ ] Custom actors added if applicable
- [ ] `analyze_threat_actors()` completed
- [ ] Assumptions documented for excluded actors
- [ ] Call `advance_phase()` to proceed to Phase 4
