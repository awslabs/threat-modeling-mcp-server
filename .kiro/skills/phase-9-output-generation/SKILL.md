---
name: phase-9-output-generation
description: Phase 9 Output Generation guide with Threat Composer export reference. Use when generating final reports, exporting to JSON/Markdown, or completing the threat modeling process.
---

# Phase 9: Output Generation and Documentation

## Objective
Generate final deliverables: Threat Composer-compatible JSON export and human-readable Markdown report. All files are saved to the `.threatmodel/` directory.

## Tools Reference

### execute_final_export_step()
**Recommended**: Automated export that generates everything with a timestamped filename.
- Calls `export_comprehensive_threat_model()` internally
- Includes state summary in the response
- Saves both JSON and Markdown to `.threatmodel/`

### export_comprehensive_threat_model(output_path)
Manual export with custom filename.
- `output_path`: Base filename (extensions added automatically)
- Generates BOTH `.json` and `.md` files
- JSON is Threat Composer compatible (schema version 1)

### export_threat_model_with_remediation_status(output_path)
Export including code validation results (use after Phase 7.5).

### Progress Tools
- `get_threat_model_progress()` -- Final progress summary with phase completion
- `list_assumptions()` -- All documented assumptions

## Output Files

### JSON Export (Threat Composer Compatible)
```
.threatmodel/comprehensive_threat_model_YYYYMMDD_HHMMSS.json
```

**Schema** (version 1):
```json
{
  "schema": 1,
  "applicationInfo": { "name": "", "description": "" },
  "architecture": { "description": "" },
  "dataflow": { "description": "" },
  "assumptions": [...],
  "mitigations": [...],
  "assumptionLinks": [...],
  "mitigationLinks": [...],
  "threats": [...]
}
```

### Threat Composer Field Constraints
| Field | Max Length |
|---|---|
| threatSource | 200 chars |
| prerequisites | 200 chars |
| threatAction | 200 chars |
| threatImpact | 200 chars |
| statement | 1400 chars |
| tags (each) | 30 chars |

### Threat Composer Status Values
| Threats | Mitigations |
|---|---|
| threatIdentified | mitigationIdentified |
| threatResolved | mitigationInProgress |
| threatResolvedNotUseful | mitigationResolved |
| | mitigationResolvedWillNotAction |

### Markdown Export (Human-Readable)
```
.threatmodel/comprehensive_threat_model_YYYYMMDD_HHMMSS.md
```

Contains:
- Executive summary with key statistics
- Business context and features
- System architecture (components, connections, data stores)
- Threat actors with relevance/priority
- Trust boundaries (zones, crossing points, boundaries)
- Assets and flows with risk levels
- Threats grouped by status
- Mitigations grouped by status with linked threats
- Assumptions with rationale
- Phase progress table

## Importing to AWS Threat Composer
1. Open AWS Threat Composer
2. Click Import
3. Select the `.json` file from `.threatmodel/`
4. All threats, mitigations, assumptions, and links will load

## Workflow

1. **Call `get_phase_9_guidance()`**
2. **Call `execute_final_export_step()`** (or `export_comprehensive_threat_model()` with custom name)
3. **Call `get_threat_model_progress()`** for final summary
4. **Present to user**:
   - File locations in `.threatmodel/`
   - Summary: N threats, N mitigations, N assumptions
   - Overall completion percentage
   - Key findings and open risks

## Completion Criteria
- [ ] JSON export generated (Threat Composer compatible)
- [ ] Markdown report generated
- [ ] Files saved to `.threatmodel/` directory
- [ ] Progress summary generated
- [ ] User informed of file locations and key findings
