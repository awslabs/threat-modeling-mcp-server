---
name: phase-9-output-generation
description: Phase 9 Output Generation guide with Threat Composer export reference. Use when generating final reports, exporting to JSON/Markdown, or completing the threat modeling process.
---

# Phase 9: Output Generation and Documentation

## Objective
Generate final deliverables: Threat Composer-compatible JSON export and human-readable Markdown report. All files are saved to the `.threatmodel/` directory.

## Tools Reference

### export_threat_model
Exports the current model and includes a state summary in the response.
- First select the modeling context with
  `manage_workflow(action="set_project", directory=...)`
- Omit `output_path` to use a timestamped filename
- Pass `output_path="my_model.json"` to choose the base filename
- Generates `<base>.tc.json` and `<base>.md`, plus a separate
  `<base>.extended.json` snapshot unless `include_extended_data=False`
- Creates and saves every file under `<selected-project>/.threatmodel/`
- Directory components in `output_path` cannot redirect any artifact
- `.tc.json` is strict Threat Composer JSON (schema version 1) and the only
  file to import; it never carries extra top-level keys
- `.extended.json` is a full server-state snapshot (NOT importable into
  Threat Composer) with internal ids, full text, residual-risk assessments,
  profiles, and phase progress

The comprehensive export includes current threat and mitigation statuses.
Markdown and the extended snapshot also include residual-risk assessments.

### Progress Tools
- `manage_workflow(action="progress")` -- Final progress summary with phase completion
- `manage_assumptions(action="list")` -- All documented assumptions

## Output Files

### JSON Export (Threat Composer Compatible)
```
.threatmodel/comprehensive_threat_model_YYYYMMDD_HHMMSS.tc.json
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
  "assumptionLinks": [],
  "mitigationLinks": [...],
  "threats": [...]
}
```

Ids in `.tc.json` are deterministic UUIDs derived from the internal ids, and
every `mitigationLinks` entry references exported entities.

### Threat Composer Field Constraints
The stored model keeps full text. These limits apply only to the `.tc.json`
copy; each shortened field is listed under "Export Warnings" in the tool
response.

| Field | Max Length |
|---|---|
| threatSource | 200 chars |
| prerequisites | 200 chars |
| threatAction | 200 chars |
| threatImpact | 200 chars |
| statement | 1400 chars |
| tags (each) | 30 chars |
| mitigation / assumption content | 1000 chars |

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
- Code-validation findings and implementation evidence
- Assumptions with rationale
- Phase progress table

## Importing to AWS Threat Composer
1. Open AWS Threat Composer
2. Click Import
3. Select the `.tc.json` file from `.threatmodel/` (never the `.extended.json` snapshot)
4. All threats, mitigations, assumptions, and links will load

## Workflow

1. **Call `manage_workflow(action="guidance", phase="9")`**
2. **Call `export_threat_model()`**, optionally with `output_path="my_model.json"`
3. **Call `manage_workflow(action="progress")`** for final summary
4. **Present to user**:
   - File locations in `.threatmodel/`
   - Summary: N threats, N mitigations, N assumptions
   - Overall completion percentage
   - Key findings and open risks

## Completion Criteria
- [ ] JSON export generated (Threat Composer compatible)
- [ ] Markdown report generated
- [ ] Files saved to `.threatmodel/` directory
- [ ] `manage_workflow(action="status")` reports Phase 9 complete for the current model
- [ ] Progress summary generated
- [ ] User informed of file locations and key findings
