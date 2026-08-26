"""Shared pytest fixtures.

The tool modules keep their state in module-level globals. Two things make that
awkward to isolate between tests:

1. Some tools reset state by *rebinding* the module attribute
   (``components = {}``) rather than mutating it, so a test that captures the
   dict object and restores it in a finally block writes into an orphan and
   leaks state into whatever runs next.
2. Some existing tests do ``from ...threat_generator import mitigations``, so
   they hold a direct reference to the original container. Restoring by
   assignment alone would leave those tests looking at a different object than
   the tool writes to.

The autouse fixture therefore restores both the attribute binding *and* the
original container's contents in place, which satisfies both patterns.
"""

import copy

import pytest
from pydantic import BaseModel

# module path -> attribute names that hold mutable state
STATEFUL_GLOBALS = {
    "threat_modeling_mcp_server.tools.business_context": ("business_context",),
    "threat_modeling_mcp_server.tools.assumption_manager": ("assumptions",),
    "threat_modeling_mcp_server.tools.architecture_analyzer": (
        "components", "connections", "data_stores",
    ),
    "threat_modeling_mcp_server.tools.threat_actor_analyzer": ("threat_actors",),
    "threat_modeling_mcp_server.tools.trust_boundary_analyzer": (
        "trust_zones", "crossing_points", "trust_boundaries",
    ),
    "threat_modeling_mcp_server.tools.asset_flow_analyzer": ("assets", "flows"),
    "threat_modeling_mcp_server.tools.threat_generator": (
        "threats", "mitigations", "mitigation_links",
        "residual_risk_assessments", "threat_counter", "mitigation_counter",
    ),
    "threat_modeling_mcp_server.tools.step_orchestrator": (
        "phase_completion", "phase_blocking_reasons", "current_phase",
        "last_detection_error", "project_directory",
    ),
    "threat_modeling_mcp_server.tools.code_security_validator": (
        "validation_project_directory", "threat_findings", "mitigation_findings",
        "finding_fingerprints", "report_fingerprint",
    ),
    "threat_modeling_mcp_server.tools.classification_profiles": (
        "software_profile", "data_asset_profiles", "user_personas", "nfr_profile",
    ),
    "threat_modeling_mcp_server.utils.comprehensive_exporter": (
        "last_successful_export_fingerprint", "last_successful_export_paths",
    ),
    # Monotonic id counters live here now, shared by every collection.
    "threat_modeling_mcp_server.utils.id_utils": ("_counters",),
}


def _restore(module, attribute, original, contents):
    """Put ``module.attribute`` back to its pre-test object and contents."""
    # Undo any rebinding first so from-imports and module lookups agree again.
    setattr(module, attribute, original)

    if isinstance(original, dict):
        original.clear()
        original.update(copy.deepcopy(contents))
    elif isinstance(original, list):
        original[:] = copy.deepcopy(contents)
    elif isinstance(original, set):
        original.clear()
        original.update(copy.deepcopy(contents))
    elif isinstance(original, BaseModel):
        for field, value in copy.deepcopy(contents).items():
            setattr(original, field, value)
    # Immutables (int, str, None) are fully restored by the setattr above.


@pytest.fixture
def empty_threat_model_state():
    """Clear every tool store so a test can assert on a genuinely empty model.

    Importing ``server`` registers tools that seed the threat-actor catalogue.
    Whether that has happened by the time a given test runs depends on collection
    order, so a test that asserts "nothing has been done yet" has to establish that for
    itself rather than relying on collection order.

    ``isolate_tool_module_state`` restores the defaults after the test.
    """
    import importlib

    for module_path, attributes in STATEFUL_GLOBALS.items():
        module = importlib.import_module(module_path)
        for attribute in attributes:
            value = getattr(module, attribute, None)
            if attribute == "phase_completion":
                # Keyed by phase number, so zero the values instead of dropping
                # the keys the orchestrator expects to find.
                value.update({phase: 0.0 for phase in value})
            elif isinstance(value, dict):
                value.clear()
            elif isinstance(value, list):
                del value[:]
    yield


@pytest.fixture(autouse=True)
def isolate_tool_module_state():
    """Snapshot and restore the tool modules' global state around every test."""
    import importlib

    snapshots = []
    for module_path, attributes in STATEFUL_GLOBALS.items():
        try:
            module = importlib.import_module(module_path)
        except ImportError:  # pragma: no cover - module list is static
            continue
        for attribute in attributes:
            if not hasattr(module, attribute):
                continue
            original = getattr(module, attribute)
            if isinstance(original, BaseModel):
                contents = copy.deepcopy(original.model_dump())
            else:
                contents = copy.deepcopy(original)
            snapshots.append((module, attribute, original, contents))

    yield

    for module, attribute, original, contents in snapshots:
        _restore(module, attribute, original, contents)
