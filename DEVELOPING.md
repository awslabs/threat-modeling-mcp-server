# Developing Threat Modeling MCP Server

## Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager

## Setup

1. Clone the repository
2. Create and activate a virtual environment:
   ```bash
   uv venv
   source .venv/bin/activate
   ```
   On Windows PowerShell, activate it with
   `.venv\Scripts\Activate.ps1` instead.
3. Install the package and the test dependencies:
   ```bash
   uv pip install -e '.[test]'
   ```
   The `test` extra adds pytest and pytest-asyncio.

## Running the Server Locally

```bash
python run_server.py
```

## Running Tests

```bash
python -m pytest
```

The tools keep state in module-level globals. `tests/conftest.py` snapshots and
restores the globals explicitly listed in `STATEFUL_GLOBALS`, which reduces
cross-test pollution but is not blanket isolation. When adding or changing
module-level state, update that mapping and verify the affected tests in more
than one order.

For tests that need the container-backed stores to be empty, request the
`empty_threat_model_state` fixture. It clears dictionary and list stores and
zeros `phase_completion`; it does not reset model or scalar globals. Initialize
those explicitly when a test depends on them. Asset, flow, and trust-boundary
stores start empty. Threat actors are populated lazily from the default
catalogue when actor operations require them.

Public domain operations are registered in `tools/domain_managers.py`. The
domain-specific analyzer modules retain the typed implementation functions and
state stores but are not registered directly. When adding a manager operation
or field, update its `describe` contract, server instructions, phase guidance,
and MCP-boundary tests together.

## Project Structure

- `threat_modeling_mcp_server/` - Main package directory
  - `server.py` - MCP server implementation
  - `models/` - Data models
  - `tools/` - Tool implementations
  - `utils/` - Utility functions
  - `validation/` - Validation logic
- `tests/` - Test suite
- `run_server.py` - Local development server runner
- `pyproject.toml` - Package configuration
