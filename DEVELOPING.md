# Developing Threat Modeling MCP Server

## Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager

## Setup

1. Clone the repository
2. Install all dependencies (including dev/test dependencies):

```bash
uv sync
```

This installs the project plus the `dev` dependency group defined in `pyproject.toml` (pytest, pytest-asyncio, etc.) into a `.venv` managed by uv.

If your environment gets into a bad state, you can recreate it:

```bash
rm -rf .venv
uv sync
```

## Running the Server Locally

```bash
uv run run_server.py
```

## Running Tests

```bash
uv run pytest
```

You don't need to run `uv sync` first — `uv run` will sync automatically if needed.

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
