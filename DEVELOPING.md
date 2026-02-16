# Developing Threat Modeling MCP Server

## Prerequisites

- Python 3.10 or higher
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager

## Setup

1. Clone the repository
2. Install development dependencies:
   ```bash
   uv pip install -e .
   ```

## Running the Server Locally

```bash
python run_server.py
```

## Running Tests

```bash
python -m pytest
```

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
