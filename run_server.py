#!/usr/bin/env python3
"""Script to run the Threat Modeling MCP Server directly."""

import os
import sys

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the server module
from threat_modeling_mcp_server.server import main

if __name__ == "__main__":
    main()
