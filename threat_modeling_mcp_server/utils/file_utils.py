"""File utility functions for the Threat Modeling MCP Server."""

import os
import pathlib
from typing import Union


def normalize_output_path(path: Union[str, pathlib.Path]) -> str:
    """Normalize a file path for consistent output.
    
    Args:
        path: The file path to normalize
        
    Returns:
        A normalized string representation of the path
    """
    if isinstance(path, str):
        path = pathlib.Path(path)
    
    # Convert to absolute path and normalize
    abs_path = path.absolute()
    normalized = os.path.normpath(str(abs_path))
    
    return normalized
