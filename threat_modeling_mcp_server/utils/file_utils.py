"""File utility functions for the Threat Modeling MCP Server."""

import os
import pathlib
from typing import Union, List


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


def read_file_content(file_path: Union[str, pathlib.Path]) -> str:
    """Read the content of a file.
    
    Args:
        file_path: Path to the file to read
        
    Returns:
        The content of the file as a string
        
    Raises:
        FileNotFoundError: If the file does not exist
        IOError: If there is an error reading the file
    """
    if isinstance(file_path, str):
        file_path = pathlib.Path(file_path)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def write_file_content(file_path: Union[str, pathlib.Path], content: str) -> None:
    """Write content to a file.
    
    Args:
        file_path: Path to the file to write
        content: Content to write to the file
        
    Raises:
        IOError: If there is an error writing to the file
    """
    if isinstance(file_path, str):
        file_path = pathlib.Path(file_path)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def list_files(directory: Union[str, pathlib.Path], 
               extensions: List[str] = None, 
               recursive: bool = True) -> List[str]:
    """List files in a directory with optional filtering by extension.
    
    Args:
        directory: Directory to list files from
        extensions: List of file extensions to include (e.g., ['.py', '.js'])
        recursive: Whether to search recursively in subdirectories
        
    Returns:
        List of file paths matching the criteria
    """
    if isinstance(directory, str):
        directory = pathlib.Path(directory)
    
    if not directory.exists() or not directory.is_dir():
        return []
    
    result = []
    
    if recursive:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if extensions is None or any(file.endswith(ext) for ext in extensions):
                    result.append(normalize_output_path(file_path))
    else:
        for item in directory.iterdir():
            if item.is_file():
                if extensions is None or any(str(item).endswith(ext) for ext in extensions):
                    result.append(normalize_output_path(item))
    
    return result
