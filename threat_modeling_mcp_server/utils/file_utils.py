"""File utility functions for the Threat Modeling MCP Server."""

import os
from pathlib import Path, PurePosixPath
from typing import Tuple, Union


def resolve_export_paths(
    project_directory: Union[str, Path],
    output_path: Union[str, Path],
) -> Tuple[str, str, str]:
    """Resolve every export path inside the selected project's .threatmodel.

    Caller-supplied directory components are intentionally discarded. The
    requested path selects only the shared base filename for the Threat
    Composer JSON, Markdown, and extended snapshot artifacts.

    Args:
        project_directory: Authoritative directory being threat modeled
        output_path: Requested base filename, optionally with an extension

    Returns:
        Absolute paths for the Threat Composer JSON (``.tc.json``), Markdown
        (``.md``), and extended server-state snapshot (``.extended.json``)

    Raises:
        ValueError: If no project is selected, the filename is invalid, or a
            resolved path would escape the selected project's .threatmodel
    """
    if not project_directory:
        raise ValueError(
            "No project directory is selected. Call "
            'manage_workflow(action="set_project", directory=...) before export.'
        )

    requested = str(output_path)
    if not requested:
        raise ValueError("output_path must select a non-empty filename.")

    # Treat both POSIX and Windows separators as directory separators so an
    # absolute or nested request can only contribute its final filename.
    filename = PurePosixPath(requested.replace("\\", "/")).name
    if filename in {"", ".", ".."}:
        raise ValueError("output_path must select a valid filename.")

    if filename.endswith(".tc.json"):
        base_filename = filename[:-len(".tc.json")]
    elif filename.endswith(".extended.json"):
        base_filename = filename[:-len(".extended.json")]
    elif filename.endswith(".json"):
        base_filename = filename[:-len(".json")]
    elif filename.endswith(".md"):
        base_filename = filename[:-len(".md")]
    else:
        base_filename = os.path.splitext(filename)[0]
    if base_filename in {"", ".", ".."}:
        raise ValueError("output_path must select a valid base filename.")

    project_path = Path(project_directory).expanduser().resolve()
    threatmodel_candidate = project_path / ".threatmodel"
    threatmodel_candidate.mkdir(parents=True, exist_ok=True)
    threatmodel_path = threatmodel_candidate.resolve()

    if not threatmodel_path.is_relative_to(project_path):
        raise ValueError(
            "The selected project's .threatmodel directory resolves outside "
            "the project directory."
        )

    json_path = (threatmodel_path / f"{base_filename}.tc.json").resolve()
    markdown_path = (threatmodel_path / f"{base_filename}.md").resolve()
    extended_path = (threatmodel_path / f"{base_filename}.extended.json").resolve()
    for resolved_path in (json_path, markdown_path, extended_path):
        if not resolved_path.is_relative_to(threatmodel_path):
            raise ValueError(
                "The resolved export path is outside the selected project's "
                ".threatmodel directory."
            )

    return str(json_path), str(markdown_path), str(extended_path)
