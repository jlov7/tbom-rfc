#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
A reference MCP server that demonstrates TBOM integration.
Exposes its own TBOM as a resource and provides tools to verify other TBOMs.
"""

import contextlib
import io
import json
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import tbomctl

# Initialize FastMCP server
mcp = FastMCP("TBOM Reference Server")

# Assume the TBOM for this server is in the current directory or relative to this script
TBOM_PATH = Path(__file__).parent / "tbom-example-full-v1.0.2.json"
SCHEMA_PATH = Path(__file__).parent / "tbom-schema-v1.0.2.json"


@mcp.resource("tbom://self")
def get_own_tbom() -> str:
    """
    Returns the TBOM (Tool Bill of Materials) for this MCP server.
    """
    if TBOM_PATH.exists():
        return TBOM_PATH.read_text(encoding="utf-8")
    return json.dumps({"error": "TBOM not found for this server."})


@mcp.tool()
def verify_tbom(tbom_json: str) -> str:
    """
    Verify a TBOM JSON string against the standard schema and internal digests.
    """
    tmp_path: Path | None = None
    try:
        json.loads(tbom_json)

        # We need the schema path
        if not SCHEMA_PATH.exists():
            return "Error: TBOM schema not found on server."

        # Use secure temporary file with proper cleanup
        fd, tmp_name = tempfile.mkstemp(suffix=".json", text=True)
        tmp_path = Path(tmp_name)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(tbom_json)

        # Mocking args for cmd_check
        class Args:
            tbom = str(tmp_path)
            schema = str(SCHEMA_PATH)
            keys = None
            keys_schema = None
            debug = False

        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = tbomctl.cmd_check(Args())

        if result == 0:
            return "TBOM is VALID (schema and digests match)."
        details = output.getvalue().strip()
        if details:
            return f"TBOM is INVALID.\n{details}"
        return "TBOM is INVALID."
    except Exception as e:
        return f"Error during verification: {e!s}"
    finally:
        # Ensure cleanup even if an exception occurs
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)


@mcp.tool()
def get_tool_digest(name: str, description: str, input_schema_json: str) -> str:
    """
    Compute the definitionDigest for a tool definition.
    """
    try:
        tool = {"name": name, "description": description, "inputSchema": json.loads(input_schema_json)}
        _, digest = tbomctl.compute_tool_digest(tool)
        return digest
    except Exception as e:
        return f"Error: {e!s}"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
