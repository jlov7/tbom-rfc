#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
A reference MCP server that demonstrates TBOM integration.
Exposes its own TBOM as a resource and provides tools to verify other TBOMs.
"""

import json
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
    try:
        json.loads(tbom_json)
        # Use a temporary file for tbomctl check
        tmp_tbom = Path("tmp_verify.json")
        tmp_tbom.write_text(tbom_json, encoding="utf-8")

        # We need the schema path
        if not SCHEMA_PATH.exists():
            return "Error: TBOM schema not found on server."

        # Mocking args for cmd_check
        class Args:
            tbom = str(tmp_tbom)
            schema = str(SCHEMA_PATH)
            keys = None
            keys_schema = None
            debug = False

        # Capture stdout/stderr? For now just run and check result
        result = tbomctl.cmd_check(Args())
        tmp_tbom.unlink()

        if result == 0:
            return "TBOM is VALID (schema and digests match)."
        else:
            return "TBOM is INVALID."
    except Exception as e:
        return f"Error during verification: {e!s}"


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


if __name__ == "__main__":
    mcp.run()
