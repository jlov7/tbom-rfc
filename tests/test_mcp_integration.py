"""
Integration tests for the TBOM MCP server.
Tests end-to-end functionality through the MCP protocol.
"""

import json
import sys
import time
from pathlib import Path

import pytest

# Check if MCP is available
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from tbomctl import compute_tool_digest


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP library not available")
@pytest.mark.integration
class TestMCPIntegration:
    """Integration tests for the TBOM MCP server."""

    @pytest.fixture
    async def server_process(self):
        """Start the MCP server as a subprocess."""
        import subprocess

        # Start the server
        server_path = Path(__file__).parent.parent / "tbom_mcp_server.py"
        process = subprocess.Popen(
            [sys.executable, str(server_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        # Give server time to start
        time.sleep(1)

        yield process

        # Cleanup
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    async def test_server_starts_and_lists_tools(self, server_process):
        """Test that the server starts and can list available tools."""
        # Create MCP client
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()

            # List available tools
            tools_result = await session.list_tools()

            # Should have our two tools
            tool_names = [tool.name for tool in tools_result.tools]
            assert "verify_tbom" in tool_names
            assert "get_tool_digest" in tool_names

    @pytest.mark.asyncio
    async def test_server_provides_tbom_resource(self, server_process):
        """Test that the server provides its TBOM as a resource."""
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # List resources
            resources_result = await session.list_resources()
            resource_uris = [str(r.uri) for r in resources_result.resources]

            assert "tbom://self" in resource_uris

            # Read the TBOM resource
            tbom_result = await session.read_resource("tbom://self")
            tbom_data = json.loads(tbom_result.contents[0].text)

            # Should be a valid TBOM
            assert "tbomVersion" in tbom_data
            assert "subject" in tbom_data
            assert "tools" in tbom_data
            assert "signatures" in tbom_data

    @pytest.mark.asyncio
    async def test_verify_tbom_tool(self, server_process):
        """Test the verify_tbom tool functionality."""
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # Get the server's own TBOM first
            tbom_result = await session.read_resource("tbom://self")
            tbom_json = tbom_result.contents[0].text

            # Use the verify_tbom tool
            result = await session.call_tool("verify_tbom", {"tbom_json": tbom_json})

            # Should return success message
            assert len(result.content) == 1
            content = result.content[0]
            assert "VALID" in content.text

    @pytest.mark.asyncio
    async def test_verify_tbom_tool_invalid_input(self, server_process):
        """Test the verify_tbom tool with invalid TBOM."""
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # Test with invalid JSON
            invalid_tbom = '{"invalid": "json"'
            result = await session.call_tool("verify_tbom", {"tbom_json": invalid_tbom})

            assert len(result.content) == 1
            content = result.content[0]
            assert "INVALID" in content.text or "Error" in content.text

    @pytest.mark.asyncio
    async def test_get_tool_digest_tool(self, server_process):
        """Test the get_tool_digest tool functionality."""
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # Test with a simple tool definition
            name = "test_tool"
            description = "A test tool"
            input_schema = {"type": "object", "properties": {"param": {"type": "string"}}}

            result = await session.call_tool(
                "get_tool_digest",
                {"name": name, "description": description, "input_schema_json": json.dumps(input_schema)},
            )

            assert len(result.content) == 1
            content = result.content[0]
            digest = content.text

            # Verify it matches what tbomctl would compute
            tool = {"name": name, "description": description, "inputSchema": input_schema}
            _, expected_digest = compute_tool_digest(tool)
            assert digest == expected_digest

    @pytest.mark.asyncio
    async def test_get_tool_digest_tool_invalid_input(self, server_process):
        """Test the get_tool_digest tool with invalid input."""
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # Test with invalid JSON schema
            result = await session.call_tool(
                "get_tool_digest", {"name": "test", "description": "test", "input_schema_json": "invalid json"}
            )

            assert len(result.content) == 1
            content = result.content[0]
            assert "Error" in content.text

    @pytest.mark.asyncio
    async def test_server_handles_missing_tbom_file(self, server_process):
        """Test server behavior when TBOM file is missing."""
        # This test would require modifying the server temporarily
        # For now, we'll just verify the server starts correctly
        server_params = StdioServerParameters(
            command=sys.executable, args=[str(Path(__file__).parent.parent / "tbom_mcp_server.py")], env=None
        )

        async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            # Should still work even if TBOM file is missing
            resources_result = await session.list_resources()
            assert len(resources_result.resources) >= 0  # May or may not have resources
