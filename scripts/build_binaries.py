#!/usr/bin/env python3
"""
Build standalone binaries for tbomctl using PyInstaller.
"""

import os
import platform
import subprocess
import sys
from pathlib import Path


def run_command(cmd, cwd=None):
    """Run a command and return True if successful."""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Command failed: {cmd}")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"Error running command {cmd}: {e}")
        return False


def build_binary(script_path, output_name, dist_dir):
    """Build a single binary using PyInstaller."""
    import subprocess
    import sys

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        output_name,
        "--distpath",
        dist_dir,
        "--specpath",
        dist_dir,
        script_path,
    ]
    print(f"Building {output_name}...")
    try:
        result = subprocess.run(cmd, cwd=os.getcwd(), capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Command failed: {' '.join(cmd)}")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"Error running PyInstaller: {e}")
        return False


def main(argv: list[str] | None = None) -> int:
    """Main build function."""
    _ = argv
    # Ensure we're in the project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)

    # Create binaries directory
    binaries_dir = project_root / "dist" / "binaries"
    binaries_dir.mkdir(parents=True, exist_ok=True)

    # Determine platform
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Build tbomctl binary
    script_path = project_root / "tbomctl.py"
    if not script_path.exists():
        print(f"Error: {script_path} not found")
        return 1

    # Create platform-specific binary name
    if system == "darwin":
        binary_name = "tbomctl-macos-arm64" if machine == "arm64" else "tbomctl-macos-x86_64"
    elif system == "linux":
        binary_name = f"tbomctl-linux-{machine}"
    elif system == "windows":
        binary_name = f"tbomctl-windows-{machine}"
    else:
        binary_name = f"tbomctl-{system}-{machine}"

    if not build_binary(script_path, binary_name, binaries_dir):
        print("Failed to build tbomctl binary")
        return 1

    # Build MCP server binary
    mcp_script_path = project_root / "tbom_mcp_server.py"
    if mcp_script_path.exists():
        mcp_binary_name = f"tbom-mcp-server-{system}-{machine}"
        if not build_binary(mcp_script_path, mcp_binary_name, binaries_dir):
            print("Failed to build MCP server binary")
            return 1

    print(f"Binaries built successfully in {binaries_dir}")
    print("Contents:")
    for binary in binaries_dir.iterdir():
        if binary.is_file():
            print(f"  {binary.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
