"""MCP server exposing the local plaude CLI as callable tools.

This runs `plaude list` / `plaude sync` as subprocesses so the BLE + crypto
logic stays inside the CLI and this server stays a thin, safe wrapper.

Run (stdio, for hermes/claude):
  venv/bin/python scripts/mcp_plaude_server.py

Run (HTTP, for bifrost mcp.client_configs):
  venv/bin/python scripts/mcp_plaude_server.py --transport http --host 0.0.0.0 --port 8844

The `--plaude` flag overrides the CLI entry point (default:
  /Users/terafin/Projects/plaude/openplaudit/venv/bin/plaude )
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

DEFAULT_PLAUDE = "/Users/terafin/Projects/plaude/openplaudit/venv/bin/plaude"

mcp = MCPServer("plaude")


PLAUDE_EXE: str = DEFAULT_PLAUDE


def _run_plaude(cli_args: list[str], timeout: float = 600.0) -> dict:
    """Run the plaude CLI and return a JSON-friendly result."""
    try:
        proc = subprocess.run(
            [PLAUDE_EXE, *cli_args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {timeout:.0f}s"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


@mcp.tool()
def plaude_list(verbose: bool = False) -> str:
    """List recordings currently on the PLAUD device (no download)."""
    return json.dumps(_run_plaude(["--verbose" if verbose else "-q", "list"]), indent=2)


@mcp.tool()
def plaude_sync(verbose: bool = False) -> str:
    """Connect to the PLAUD device, download any new recordings, decode to WAV.

    Requires the device to be awake (tap the Record button) and idle (not
    currently recording). Returns per-recording results.
    """
    return json.dumps(_run_plaude(["--verbose" if verbose else "-q", "sync"]), indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8844)
    parser.add_argument("--plaude", default=DEFAULT_PLAUDE, help="path to the plaude CLI")
    args = parser.parse_args()

    global PLAUDE_EXE
    PLAUDE_EXE = args.plaude

    if args.transport == "http":
        mcp.run(transport="http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
