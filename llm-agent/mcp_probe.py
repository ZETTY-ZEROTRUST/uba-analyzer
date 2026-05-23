"""ZETI UBA — MCP server probe / diagnostic.

Connects to each of the 3 stdio MCP servers using the orchestrator's own
``config.mcp_server_specs()``, lists their tools, and checks whether
``mcp_router.py``'s MITRE/NVD wrapper tool-name assumptions hold against the
real servers. Run on the UBA server:

    /opt/zeti-uba/llm-agent/.venv/bin/python /opt/zeti-uba/llm-agent/mcp_probe.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, "/opt/zeti-uba/llm-agent")

import config
import mcp_router
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PER_SERVER_TIMEOUT = 280


async def _probe(key: str, spec: dict) -> None:
    print(f"\n=== {key} ===", flush=True)
    print(f"  cmd: {spec['command']} {spec.get('args')}", flush=True)
    params = StdioServerParameters(
        command=spec["command"],
        args=spec.get("args", []),
        env={**os.environ, **spec.get("env", {})},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            schemas = {t.name: (t.inputSchema or {}) for t in listed.tools}
            print(f"  OK — {len(schemas)} tools:", flush=True)
            for name in sorted(schemas):
                print(f"    - {name}")
            _check_router(key, schemas)


def _check_router(key: str, schemas: dict) -> None:
    if key == "mitre":
        pairs = [("MITRE id-lookup", mcp_router.MITRE_ID_TOOLS),
                 ("MITRE text-search", mcp_router.MITRE_TEXT_TOOLS)]
    elif key == "cve":
        pairs = [("NVD id-lookup", mcp_router.NVD_ID_TOOLS),
                 ("NVD search", mcp_router.NVD_SEARCH_TOOLS)]
    else:
        return
    print("  -- router wrapper check --", flush=True)
    for label, cands in pairs:
        picked = next((n for n in cands if n in schemas), None)
        if picked:
            schema = schemas[picked] or {}
            req = schema.get("required", [])
            props = list((schema.get("properties", {}) or {}))
            print(f"    {label}: MATCH '{picked}'  required={req} props={props}")
        else:
            print(f"    {label}: NO MATCH — candidates {cands} — FIX mcp_router.py")


async def main() -> None:
    specs = config.mcp_server_specs()
    for key in ("es", "mitre", "cve"):
        try:
            await asyncio.wait_for(_probe(key, specs[key]), timeout=PER_SERVER_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL — {type(exc).__name__}: {exc}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
