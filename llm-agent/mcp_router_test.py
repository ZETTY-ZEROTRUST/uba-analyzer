"""ZETI UBA — MCPRouter end-to-end test against the live MCP servers.

Exercises the actual ``MCPRouter.dispatch`` wrappers (MITRE / NVD / ES) so the
schema-driven argument building is verified before a full Phase 3a smoke test.

    /opt/zeti-uba/llm-agent/.venv/bin/python /opt/zeti-uba/llm-agent/mcp_router_test.py
"""

from __future__ import annotations

import asyncio
import sys

sys.path.insert(0, "/opt/zeti-uba/llm-agent")

from mcp_router import MCPRouter

CASES = [
    ("search_mitre_attack", {"keywords": "T1110"}),
    ("search_mitre_attack", {"keywords": "credential access"}),
    ("search_nvd_cve", {"query": "CVE-2024-3400"}),
    ("query_elasticsearch", {"index": "uba-alerts-sample",
                             "query": {"match_all": {}}, "size": 1}),
]


async def main() -> None:
    async with MCPRouter() as router:
        print("connected — tool counts:", flush=True)
        for key, tools in router.tool_index.items():
            print(f"  {key}: {len(tools)} tools")
        for name, args in CASES:
            print(f"\n--- {name} {args} ---", flush=True)
            out = await router.dispatch(name, args)
            verdict = "ERROR" if out.lstrip().startswith('{"error"') else "OK"
            print(f"[{verdict}] {out[:700]}")


if __name__ == "__main__":
    asyncio.run(main())
