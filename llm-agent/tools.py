"""Anthropic Messages API tool definitions for the ZETI UBA ReAct loop.

These three tool schemas are the only ones LLM_AGENT exposes to claude-haiku-4-5
(Phase 3a) and claude-sonnet-4-6 (Phase 3b). At runtime each ``tool_use`` block
is routed to the matching MCP server over stdio:

    query_elasticsearch  → zeti-es-mcp     (Python, /opt/zeti-uba/mcp/es-mcp)
    search_mitre_attack  → mitre-attack-mcp (pipx, py3.13)
    search_nvd_cve       → cve-mcp-server   (uv, py3.12)
"""

from __future__ import annotations

from typing import Any

ES_TOOL: dict[str, Any] = {
    "name": "query_elasticsearch",
    "description": (
        "Run a query against ZETI Elasticsearch indices. Use this to enrich an alert "
        "with baseline data (UA diversity for an IP, endpoint patterns for a sub, "
        "response-byte time series, etc.). Keep `size` small — results are fed back "
        "into the agent context."
    ),
    "input_schema": {
        "type": "object",
        "required": ["index", "query"],
        "properties": {
            "index": {
                "type": "string",
                "description": "ES index or pattern (e.g. 'logs-zeti-*', 'mitre-attack').",
            },
            "query": {
                "type": "object",
                "description": "Elasticsearch query DSL `query` clause.",
            },
            "time_range": {
                "type": "object",
                "description": "Optional time filter.",
                "properties": {
                    "field": {"type": "string", "default": "@timestamp"},
                    "gte": {"type": "string"},
                    "lte": {"type": "string"},
                },
            },
            "size": {
                "type": "integer",
                "default": 50,
                "minimum": 1,
                "maximum": 500,
            },
        },
    },
}

MITRE_TOOL: dict[str, Any] = {
    "name": "search_mitre_attack",
    "description": (
        "Search the locally cached MITRE ATT&CK STIX dataset (refreshed weekly). "
        "Returns tactic/technique/sub-technique objects with id, name, description, "
        "detection, mitigations. Use this to map the dominant factor to ATT&CK "
        "technique IDs — the validator will drop any id that is not present here."
    ),
    "input_schema": {
        "type": "object",
        "required": ["keywords"],
        "properties": {
            "keywords": {
                "type": "string",
                "description": (
                    "Free-text keywords or a comma-separated list. Examples: "
                    "'credential access', 'T1606', 'exfiltration over c2'."
                ),
            },
            "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50},
        },
    },
}

NVD_TOOL: dict[str, Any] = {
    "name": "search_nvd_cve",
    "description": (
        "Search NVD for CVEs matching the query. Uses local cve-cache.json first "
        "(6 critical CVEs), then NVD API (rate-limited to 5 req/30s without an API "
        "key). Returns CVE IDs with CVSS score and short description."
    ),
    "input_schema": {
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "type": "string",
                "description": "Keyword or CVE id. Examples: 'kubernetes secrets', 'CVE-2024-3400'.",
            },
            "cvss_min": {"type": "number", "default": 7.0, "minimum": 0.0, "maximum": 10.0},
            "limit": {"type": "integer", "default": 5, "minimum": 1, "maximum": 20},
        },
    },
}

ALL_TOOLS: list[dict[str, Any]] = [ES_TOOL, MITRE_TOOL, NVD_TOOL]
