"""ZETI UBA — MCP router for the ReAct loop (includes the MITRE wrapper).

The Anthropic-side tool spec (``tools.py``) exposes exactly three tools. Two of
the three back-end MCP servers do NOT expose a matching single tool:

    query_elasticsearch  → zeti-es-mcp       — 1:1, forwarded as-is.
    search_mitre_attack  → mitre-attack-mcp  — server exposes 50+ fine-grained
                           tools; this router is the thin wrapper that turns a
                           free-text ``keywords`` call into get_object_by_attack_id
                           / get_objects_by_content lookups.
    search_nvd_cve       → cve-mcp-server    — 27 tools; routed to lookup_cve /
                           search_cves depending on whether the query is a CVE id.

The wrapper is schema-driven: on connect it reads each server's ``list_tools``
and fills the chosen tool's first required string argument, so it survives
minor arg-name differences between MCP server versions.

Usage::

    async with MCPRouter() as router:
        result_json = await router.dispatch("search_mitre_attack",
                                            {"keywords": "credential access, T1110"})
"""

from __future__ import annotations

import json
import os
import re
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import config

ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Candidate tool names per server, in preference order. The first one the
# server actually exposes wins — keeps the wrapper resilient across versions.
MITRE_ID_TOOLS = ["get_object_by_attack_id", "get_technique_by_id", "get_objects_by_attack_id"]
MITRE_TEXT_TOOLS = ["get_objects_by_content", "get_objects_by_name", "search_objects", "search"]
NVD_ID_TOOLS = ["lookup_cve", "get_cve", "cve_lookup"]
NVD_SEARCH_TOOLS = ["search_cves", "search_cve", "search"]

# ATT&CK techniques are STIX `attack-pattern` objects. The orchestrator only
# maps factors to technique IDs (grounding validates T#### only), so the MITRE
# wrapper always scopes lookups to attack-pattern — and mitre-attack-mcp's
# get_object_by_attack_id / get_objects_by_content REQUIRE that type argument.
MITRE_STIX_TYPE = "attack-pattern"


def _unwrap(call_result: Any) -> Any:
    """Flatten an MCP CallToolResult to a JSON value (or raw text)."""
    parts: list[str] = []
    for block in getattr(call_result, "content", None) or []:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(text)
    joined = "\n".join(parts).strip()
    if not joined:
        return {"error": "empty MCP response"} if getattr(call_result, "isError", False) else {}
    try:
        return json.loads(joined)
    except (json.JSONDecodeError, ValueError):
        return joined


def _aslist(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("results", "objects", "data", "hits", "techniques"):
            if isinstance(value.get(key), list):
                return value[key]
    return [value]


def _object_id(obj: Any) -> str:
    """Best-effort stable id for dedup (ATT&CK id / stix id / name)."""
    if not isinstance(obj, dict):
        return str(obj)
    for key in ("attack_id", "external_id", "id", "stix_id", "technique_id", "name"):
        if obj.get(key):
            return str(obj[key])
    return json.dumps(obj, sort_keys=True)[:120]


class MCPRouter:
    """Holds one persistent stdio session per MCP server for a loop's lifetime."""

    def __init__(self) -> None:
        self._stack: AsyncExitStack | None = None
        self.sessions: dict[str, ClientSession] = {}
        # server key -> {tool_name: input_schema}
        self.tool_index: dict[str, dict[str, dict[str, Any]]] = {}

    async def __aenter__(self) -> "MCPRouter":
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        for key, spec in config.mcp_server_specs().items():
            params = StdioServerParameters(
                command=spec["command"],
                args=spec.get("args", []),
                env={**os.environ, **spec.get("env", {})},
            )
            read, write = await self._stack.enter_async_context(stdio_client(params))
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
            self.sessions[key] = session
            self.tool_index[key] = {t.name: (t.inputSchema or {}) for t in listed.tools}
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._stack is not None:
            await self._stack.__aexit__(*exc)
            self._stack = None

    # -- low-level ----------------------------------------------------------

    def _pick_tool(self, server: str, candidates: list[str]) -> tuple[str | None, dict[str, Any]]:
        available = self.tool_index.get(server, {})
        for name in candidates:
            if name in available:
                return name, available[name]
        return None, {}

    @staticmethod
    def _fill(schema: dict[str, Any], value: str) -> dict[str, Any]:
        """Map ``value`` onto the tool's first (required) string argument."""
        props: dict[str, Any] = (schema or {}).get("properties", {}) or {}
        required: list[str] = (schema or {}).get("required", []) or []
        for name in required:
            if props.get(name, {}).get("type") in (None, "string"):
                return {name: value}
        for name, spec in props.items():
            if spec.get("type") in (None, "string"):
                return {name: value}
        return {"query": value}

    async def _call(self, server: str, tool: str, args: dict[str, Any]) -> Any:
        session = self.sessions.get(server)
        if session is None:
            raise RuntimeError(f"MCP server '{server}' not connected")
        result = await session.call_tool(tool, args)
        return _unwrap(result)

    # -- wrappers -----------------------------------------------------------

    def _mitre_args(self, tool: str, schema: dict[str, Any], value: str) -> dict[str, Any]:
        """Build args for a mitre-attack-mcp lookup tool.

        These tools require a STIX-type argument alongside the query value, so
        the generic ``_fill`` (single required arg) is not enough.
        """
        if tool == "get_object_by_attack_id":
            return {"attack_id": value, "stix_type": MITRE_STIX_TYPE}
        if tool == "get_objects_by_content":
            return {"content": value, "object_type": MITRE_STIX_TYPE}
        if tool == "get_objects_by_name":
            return {"name": value, "object_type": MITRE_STIX_TYPE}
        return self._fill(schema, value)

    async def _mitre(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        keywords = str(tool_input.get("keywords", ""))
        limit = max(1, min(int(tool_input.get("limit", 10) or 10), 50))
        tokens = [t.strip() for t in re.split(r"[,\n;]", keywords) if t.strip()]
        ids = [t.upper() for t in tokens if ATTACK_ID_RE.match(t.upper())]
        text_terms = [t for t in tokens if not ATTACK_ID_RE.match(t.upper())]

        collected: list[Any] = []
        notes: list[str] = []

        id_tool, id_schema = self._pick_tool("mitre", MITRE_ID_TOOLS)
        for tid in ids:
            if not id_tool:
                notes.append("no attack-id lookup tool on mitre-attack-mcp")
                break
            try:
                collected += _aslist(
                    await self._call("mitre", id_tool, self._mitre_args(id_tool, id_schema, tid))
                )
            except Exception as exc:  # noqa: BLE001 — surface to LLM, don't crash loop
                notes.append(f"{tid}: {exc}")

        if text_terms:
            text_tool, text_schema = self._pick_tool("mitre", MITRE_TEXT_TOOLS)
            if text_tool:
                query = " ".join(text_terms)
                try:
                    collected += _aslist(
                        await self._call(
                            "mitre", text_tool, self._mitre_args(text_tool, text_schema, query)
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    notes.append(f"text search '{query}': {exc}")
            else:
                notes.append("no content/name search tool on mitre-attack-mcp")

        # dedup, preserving order, trim to limit.
        seen: set[str] = set()
        unique: list[Any] = []
        for obj in collected:
            oid = _object_id(obj)
            if oid in seen:
                continue
            seen.add(oid)
            unique.append(obj)
            if len(unique) >= limit:
                break

        out: dict[str, Any] = {"results": unique, "count": len(unique)}
        if notes:
            out["notes"] = notes
        return out

    async def _nvd(self, tool_input: dict[str, Any]) -> dict[str, Any]:
        query = str(tool_input.get("query", "")).strip()
        cvss_min = float(tool_input.get("cvss_min", 7.0) or 0.0)
        if CVE_ID_RE.match(query):
            tool, schema = self._pick_tool("cve", NVD_ID_TOOLS)
            arg = query.upper()
        else:
            tool, schema = self._pick_tool("cve", NVD_SEARCH_TOOLS)
            arg = query
        if not tool:
            return {"error": "no usable lookup tool on cve-mcp-server", "results": []}
        raw = await self._call("cve", tool, self._fill(schema, arg))
        return {"results": raw, "cvss_min": cvss_min}

    # -- public dispatch ----------------------------------------------------

    async def dispatch(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        """Route one Anthropic ``tool_use`` block to its MCP server.

        Returns a JSON string sized for a ``tool_result`` content block. Never
        raises — back-end failures come back as ``{"error": ...}`` so the ReAct
        loop can react instead of dying.
        """
        try:
            if tool_name == "query_elasticsearch":
                payload: Any = await self._call("es", "query_elasticsearch", tool_input)
            elif tool_name == "search_mitre_attack":
                payload = await self._mitre(tool_input)
            elif tool_name == "search_nvd_cve":
                payload = await self._nvd(tool_input)
            else:
                payload = {"error": f"unknown tool '{tool_name}'"}
        except Exception as exc:  # noqa: BLE001
            payload = {"error": f"{type(exc).__name__}: {exc}"}

        text = json.dumps(payload, ensure_ascii=False, default=str)
        if len(text) > config.TOOL_RESULT_CHAR_CAP:
            text = text[: config.TOOL_RESULT_CHAR_CAP] + " …[truncated to fit context]"
        return text
