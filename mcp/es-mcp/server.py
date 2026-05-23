"""ZETI UBA — Elasticsearch MCP server.

Single tool: ``query_elasticsearch(index, query, time_range, size)``.

Spec contract:
    - ``index``  : ES index pattern (e.g. ``"logs-zeti-*"``).
    - ``query``  : Elasticsearch query DSL ``query`` clause.
    - ``time_range``: ``{"gte": "...", "lte": "...", "field": "@timestamp"}``
                    or null for no time filter.
    - ``size``   : number of hits (default 50, hard cap 500 to protect tokens).

Auth env (priority): ``ES_API_KEY`` > (``ES_USERNAME`` + ``ES_PASSWORD``).
Endpoint env: ``ES_URL`` (default ``https://localhost:9200``).
Cert verify:  ``ES_SSL_VERIFY=false`` to skip (dev only).

stdio MCP transport (Claude Code / Anthropic-side ReAct loop reads this over a pipe).
"""

from __future__ import annotations

import os
import sys
from typing import Any

from elasticsearch import Elasticsearch
from fastmcp import FastMCP

HARD_CAP_SIZE = 500
DEFAULT_SIZE = 50


def _build_client() -> Elasticsearch:
    url = os.environ.get("ES_URL", "https://localhost:9200")
    verify = os.environ.get("ES_SSL_VERIFY", "true").lower() != "false"

    api_key = os.environ.get("ES_API_KEY")
    if api_key:
        return Elasticsearch(url, api_key=api_key, verify_certs=verify, request_timeout=15)

    user = os.environ.get("ES_USERNAME")
    pwd = os.environ.get("ES_PASSWORD")
    if user and pwd:
        return Elasticsearch(url, basic_auth=(user, pwd), verify_certs=verify, request_timeout=15)

    print(
        "ES_API_KEY or (ES_USERNAME + ES_PASSWORD) is required",
        file=sys.stderr,
    )
    sys.exit(2)


_es = _build_client()
mcp = FastMCP("zeti-es-mcp")


@mcp.tool()
def query_elasticsearch(
    index: str,
    query: dict[str, Any],
    time_range: dict[str, Any] | None = None,
    size: int = DEFAULT_SIZE,
) -> dict[str, Any]:
    """Run an Elasticsearch query against ZETI indices.

    Returns ``{"total": int, "hits": [...]}``. Each hit has ``_id``, ``_source``,
    ``_score``. Caller is the LLM ReAct loop; keep results small.
    """
    size = max(1, min(int(size), HARD_CAP_SIZE))

    body_query: dict[str, Any] = query
    if time_range:
        field = time_range.get("field", "@timestamp")
        gte = time_range.get("gte")
        lte = time_range.get("lte")
        rng: dict[str, Any] = {}
        if gte is not None:
            rng["gte"] = gte
        if lte is not None:
            rng["lte"] = lte
        if rng:
            body_query = {
                "bool": {
                    "must": [query],
                    "filter": [{"range": {field: rng}}],
                }
            }

    resp = _es.search(index=index, query=body_query, size=size)
    return {
        "total": resp["hits"]["total"]["value"],
        "hits": [
            {"_id": h["_id"], "_score": h.get("_score"), "_source": h.get("_source")}
            for h in resp["hits"]["hits"]
        ],
    }


@mcp.tool()
def list_indices(pattern: str = "*") -> list[str]:
    """List ES indices matching ``pattern``. Cheap helper used during agent bootstrapping."""
    cat = _es.cat.indices(index=pattern, format="json", h="index")
    return [row["index"] for row in cat]


if __name__ == "__main__":
    mcp.run()
