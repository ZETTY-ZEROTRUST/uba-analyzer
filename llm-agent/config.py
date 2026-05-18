"""ZETI UBA — Runtime configuration for the ReAct orchestrator.

Centralises everything the orchestrator + MCP router need so deployment can be
re-pointed with env vars and no code change. Defaults assume the UBA server
layout (``/opt/zeti-uba``); on a dev box override ``ZETI_ROOT``.

Env vars
--------
ANTHROPIC_API_KEY     (required) — read by the anthropic SDK directly.
ZETI_ROOT             deploy root (default ``/opt/zeti-uba``).
UBA_HAIKU_MODEL       Phase 3a model id.
UBA_SONNET_MODEL      Phase 3b model id.
UBA_ES_URL / UBA_ES_API_KEY / UBA_ES_SSL_VERIFY
                      write-capable ES creds for uba-alerts / uba-intelligence
                      + grounding lookups. Falls back to the read-only es-mcp
                      .env when unset (writes will then 403 — see project memory).
NVD_API_KEY           optional — lifts NVD rate limit 5→50 req/30s.
ES_MCP_PYTHON / ES_MCP_SERVER   override the es-mcp launch command.
MITRE_MCP_CMD / MITRE_MCP_ARGS  override the mitre-attack-mcp launch command.
CVE_MCP_CMD / CVE_MCP_ARGS      override the cve-mcp launch command.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any

# --- Paths -----------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = REPO_ROOT / "llm-agent"
PROMPTS_DIR = REPO_ROOT / "prompts"

# On the UBA server everything is deployed under /opt/zeti-uba.
DEPLOY_ROOT = Path(os.environ.get("ZETI_ROOT", "/opt/zeti-uba"))

STATE_PATH = Path(
    os.environ.get("UBA_STATE_PATH", str(DEPLOY_ROOT / "logs" / "orchestrator-state.json"))
)

# --- Models ----------------------------------------------------------------
HAIKU_MODEL = os.environ.get("UBA_HAIKU_MODEL", "claude-haiku-4-5-20251001")
SONNET_MODEL = os.environ.get("UBA_SONNET_MODEL", "claude-sonnet-4-6")

# --- ReAct loop limits -----------------------------------------------------
PHASE_3A_MAX_ITERS = 5
PHASE_3B_MAX_ITERS = 8
MAX_TOKENS = 4096

# Tool results are fed straight back into the agent context — cap their size
# so a large ES hit set cannot blow the token budget.
TOOL_RESULT_CHAR_CAP = 6000


def _split(value: str) -> list[str]:
    return shlex.split(value) if value else []


def _load_dotenv(path: Path) -> dict[str, str]:
    """Minimal .env reader (KEY=VALUE, ignores blanks/comments)."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def _es_mcp_env() -> dict[str, str]:
    return _load_dotenv(DEPLOY_ROOT / "mcp" / "es-mcp" / ".env")


def mcp_server_specs() -> dict[str, dict[str, Any]]:
    """Launch spec ({command, args, env}) for each stdio MCP server.

    Keys: ``es`` (self-written), ``mitre`` (stoyky/mitre-attack-mcp),
    ``cve`` (mukul975/cve-mcp-server).
    """
    es_dir = DEPLOY_ROOT / "mcp" / "es-mcp"
    cve_dir = DEPLOY_ROOT / "mcp" / "cve-mcp"

    cve_env: dict[str, str] = {}
    if os.environ.get("NVD_API_KEY"):
        cve_env["NVD_API_KEY"] = os.environ["NVD_API_KEY"]

    return {
        "es": {
            "command": os.environ.get("ES_MCP_PYTHON", str(es_dir / ".venv" / "bin" / "python")),
            "args": [os.environ.get("ES_MCP_SERVER", str(es_dir / "server.py"))],
            "env": _es_mcp_env(),
        },
        "mitre": {
            "command": os.environ.get(
                "MITRE_MCP_CMD", str(Path.home() / ".local" / "bin" / "mitre-attack-mcp")
            ),
            # mitre-attack-mcp takes the STIX data dir as `--data-dir DIR` (named arg).
            "args": _split(
                os.environ.get(
                    "MITRE_MCP_ARGS",
                    f"--data-dir {DEPLOY_ROOT / 'mcp' / 'mitre-data'}",
                )
            ),
            "env": {},
        },
        "cve": {
            "command": os.environ.get(
                "CVE_MCP_CMD", str(cve_dir / ".venv" / "bin" / "cve-mcp")
            ),
            "args": _split(os.environ.get("CVE_MCP_ARGS", "")),
            "env": cve_env,
        },
    }


def es_write_config() -> dict[str, Any]:
    """ES connection used by the orchestrator itself (grounding + alert writes).

    Prefers the write-capable ``UBA_ES_*`` creds; falls back to the read-only
    es-mcp key (alert writes will then fail with 403 — provision a write key).
    """
    es_env = _es_mcp_env()
    verify_raw = os.environ.get("UBA_ES_SSL_VERIFY") or es_env.get("ES_SSL_VERIFY", "true")
    return {
        "url": os.environ.get("UBA_ES_URL") or es_env.get("ES_URL", "https://localhost:9200"),
        "api_key": os.environ.get("UBA_ES_API_KEY") or es_env.get("ES_API_KEY"),
        "verify": str(verify_raw).lower() != "false",
    }


NVD_API_KEY = os.environ.get("NVD_API_KEY")
