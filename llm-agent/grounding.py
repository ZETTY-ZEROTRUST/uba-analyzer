"""ZETI UBA — Grounding validator for LLM output.

Spec: every MITRE technique id in the LLM's output must exist in the local
``mitre-attack`` ES index; every CVE id must exist in ``cve-cache.json`` or
pass an NVD lookup. Invalid ids are stripped from the output and counted.

The resulting validation record is stored at ``uba-alerts.grounding_validation``
(nested) in ES so downstream dashboards can flag noisy LLM versions.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from elasticsearch import Elasticsearch, NotFoundError

MITRE_INDEX = "mitre-attack"
CVE_CACHE_PATH = Path(
    os.environ.get("CVE_CACHE_PATH", "/opt/zeti-uba/llm-agent/cve-cache.json")
)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class ValidationResult:
    mitre_id_valid: bool = True
    cve_id_valid: bool = True
    hallucination_count: int = 0
    removed_mitre_ids: list[str] = field(default_factory=list)
    removed_cve_ids: list[str] = field(default_factory=list)


def _load_cve_cache() -> set[str]:
    if not CVE_CACHE_PATH.exists():
        return set()
    try:
        data = json.loads(CVE_CACHE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    if isinstance(data, dict):
        return {k for k in data.keys() if CVE_ID_RE.match(k)}
    if isinstance(data, list):
        return {item for item in data if isinstance(item, str) and CVE_ID_RE.match(item)}
    return set()


def _mitre_id_exists(es: Elasticsearch, technique_id: str) -> bool:
    if not MITRE_ID_RE.match(technique_id):
        return False
    try:
        return bool(es.exists(index=MITRE_INDEX, id=technique_id))
    except NotFoundError:
        return False


def _nvd_id_exists(cve_id: str, api_key: str | None = None, timeout: float = 5.0) -> bool:
    if not CVE_ID_RE.match(cve_id):
        return False
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = requests.get(
            NVD_API,
            params={"cveId": cve_id},
            headers=headers,
            timeout=timeout,
        )
    except requests.RequestException:
        return False
    if resp.status_code != 200:
        return False
    payload = resp.json()
    return int(payload.get("totalResults", 0)) > 0


def _mapping_id(mapping: Any) -> str:
    """A mitre/cve mapping entry may be a bare id string or a dict — the LLM
    is not perfectly consistent. Pull the id out of whichever shape arrived."""
    if isinstance(mapping, str):
        return mapping.strip()
    if isinstance(mapping, dict):
        return str(mapping.get("id") or mapping.get("technique_id")
                   or mapping.get("cve_id") or "").strip()
    return ""


def _as_mapping_list(value: Any) -> list[Any]:
    """``mitre_mapping`` / ``cve_mapping`` may arrive as a flat list, as a
    single mapping dict, or as a dict that wraps the list under a key
    (e.g. ``{"techniques": [...]}``). Normalise to a flat list of entries so
    the validator never mistakes a wrapper key for an id."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        if any(k in value for k in ("id", "technique_id", "cve_id")):
            return [value]  # a single mapping entry
        for inner in value.values():
            if isinstance(inner, list):
                return inner  # unwrap {"techniques": [...]}
        return []
    return []


def validate_llm_output(
    llm_response: dict[str, Any],
    es: Elasticsearch,
    nvd_api_key: str | None = None,
) -> tuple[dict[str, Any], ValidationResult]:
    """Strip hallucinated MITRE/CVE ids from ``llm_response`` in place.

    ``llm_response`` is the parsed JSON object from Phase 3a or Phase 3b.
    Returns the cleaned response and a ``ValidationResult`` summary.
    """
    result = ValidationResult()
    cve_cache = _load_cve_cache()

    cleaned_mitre = []
    for mapping in _as_mapping_list(llm_response.get("mitre_mapping")):
        tid = _mapping_id(mapping)
        if _mitre_id_exists(es, tid):
            cleaned_mitre.append(mapping if isinstance(mapping, dict) else {"id": tid})
        else:
            result.mitre_id_valid = False
            result.hallucination_count += 1
            result.removed_mitre_ids.append(tid)
    llm_response["mitre_mapping"] = cleaned_mitre

    cleaned_cve = []
    for mapping in _as_mapping_list(llm_response.get("cve_mapping")):
        cid = _mapping_id(mapping)
        in_cache = cid in cve_cache
        if in_cache or _nvd_id_exists(cid, api_key=nvd_api_key):
            cleaned_cve.append(mapping if isinstance(mapping, dict) else {"id": cid})
        else:
            result.cve_id_valid = False
            result.hallucination_count += 1
            result.removed_cve_ids.append(cid)
    llm_response["cve_mapping"] = cleaned_cve

    return llm_response, result
