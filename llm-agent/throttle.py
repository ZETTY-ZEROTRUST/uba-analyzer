"""ZETI UBA — Phase 3a trigger gate (score floor + throttle + cost guard).

Spec (project memory: project-zeti-uba):
    - Phase 3a runs only when ``total_score >= max(p99_today, 50)``.
    - Throttled per target to 1/hour, with THREE exceptions that fire anyway:
        1. score jump ≥ 20 vs the target's last analysed score,
        2. an override factor (ip_user_diversity / response_sensitivity) newly fired,
        3. ``data_exfiltration_detected`` flipping from false → true.
    - Global cost guard: at most 10 LLM calls per rolling 5 minutes.

State is persisted to a JSON file so the gate survives process restarts. It is
deliberately decoupled from ES — the factor_engine indices are out of scope and
their live schema is uncertain (see project memory).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

WINDOW_THROTTLE = 3600  # per-target 1/hour
WINDOW_COST = 300       # cost-guard rolling window: 5 minutes
COST_MAX = 10           # max LLM calls per WINDOW_COST
SCORE_JUMP = 20         # exception 1 threshold
SCORE_FLOOR_MIN = 50    # floor never drops below this
OVERRIDE_FACTORS = {"ip_user_diversity", "response_sensitivity"}   # v12 영문 의미명 키


class TriggerGate:
    """Decides whether a factor_engine alert should spend a Phase 3a LLM call."""

    def __init__(self, state_path: str | Path) -> None:
        self.state_path = Path(state_path)
        self.state: dict[str, Any] = {"targets": {}, "calls": []}
        self._load()

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if isinstance(data, dict):
            self.state["targets"] = data.get("targets", {}) or {}
            self.state["calls"] = data.get("calls", []) or []

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _key(alert: dict[str, Any]) -> str:
        return f"{alert.get('target_type', '?')}:{alert.get('target_id', '?')}"

    @staticmethod
    def _active_overrides(alert: dict[str, Any]) -> set[str]:
        scores = alert.get("factor_scores") or {}
        active: set[str] = set()
        for factor in OVERRIDE_FACTORS:
            try:
                if float(scores.get(factor, 0) or 0) > 0:
                    active.add(factor)
            except (TypeError, ValueError):
                continue
        return active

    def _prune(self, now: float) -> None:
        self.state["calls"] = [t for t in self.state["calls"] if now - t < WINDOW_COST]

    def previous_score(self, alert: dict[str, Any]) -> float | None:
        """Last analysed score for this target — read BEFORE ``commit``."""
        tgt = self.state["targets"].get(self._key(alert))
        return tgt.get("last_score") if tgt else None

    # -- decision -----------------------------------------------------------

    def evaluate(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"run": bool, "reason": str}`` for one alert."""
        now = time.time()
        try:
            total = float(alert.get("total_score", 0) or 0)
        except (TypeError, ValueError):
            return {"run": False, "reason": "total_score not numeric"}

        floor = max(float(alert.get("p99_today", 0) or 0), SCORE_FLOOR_MIN)
        if total < floor:
            return {"run": False, "reason": f"below score floor ({total:.0f} < {floor:.0f})"}

        self._prune(now)
        if len(self.state["calls"]) >= COST_MAX:
            return {"run": False, "reason": f"cost guard ({COST_MAX} LLM calls/5min reached)"}

        tgt = self.state["targets"].get(self._key(alert))
        if tgt is None or (now - tgt.get("last_run", 0)) >= WINDOW_THROTTLE:
            return {"run": True, "reason": "hourly window open"}

        # Within the 1/hour window — only the three exceptions get through.
        delta = total - float(tgt.get("last_score", total))
        if delta >= SCORE_JUMP:
            return {"run": True, "reason": f"exception: score jump +{delta:.0f}"}

        new_overrides = self._active_overrides(alert) - set(tgt.get("override_active", []))
        if new_overrides:
            return {"run": True, "reason": f"exception: override factor newly fired {sorted(new_overrides)}"}

        if alert.get("data_exfiltration_detected") and not tgt.get("exfil", False):
            return {"run": True, "reason": "exception: data_exfiltration_detected flipped true"}

        return {"run": False, "reason": "throttled (1/hour, no exception met)"}

    def commit(self, alert: dict[str, Any]) -> None:
        """Record that a Phase 3a LLM call is being spent on ``alert``.

        Call this immediately before invoking the ReAct loop, AFTER reading
        ``previous_score`` — it overwrites the target's last analysed score.
        """
        now = time.time()
        self.state["targets"][self._key(alert)] = {
            "last_run": now,
            "last_score": float(alert.get("total_score", 0) or 0),
            "override_active": sorted(self._active_overrides(alert)),
            "exfil": bool(alert.get("data_exfiltration_detected")),
        }
        self.state["calls"].append(now)
        self._prune(now)
        self._save()
