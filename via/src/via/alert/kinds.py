# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The kind of an alert mail (v0.29.0): Alerte, Hot Topic or Information.

The kind is what the client sees first: the colour of the tag and the subject. It follows rules of
the profile (`alerts.kinds`), the first that matches wins, in one of two lists: `triaged` when the
last daily run decided a CVE of the alert on an asset of the tenant (its decision: ACT, ATTEND,
TRACK), `untriaged` when it has not yet (a CVE newer than the run). No rule matched: Information.
The `level` of the watch (urgent, info) stays what decides whether an alert is drafted at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

KINDS = ("alerte", "hot_topic", "information")  # strongest first
DECISIONS = ("ACT", "ATTEND", "TRACK")  # strongest first

DEFAULT_RULES: dict[str, list[dict[str, Any]]] = {
    "triaged": [
        {"kind": "alerte", "when": {"decision": "ACT"}},
        {"kind": "hot_topic", "when": {"decision": "ATTEND", "kev": True}},
        {"kind": "hot_topic", "when": {"decision": "ATTEND", "epss_min": 0.10}},
    ],
    "untriaged": [
        {"kind": "alerte", "when": {"kev": True}},
        {"kind": "hot_topic", "when": {"kev": False, "epss_min": 0.80}},
    ],
}


@dataclass(frozen=True)
class Kind:
    kind: str  # alerte | hot_topic | information
    triaged: bool
    decision: str  # the strongest decision of the run on the alert's assets, "" when not triaged
    rule: dict[str, Any]  # the rule that matched, {} for information

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "triaged": self.triaged, "decision": self.decision, "rule": dict(self.rule)}


def rules(alerts_section: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """The rules of the profile, each list defaulting to DEFAULT_RULES."""
    given = (alerts_section or {}).get("kinds") or {}
    return {name: list(given.get(name, DEFAULT_RULES[name])) for name in ("triaged", "untriaged")}


def _matches(when: dict[str, Any], facts: dict[str, Any]) -> bool:
    for key, want in when.items():
        if key == "decision":
            wanted = [want] if isinstance(want, str) else list(want)
            if facts.get("decision") not in wanted:
                return False
        elif key == "kev":
            if bool(facts.get("kev")) != bool(want):
                return False
        elif key in ("epss_min", "cvss_min"):
            value = facts.get(key[:-4])
            if value is None or value < float(want):
                return False
        else:
            return False
    return True


def classify(facts: dict[str, Any], section: dict[str, Any] | None = None) -> Kind:
    """The kind for `facts`: decision (ACT, ATTEND, TRACK or "" when not triaged), kev, epss, cvss."""
    triaged = bool(facts.get("decision"))
    for rule in rules(section)["triaged" if triaged else "untriaged"]:
        if rule.get("kind") in KINDS and _matches(rule.get("when") or {}, facts):
            return Kind(rule["kind"], triaged, facts.get("decision") or "", dict(rule))
    return Kind("information", triaged, facts.get("decision") or "", {})


def strongest_decision(levels: list[str]) -> str:
    known = [d for d in levels if d in DECISIONS]
    return min(known, key=DECISIONS.index) if known else ""


def facts_of(alert: Any, decisions: dict[tuple[str, str], str] | None) -> dict[str, Any]:
    """What a rule tests on an alert: the strongest decision of the last run on the pairs (asset, CVE)
    the alert names, KEV, and the highest EPSS and CVSS of its records."""
    pairs = {(a.id, f.cve_id) for a, f in getattr(alert, "detected", [])}
    pairs |= {(a.id, c) for a, _ in getattr(alert, "exposed", []) for c in alert.item.cves}
    pairs |= {(f.asset_ref, f.cve_id) for f in getattr(alert, "findings", [])}
    decided = [decisions[p] for p in pairs if p in (decisions or {})]
    recs = alert.records
    scores = [m.score for r in recs if (m := r.best_cvss()) is not None and m.score is not None]
    return {
        "decision": strongest_decision(decided),
        "kev": alert.item.origin == "kev" or any(r.in_kev for r in recs),
        "epss": max((r.epss for r in recs if r.epss is not None), default=None),
        "cvss": max(scores, default=None),
    }


def apply(alerts: list[Any], profile: Any, decisions: dict[tuple[str, str], str] | None) -> None:
    """Set the kind of every alert, and what the sheet needs of the profile to write it."""
    sla = getattr(profile, "sla", None)
    timezone = sla.timezone if sla is not None else ("Europe/Paris" if profile.language == "fr" else "UTC")
    for a in alerts:
        a.kind = classify(facts_of(a, decisions), profile.alerts)
        a.client_name, a.timezone, a.sla = profile.name or profile.id, timezone, sla
