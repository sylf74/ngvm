# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The subject of a CVE record (v0.29.0): what an analyst groups "what was published since
yesterday" by. One CNA burst (WPScan's WordPress plugins, the Linux kernel's CNA) can publish
hundreds of records in an hour; listed one by one they hide everything else.

The subject is the ecosystem or product family when the record says it (WordPress, the Linux
kernel), else the vendor of its first affected product, else the CNA. WPScan and the other WordPress
CNAs give the vendor "Unknown" or the plugin's author: the CNA decides first.
"""

from __future__ import annotations

import re
from typing import Any

from ngvm.models import VulnRecord

# CNAs that publish for one ecosystem only (cveMetadata.assignerShortName, case ignored).
CNA_SUBJECTS = {
    "wpscan": "WordPress",
    "wordfence": "WordPress",
    "patchstack": "WordPress",
    "linux": "Linux kernel",
}
UNKNOWN_VENDORS = {"", "unknown", "n/a", "na", "none", "unspecified", "-"}
_WORDPRESS = re.compile(r"\bwordpress\b", re.I)
_KERNEL = re.compile(r"\blinux kernel\b|^in the linux kernel", re.I)
UNREAD = "(record not read)"


def subject(record: VulnRecord | None) -> str:
    """The subject of one record; UNREAD when the record could not be read."""
    if record is None:
        return UNREAD
    cna = (record.assigner or "").strip()
    if cna.lower() in CNA_SUBJECTS:
        return CNA_SUBJECTS[cna.lower()]
    products = [(a.vendor or "", a.product or "", " ".join(a.cpes or [])) for a in record.affected]
    for vendor, product, cpes in products:
        if _WORDPRESS.search(product) or ":wordpress:" in cpes.lower():  # target_sw of the CPE
            return "WordPress"
        if vendor.lower() == "linux" and product.lower() in ("linux", "linux kernel", "kernel"):
            return "Linux kernel"
    if _KERNEL.search(record.description or ""):
        return "Linux kernel"
    if _WORDPRESS.search(record.description or "") and re.search(r"\b(plugin|theme)\b", record.description, re.I):
        return "WordPress"
    for vendor, _product, _cpes in products:
        if vendor.strip().lower() not in UNKNOWN_VENDORS:
            return vendor.strip()
    return cna or "(unspecified)"


def group(entries: list[tuple[str, str, str]], records: dict[str, VulnRecord]) -> list[dict[str, Any]]:
    """One entry per subject of `entries` (cve, new or updated, at): its count, new and updated, the
    highest CVSS, how many in KEV, the highest EPSS, the CNAs, and every CVE id (newest first). Ranked
    by KEV, highest CVSS, then count; the tool server ranks again with the tenant's alerts."""
    out: dict[str, dict[str, Any]] = {}
    for cve, change, at in entries:
        record = records.get(cve)
        name = subject(record)
        g = out.setdefault(
            name,
            {"subject": name, "count": 0, "new": 0, "updated": 0, "max_cvss": None, "kev": 0, "max_epss": None,
             "cnas": set(), "latest": at, "cves": []},
        )  # fmt: skip
        g["count"] += 1
        g[change] += 1
        g["cves"].append(cve)
        if record is not None:
            best = record.best_cvss()
            if best and best.score is not None and (g["max_cvss"] is None or best.score > g["max_cvss"]):
                g["max_cvss"] = best.score
            if record.in_kev:
                g["kev"] += 1
            if record.epss is not None and (g["max_epss"] is None or record.epss > g["max_epss"]):
                g["max_epss"] = record.epss
            if record.assigner:
                g["cnas"].add(record.assigner)
    for g in out.values():
        g["cnas"] = sorted(g["cnas"])
    return sorted(out.values(), key=rank)


def rank(g: dict[str, Any]) -> tuple:
    """KEV first, then a tenant alert, then the highest CVSS, then the volume."""
    return (-g.get("kev", 0), -g.get("alerts", 0), -(g.get("max_cvss") or 0), -g["count"], g["subject"].lower())
