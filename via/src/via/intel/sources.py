# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Data sources: CVE JSON 5 records, CISA KEV, FIRST EPSS, cvelistV5 delta log, CERT-FR feeds,
package advisories of the distributions (Red Hat, OSV; v0.23.0), Google Threat Intelligence
(optional, licensed).

All network access goes through one httpx client (it honours HTTPS_PROXY, NO_PROXY, SSL_CERT_FILE)
and a small file cache, so a daily run does not refetch what it already has. With `fixtures_dir`,
the sources read local files only (tests, air-gapped demos).

With a relay of the sources (`relay_url`, `relay_hosts`, v0.23.4), every request to a host listed,
redirects and URLs found in the data included (CSAF documents), goes to `<relay>/<host>/<path>`
with the relay's token: one hook on the client, so no URL of a source is rewritten by hand. A
request that carries credentials (GTI's key) never goes through the relay.
"""

from __future__ import annotations

import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from ngvm.config import SourceSettings

CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


class SourceError(RuntimeError):
    pass


RELAY_TOKEN_HEADER = "X-NGVM-Relay-Token"
CREDENTIALS = ("authorization", "x-apikey", "proxy-authorization")


class Relay:
    """Sends the requests to the hosts listed through the relay of the sources (topology R)."""

    def __init__(self, url: str, hosts: list[str], token: str):
        self.url = url.rstrip("/")
        self.base = urlsplit(self.url)
        self.hosts = {h.strip().lower() for h in hosts if h.strip()}
        self.token = token
        self.routes: Counter[str] = Counter()  # "relay <host>" / "direct <host>" -> requests

    @classmethod
    def from_settings(cls, settings: SourceSettings) -> Relay | None:
        if not settings.relay_url:
            return None
        if not settings.relay_url.startswith("https://"):
            raise SourceError("relay_url must be an https URL")
        return cls(settings.relay_url, settings.relay_hosts, settings.relay_token())

    def rewrite(self, request: httpx.Request) -> None:
        """An httpx request hook: run before each request, redirects included."""
        host = (request.url.host or "").lower()
        if host == (self.base.hostname or "").lower():
            return  # already through the relay
        credentials = any(h in request.headers for h in CREDENTIALS)
        if request.url.scheme != "https" or host not in self.hosts or credentials:
            self.routes[f"direct {host}"] += 1
            return
        path = request.url.raw_path.decode("ascii")
        request.url = httpx.URL(f"{self.url}/{host}{path}")
        request.headers["Host"] = self.base.netloc
        if self.token:
            request.headers[RELAY_TOKEN_HEADER] = self.token
        self.routes[f"relay {host}"] += 1

    def route_of(self, url: str) -> str:
        host = (urlsplit(url).hostname or "").lower()
        return "relay" if host in self.hosts and url.startswith("https://") else "direct"

    def problem(self, client: httpx.Client, timeout: float = 15) -> str | None:
        """Why the relay cannot be reached, or None (v0.27.7). Any HTTP answer, an error included,
        says it is there; only a connection that cannot be made says it is not: a relay stopped
        out of its hours, an address changed, a firewall."""
        try:
            client.get(self.url + "/", timeout=timeout)
        except httpx.TransportError as exc:
            return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        return None


class SourceAuthError(SourceError):
    """The source refused the credentials (HTTP 401 / 403): stop asking it for this run."""


class GtiBudgetError(SourceError):
    """The GTI calls of the day are spent (v0.29.0): no more lookup until the next UTC day."""


class CacheFullError(SourceError):
    """The volume of the cache is full: said as it is, not as a trace of a file half written."""


CACHE_SUFFIXES = (".json", ".txt", ".none", ".tmp")


def write_cache(path: Path, text: str) -> None:
    """Write a cache file whole or not at all (a temporary file, then a rename): a reader never
    finds half a file, as a full volume left the KEV's (v0.26.0)."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        if exc.errno in (errno.ENOSPC, errno.EDQUOT):
            raise CacheFullError(
                f"the cache volume is full ({path.parent}): no space left to keep what the sources "
                "answer; give it more room (NGVM_INTEL_SIZE for the shared service) or empty it"
            ) from exc
        raise


def purge_cache(cache_dir: str | Path, max_age_hours: float, now: float | None = None) -> tuple[int, int, int]:
    """Remove the cache files older than `max_age_hours`: nothing reads them any more, and one file
    per request never removed filled the volume. (files removed, files kept, bytes kept)."""
    now = time.time() if now is None else now
    removed = kept = size = 0
    root = Path(cache_dir)
    if not root.is_dir():
        return 0, 0, 0
    for entry in os.scandir(root):
        if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(CACHE_SUFFIXES):
            continue
        try:
            stat = entry.stat(follow_symlinks=False)
            if now - stat.st_mtime > max_age_hours * 3600:
                os.unlink(entry.path)
                removed += 1
            else:
                kept += 1
                size += stat.st_size
        except OSError:
            continue  # removed meanwhile by another pass
    return removed, kept, size


def cache_validity_hours(settings: SourceSettings) -> float:
    """The longest time a cache file is read again: older, it is only room taken."""
    return max(
        settings.cve_cache_hours,
        settings.feed_cache_hours,
        settings.gti_cache_hours,
        settings.gti_missing_hours,
        settings.packages_cache_hours,
    )


GTI_BUDGET_FILE = "gti-budget.state"  # not a cache suffix: purge_cache never removes it


class DailyBudget:
    """The GTI calls of one UTC day, shared by every request, thread and process that uses this cache
    directory (v0.29.0): a file `{"day": "YYYY-MM-DD", "calls": n}` updated under an exclusive lock.
    `take()` counts one call and says whether it was within the budget."""

    _lock = threading.Lock()

    def __init__(self, path: Path, daily: int, now: Callable[[], dt.datetime] | None = None):
        self.path, self.daily = path, daily
        self._now = now or (lambda: dt.datetime.now(dt.UTC))

    def _day(self) -> str:
        return self._now().astimezone(dt.UTC).date().isoformat()

    def _read(self, handle: Any) -> dict[str, Any]:
        handle.seek(0)
        try:
            data = json.loads(handle.read() or "{}")
        except ValueError:
            data = {}
        return data if isinstance(data, dict) and data.get("day") == self._day() else {"day": self._day(), "calls": 0}

    def used(self) -> dict[str, Any]:
        """{"day", "calls", "daily"} of today; the budget untouched."""
        if not self.path.exists():
            return {"day": self._day(), "calls": 0, "daily": self.daily}
        with self._lock, open(self.path, encoding="utf-8") as handle:
            return {**self._read(handle), "daily": self.daily}

    def take(self) -> bool:
        if self.daily <= 0:
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, open(self.path, "a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                data = self._read(handle)
                if int(data.get("calls") or 0) >= self.daily:
                    return False
                data["calls"] = int(data.get("calls") or 0) + 1
                handle.seek(0)
                handle.truncate()
                handle.write(json.dumps(data))
                handle.flush()
                return True
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)


def cve_bucket(cve_id: str) -> tuple[str, str]:
    m = CVE_ID.match(cve_id)
    if not m:
        raise SourceError(f"invalid CVE id: {cve_id!r}")
    return m.group(1), f"{int(m.group(2)) // 1000}xxx"


class Sources:
    def __init__(
        self,
        settings: SourceSettings,
        fixtures_dir: str | Path | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self.settings = settings
        self.fixtures = Path(fixtures_dir) if fixtures_dir else None
        self.cache = Path(settings.cache_dir)
        self.relay = Relay.from_settings(settings)
        self._client = httpx.Client(
            timeout=settings.timeout_seconds,
            follow_redirects=True,
            transport=transport,
            headers={"User-Agent": "verdict/0.1"},
            event_hooks={"request": [self.relay.rewrite]} if self.relay else None,
        )
        self._kev: dict[str, dict[str, Any]] | None = None
        self.gti_calls = 0  # network lookups made to GTI in this run (cache hits excluded)
        self.gti_budget = DailyBudget(self.cache / GTI_BUDGET_FILE, settings.gti_daily_calls)
        self.gti_over_budget = 0  # lookups not made because the day's budget was spent (v0.29.0)
        self.cache_repaired = 0  # cache files found unreadable and fetched again (v0.26.0)
        self.cache_full = ""  # why the cache keeps nothing more in this run ("" when it does)
        self.epss_dates: dict[str, str] = {}  # cve -> day of its EPSS score (since v0.15.2)

    # -- plumbing ---------------------------------------------------------------------------
    def _cache_path(self, url: str) -> Path:
        return self.cache / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")

    def _keep(self, path: Path, text: str) -> None:
        """Keep an answer in the cache. On a full volume the answer is still used, only not kept:
        said once, in clear, and in the notes of the collection."""
        if self.cache_full:
            return
        try:
            write_cache(path, text)
        except CacheFullError as exc:
            self.cache_full = str(exc)
            print(f"WARN {exc}", file=sys.stderr)

    def _cached(self, key: str, max_age_hours: float) -> Path | None:
        path = self._cache_path(key)
        if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
            return path
        return None

    def _get_json(
        self,
        url: str,
        max_age_hours: float,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        retries_429: int = 0,
    ) -> Any:
        key = url + ("?" + json.dumps(params, sort_keys=True) if params else "")
        path = self._cache_path(key)
        if self._cached(key, max_age_hours):
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):  # half written before v0.26.0, or damaged: as if absent
                path.unlink(missing_ok=True)
                self.cache_repaired += 1
                print(f"WARN cache unreadable, fetched again: {path.name} ({url})", file=sys.stderr)
        for attempt in range(retries_429 + 1):
            try:
                resp = self._client.get(url, params=params, headers=headers)
            except httpx.HTTPError as exc:
                raise SourceError(f"GET {url}: {exc}") from exc
            if resp.status_code != 429 or attempt == retries_429:
                break
            wait = resp.headers.get("Retry-After", "")
            time.sleep(min(float(wait), 60) if wait.isdigit() else 2 * (attempt + 1))
        if resp.status_code == 404:
            return None
        if resp.status_code in (401, 403) and headers:
            raise SourceAuthError(f"GET {url}: HTTP {resp.status_code} (credentials refused)")
        if resp.status_code >= 400:
            raise SourceError(f"GET {url}: HTTP {resp.status_code}")
        data = resp.json()
        self._keep(path, json.dumps(data))
        return data

    def get_text(self, url: str, max_age_hours: float) -> str:
        path = self._cache_path(url).with_suffix(".txt")
        if path.exists() and time.time() - path.stat().st_mtime < max_age_hours * 3600:
            return path.read_text(encoding="utf-8")
        try:
            resp = self._client.get(url)
        except httpx.HTTPError as exc:
            raise SourceError(f"GET {url}: {exc}") from exc
        if resp.status_code >= 400:
            raise SourceError(f"GET {url}: HTTP {resp.status_code}")
        self._keep(path, resp.text)
        return resp.text

    def _fixture(self, name: str) -> Any:
        path = self.fixtures / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    # -- CVE records ------------------------------------------------------------------------
    def cve_record(self, cve_id: str) -> dict[str, Any] | None:
        year, bucket = cve_bucket(cve_id)
        if self.fixtures:
            return self._fixture(f"cves/{cve_id}.json")
        url = self.settings.cve_record_url.format(year=year, bucket=bucket, cve_id=cve_id)
        return self._get_json(url, self.settings.cve_cache_hours)

    def new_cve_ids(self, since: dt.datetime, include_updated: bool = False, max_age_hours: float = 1) -> list[str]:
        """CVE ids published (and optionally updated) since `since`, from cvelistV5's deltaLog."""
        if self.fixtures:
            log = self._fixture("deltaLog.json") or []
        else:
            log = self._get_json(self.settings.delta_log_url, max_age_hours) or []
        ids: list[str] = []
        for fetch in log:
            when = dt.datetime.fromisoformat(fetch["fetchTime"].replace("Z", "+00:00"))
            if when < since:
                continue
            kinds = ["new", "updated"] if include_updated else ["new"]
            for kind in kinds:
                for item in fetch.get(kind, []):
                    if item["cveId"] not in ids:
                        ids.append(item["cveId"])
        return ids

    def delta_entries(self, max_age_hours: float = 0.15) -> list[tuple[str, str, str]]:
        """Every change of cvelistV5's deltaLog (about 30 days): (CVE id, new or updated, when
        CVE.org published it, UTC ISO), newest first (v0.23.4: the chat's list_new_cves)."""
        if self.fixtures:
            log = self._fixture("deltaLog.json") or []
        else:
            log = self._get_json(self.settings.delta_log_url, max_age_hours) or []
        out: list[tuple[str, str, str, str, int]] = []
        for fetch in log:
            when = dt.datetime.fromisoformat(fetch["fetchTime"].replace("Z", "+00:00")).astimezone(dt.UTC)
            for kind in ("new", "updated"):
                for item in fetch.get(kind, []):
                    at = when.isoformat(timespec="seconds")
                    out.append((item["cveId"], kind, at, str(item.get("dateUpdated") or ""), -len(out)))
        # v0.29.0: within one fetch, the record's own dateUpdated (newest first), then the order of the
        # list: one fetch of 2026-11-21 came out oldest first, against "newest first".
        out.sort(key=lambda e: (e[2], e[3], e[4]), reverse=True)
        return [(cve, kind, at) for cve, kind, at, _, _ in out]

    # -- KEV --------------------------------------------------------------------------------
    def kev(self) -> dict[str, dict[str, Any]]:
        if self._kev is None:
            if self.fixtures:
                data = self._fixture("kev.json") or {"vulnerabilities": []}
            else:
                data = self._get_json(self.settings.kev_url, self.settings.feed_cache_hours)
                if data is None:
                    raise SourceError("KEV feed not found")
            self._kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        return self._kev

    def kev_added_since(self, since: dt.date) -> list[str]:
        return [cve for cve, v in self.kev().items() if dt.date.fromisoformat(v["dateAdded"]) >= since]

    # -- EPSS -------------------------------------------------------------------------------
    def epss(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """cve -> (score, percentile). Missing CVEs (too recent, rejected) are simply absent.
        The day of each score is kept in `epss_dates` (since v0.15.2)."""
        out: dict[str, tuple[float, float]] = {}
        if self.fixtures:
            rows = (self._fixture("epss.json") or {}).get("data", [])
            wanted = set(cve_ids)
            rows = [r for r in rows if r["cve"] in wanted]
        else:
            rows = []
            for i in range(0, len(cve_ids), 50):
                chunk = cve_ids[i : i + 50]
                data = self._get_json(self.settings.epss_url, self.settings.feed_cache_hours, {"cve": ",".join(chunk)})
                rows.extend((data or {}).get("data", []))
        for r in rows:
            out[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
            if r.get("date"):
                self.epss_dates[r["cve"]] = r["date"]
        return out

    # -- CERT-FR -----------------------------------------------------------------------------
    def certfr_feed(self, kind: str, max_age_hours: float = 0.1) -> str:
        """RSS feed of CERT-FR publications: kind = "alerte" or "avis"."""
        if self.fixtures:
            path = self.fixtures / "certfr" / f"{kind}.xml"
            return path.read_text(encoding="utf-8") if path.exists() else ""
        return self.get_text(f"{self.settings.certfr_url}/{kind}/feed/", max_age_hours)

    def certfr_item(self, link: str) -> dict[str, Any] | None:
        """Structured view (JSON) of one CERT-FR publication, from its page link."""
        ref = link.rstrip("/").rsplit("/", 1)[-1]
        if self.fixtures:
            return self._fixture(f"certfr/{ref}.json")
        return self._get_json(link.rstrip("/") + "/json/", 24)

    # -- any feed (watch mode) -------------------------------------------------------------------
    @staticmethod
    def fixture_name(url: str) -> str:
        return re.sub(r"[^A-Za-z0-9.]+", "_", url.split("://", 1)[-1]).strip("_")

    def fetch_text(self, url: str, max_age_hours: float = 0.1) -> str:
        if self.fixtures:
            path = self.fixtures / "feeds" / self.fixture_name(url)
            return path.read_text(encoding="utf-8") if path.exists() else ""
        return self.get_text(url, max_age_hours)

    def fetch_json(self, url: str, max_age_hours: float = 0.1) -> Any:
        if self.fixtures:
            text = self.fetch_text(url)
            return json.loads(text) if text else None
        return self._get_json(url, max_age_hours)

    # -- package advisories of the distributions (D20, v0.23.0) -----------------------------------
    def package_advisory(self, source: str, cve_id: str) -> dict[str, Any] | None:
        """Raw advisory of one distribution for one CVE: Red Hat's security data, or the OSV entry of
        Debian or Ubuntu; None when it has none. Only the CVE id leaves; an answer without an
        advisory is cached too, so a CVE that concerns no distribution is not asked again."""
        cve_bucket(cve_id)
        if self.fixtures:
            name = cve_id if source == "redhat" else f"{source.upper()}-{cve_id}"
            return self._fixture(f"packages/{source}/{name}.json")
        if source == "redhat":
            url = self.settings.redhat_url.format(cve_id=cve_id)
        elif source in ("debian", "ubuntu"):
            url = self.settings.osv_url.format(id=f"{source.upper()}-{cve_id}")
        else:
            raise SourceError(f"unknown package source {source!r}")
        marker = self._cache_path(url).with_suffix(".none")
        hours = self.settings.packages_cache_hours
        if marker.exists() and time.time() - marker.stat().st_mtime < hours * 3600:
            return None
        data = self._get_json(url, hours)
        if data is None:
            self._keep(marker, "")
        return data

    # -- Google Threat Intelligence ---------------------------------------------------------------
    def gti_url(self, cve_id: str) -> str:
        cve_bucket(cve_id)  # validates the id before it goes anywhere
        return f"{self.settings.gti_url.rstrip('/')}/collections/vulnerability--{cve_id.lower()}"

    def _gti_missing(self, url: str) -> Path:
        return self._cache_path(url).with_suffix(".none")

    def gti_cached(self, cve_id: str) -> bool:
        """The answer is in the cache, or GTI said it did not know the CVE within gti_missing_hours
        (v0.29.0): no call, no budget."""
        url = self.gti_url(cve_id)
        if self._cached(url, self.settings.gti_cache_hours) is not None:
            return True
        marker = self._gti_missing(url)
        return marker.exists() and time.time() - marker.stat().st_mtime < self.settings.gti_missing_hours * 3600

    def gti_vulnerability(self, cve_id: str) -> dict[str, Any] | None:
        """GTI's vulnerability object of one CVE, or None when GTI does not know it. A 404 is kept as a
        marker for gti_missing_hours (v0.29.0: it was asked again at every request). A lookup beyond
        the day's budget raises GtiBudgetError."""
        if self.fixtures:
            return self._fixture(f"gti/{cve_id}.json")
        key = self.settings.gti_api_key
        if not key:
            raise SourceAuthError(f"GTI API key missing: set the variable {self.settings.gti_api_key_env}")
        url = self.gti_url(cve_id)
        if self._cached(url, self.settings.gti_cache_hours) is None:
            marker = self._gti_missing(url)
            if marker.exists() and time.time() - marker.stat().st_mtime < self.settings.gti_missing_hours * 3600:
                return None
            if not self.gti_budget.take():
                self.gti_over_budget += 1
                raise GtiBudgetError(f"GTI: daily budget of {self.settings.gti_daily_calls} calls spent")
            self.gti_calls += 1
        data = self._get_json(url, self.settings.gti_cache_hours, headers={"x-apikey": key}, retries_429=3)
        if data is None:
            self._keep(self._gti_missing(url), "")
        return data

    def gti_search(self, query: str, limit: int = 40, max_age_hours: float = 1) -> list[dict[str, Any]]:
        """GTI vulnerability objects matching a search filter (v0.22.0): GET {gti_url}/collections
        ?filter=<query>. Only the filter leaves the network: a technology name or the radar's criteria,
        never a client. Counts as one call."""
        if self.fixtures:
            name = hashlib.sha256(query.encode()).hexdigest()[:16]
            data = self._fixture(f"gti/search/{name}.json") or {}
            return list(data.get("data") or [])
        key = self.settings.gti_api_key
        if not key:
            raise SourceAuthError(f"GTI API key missing: set the variable {self.settings.gti_api_key_env}")
        url = f"{self.settings.gti_url.rstrip('/')}/collections"
        params = {"filter": query, "limit": str(limit), "order": "last_modification_date-"}
        if not self._cached(url + "?" + json.dumps(params, sort_keys=True), max_age_hours):
            if not self.gti_budget.take():
                self.gti_over_budget += 1
                raise GtiBudgetError(f"GTI: daily budget of {self.settings.gti_daily_calls} calls spent")
            self.gti_calls += 1
        data = self._get_json(url, max_age_hours, params=params, headers={"x-apikey": key}, retries_429=3)
        return list((data or {}).get("data") or [])

    def close(self) -> None:
        self._client.close()
