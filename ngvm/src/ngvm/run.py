# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""What a step of a run took: the duration of each phase and the memory it needed (v0.26.0).

A watch passage was killed for memory and then ran out of time without anything saying which phase
cost what (incident of 13 to 15 November 2026). Phases wrap the work, and the line they produce
goes in the log of the step; the numbers are also kept for the services that report a run.
"""

from __future__ import annotations

import resource
import time
from collections.abc import Iterator
from contextlib import contextmanager


def peak_memory_mb() -> float:
    """The most memory this process has used, in MB (ru_maxrss: KB on Linux, bytes on macOS)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / (1024 if peak > 1 << 24 else 1) / 1024, 1)


class Phases:
    """The phases of a step, in order, with their seconds; `line()` says it in one line."""

    def __init__(self):
        self.seconds: dict[str, float] = {}
        self._started: dict[str, float] = {}

    def start(self, name: str) -> None:
        """Begin a phase whose work does not fit in one block."""
        self._started[name] = time.perf_counter()

    def stop(self, name: str) -> None:
        started = self._started.pop(name, None)
        if started is not None:
            self.seconds[name] = round(self.seconds.get(name, 0.0) + time.perf_counter() - started, 1)

    @contextmanager
    def __call__(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.seconds[name] = round(self.seconds.get(name, 0.0) + time.perf_counter() - start, 1)

    def to_dict(self) -> dict[str, float]:
        return dict(self.seconds)

    def line(self) -> str:
        phases = ", ".join(f"{name} {seconds:.0f}s" for name, seconds in self.seconds.items())
        return f"timing: {phases}; peak memory {peak_memory_mb():.0f} MB"
