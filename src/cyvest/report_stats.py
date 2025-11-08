from __future__ import annotations

from dataclasses import dataclass

from logurich import logger

from .models import Level


@dataclass
class _SeenEntry:
    level: Level
    stat_name: str | None
    default_stat: str | None


class ReportStats:
    """Helper that tracks report statistics and level transitions."""

    def __init__(self) -> None:
        self._values: dict[str, int] = {}
        self._seen: dict[str, _SeenEntry] = {}

    def init(self, key: str, value: int = 0) -> None:
        self._values[key] = value

    def increment(self, key: str, value: int = 1) -> None:
        self._values[key] = self._values.get(key, 0) + value

    def decrement(self, key: str, value: int = 1) -> None:
        self._values[key] = self._values.get(key, 0) - value

    def reduce(self, target: dict[str, int]) -> dict[str, int]:
        for key, value in self._values.items():
            target[key] = target.get(key, 0) + value
        return target

    def snapshot(self) -> dict[str, int]:
        return dict(self._values)

    def track(
        self,
        *,
        full_key: str,
        stat_name: str | None,
        default_stat_name: str | None,
        level: Level,
        generated_by: set[str],
    ) -> bool:
        if stat_name is None:
            return False

        entry = self._seen.get(full_key)
        if entry:
            if stat_name != entry.stat_name and level > entry.level:
                logger.debug(
                    "%s: update stat %s -> %s - default: %s (gen by: %s)",
                    full_key,
                    entry.stat_name,
                    stat_name,
                    default_stat_name,
                    generated_by,
                )
                if entry.stat_name and entry.stat_name != entry.default_stat:
                    self.decrement(entry.stat_name)
                if stat_name != default_stat_name:
                    self.increment(stat_name)
                self._seen[full_key] = _SeenEntry(level=level, stat_name=stat_name, default_stat=default_stat_name)
            return True

        logger.debug(
            "%s: add stat %s - default: %s (gen by: %s)",
            full_key,
            stat_name,
            default_stat_name,
            generated_by,
        )
        self._seen[full_key] = _SeenEntry(level=level, stat_name=stat_name, default_stat=default_stat_name)
        self.increment(stat_name)
        if default_stat_name and stat_name != default_stat_name:
            self.increment(default_stat_name)
        return True
