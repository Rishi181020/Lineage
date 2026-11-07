from __future__ import annotations

from copy import deepcopy
from threading import RLock

from ..models import EntityRecord, Event, Run, SourceTier
from .base import Store


class MemoryStore(Store):
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}
        self._events: dict[str, list[Event]] = {}
        self._entities: dict[str, dict[str, EntityRecord]] = {}
        self._lock = RLock()

    def put_run(self, run: Run) -> None:
        with self._lock:
            self._runs[run.id] = deepcopy(run)

    def get_run(self, run_id: str) -> Run | None:
        with self._lock:
            run = self._runs.get(run_id)
            return deepcopy(run) if run else None

    def list_runs(self) -> list[Run]:
        with self._lock:
            return [deepcopy(run) for run in self._runs.values()]

    def update_run(self, run_id: str, **changes: object) -> Run:
        with self._lock:
            if run_id not in self._runs:
                raise KeyError(run_id)
            run = self._runs[run_id]
            for name, value in changes.items():
                if not hasattr(run, name):
                    raise AttributeError(name)
                setattr(run, name, value)
            return deepcopy(run)

    def append_event(self, event: Event) -> Event:
        with self._lock:
            events = self._events.setdefault(event.run_id, [])
            stored = event.model_copy(deep=True)
            stored.seq = len(events) + 1
            events.append(stored)
            return deepcopy(stored)

    def list_events(self, run_id: str, after: int = 0) -> list[Event]:
        with self._lock:
            return [
                deepcopy(event)
                for event in self._events.get(run_id, [])
                if event.seq > after
            ]

    def observe_entity(
        self,
        run_id: str,
        entity: str,
        tier: SourceTier,
        span_id: str,
    ) -> EntityRecord:
        with self._lock:
            index = self._entities.setdefault(run_id, {})
            record = index.get(entity)
            if record is None:
                record = EntityRecord(entity=entity, best_tier=tier)
                index[entity] = record
            record.observe(tier, span_id)
            return deepcopy(record)

    def get_entity(self, run_id: str, entity: str) -> EntityRecord | None:
        with self._lock:
            record = self._entities.get(run_id, {}).get(entity)
            return deepcopy(record) if record else None

    def entity_index(self, run_id: str) -> dict[str, EntityRecord]:
        with self._lock:
            return deepcopy(self._entities.get(run_id, {}))

    def clear(self) -> None:
        with self._lock:
            self._runs.clear()
            self._events.clear()
            self._entities.clear()
