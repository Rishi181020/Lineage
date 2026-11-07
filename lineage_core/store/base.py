from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import EntityRecord, Event, Run, SourceTier


class Store(ABC):
    @abstractmethod
    def put_run(self, run: Run) -> None: ...

    @abstractmethod
    def get_run(self, run_id: str) -> Run | None: ...

    @abstractmethod
    def list_runs(self) -> list[Run]: ...

    @abstractmethod
    def update_run(self, run_id: str, **changes: object) -> Run: ...

    @abstractmethod
    def append_event(self, event: Event) -> Event: ...

    @abstractmethod
    def list_events(self, run_id: str, after: int = 0) -> list[Event]: ...

    @abstractmethod
    def observe_entity(
        self,
        run_id: str,
        entity: str,
        tier: SourceTier,
        span_id: str,
    ) -> EntityRecord: ...

    @abstractmethod
    def get_entity(self, run_id: str, entity: str) -> EntityRecord | None: ...

    @abstractmethod
    def entity_index(self, run_id: str) -> dict[str, EntityRecord]: ...
