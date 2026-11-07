from __future__ import annotations

from typing import Any

import boto3

from .memory import MemoryStore


class DynamoStore(MemoryStore):
    """M0 interface-compatible placeholder; persistence lands in the AWS milestone."""

    def __init__(
        self,
        *,
        runs_table: str = "lineage-runs",
        events_table: str = "lineage-events",
        entities_table: str = "lineage-entities",
        region: str = "us-west-2",
        resource: Any | None = None,
    ) -> None:
        super().__init__()
        dynamo = resource or boto3.resource("dynamodb", region_name=region)
        self.runs_table = dynamo.Table(runs_table)
        self.events_table = dynamo.Table(events_table)
        self.entities_table = dynamo.Table(entities_table)

    def put_run(self, run: Any) -> None:
        raise NotImplementedError("DynamoDB persistence is implemented in M0b")
