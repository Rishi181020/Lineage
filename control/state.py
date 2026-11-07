"""Shared in-process control-plane state (one process, three ports)."""

from __future__ import annotations

import secrets
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

import jwt
import yaml

from lineage_core.config import get_settings
from lineage_core.models import Binding, Event, Run, SourceTier
from lineage_core.placeholders import create as create_placeholder
from lineage_core.secrets.file import FileSecrets
from lineage_core.store.memory import MemoryStore
from lineage_core.tokens import mint_local

from .bus import EventBus

IP_POOL = [f"172.30.0.{i}" for i in range(100, 200)]


class ControlState:
    def __init__(self) -> None:
        settings = get_settings()
        self.settings = settings
        self.store = MemoryStore()
        self.bus = EventBus()
        self.lock = threading.RLock()
        self.policy = self._load_policy(settings.policy_path)
        import os

        self.operator_token = os.environ.get("LINEAGE_OPERATOR_TOKEN") or self._read_token(
            settings.operator_token_path, "lineage-operator-dev"
        )
        self.service_token = os.environ.get("LINEAGE_SERVICE_TOKEN") or self._read_token(
            settings.service_token_path, "lineage-service-dev"
        )
        self.secrets = FileSecrets(settings.local_secrets_path)
        self._used_ips: set[str] = set()
        self._spans: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _read_token(path: Path, default: str) -> str:
        try:
            return path.read_text(encoding="utf-8").strip() or default
        except FileNotFoundError:
            return default

    @staticmethod
    def _load_policy(path: Path) -> dict[str, Any]:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        demo = path.parent / "demo.yaml"
        if demo.exists():
            override = yaml.safe_load(demo.read_text(encoding="utf-8")) or {}
            data.update(override)
        return data

    def allocate_ip(self) -> str:
        with self.lock:
            for ip in IP_POOL:
                if ip not in self._used_ips:
                    self._used_ips.add(ip)
                    return ip
            raise RuntimeError("agent IP pool exhausted")

    def release_ip(self, ip: str | None) -> None:
        if not ip:
            return
        with self.lock:
            self._used_ips.discard(ip)

    def create_run(
        self,
        *,
        task: str,
        mode: str,
        mcp_allow: list[str],
        binding_ids: list[str],
        replay: bool = False,
    ) -> tuple[Run, str, dict[str, str]]:
        policy_bindings = self.policy.get("bindings", {}) or {}
        bindings: list[Binding] = []
        placeholders = []
        env: dict[str, str] = {}
        for binding_id in binding_ids:
            raw = policy_bindings.get(binding_id)
            if not raw:
                raise KeyError(f"unknown binding: {binding_id}")
            binding = Binding(id=binding_id, **raw)
            ph = create_placeholder(binding_id)
            bindings.append(binding)
            placeholders.append(ph)
            env[binding.env_var] = ph.value

        run_id = f"run_{uuid4().hex[:12]}"
        hook_token = secrets.token_urlsafe(24)
        run_token = mint_local(
            run_id,
            self.settings.local_signing_key,
            mcp_allow=mcp_allow,
            bindings=binding_ids,
        )
        jti = jwt.decode(
            run_token, options={"verify_signature": False}
        )["jti"]
        run = Run(
            id=run_id,
            task=task,
            mode=mode or self.policy.get("mode_default", "interactive"),
            mcp_allow=mcp_allow,
            bindings=bindings,
            placeholders=placeholders,
            ip=self.allocate_ip(),
            hook_token=hook_token,
            token_jti=jti,
            replay=replay,
        )
        for binding in bindings:
            for host in binding.hosts:
                self.store.observe_entity(
                    run_id, f"host:{host.lower()}", SourceTier.TRUSTED, "binding"
                )
        for host in (self.policy.get("allowlist", {}) or {}).get("hosts", []):
            self.store.observe_entity(
                run_id, f"host:{str(host).lower()}", SourceTier.TRUSTED, "policy"
            )
        self.store.put_run(run)
        self._spans[run_id] = {}
        return run, run_token, env

    def get_run_by_hook_token(self, token: str) -> Run | None:
        for run in self.store.list_runs():
            if run.hook_token and secrets.compare_digest(run.hook_token, token):
                return run
        return None

    def get_run_by_ip(self, ip: str) -> Run | None:
        for run in self.store.list_runs():
            if run.ip == ip:
                return run
        return None

    def remember_span(self, run_id: str, span_id: str, span: Any) -> None:
        self._spans.setdefault(run_id, {})[span_id] = span

    def span_map(self, run_id: str) -> dict[str, Any]:
        return dict(self._spans.get(run_id, {}))

    def publish(self, event_type: str, run_id: str, payload: dict[str, Any]) -> None:
        event = self.store.append_event(
            Event(run_id=run_id, type=event_type, payload=payload)
        )
        run = self.store.get_run(run_id)
        self.bus.publish(
            {
                "type": event_type,
                "run_id": run_id,
                "seq": event.seq,
                "payload": payload,
                "replay": bool(run.replay) if run else False,
            }
        )


_STATE: ControlState | None = None
_STATE_LOCK = threading.Lock()


def get_state() -> ControlState:
    global _STATE
    with _STATE_LOCK:
        if _STATE is None:
            _STATE = ControlState()
        return _STATE
