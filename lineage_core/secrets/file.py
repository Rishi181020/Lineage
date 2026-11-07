from __future__ import annotations

from pathlib import Path

import yaml

from .base import SecretsBackend


class FileSecrets(SecretsBackend):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("secrets file must contain a YAML mapping")
        return {str(key): str(value) for key, value in data.items()}

    def get(self, secret_ref: str) -> str:
        secrets = self._load()
        if secret_ref not in secrets:
            raise KeyError(secret_ref)
        return secrets[secret_ref]
