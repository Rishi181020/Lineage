from abc import ABC, abstractmethod


class SecretsBackend(ABC):
    @abstractmethod
    def get(self, secret_ref: str) -> str: ...
