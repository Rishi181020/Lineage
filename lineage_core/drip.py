from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class DripResult:
    blocked: bool
    reason: str = ""
    distinct_paths: int = 0


class DripDetector:
    def __init__(
        self,
        *,
        max_distinct_paths: int = 8,
        window_s: float = 60,
        max_body_bytes: int = 512,
        min_substring: int = 8,
    ) -> None:
        self.max_distinct_paths = max_distinct_paths
        self.window_s = window_s
        self.max_body_bytes = max_body_bytes
        self.min_substring = min_substring
        self._requests: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)

    def check(
        self,
        host: str,
        path: str,
        *,
        body_size: int = 0,
        sensitive_values: list[str] | tuple[str, ...] = (),
        now: float | None = None,
    ) -> DripResult:
        now = time.monotonic() if now is None else now
        bucket = self._requests[host.lower()]
        while bucket and now - bucket[0][0] > self.window_s:
            bucket.popleft()
        bucket.append((now, unquote(path), body_size))

        small_paths = {item_path for _, item_path, size in bucket if size < self.max_body_bytes}
        if body_size < self.max_body_bytes and len(small_paths) > self.max_distinct_paths:
            return DripResult(
                True,
                "too many distinct small requests to one host",
                len(small_paths),
            )

        joined = "".join(item_path for _, item_path, _ in bucket)
        for secret in sensitive_values:
            if len(secret) < self.min_substring:
                continue
            for start in range(len(secret) - self.min_substring + 1):
                fragment = secret[start : start + self.min_substring]
                if fragment in joined:
                    return DripResult(
                        True,
                        "request paths reconstruct private data",
                        len(small_paths),
                    )
        return DripResult(False, distinct_paths=len(small_paths))

    def clear(self, host: str | None = None) -> None:
        if host is None:
            self._requests.clear()
        else:
            self._requests.pop(host.lower(), None)
