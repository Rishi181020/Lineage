"""Run control on ports 8000/8001/8002 in one process so state is shared."""

from __future__ import annotations

import asyncio

import uvicorn

from .app import app
from .state import get_state


async def _serve() -> None:
    state = get_state()
    state.bus.bind_loop(asyncio.get_running_loop())
    configs = [
        uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
        for port in (8000, 8001, 8002)
    ]
    servers = [uvicorn.Server(config) for config in configs]
    await asyncio.gather(*(server.serve() for server in servers))


def main() -> None:
    asyncio.run(_serve())


if __name__ == "__main__":
    main()
