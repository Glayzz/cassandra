"""Shared long-lived clients. Instantiate once at app startup."""
from __future__ import annotations

from .chains.etherscan import Etherscan
from .chains.rpc import Rpc
from .chains.prices import Prices
from .chains.solana import SolanaRpc
from .chains.goplus import GoPlus


class Deps:
    def __init__(self) -> None:
        self.etherscan = Etherscan()
        self.rpc = Rpc(etherscan=self.etherscan)
        self.prices = Prices()
        self.solana = SolanaRpc()
        self.goplus = GoPlus()

    async def close(self) -> None:
        await self.etherscan.close()
        await self.rpc.close()
        await self.prices.close()
        await self.solana.close()
        await self.goplus.close()


_deps: Deps | None = None


def get_deps() -> Deps:
    global _deps
    if _deps is None:
        _deps = Deps()
    return _deps


async def shutdown() -> None:
    global _deps
    if _deps is not None:
        await _deps.close()
        _deps = None
