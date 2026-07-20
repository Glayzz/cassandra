"""Direct JSON-RPC helper - used for token metadata and eth_call reads.

Falls back to Etherscan proxy if no Alchemy key is set.
"""
from __future__ import annotations

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

from ..config import get_settings
from .etherscan import Etherscan

# Public RPCs as ultimate fallback (rate-limited but free)
_PUBLIC_RPC = {
    1: "https://eth.llamarpc.com",
    8453: "https://mainnet.base.org",
    10: "https://mainnet.optimism.io",
    42161: "https://arb1.arbitrum.io/rpc",
    137: "https://polygon-rpc.com",
    56: "https://bsc-dataseed.binance.org",
}


class Rpc:
    def __init__(self, etherscan: Etherscan | None = None,
                 client: httpx.AsyncClient | None = None) -> None:
        self._s = get_settings()
        self._client = client or httpx.AsyncClient(timeout=20.0)
        self._etherscan = etherscan

    async def close(self) -> None:
        await self._client.aclose()

    def _url(self, chain_id: int) -> str | None:
        url = self._s.alchemy_url(chain_id)
        if url:
            return url
        return _PUBLIC_RPC.get(chain_id)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(initial=0.5, max=4.0))
    async def call(self, chain_id: int, method: str, params: list) -> object:
        url = self._url(chain_id)
        if url:
            r = await self._client.post(url, json={
                "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
            })
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                raise RuntimeError(f"rpc error: {data['error']}")
            return data["result"]
        # Etherscan proxy fallback (only supports a subset)
        if self._etherscan and method == "eth_call":
            to = params[0]["to"]; data = params[0]["data"]
            return await self._etherscan.eth_call(to, data, chain_id)
        raise RuntimeError(f"no rpc available for chain {chain_id}")

    async def eth_call(self, chain_id: int, to: str, data: str) -> str:
        res = await self.call(chain_id, "eth_call", [{"to": to, "data": data}, "latest"])
        return res  # type: ignore[return-value]
