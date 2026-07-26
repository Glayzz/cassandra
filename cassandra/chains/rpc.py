"""Direct JSON-RPC helper - used for token metadata and eth_call reads.

Falls back to Etherscan proxy if no Alchemy key is set.
"""
from __future__ import annotations

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

from ..config import get_settings
from .etherscan import Etherscan

# Public RPCs as ultimate fallback (rate-limited but free). Several per chain:
# a single public endpoint rate-limiting us would silently disable the
# structural checks in `foresee.counterparty`, which is exactly when a user is
# relying on them. Tried in order until one answers.
_PUBLIC_RPC: dict[int, list[str]] = {
    1: ["https://eth.llamarpc.com", "https://rpc.ankr.com/eth",
        "https://ethereum-rpc.publicnode.com", "https://cloudflare-eth.com"],
    8453: ["https://mainnet.base.org", "https://base.llamarpc.com",
           "https://base-rpc.publicnode.com"],
    10: ["https://mainnet.optimism.io", "https://optimism-rpc.publicnode.com"],
    42161: ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"],
    137: ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com"],
    56: ["https://bsc-dataseed.binance.org", "https://bsc-rpc.publicnode.com"],
}


class Rpc:
    def __init__(self, etherscan: Etherscan | None = None,
                 client: httpx.AsyncClient | None = None) -> None:
        self._s = get_settings()
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(9.0, connect=4.0, read=8.0)
        )
        self._etherscan = etherscan

    async def close(self) -> None:
        await self._client.aclose()

    def _urls(self, chain_id: int) -> list[str]:
        """Every endpoint worth trying for this chain, best first."""
        urls: list[str] = []
        configured = self._s.alchemy_url(chain_id)
        if configured:
            urls.append(configured)
        urls.extend(_PUBLIC_RPC.get(chain_id, []))
        return urls

    async def _post(self, url: str, method: str, params: list) -> object:
        r = await self._client.post(url, json={
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        })
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"rpc error: {data['error']}")
        return data["result"]

    @retry(stop=stop_after_attempt(2), wait=wait_exponential_jitter(initial=0.3, max=1.5))
    async def call(self, chain_id: int, method: str, params: list) -> object:
        last: Exception | None = None
        for url in self._urls(chain_id):
            try:
                return await self._post(url, method, params)
            except Exception as e:      # rate-limited / down / rejected -> next one
                last = e
                continue

        # Etherscan proxy fallback (supports a useful subset)
        if self._etherscan:
            if method == "eth_call":
                return await self._etherscan.eth_call(
                    params[0]["to"], params[0]["data"], chain_id)
            if method == "eth_getCode":
                return await self._etherscan.eth_get_code(params[0], chain_id)
        if last:
            raise last
        raise RuntimeError(f"no rpc available for chain {chain_id}")

    async def eth_call(self, chain_id: int, to: str, data: str) -> str:
        res = await self.call(chain_id, "eth_call", [{"to": to, "data": data}, "latest"])
        return res  # type: ignore[return-value]

    async def block_number(self, chain_id: int) -> int:
        res = await self.call(chain_id, "eth_blockNumber", [])
        return int(res, 16) if isinstance(res, str) else int(res)

    async def get_logs(self, chain_id: int, *, topics: list, from_block: int,
                       to_block: str | int = "latest",
                       address: str | None = None) -> list[dict]:
        """`eth_getLogs` - the RPC route to event history.

        This is the fallback for chains an Etherscan plan doesn't cover: approvals
        are discoverable from `Approval` events without any explorer API. Public
        endpoints cap the block span, so callers pass a bounded window.
        """
        params: dict = {
            "fromBlock": hex(from_block) if isinstance(from_block, int) else from_block,
            "toBlock": hex(to_block) if isinstance(to_block, int) else to_block,
            "topics": topics,
        }
        if address:
            params["address"] = address
        res = await self.call(chain_id, "eth_getLogs", [params])
        return res if isinstance(res, list) else []

    async def get_code(self, chain_id: int, address: str) -> str:
        """Runtime bytecode at `address`. "0x" (empty) means it is an EOA, not a
        contract - the single strongest signal that an approval spender is a drainer."""
        res = await self.call(chain_id, "eth_getCode", [address, "latest"])
        return res or "0x"  # type: ignore[return-value]
