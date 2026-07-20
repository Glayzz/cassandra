"""Token price lookup via DeFiLlama (free, no key)."""
from __future__ import annotations

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

# DeFiLlama chain slugs
_CHAIN_SLUG = {
    1: "ethereum",
    8453: "base",
    10: "optimism",
    42161: "arbitrum",
    137: "polygon",
    56: "bsc",
    43114: "avax",
}


class Prices:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(timeout=15.0)

    async def close(self) -> None:
        await self._client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(initial=0.5, max=4.0))
    async def usd_prices(self, tokens: list[tuple[int, str]]) -> dict[str, float]:
        """Batch-fetch USD prices. Input: [(chain_id, token_address)]. Output: {addr_lower: price}."""
        if not tokens:
            return {}
        keys = []
        addr_by_key: dict[str, str] = {}
        for chain_id, addr in tokens:
            slug = _CHAIN_SLUG.get(chain_id)
            if not slug or not addr:
                continue
            key = f"{slug}:{addr.lower()}"
            keys.append(key)
            addr_by_key[key] = addr.lower()
        if not keys:
            return {}
        url = f"https://coins.llama.fi/prices/current/{','.join(keys)}"
        r = await self._client.get(url)
        r.raise_for_status()
        data = r.json().get("coins", {})
        out: dict[str, float] = {}
        for key, obj in data.items():
            addr = addr_by_key.get(key)
            if addr and isinstance(obj.get("price"), (int, float)):
                out[addr] = float(obj["price"])
        return out

    @retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(initial=0.5, max=4.0))
    async def usd_prices_solana(self, mints: list[str]) -> dict[str, float]:
        """USD prices for SPL mints. Solana addresses are case-sensitive base58 -
        do NOT lowercase them. Output keyed by the original mint string."""
        if not mints:
            return {}
        keys = [f"solana:{m}" for m in mints if m]
        url = f"https://coins.llama.fi/prices/current/{','.join(keys)}"
        r = await self._client.get(url)
        r.raise_for_status()
        data = r.json().get("coins", {})
        out: dict[str, float] = {}
        for key, obj in data.items():
            mint = key.split(":", 1)[1] if ":" in key else key
            if isinstance(obj.get("price"), (int, float)):
                out[mint] = float(obj["price"])
        return out

    async def sol_price(self) -> float | None:
        """USD price of native SOL."""
        r = await self._client.get("https://coins.llama.fi/prices/current/coingecko:solana")
        r.raise_for_status()
        obj = r.json().get("coins", {}).get("coingecko:solana", {})
        p = obj.get("price")
        return float(p) if isinstance(p, (int, float)) else None

    async def native_price(self, chain_id: int) -> float | None:
        """USD price of the chain's native coin (ETH, MATIC, BNB, etc.)."""
        native = {
            1: "coingecko:ethereum",
            8453: "coingecko:ethereum",
            10: "coingecko:ethereum",
            42161: "coingecko:ethereum",
            137: "coingecko:matic-network",
            56: "coingecko:binancecoin",
            43114: "coingecko:avalanche-2",
        }.get(chain_id)
        if not native:
            return None
        r = await self._client.get(f"https://coins.llama.fi/prices/current/{native}")
        r.raise_for_status()
        obj = r.json().get("coins", {}).get(native, {})
        p = obj.get("price")
        return float(p) if isinstance(p, (int, float)) else None
