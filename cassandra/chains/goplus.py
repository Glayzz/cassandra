"""GoPlus Security API client - production-grade Web3 risk data (free, no key required).

Endpoints used:
  - EVM token security:  /token_security/{chain_id}?contract_addresses=<addr>
  - Solana token security: /solana/token_security?contract_addresses=<mint>
  - Address (malicious) security: /address_security/{addr}?chain_id=<id>

All calls are cached (TTL) and fully defensive: any error or non-OK response
returns None, so the oracles always fall back to their own heuristics. GoPlus is
an enhancement, never a hard dependency.

An optional GOPLUS_API_KEY (App key/secret exchanged for an access token) raises
rate limits; the free anonymous tier works without it.
"""
from __future__ import annotations

import httpx

from .cache import TTLCache
from ..config import get_settings

_BASE = "https://api.gopluslabs.io/api/v1"

# chains GoPlus token-security supports that we also support
GOPLUS_EVM_CHAINS = {1, 10, 56, 137, 8453, 42161, 43114}


class GoPlus:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        s = get_settings()
        self._key = s.goplus_api_key
        self._client = client or httpx.AsyncClient(timeout=15.0)
        self._cache = TTLCache(ttl=300.0)

    async def close(self) -> None:
        await self._client.aclose()

    async def _get(self, path: str, params: dict) -> object | None:
        headers = {"Authorization": self._key} if self._key else {}
        r = await self._client.get(_BASE + path, params=params, headers=headers)
        r.raise_for_status()
        data = r.json()
        if data.get("code") == 1:
            return data.get("result")
        return None

    async def evm_token_security(self, chain_id: int, address: str) -> dict | None:
        if chain_id not in GOPLUS_EVM_CHAINS or not address:
            return None
        addr = address.lower()

        async def f():
            try:
                res = await self._get(f"/token_security/{chain_id}", {"contract_addresses": addr})
                if isinstance(res, dict):
                    return res.get(addr) or (next(iter(res.values())) if res else None)
            except Exception:
                return None
            return None

        return await self._cache.get_or_set(f"tok:{chain_id}:{addr}", f)

    async def solana_token_security(self, mint: str) -> dict | None:
        if not mint:
            return None

        async def f():
            try:
                res = await self._get("/solana/token_security", {"contract_addresses": mint})
                if isinstance(res, dict):
                    return res.get(mint) or (next(iter(res.values())) if res else None)
            except Exception:
                return None
            return None

        return await self._cache.get_or_set(f"soltok:{mint}", f)

    async def address_security(self, address: str, chain_id: int = 1) -> dict | None:
        if not address:
            return None
        addr = address.lower()

        async def f():
            try:
                return await self._get(f"/address_security/{addr}", {"chain_id": chain_id})
            except Exception:
                return None

        return await self._cache.get_or_set(f"addr:{chain_id}:{addr}", f)
