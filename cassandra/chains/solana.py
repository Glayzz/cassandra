"""Solana JSON-RPC client.

Public RPC (api.mainnet-beta.solana.com) works but is rate-limited; set
SOLANA_RPC_URL or HELIUS_API_KEY for the demo. All reads are stateless.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential_jitter

from ..config import get_settings

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"


class SolanaError(RuntimeError):
    pass


class SolanaRpc:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        s = get_settings()
        self._url = s.solana_url()
        self._das_url = s.helius_das_url()
        self._client = client or httpx.AsyncClient(timeout=25.0)
        # public RPC is fragile; keep concurrency low
        self._sem = asyncio.Semaphore(4)
        self._id = 0

    async def close(self) -> None:
        await self._client.aclose()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential_jitter(initial=0.6, max=5.0))
    async def _rpc(self, method: str, params: list, url: str | None = None) -> Any:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        async with self._sem:
            r = await self._client.post(url or self._url, json=payload)
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            err = data["error"]
            # 429 / server busy -> retry
            if isinstance(err, dict) and err.get("code") in (-32005, 429):
                raise SolanaError(f"rate limited: {err}")
            raise SolanaError(f"rpc error: {err}")
        return data.get("result")

    # ---- basic reads ----

    async def get_balance(self, pubkey: str) -> int:
        res = await self._rpc("getBalance", [pubkey])
        return int(res.get("value", 0)) if isinstance(res, dict) else int(res or 0)

    async def get_account_info(self, pubkey: str, encoding: str = "jsonParsed") -> dict | None:
        res = await self._rpc("getAccountInfo", [pubkey, {"encoding": encoding}])
        if not res:
            return None
        return res.get("value")

    async def get_multiple_accounts(self, pubkeys: list[str],
                                    encoding: str = "jsonParsed") -> list[dict | None]:
        if not pubkeys:
            return []
        res = await self._rpc("getMultipleAccounts", [pubkeys, {"encoding": encoding}])
        return res.get("value", []) if isinstance(res, dict) else []

    async def get_token_accounts_by_owner(self, owner: str, program_id: str) -> list[dict]:
        res = await self._rpc("getTokenAccountsByOwner", [
            owner, {"programId": program_id}, {"encoding": "jsonParsed"},
        ])
        return res.get("value", []) if isinstance(res, dict) else []

    async def get_token_supply(self, mint: str) -> dict | None:
        res = await self._rpc("getTokenSupply", [mint])
        return res.get("value") if isinstance(res, dict) else None

    async def get_signatures_for_address(self, address: str, limit: int = 100,
                                         before: str | None = None) -> list[dict]:
        opts: dict = {"limit": limit}
        if before:
            opts["before"] = before
        res = await self._rpc("getSignaturesForAddress", [address, opts])
        return res or []

    async def get_transaction(self, signature: str) -> dict | None:
        return await self._rpc("getTransaction", [
            signature,
            {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
        ])

    # ---- Helius DAS (optional, only if a Helius key is configured) ----

    async def das_get_asset(self, mint: str) -> dict | None:
        if not self._das_url:
            return None
        try:
            res = await self._rpc("getAsset", {"id": mint}, url=self._das_url)
            return res
        except Exception:
            return None
