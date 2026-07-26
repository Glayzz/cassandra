"""Etherscan v2 multichain client.

Docs: https://docs.etherscan.io/etherscan-v2

One endpoint, chainid as a query param, one API key across 50+ chains.
Free tier: 5 rps, 100k calls/day.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
from tenacity import (retry, retry_if_exception_type, stop_after_attempt,
                      wait_exponential_jitter)

from ..config import get_settings


class EtherscanError(RuntimeError):
    pass


class EtherscanUnsupportedChain(EtherscanError):
    """This chain is not available on the current API plan.

    Permanent for the life of the key, so callers should degrade to an
    RPC-only path rather than retrying.
    """


class EtherscanRateLimited(EtherscanError):
    """Transient - worth a retry."""


class Etherscan:
    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        s = get_settings()
        self._base = s.etherscan_base
        self._key = s.etherscan_api_key
        # Tight, explicit timeouts so a single hung upstream can never stall a
        # whole tool call past the platform's task budget. connect fast, read short.
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(9.0, connect=4.0, read=8.0)
        )
        # The documented free-tier ceiling is 5 rps, but the API actually enforces
        # 3/sec ("Max calls per sec rate limit reached (3/sec)"). Two in flight
        # keeps us under it; going wider produces errors we then have to retry,
        # which is slower than being polite in the first place.
        self._sem = asyncio.Semaphore(2)
        # Chains this key has already told us it cannot serve. Checked before
        # every request so we fail instantly instead of burning the budget.
        self._unsupported: set[int] = set()

    async def close(self) -> None:
        await self._client.aclose()

    @retry(stop=stop_after_attempt(2), wait=wait_exponential_jitter(initial=0.3, max=1.5),
           retry=retry_if_exception_type(EtherscanRateLimited))
    async def _get(self, params: dict[str, Any]) -> Any:
        chain_id = params.get("chainid")
        if chain_id in self._unsupported:
            raise EtherscanUnsupportedChain(
                f"chain {chain_id} is not available on this Etherscan plan")
        params = {**params, "apikey": self._key}
        async with self._sem:
            r = await self._client.get(self._base, params=params)
        r.raise_for_status()
        data = r.json()
        # The `proxy` module answers in raw JSON-RPC shape ({jsonrpc, id, result})
        # with no `status` field, so it must be unwrapped before the status check
        # below - otherwise every proxy call raises and the RPC fallback is dead.
        if "jsonrpc" in data:
            if "error" in data:
                raise EtherscanError(f"etherscan proxy error: {data['error']}")
            return data.get("result")
        # Etherscan wraps everything else: {status, message, result}
        # status=1 -> ok, status=0 -> either "no records" or error
        if data.get("status") == "1":
            return data["result"]
        # No records for a valid query returns status=0 message="No transactions found"
        msg = str(data.get("message", "")).lower()
        result = data.get("result")
        blob = f"{msg} {result}".lower()
        if "no" in msg and ("transactions" in msg or "records" in msg or "found" in msg):
            return [] if isinstance(result, list) else result

        # Plan limitation: this key cannot read this chain, ever. Remember it so
        # later calls short-circuit, and raise a distinct type so callers can
        # degrade to RPC instead of reporting a generic failure.
        if "not supported for this chain" in blob or "upgrade your api" in blob:
            if chain_id is not None:
                self._unsupported.add(chain_id)
            raise EtherscanUnsupportedChain(
                f"chain {chain_id} is not available on this Etherscan plan")

        # Transient: worth exactly one retry. The live message is
        # "Max calls per sec rate limit reached (3/sec)", which lives in `result`.
        if "rate limit" in blob or "max rate" in blob or "too many request" in blob:
            raise EtherscanRateLimited(f"rate limited: {msg} / {result}")

        # otherwise it's a real error
        raise EtherscanError(f"etherscan error: {msg} / {result}")

    # ---- account module ----

    async def txlist(self, address: str, chain_id: int, page: int = 1, offset: int = 100,
                     sort: str = "desc") -> list[dict]:
        return await self._get({
            "chainid": chain_id, "module": "account", "action": "txlist",
            "address": address, "page": page, "offset": offset,
            "startblock": 0, "endblock": 99999999, "sort": sort,
        })

    async def txlist_internal(self, address: str, chain_id: int, page: int = 1,
                              offset: int = 100) -> list[dict]:
        return await self._get({
            "chainid": chain_id, "module": "account", "action": "txlistinternal",
            "address": address, "page": page, "offset": offset,
            "startblock": 0, "endblock": 99999999, "sort": "desc",
        })

    async def erc20_transfers(self, address: str, chain_id: int, page: int = 1,
                              offset: int = 100) -> list[dict]:
        return await self._get({
            "chainid": chain_id, "module": "account", "action": "tokentx",
            "address": address, "page": page, "offset": offset,
            "startblock": 0, "endblock": 99999999, "sort": "desc",
        })

    async def erc721_transfers(self, address: str, chain_id: int, page: int = 1,
                               offset: int = 100) -> list[dict]:
        return await self._get({
            "chainid": chain_id, "module": "account", "action": "tokennfttx",
            "address": address, "page": page, "offset": offset,
            "startblock": 0, "endblock": 99999999, "sort": "desc",
        })

    async def balance(self, address: str, chain_id: int) -> int:
        wei_str = await self._get({
            "chainid": chain_id, "module": "account", "action": "balance",
            "address": address, "tag": "latest",
        })
        return int(wei_str)

    # ---- contract module ----

    async def get_source(self, contract: str, chain_id: int) -> dict:
        res = await self._get({
            "chainid": chain_id, "module": "contract", "action": "getsourcecode",
            "address": contract,
        })
        # returns a single-element list
        return res[0] if isinstance(res, list) and res else {}

    async def get_contract_creation(self, contracts: list[str], chain_id: int) -> list[dict]:
        # up to 5 addresses per call
        return await self._get({
            "chainid": chain_id, "module": "contract", "action": "getcontractcreation",
            "contractaddresses": ",".join(contracts),
        })

    async def get_abi(self, contract: str, chain_id: int) -> str | None:
        try:
            return await self._get({
                "chainid": chain_id, "module": "contract", "action": "getabi",
                "address": contract,
            })
        except EtherscanError:
            return None

    # ---- logs module ----

    async def get_logs(self, chain_id: int, address: str, topic0: str,
                       topic1: str | None = None, from_block: int = 0,
                       offset: int = 200) -> list[dict]:
        params = {
            "chainid": chain_id, "module": "logs", "action": "getLogs",
            "address": address, "topic0": topic0,
            "fromBlock": from_block, "toBlock": "latest",
            "page": 1, "offset": offset,
        }
        if topic1:
            params["topic1"] = topic1
            params["topic0_1_opr"] = "and"
        try:
            res = await self._get(params)
            return res if isinstance(res, list) else []
        except Exception:
            return []

        # ---- proxy module (raw JSON-RPC) ----

    async def eth_call(self, to: str, data: str, chain_id: int) -> str:
        return await self._get({
            "chainid": chain_id, "module": "proxy", "action": "eth_call",
            "to": to, "data": data, "tag": "latest",
        })

    async def eth_get_code(self, address: str, chain_id: int) -> str:
        """Runtime bytecode via the Etherscan proxy module - the fallback path when
        every JSON-RPC endpoint for the chain is rate-limited or down."""
        return await self._get({
            "chainid": chain_id, "module": "proxy", "action": "eth_getCode",
            "address": address, "tag": "latest",
        })

    async def eth_block_by_number(self, block: str, chain_id: int) -> dict:
        return await self._get({
            "chainid": chain_id, "module": "proxy", "action": "eth_getBlockByNumber",
            "tag": block, "boolean": "false",
        })
