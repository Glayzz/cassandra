"""Pluggable on-chain intelligence provider.

This is the seam for external trackers - e.g. the $MWOR DEV fleet-forensics /
funding-trace / creator-tracker stack (Helius-based). A provider implements the
`Tracker` protocol; Cassandra loads it from the `CASSANDRA_TRACKER` env var and
uses it to ENRICH oracle results. It is entirely optional:

  - No env var set  -> get_tracker() returns None -> enrich_* are no-ops.
  - Env var set     -> the provider's data is attached under result["intel"].

So the core oracles never change behaviour unless a tracker is explicitly wired
in, which keeps production deploys safe.

Enable it:
    export CASSANDRA_TRACKER="my_tracker_module:Provider"
    # or, to test the wiring with the bundled stub:
    export CASSANDRA_TRACKER="cassandra.integrations.tracker:DemoTracker"

Mapping (see INTEGRATION.md for the full guide):
  funding_trace(address)      -> enriches foresee_scan + foresee_identity
  wallet_cluster(addresses)   -> enriches foresee_identity  (fleet forensics)
  creator_history(token)      -> enriches foresee_token     (creator tracking)
"""
from __future__ import annotations

import importlib
import logging
import os
from typing import Protocol, runtime_checkable

log = logging.getLogger("cassandra.tracker")


@runtime_checkable
class Tracker(Protocol):
    """Implement any subset of these. Missing methods are simply skipped.

    Every method is async and returns a JSON-serialisable dict (or None). `chain`
    is one of: ethereum, base, arbitrum, optimism, polygon, bsc, solana.
    """
    name: str

    async def funding_trace(self, address: str, chain: str) -> dict | None: ...
    async def creator_history(self, token: str, chain: str) -> dict | None: ...
    async def wallet_cluster(self, addresses: list[str], chain: str) -> dict | None: ...


_cache: dict = {"loaded": False, "tracker": None}


def get_tracker():
    """Load the configured tracker once (cached). Returns an instance or None."""
    if _cache["loaded"]:
        return _cache["tracker"]
    _cache["loaded"] = True
    spec = os.environ.get("CASSANDRA_TRACKER", "").strip()
    if not spec:
        _cache["tracker"] = None
        return None
    try:
        mod_name, _, attr = spec.partition(":")
        mod = importlib.import_module(mod_name)
        obj = getattr(mod, attr or "Tracker")
        inst = obj() if isinstance(obj, type) else obj
        _cache["tracker"] = inst
        log.info("tracker loaded: %s", getattr(inst, "name", spec))
    except Exception:
        log.exception("failed to load tracker %r - continuing without it", spec)
        _cache["tracker"] = None
    return _cache["tracker"]


async def _safe(method, *args):
    if method is None:
        return None
    try:
        return await method(*args)
    except Exception:
        log.exception("tracker call failed")
        return None


async def enrich_scan(result: dict, wallet: str, chain: str) -> dict:
    t = get_tracker()
    if not t or not isinstance(result, dict):
        return result
    intel = await _safe(getattr(t, "funding_trace", None), wallet, chain)
    if intel:
        result.setdefault("intel", {})["funding"] = intel
    return result


async def enrich_identity(result: dict, wallets: list[str], chain: str) -> dict:
    t = get_tracker()
    if not t or not isinstance(result, dict):
        return result
    intel = await _safe(getattr(t, "wallet_cluster", None), wallets, chain)
    if intel:
        result.setdefault("intel", {})["cluster"] = intel
    return result


async def enrich_token(result: dict, token: str, chain: str) -> dict:
    t = get_tracker()
    if not t or not isinstance(result, dict):
        return result
    intel = await _safe(getattr(t, "creator_history", None), token, chain)
    if intel:
        result.setdefault("intel", {})["creator"] = intel
    return result


class DemoTracker:
    """A stub provider used only to test the integration wiring end-to-end.
    Replace with the real $MWOR DEV modules (see INTEGRATION.md)."""
    name = "demo"

    async def funding_trace(self, address: str, chain: str) -> dict | None:
        return {"source": "demo", "hops": 2,
                "note": f"funding-trace stub for {address[:8]}... on {chain}"}

    async def creator_history(self, token: str, chain: str) -> dict | None:
        return {"source": "demo", "prior_tokens": 3,
                "note": f"creator-history stub for {token[:8]}... on {chain}"}

    async def wallet_cluster(self, addresses: list[str], chain: str) -> dict | None:
        return {"source": "demo", "cluster_size": len(addresses),
                "note": "fleet-forensics cluster stub"}
