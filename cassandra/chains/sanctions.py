"""OFAC sanctions screening via the Chainalysis on-chain oracle.

Chainalysis publishes a public contract that answers one question:
`isSanctioned(address) -> bool`, maintained from OFAC and related embargo lists.
It needs no API key and no customer relationship - it is an ordinary `eth_call`.

That makes it the right shape for Cassandra: the answer is authoritative, it
costs one RPC read, it works on chains where an explorer plan does not, and it
stays current without anyone maintaining a list in this repo.

Chainalysis states it cannot guarantee accuracy or timeliness, so a positive is
reported as what it is - a sanctions-list hit - and a negative is never reported
as proof of innocence. A failed lookup returns None (unknown), never False.

Docs: https://go.chainalysis.com/chainalysis-oracle-docs.html
"""
from __future__ import annotations

from eth_hash.auto import keccak

from .cache import TTLCache

# Chainalysis deployed the oracle at the same address on every chain it covers.
ORACLE_ADDRESS = "0x40c57923924b5c5c5455c48d93317139addac8fb"

# Chains where the oracle is published. A chain missing here is simply not
# screened - it is not treated as clean.
SUPPORTED_CHAINS = {
    1,      # Ethereum
    10,     # Optimism
    56,     # BNB Chain
    137,    # Polygon
    42161,  # Arbitrum
    43114,  # Avalanche
}

_SELECTOR = "0x" + keccak(b"isSanctioned(address)").hex()[:8]

# Sanctions designations change on a policy timescale, not a block timescale.
_cache = TTLCache(ttl=3600.0)


def _encode(address: str) -> str:
    return _SELECTOR + address.lower().replace("0x", "").rjust(64, "0")


async def is_sanctioned(rpc, chain_id: int, address: str) -> bool | None:
    """True / False from the oracle, or None when it could not be consulted.

    None is meaningfully different from False and callers must not collapse the
    two: one means "not on the list", the other means "we did not get to ask".
    """
    if not rpc or not address or chain_id not in SUPPORTED_CHAINS:
        return None
    addr = address.strip().lower()
    if not addr.startswith("0x") or len(addr) != 42:
        return None

    async def _lookup():
        try:
            raw = await rpc.eth_call(chain_id, ORACLE_ADDRESS, _encode(addr))
        except Exception:
            return None
        if not raw or raw in ("0x", "0x0"):
            return None            # no oracle at this address on this chain
        try:
            return int(raw, 16) != 0
        except Exception:
            return None

    return await _cache.get_or_set(f"ofac:{chain_id}:{addr}", _lookup)


def finding(address: str) -> dict:
    """The finding to raise when the oracle returns True."""
    return {
        "kind": "ofac_sanctioned",
        "severity": "critical",
        "message": (
            f"{address} is on an OFAC sanctions list according to the Chainalysis "
            "on-chain sanctions oracle. Sending to, or granting any allowance to, a "
            "sanctioned address is not merely risky - in most jurisdictions it is a "
            "legal violation, and funds that touch it are frequently frozen by "
            "exchanges downstream."
        ),
        "source": "chainalysis_sanctions_oracle",
    }
