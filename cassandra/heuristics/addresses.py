"""Address utilities + known-address registries.

Two registries with opposite jobs:

* ``KNOWN_ROUTERS`` - infrastructure that is *expected* to hold allowances.
  This is the more valuable of the two: it suppresses false positives, so a
  warning from Cassandra keeps meaning something.
* ``KNOWN_DRAINERS`` - addresses already known to be hostile.

A blocklist alone can never keep up with drainer campaigns, which rotate
addresses constantly. It is a fast first pass, not the detection strategy -
``foresee.counterparty`` does the structural work that catches the addresses no
feed has seen yet, and GoPlus supplies live coverage of the ones that are known.
"""
from __future__ import annotations

from eth_utils import to_checksum_address, is_address

# Well-known infrastructure - not exhaustive, expandable via config
KNOWN_ROUTERS: dict[str, str] = {
    # Uniswap V2
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    # Uniswap V3
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router 2",
    # Uniswap Universal Router
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    # 1inch V5
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5 Router",
    # Seaport 1.5 / 1.6
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "Seaport 1.5",
    "0x0000000000000068f116a894984e2db1123eb395": "Seaport 1.6",
    # 0x
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    # LayerZero
    "0x1a44076050125825900e736c501f859c50fe728c": "LayerZero V2 Endpoint",
    # Across
    "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": "Across Bridge",
    # Permit2 - legitimate infrastructure, and the rail most phishing rides on
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
    # Aggregators / routers
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch V6 Router",
    "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Meta Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch V4 Router",
    "0x881d40237659c251811cec9c364ef91dc08d300c": "Metamask Swap Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x00000000009726632680fb29d3f7a9734e3010e2": "Rainbow Router",
    # CoW / Cowswap
    "0x9008d19f58aabd9ed0d60971565aa8510560ab41": "CoW Protocol Settlement",
    # Lending
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool",
    "0xc3d688b66703497daa19211eedff47f25384cdc3": "Compound V3 USDC",
    # NFT marketplaces
    "0x1e0049783f008a0085193e00003d00cd54003c71": "OpenSea Conduit",
    "0x59728544b08ab483533076417fbbb2fd0b17ce3a": "LooksRare Exchange",
    "0x000000000000ad05ccc4f10045630fb830b95127": "Blur Marketplace",
    # WETH
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    # USDC / USDT / DAI (as contract targets, they're common)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
}

# Deliberately small. Sanctions screening is NOT done here - it is a live
# `isSanctioned` call against the Chainalysis on-chain oracle (see
# `chains.sanctions`), which tracks OFAC designations as they change.
#
# Keeping designations in source is actively harmful: Tornado Cash was hardcoded
# here until the oracle reported it clean, because OFAC delisted it in March 2025.
# A stale local list produces confident false accusations, which is the one thing
# a security oracle cannot afford.
#
# What remains here are non-sanctions entries: addresses with public, documented
# theft history that no feed covers. Live coverage of rotating drainer
# infrastructure comes from GoPlus (`reputation.check`), sanctions from the
# on-chain oracle, and everything nobody has seen yet from the structural checks
# in `foresee.counterparty`.
KNOWN_DRAINERS: set[str] = set()


# The real address of each heavily-impersonated symbol, per chain. A token that
# calls itself USDC while living at a different address is claiming to be money
# it is not - one of the cheapest scams to run and, with this table, one of the
# cheapest to catch.
CANONICAL_TOKENS: dict[int, dict[str, str]] = {
    1: {  # Ethereum
        "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
        "WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "WBTC": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
        "LINK": "0x514910771af9ca656af840dff83e8264ecf986ca",
        "UNI": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
        "AAVE": "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9",
        "PEPE": "0x6982508145454ce325ddbe47a25d4ec3d2311933",
        "SHIB": "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce",
    },
    8453: {  # Base
        "USDC": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        "WETH": "0x4200000000000000000000000000000000000006",
        "DAI": "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",
    },
    42161: {  # Arbitrum
        "USDC": "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        "USDT": "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
        "WETH": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
        "ARB": "0x912ce59144191c1204e64559fe8253a0e49e6548",
    },
    10: {  # Optimism
        "USDC": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
        "WETH": "0x4200000000000000000000000000000000000006",
        "OP": "0x4200000000000000000000000000000000000042",
    },
    137: {  # Polygon
        "USDC": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
        "USDT": "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
        "WETH": "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
    },
    56: {  # BNB Chain
        "USDT": "0x55d398326f99059ff775485246999027b3197955",
        "USDC": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
        "WBNB": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    },
}


def impersonation_check(symbol: str | None, address: str, chain_id: int) -> dict | None:
    """Does this token claim a symbol that belongs to a different, real token?

    Returns a finding, or None when the symbol is unknown or the address is the
    genuine one. Unknown symbols are not suspicious - most tokens are new.
    """
    if not symbol or not address:
        return None
    canon = CANONICAL_TOKENS.get(chain_id, {})
    real = canon.get(str(symbol).strip().upper())
    if not real:
        return None
    if address.lower() == real:
        return None
    return {
        "kind": "symbol_impersonation",
        "severity": "critical",
        "message": (
            f"This contract calls itself `{symbol}`, but the real {symbol} on this "
            f"chain is {real}. This token is not {symbol} - it borrowed the name so "
            "wallets and price widgets display something you already trust."
        ),
        "claimed_symbol": str(symbol),
        "real_address": real,
    }


def normalize(addr: str) -> str | None:
    if not addr:
        return None
    addr = addr.strip()
    if not is_address(addr):
        return None
    return to_checksum_address(addr)


def label_for(addr: str) -> str | None:
    if not addr:
        return None
    return KNOWN_ROUTERS.get(addr.lower())


def is_known_drainer(addr: str) -> bool:
    return addr.lower() in KNOWN_DRAINERS
