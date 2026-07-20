"""Address utilities + known-address registries.

For the demo we ship a curated known-drainer set. Cassandra pulls updates
from configured feeds on boot in production.
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
    # WETH
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    # USDC / USDT / DAI (as contract targets, they're common)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
}

# Known drainer contracts and campaigns - a starter set.
# Real deployment pulls the latest from a drainer feed.
KNOWN_DRAINERS: set[str] = {
    # Inferno drainer families - abbreviated placeholder set
    # (deliberately conservative for the demo; expandable at runtime)
    "0x0000db5c8b030ae20308ac975898e09741e70000",
    "0x000000eebc85dea88a26ab6a4a5b4c6b40000000",
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
