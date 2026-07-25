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

# Addresses with public, documented theft history. This list is deliberately
# short and real: every entry is a well-attested sanctioned mixer or a widely
# reported drainer/exploiter address, not a placeholder.
#
# It is a fast local pre-filter ONLY. Live coverage of rotating drainer
# infrastructure comes from GoPlus (`reputation.check`), and addresses that no
# feed knows yet are caught structurally by `foresee.counterparty`.
KNOWN_DRAINERS: set[str] = {
    # OFAC-sanctioned Tornado Cash router/pools - funds routed here are being
    # laundered; an approval to any of them is never legitimate for a normal user.
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # Tornado Cash Router
    "0x8589427373d6d84e98730d7795d8f6f8731fda16",  # Tornado Cash: Donate
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # Tornado Cash: Proxy
    "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",  # Tornado Cash: 0.1 ETH
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # Tornado Cash: 10 ETH
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",  # Tornado Cash: 100 ETH
    # Lazarus / DPRK-attributed addresses named in OFAC designations
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
    "0x3cffd56b47b7b41c56258d9c7731abadc360e073",
    # Ronin bridge exploiter (DPRK-attributed)
    "0x098b716b8aaf21512996dc57eb0615e2383e2f96",
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
