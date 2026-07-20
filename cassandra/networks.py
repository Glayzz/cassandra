"""Network resolution - maps a caller's `chain` string to EVM(chain_id) or Solana.

Cassandra now speaks two very different worlds:
  - EVM chains (Ethereum, Base, Arbitrum, Optimism, Polygon, BSC) - account model,
    ERC-20 allowances, EIP-712, keccak selectors.
  - Solana - program model, SPL token delegates, base58 keys, instruction decoding.

Everything upstream passes a single `chain` string; this module is the one place
that decides which pipeline handles it.
"""
from __future__ import annotations

from dataclasses import dataclass

_EVM_ALIASES: dict[str, int] = {
    "ethereum": 1, "eth": 1, "mainnet": 1, "1": 1,
    "base": 8453, "8453": 8453,
    "arbitrum": 42161, "arb": 42161, "42161": 42161,
    "optimism": 10, "op": 10, "10": 10,
    "polygon": 137, "matic": 137, "137": 137,
    "bsc": 56, "bnb": 56, "56": 56,
    "avalanche": 43114, "avax": 43114, "43114": 43114,
}

_EVM_IDS = set(_EVM_ALIASES.values())

_SOLANA_ALIASES = {"solana", "sol", "mainnet-beta", "solana-mainnet", "svm"}

EVM_LABELS = {
    1: "Ethereum", 8453: "Base", 42161: "Arbitrum", 10: "Optimism",
    137: "Polygon", 56: "BNB Chain", 43114: "Avalanche",
}


@dataclass(frozen=True)
class Network:
    kind: str          # "evm" | "solana"
    chain_id: int | None  # set for evm, None for solana
    label: str

    @property
    def is_solana(self) -> bool:
        return self.kind == "solana"

    @property
    def is_evm(self) -> bool:
        return self.kind == "evm"


SOLANA = Network(kind="solana", chain_id=None, label="Solana")


def resolve(chain: str | int | None = None, chain_id: int | None = None) -> Network:
    """Resolve a caller-supplied chain identifier.

    Priority: explicit `chain` string > legacy `chain_id` int > default Ethereum.
    """
    if chain is not None:
        c = str(chain).strip().lower()
        if c in _SOLANA_ALIASES:
            return SOLANA
        if c in _EVM_ALIASES:
            cid = _EVM_ALIASES[c]
            return Network("evm", cid, EVM_LABELS.get(cid, f"chain {cid}"))
        if c.isdigit() and int(c) in _EVM_IDS:
            cid = int(c)
            return Network("evm", cid, EVM_LABELS.get(cid, f"chain {cid}"))
    if chain_id is not None:
        return Network("evm", int(chain_id), EVM_LABELS.get(int(chain_id), f"chain {chain_id}"))
    return Network("evm", 1, "Ethereum")
