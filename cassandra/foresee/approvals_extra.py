"""Permit2 + NFT (setApprovalForAll) approval coverage.

These are the drainer vectors the basic ERC-20 allowance scan misses:
  - Permit2: the canonical 0x000000000022D473030F116dDEE9F6B43aC78BA3 router that
    holds delegated allowances the wallet granted via signatures.
  - NFT operators: ERC-721/1155 setApprovalForAll grants (whole-collection access).

Both are discovered from event logs, then confirmed with a live on-chain read so
only currently-active grants are reported. Fully defensive: any failure returns [].
"""
from __future__ import annotations

from eth_hash.auto import keccak
from eth_abi import encode as abi_encode

from ..chains.etherscan import Etherscan
from ..chains.rpc import Rpc
from ..chains.prices import Prices

PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"

_UNLIMITED = (1 << 159)  # Permit2 amounts are uint160

# event topic0 hashes
_APPROVAL_FOR_ALL = "0x" + keccak(b"ApprovalForAll(address,address,bool)").hex()
_PERMIT2_APPROVAL = "0x" + keccak(b"Approval(address,address,address,uint160,uint48)").hex()

# function selectors
_IS_APPROVED_FOR_ALL = "0x" + keccak(b"isApprovedForAll(address,address)").hex()[:8]
_PERMIT2_ALLOWANCE = "0x" + keccak(b"allowance(address,address,address)").hex()[:8]


def _topic_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


def _pad(addr: str) -> str:
    return addr.lower().replace("0x", "").rjust(64, "0")


async def nft_operator_approvals(wallet: str, chain_id: int, etherscan: Etherscan,
                                 rpc: Rpc) -> list[dict]:
    """Active setApprovalForAll grants (whole-collection operator access).

    Collections are derived from the wallet's NFT transfer history, then each is
    queried for ApprovalForAll logs by this owner and confirmed live.
    """
    try:
        nft_txs = await etherscan.erc721_transfers(wallet, chain_id, offset=300)
    except Exception:
        nft_txs = []
    collections: list[str] = []
    seen_c: set[str] = set()
    for t in nft_txs or []:
        c = (t.get("contractAddress") or "").lower()
        if c and c not in seen_c:
            seen_c.add(c); collections.append(c)
    collections = collections[:12]

    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for coll in collections:
        logs = await etherscan.get_logs(chain_id, address=coll, topic0=_APPROVAL_FOR_ALL,
                                        topic1=_topic_addr(wallet), offset=100)
        for lg in logs or []:
            topics = lg.get("topics") or []
            if len(topics) < 3:
                continue
            operator = "0x" + topics[2][-40:]
            key = (coll, operator.lower())
            if key in seen:
                continue
            seen.add(key)
            data = _IS_APPROVED_FOR_ALL + _pad(wallet) + _pad(operator)
            try:
                raw = await rpc.eth_call(chain_id, coll, data)
                active = int(raw, 16) == 1 if raw and raw != "0x" else False
            except Exception:
                active = False
            if not active:
                continue
            out.append({
                "kind": "nft_operator",
                "token": coll,
                "token_symbol": "NFT collection",
                "spender": operator,
                "spender_label": None,
                "spender_is_known_drainer": False,
                "allowance_raw": "ALL",
                "unlimited": True,
                "exposure_usd": None,
                "revoke_calldata": "0xa22cb465" + abi_encode(["address", "bool"], [operator, False]).hex(),
            })
    return out


async def permit2_approvals(wallet: str, chain_id: int, etherscan: Etherscan,
                            rpc: Rpc, prices: Prices) -> list[dict]:
    """Active Permit2 allowances (delegated token spend via the Permit2 router)."""
    logs = await etherscan.get_logs(chain_id, address=PERMIT2, topic0=_PERMIT2_APPROVAL,
                                    topic1=_topic_addr(wallet), offset=200)
    seen: set[tuple[str, str]] = set()
    pairs: list[tuple[str, str]] = []
    for lg in logs or []:
        topics = lg.get("topics") or []
        if len(topics) < 4:
            continue
        token = "0x" + topics[2][-40:]
        spender = "0x" + topics[3][-40:]
        key = (token.lower(), spender.lower())
        if key in seen:
            continue
        seen.add(key)
        pairs.append((token, spender))

    out: list[dict] = []
    for token, spender in pairs[:40]:
        # Permit2.allowance(owner, token, spender) -> (amount uint160, expiration uint48, nonce uint48)
        data = _PERMIT2_ALLOWANCE + _pad(wallet) + _pad(token) + _pad(spender)
        try:
            raw = await rpc.eth_call(chain_id, PERMIT2, data)
        except Exception:
            continue
        if not raw or raw == "0x" or len(raw) < 3:
            continue
        b = raw[2:]
        amount = int(b[0:64], 16) if len(b) >= 64 else 0
        expiration = int(b[64:128], 16) if len(b) >= 128 else 0
        if amount <= 0:
            continue
        out.append({
            "kind": "permit2",
            "token": token,
            "token_symbol": None,
            "spender": spender,
            "spender_label": None,
            "spender_is_known_drainer": False,
            "allowance_raw": str(amount),
            "unlimited": amount >= _UNLIMITED,
            "expiration": expiration,
            "exposure_usd": None,
            "revoke_instruction": {
                "contract": "Permit2 (0x0000…78BA3)",
                "call": "approve(token, spender, 0, 0)",
                "args": [token, spender, 0, 0],
                "note": "Set your Permit2 allowance for this token+spender to zero.",
            },
        })
    return out
