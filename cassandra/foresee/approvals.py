"""foresee_approvals - every open approval + live USD exposure + revoke calldata.

Strategy: pull ERC-20 transfer logs where the wallet appears as the token holder,
then for every unique (token, spender) pair, read `allowance(owner, spender)` live.
Any non-zero allowance is an open door.

Live USD exposure = current allowance * live price (capped at holder's current balance).
Because if you have $500 of USDC and an unlimited approval, the drainer can only take $500.
"""
from __future__ import annotations

from typing import Any

from eth_abi import encode as abi_encode
from eth_hash.auto import keccak

from ..heuristics.addresses import KNOWN_ROUTERS, is_known_drainer, label_for
from ..chains.etherscan import Etherscan
from ..chains.rpc import Rpc
from ..chains.prices import Prices


_UNLIMITED = (1 << 255)

# Approval(address indexed owner, address indexed spender, uint256 value)
_APPROVAL_TOPIC0 = "0x" + keccak(b"Approval(address,address,uint256)").hex()
_MAX_LOG_TOKENS = 40


def _topic_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


async def audit_approvals(
    wallet: str,
    chain_id: int,
    etherscan: Etherscan,
    rpc: Rpc,
    prices: Prices,
    max_pairs: int = 60,
) -> dict:
    """Return every non-zero ERC-20 allowance held by `wallet` on `chain_id`."""
    wallet_l = wallet.lower()

    # 1. Pull ERC-20 transfers this wallet has been part of. Each APPROVAL leaves a
    # `Transfer` fingerprint eventually, but a cheaper proxy: the tokens the wallet
    # has ever touched are the tokens where approvals may exist. This gives us a
    # candidate token list without needing a full log scan.
    tx = await etherscan.erc20_transfers(wallet, chain_id, page=1, offset=500)

    # Build (token, spender) candidate pairs from historical `approve` calls.
    # Approve emits `Approval(owner, spender, value)` - but etherscan tokentx returns
    # only transfers, so we approximate: for each token the wallet has interacted with,
    # every contract that ever moved that token via transferFrom on the wallet is a
    # candidate spender. Cheaper alternative: read the wallet's outbound tx list,
    # decode `approve` and `increaseAllowance` calls directly.
    outbound = await etherscan.txlist(wallet, chain_id, page=1, offset=1000)

    candidate_pairs: set[tuple[str, str]] = set()
    tokens_seen: dict[str, dict] = {}

    for t in tx:
        addr = (t.get("contractAddress") or "").lower()
        if addr and addr not in tokens_seen:
            tokens_seen[addr] = {
                "symbol": t.get("tokenSymbol"),
                "decimals": _safe_int(t.get("tokenDecimal")),
            }

    for tr in outbound:
        input_data = (tr.get("input") or "").lower()
        to = (tr.get("to") or "").lower()
        if not input_data or len(input_data) < 10:
            continue
        selector = input_data[:10]
        # approve(address,uint256) => 0x095ea7b3
        # increaseAllowance(address,uint256) => 0x39509351
        if selector in ("0x095ea7b3", "0x39509351") and to and input_data[10:74]:
            spender_hex = "0x" + input_data[34:74]
            candidate_pairs.add((to, spender_hex))
            if to not in tokens_seen:
                tokens_seen[to] = {"symbol": None, "decimals": None}

    # Log-based discovery (comprehensive): for every token the wallet has touched,
    # read Approval(owner, spender) events directly. This catches approvals set via
    # routers/aggregators and approvals older than the recent txlist window - the
    # cases the outbound-selector scan above misses. This is what makes coverage
    # match dedicated revoke tools rather than a best-effort guess.
    for token in list(tokens_seen.keys())[:_MAX_LOG_TOKENS]:
        try:
            logs = await etherscan.get_logs(
                chain_id, address=token, topic0=_APPROVAL_TOPIC0,
                topic1=_topic_addr(wallet_l), offset=100,
            )
        except Exception:
            logs = []
        for lg in logs or []:
            topics = lg.get("topics") or []
            if len(topics) < 3:
                continue
            spender_hex = ("0x" + topics[2][-40:]).lower()
            candidate_pairs.add((token, spender_hex))
            tokens_seen.setdefault(token, {"symbol": None, "decimals": None})

    if not candidate_pairs:
        return {
            "wallet": wallet, "chain_id": chain_id,
            "open_approvals": [], "total_exposure_usd": 0,
            "summary": "No open approvals found for this wallet (no Approval events or approve calls).",
        }

    # 2. Live-read allowance() for every candidate pair. Cap the list to max_pairs
    # to protect the free-tier budget - real deploy would page.
    pairs = list(candidate_pairs)[:max_pairs]

    open_allowances: list[dict] = []
    for token, spender in pairs:
        try:
            allowance = await _read_allowance(rpc, chain_id, token, wallet_l, spender)
        except Exception:
            continue
        if allowance <= 0:
            continue
        meta = tokens_seen.get(token, {})
        if not meta.get("symbol"):
            meta = {**meta, **(await _read_token_meta(rpc, chain_id, token))}
        open_allowances.append({
            "token": token,
            "token_symbol": meta.get("symbol"),
            "token_decimals": meta.get("decimals"),
            "spender": spender,
            "spender_label": label_for(spender),
            "spender_is_known_drainer": is_known_drainer(spender),
            "allowance_raw": str(allowance),
            "unlimited": allowance >= _UNLIMITED,
        })

    # 3. Get live prices + balances -> live USD exposure per allowance
    if open_allowances:
        price_map = await prices.usd_prices(
            [(chain_id, a["token"]) for a in open_allowances]
        )
        # balance for each token
        for a in open_allowances:
            try:
                bal = await _read_balance(rpc, chain_id, a["token"], wallet_l)
            except Exception:
                bal = 0
            a["holder_balance_raw"] = str(bal)
            p = price_map.get(a["token"])
            a["token_usd_price"] = p
            # exposure_usd = min(allowance, balance) * price / 10^decimals
            decimals = a.get("token_decimals") or 18
            spendable_raw = min(int(a["allowance_raw"]), bal) if not a["unlimited"] else bal
            a["exposure_usd"] = (spendable_raw / (10 ** decimals)) * p if p else None

    total_exposure = sum(
        (a["exposure_usd"] or 0) for a in open_allowances if isinstance(a["exposure_usd"], (int, float))
    )

    # 4. Rank
    open_allowances.sort(
        key=lambda a: (
            0 if a["spender_is_known_drainer"] else 1,
            -(a.get("exposure_usd") or 0),
            0 if a["unlimited"] else 1,
        ),
    )

    # 5. Add revoke calldata (approve(spender, 0)) for each
    for a in open_allowances:
        a["revoke_calldata"] = _encode_approve(a["spender"], 0)

    # 6. Summary
    # --- Permit2 + NFT operator approvals (modern drainer vectors) ---
    try:
        from .approvals_extra import nft_operator_approvals, permit2_approvals, PERMIT2
        extra = []
        extra += await permit2_approvals(wallet, chain_id, etherscan, rpc, prices)
        extra += await nft_operator_approvals(wallet, chain_id, etherscan, rpc)
        # price permit2 rows where possible
        p2_mints = [(chain_id, e["token"]) for e in extra if e.get("kind") == "permit2" and e.get("token")]
        if p2_mints:
            try:
                pm = await prices.usd_prices(p2_mints)
            except Exception:
                pm = {}
            for e in extra:
                if e.get("kind") == "permit2":
                    pr = pm.get((e.get("token") or "").lower())
                    e["token_usd_price"] = pr
        # flag approvals whose spender is the Permit2 router
        for a in open_allowances:
            if (a.get("spender") or "").lower() == PERMIT2:
                a["spender_label"] = "Permit2 router"
                a["note"] = "Approved to Permit2 - check your Permit2 delegations below."
        open_allowances.extend(extra)
    except Exception:
        pass

    critical = [a for a in open_allowances if a["spender_is_known_drainer"]]
    unlimited = [a for a in open_allowances if a["unlimited"] and not a["spender_is_known_drainer"]]
    summary = (
        f"{len(open_allowances)} open approvals, ~${total_exposure:,.2f} live USD exposure. "
        + (f"{len(critical)} to KNOWN DRAINERS. " if critical else "")
        + (f"{len(unlimited)} unlimited approvals to unlabeled contracts." if unlimited else "")
    )

    return {
        "wallet": wallet,
        "chain_id": chain_id,
        "open_approvals": open_allowances,
        "total_exposure_usd": round(total_exposure, 2),
        "candidate_pairs_examined": len(pairs),
        "summary": summary,
    }


# ---- On-chain reads ----

async def _read_allowance(rpc: Rpc, chain_id: int, token: str, owner: str, spender: str) -> int:
    # allowance(address,address) -> 0xdd62ed3e
    data = "0xdd62ed3e" + _pad_addr(owner) + _pad_addr(spender)
    raw = await rpc.eth_call(chain_id, token, data)
    return int(raw, 16) if raw and raw != "0x" else 0


async def _read_balance(rpc: Rpc, chain_id: int, token: str, owner: str) -> int:
    # balanceOf(address) -> 0x70a08231
    data = "0x70a08231" + _pad_addr(owner)
    raw = await rpc.eth_call(chain_id, token, data)
    return int(raw, 16) if raw and raw != "0x" else 0


async def _read_token_meta(rpc: Rpc, chain_id: int, token: str) -> dict:
    out: dict = {}
    try:
        raw = await rpc.eth_call(chain_id, token, "0x313ce567")  # decimals
        out["decimals"] = int(raw, 16) if raw and raw != "0x" else None
    except Exception:
        out["decimals"] = None
    try:
        raw = await rpc.eth_call(chain_id, token, "0x95d89b41")  # symbol
        out["symbol"] = _decode_string(raw)
    except Exception:
        out["symbol"] = None
    return out


def _decode_string(raw: str) -> str | None:
    if not raw or raw == "0x":
        return None
    b = bytes.fromhex(raw[2:])
    try:
        if len(b) >= 96:
            length = int.from_bytes(b[32:64], "big")
            s = b[64:64 + length].decode("utf-8", errors="replace").strip("\x00")
            return s or None
        return b[:32].decode("utf-8", errors="replace").strip("\x00") or None
    except Exception:
        return None


def _pad_addr(a: str) -> str:
    a = a.lower().replace("0x", "")
    return a.rjust(64, "0")


def _encode_approve(spender: str, amount: int) -> str:
    """approve(spender, amount) calldata."""
    args = abi_encode(["address", "uint256"], [spender, amount]).hex()
    return "0x095ea7b3" + args


def _safe_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
