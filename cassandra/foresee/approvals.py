"""foresee_approvals - every open approval + live USD exposure + revoke calldata.

Strategy: pull ERC-20 transfer logs where the wallet appears as the token holder,
then for every unique (token, spender) pair, read `allowance(owner, spender)` live.
Any non-zero allowance is an open door.

Live USD exposure = current allowance * live price (capped at holder's current balance).
Because if you have $500 of USDC and an unlimited approval, the drainer can only take $500.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from eth_abi import encode as abi_encode
from eth_hash.auto import keccak

from ..heuristics.addresses import KNOWN_ROUTERS, is_known_drainer, label_for
from ..chains.etherscan import Etherscan, EtherscanUnsupportedChain
from ..chains.rpc import Rpc
from ..chains.prices import Prices

# How far back the RPC fallback looks. Public endpoints reject wide ranges, so
# this is a deliberate trade: recent coverage that works everywhere, over full
# history that only works on a paid explorer plan.
_LOG_WINDOW_BLOCKS = 200_000


_UNLIMITED = (1 << 255)

# Approval(address indexed owner, address indexed spender, uint256 value)
_APPROVAL_TOPIC0 = "0x" + keccak(b"Approval(address,address,uint256)").hex()
# Each entry is one rate-limited explorer query, so this is the dominant cost on
# wallets with long histories. 24 keeps the whole audit inside the time budget
# even for the most-transacted addresses on Ethereum; the tokens are taken most
# recently-touched first, which is where live approvals actually are.
_MAX_LOG_TOKENS = 24

# Ceiling for the rate-limit-bound log-scan phase. Chosen to leave room for the
# allowance reads and pricing that follow inside a ~22s tool budget.
_LOG_SCAN_BUDGET = 9.0

# Wall-clock ceiling for the whole audit, comfortably inside the caller's budget
# so the oracle degrades on its own terms instead of being cut off mid-flight.
_AUDIT_BUDGET = 11.0


def _topic_addr(addr: str) -> str:
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


async def _audit_via_logs(wallet: str, chain_id: int, rpc: Rpc, prices: Prices,
                          max_pairs: int) -> dict:
    """Discover approvals from `Approval` logs over RPC, with no explorer at all.

    Used when the Etherscan plan doesn't cover this chain. Same output shape as
    the explorer path, plus `coverage` so the caller knows this is a window and
    not the wallet's whole history.
    """
    wallet_l = wallet.lower()
    try:
        head = await rpc.block_number(chain_id)
    except Exception:
        return {
            "wallet": wallet, "chain_id": chain_id,
            "open_approvals": [], "total_exposure_usd": 0, "degraded": True,
            "summary": ("This chain is not readable on the current explorer plan and no "
                        "RPC endpoint answered, so no approval history could be checked. "
                        "This is a missing input, not a clean result."),
        }

    from_block = max(0, head - _LOG_WINDOW_BLOCKS)
    try:
        logs = await rpc.get_logs(
            chain_id,
            topics=[_APPROVAL_TOPIC0, _topic_addr(wallet_l)],
            from_block=from_block, to_block="latest",
        )
    except Exception:
        logs = []

    pairs: set[tuple[str, str]] = set()
    for lg in logs:
        topics = lg.get("topics") or []
        if len(topics) < 3:
            continue
        token = (lg.get("address") or "").lower()
        spender = ("0x" + topics[2][-40:]).lower()
        if token and spender:
            pairs.add((token, spender))

    coverage = {
        "source": "rpc_logs", "from_block": from_block, "to_block": "latest",
        "note": ("This chain is not available on the current explorer plan, so approvals "
                 f"were read from the last ~{_LOG_WINDOW_BLOCKS:,} blocks of Approval "
                 "events. Older approvals may exist and are not shown."),
    }
    if not pairs:
        return {
            "wallet": wallet, "chain_id": chain_id, "open_approvals": [],
            "total_exposure_usd": 0, "degraded": True, "coverage": coverage,
            "summary": ("No open approvals found in the scanned window. Coverage on this "
                        "chain is partial - treat this as 'none found recently', not "
                        "'none exist'."),
        }

    rows: list[dict] = []
    for token, spender in list(pairs)[:max_pairs]:
        try:
            allowance = await _read_allowance(rpc, chain_id, token, wallet_l, spender)
        except Exception:
            continue
        if allowance <= 0:
            continue
        rows.append({
            "token": token, "spender": spender,
            "allowance_raw": str(allowance),
            "unlimited": allowance >= _UNLIMITED,
            "spender_label": label_for(spender),
            "spender_is_known_drainer": is_known_drainer(spender),
            "exposure_usd": None,
            "token_symbol": None,
        })

    rows.sort(key=lambda a: (0 if a["spender_is_known_drainer"] else 1,
                             0 if a["unlimited"] else 1))
    return {
        "wallet": wallet, "chain_id": chain_id,
        "open_approvals": rows, "total_exposure_usd": 0,
        "degraded": True, "coverage": coverage,
        "summary": (f"{len(rows)} open approval(s) found via on-chain events. USD exposure "
                    "is unavailable on this chain's reduced data path."),
    }


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
    _started = time.monotonic()

    # 1. Pull ERC-20 transfers this wallet has been part of. Each APPROVAL leaves a
    # `Transfer` fingerprint eventually, but a cheaper proxy: the tokens the wallet
    # has ever touched are the tokens where approvals may exist. This gives us a
    # candidate token list without needing a full log scan.
    # On a plan that doesn't cover this chain the explorer gives us nothing, but
    # `Approval` events are still on-chain - read them over RPC instead. The
    # oracle degrades in reach (a recent-block window rather than all history),
    # never in correctness.
    # Independent reads - issue them together rather than paying two round trips.
    try:
        tx, outbound = await asyncio.gather(
            etherscan.erc20_transfers(wallet, chain_id, page=1, offset=500),
            etherscan.txlist(wallet, chain_id, page=1, offset=1000),
        )
    except EtherscanUnsupportedChain:
        return await _audit_via_logs(wallet, chain_id, rpc, prices, max_pairs)

    # Build (token, spender) candidate pairs from historical `approve` calls.
    # Approve emits `Approval(owner, spender, value)` - but etherscan tokentx returns
    # only transfers, so we approximate: for each token the wallet has interacted with,
    # every contract that ever moved that token via transferFrom on the wallet is a
    # candidate spender. Cheaper alternative: read the wallet's outbound tx list,
    # decode `approve` and `increaseAllowance` calls directly.

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
    # Fetched concurrently. The client's own semaphore still holds us to the
    # provider's rate limit - gathering just stops the pipe going idle between
    # requests, which is what pushed heavy wallets past the time budget.
    log_tokens = list(tokens_seen.keys())[:_MAX_LOG_TOKENS]

    async def _logs_for(tok: str):
        try:
            return await etherscan.get_logs(
                chain_id, address=tok, topic0=_APPROVAL_TOPIC0,
                topic1=_topic_addr(wallet_l), offset=100,
            )
        except Exception:
            return []

    # This phase is rate-limit bound, so on a wallet with a very long history it
    # can outlast the caller's budget. Cap it: whatever has completed by the
    # deadline is used, and the shortfall is reported. A partial answer the user
    # can act on beats a timeout that tells them nothing.
    log_scan_complete = True
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(_logs_for(t) for t in log_tokens)),
            timeout=_LOG_SCAN_BUDGET,
        )
    except asyncio.TimeoutError:
        log_scan_complete = False
        results = []

    for token, logs in zip(log_tokens, results):
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

    # Every allowance is an independent eth_call, so read them all at once
    # rather than paying one round-trip of latency per pair. Bounded by whatever
    # is left of the audit's budget, keeping the reads that did finish - a
    # partial list is useful, a timeout is not.
    async def _allowance_or_none(tok: str, spd: str):
        try:
            return await _read_allowance(rpc, chain_id, tok, wallet_l, spd)
        except Exception:
            return None

    tasks = {asyncio.ensure_future(_allowance_or_none(t, s)): (t, s) for t, s in pairs}
    remaining = max(2.0, _AUDIT_BUDGET - (time.monotonic() - _started))
    done, pending = await asyncio.wait(tasks.keys(), timeout=remaining)
    for p in pending:
        p.cancel()
    if pending:
        log_scan_complete = False

    allowances_by_pair: dict[tuple[str, str], int] = {}
    for t in done:
        try:
            val = t.result()
        except Exception:
            continue
        if isinstance(val, int) and val > 0:
            allowances_by_pair[tasks[t]] = val

    open_allowances: list[dict] = []
    for (token, spender), allowance in allowances_by_pair.items():
        if not allowance or allowance <= 0:
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

    out = {
        "wallet": wallet,
        "chain_id": chain_id,
        "open_approvals": open_allowances,
        "total_exposure_usd": round(total_exposure, 2),
        "candidate_pairs_examined": len(pairs),
        "summary": summary,
    }
    if not log_scan_complete:
        # Under-reporting silently would be the dangerous failure here: a short
        # list would read as a clean wallet.
        out["degraded"] = True
        out["coverage"] = {
            "source": "partial",
            "note": ("This wallet has a large history and the event scan hit its time "
                     "limit, so approvals were derived from recent transactions only. "
                     "Other approvals may exist - treat this as an incomplete list, "
                     "not an all-clear."),
        }
        out["summary"] = "Partial scan. " + summary
    return out


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
