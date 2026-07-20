"""foresee_identity - are these wallets the same person?

Evidence sources (all on-chain, no KYC data):
1. Funding graph: who funded each wallet early on (normal AND internal transfers)?
   Overlap of the early-funder set is a strong signal.
2. Direct transfers between the wallets, ever (ETH or tokens).
3. Common counterparties: overlap of frequent-interaction sets (ETH + ERC-20).
4. Time-of-day fingerprint: same hourly schedule?
5. Gas-price fingerprint: same typical gwei habits?
6. Contract-usage fingerprint: same top interacted-with contracts + tokens?

We return a probability + a breakdown of each signal's contribution.
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timezone

from ..chains.etherscan import Etherscan


async def compare_wallets(
    wallets: list[str],
    chain_id: int,
    etherscan: Etherscan,
    tx_sample: int = 300,
) -> dict:
    if len(wallets) < 2 or len(wallets) > 5:
        return {"error": "provide 2-5 wallets"}
    profiles = []
    for w in wallets:
        p = await _profile(w, chain_id, etherscan, tx_sample)
        profiles.append(p)

    pairs = []
    for i in range(len(wallets)):
        for j in range(i + 1, len(wallets)):
            pairs.append(_compare_pair(profiles[i], profiles[j]))

    if len(wallets) == 2:
        overall_p = pairs[0]["probability_same"]
    else:
        # weakest link controls: multi-wallet identity requires every pair to correlate
        overall_p = min(p["probability_same"] for p in pairs)
    verdict = _verdict(overall_p)

    return {
        "wallets": wallets,
        "chain_id": chain_id,
        "overall_probability_same": overall_p,
        "verdict": verdict,
        "pairs": pairs,
        "profiles": [_public_profile(p) for p in profiles],
    }


# ---- Profile builder ----

async def _profile(wallet: str, chain_id: int, etherscan: Etherscan, sample: int) -> dict:
    wallet_l = wallet.lower()

    # Pull three streams. Each is one Etherscan call; keep offsets modest for rate limits.
    txs = await _safe(etherscan.txlist(wallet, chain_id, page=1, offset=sample))
    internal = await _safe(etherscan.txlist_internal(wallet, chain_id, page=1, offset=200))
    erc20 = await _safe(etherscan.erc20_transfers(wallet, chain_id, page=1, offset=200))

    counterparties: Counter = Counter()
    contract_calls: Counter = Counter()
    hours: list[int] = []
    gas_prices: list[int] = []

    # Collect the *earliest* incoming funders across normal + internal transfers.
    # Same-person wallets very often share an early funder (a CEX withdrawal address,
    # a personal hot wallet, a bridge) even when the literal first tx differs.
    incoming: list[tuple[int, str]] = []  # (timestamp, from_addr)

    for tx in txs:
        fr = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        ts = int(tx.get("timeStamp") or 0)
        gas = int(tx.get("gasPrice") or 0)
        input_data = tx.get("input") or "0x"
        val = int(tx.get("value") or 0)

        if fr == wallet_l and to:
            counterparties[to] += 1
        elif to == wallet_l and fr:
            counterparties[fr] += 1
            if val > 0:
                incoming.append((ts, fr))
        if ts:
            hours.append(datetime.fromtimestamp(ts, tz=timezone.utc).hour)
        if gas:
            gas_prices.append(gas)
        if fr == wallet_l and len(input_data) > 2:
            contract_calls[to] += 1

    for tx in internal:
        fr = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        ts = int(tx.get("timeStamp") or 0)
        val = int(tx.get("value") or 0)
        if fr == wallet_l and to:
            counterparties[to] += 1
        elif to == wallet_l and fr:
            counterparties[fr] += 1
            if val > 0:
                incoming.append((ts, fr))  # internal funding (CEX / contract payouts)

    for tx in erc20:
        fr = (tx.get("from") or "").lower()
        to = (tx.get("to") or "").lower()
        token = (tx.get("contractAddress") or "").lower()
        other = to if fr == wallet_l else fr
        if other and other != wallet_l:
            counterparties[other] += 1
        if token:
            contract_calls[token] += 1  # shared token usage is a strong dapp fingerprint

    # earliest funder + a small set of early funders
    incoming.sort(key=lambda x: x[0] if x[0] else 1 << 62)
    funder = incoming[0][1] if incoming else None
    first_tx_ts = incoming[0][0] if incoming else None
    early_funders = {f for _, f in incoming[:6] if f}

    return {
        "wallet": wallet_l,
        "funder": funder,
        "early_funders": early_funders,
        "first_tx_ts": first_tx_ts,
        "counterparties": counterparties,
        "hours": hours,
        "gas_prices": gas_prices,
        "contract_calls": contract_calls,
        "tx_count_sampled": len(txs) + len(internal) + len(erc20),
    }


async def _safe(coro):
    try:
        return await coro
    except Exception:
        return []


def _public_profile(p: dict) -> dict:
    return {
        "wallet": p["wallet"],
        "first_tx_ts": p["first_tx_ts"],
        "funder": p["funder"],
        "early_funders": sorted(p.get("early_funders") or []),
        "tx_count_sampled": p["tx_count_sampled"],
        "top_counterparties": [
            {"address": a, "count": c} for a, c in p["counterparties"].most_common(5)
        ],
        "hour_distribution": _hour_hist(p["hours"]),
        "median_gas_gwei": round(statistics.median(p["gas_prices"]) / 1e9, 2)
        if p["gas_prices"] else None,
    }


# ---- Pair comparison ----

def _compare_pair(p1: dict, p2: dict) -> dict:
    signals: list[dict] = []
    score = 0.0

    # 1. Shared funder — match on the single earliest OR any overlap of early funders.
    ef1 = p1.get("early_funders") or set()
    ef2 = p2.get("early_funders") or set()
    shared_set = ef1 & ef2
    same_first = bool(p1["funder"] and p1["funder"] == p2["funder"])
    if same_first or shared_set:
        addr = p1["funder"] if same_first else next(iter(shared_set))
        signals.append({
            "id": "shared_funder", "weight": 0.35, "hit": True,
            "detail": f"Both wallets share an early funder: {addr}.",
        })
        score += 0.35
    else:
        signals.append({
            "id": "shared_funder", "weight": 0.35, "hit": False,
            "detail": f"No shared early funder ({p1['funder']} vs {p2['funder']}).",
        })

    # 2. Direct transfers between them (ETH or tokens)
    direct = (p1["counterparties"].get(p2["wallet"], 0)
              + p2["counterparties"].get(p1["wallet"], 0))
    if direct > 0:
        signals.append({"id": "direct_transfers", "weight": 0.25, "hit": True,
                        "detail": f"{direct} direct transfer(s) between the two wallets."})
        score += 0.25
    else:
        signals.append({"id": "direct_transfers", "weight": 0.25, "hit": False,
                        "detail": "No direct transfers observed between the wallets."})

    # 3. Common counterparties (Jaccard on top-30)
    top1 = set(a for a, _ in p1["counterparties"].most_common(30))
    top2 = set(a for a, _ in p2["counterparties"].most_common(30))
    if top1 and top2:
        jacc = len(top1 & top2) / len(top1 | top2)
        if jacc >= 0.25:
            signals.append({"id": "counterparty_overlap", "weight": 0.15, "hit": True,
                            "detail": f"{jacc:.0%} counterparty overlap on top-30 sets."})
            score += 0.15
        else:
            signals.append({"id": "counterparty_overlap", "weight": 0.15, "hit": False,
                            "detail": f"Only {jacc:.0%} counterparty overlap."})

    # 4. Hour fingerprint
    cos = _cosine(_hour_hist(p1["hours"]), _hour_hist(p2["hours"]))
    if cos >= 0.85:
        signals.append({"id": "hour_fingerprint", "weight": 0.10, "hit": True,
                        "detail": f"Time-of-day pattern cosine similarity: {cos:.2f}."})
        score += 0.10
    else:
        signals.append({"id": "hour_fingerprint", "weight": 0.10, "hit": False,
                        "detail": f"Time-of-day pattern cosine similarity: {cos:.2f}."})

    # 5. Gas-price fingerprint
    if p1["gas_prices"] and p2["gas_prices"]:
        m1 = statistics.median(p1["gas_prices"]); m2 = statistics.median(p2["gas_prices"])
        if max(m1, m2) > 0:
            rel = abs(m1 - m2) / max(m1, m2)
            if rel < 0.2:
                signals.append({"id": "gas_fingerprint", "weight": 0.05, "hit": True,
                                "detail": f"Similar gas habits (medians differ by {rel:.0%})."})
                score += 0.05
            else:
                signals.append({"id": "gas_fingerprint", "weight": 0.05, "hit": False,
                                "detail": f"Different gas habits (medians differ by {rel:.0%})."})

    # 6. Contract / token usage overlap
    c1 = set(a for a, _ in p1["contract_calls"].most_common(25))
    c2 = set(a for a, _ in p2["contract_calls"].most_common(25))
    if c1 and c2:
        j2 = len(c1 & c2) / len(c1 | c2)
        if j2 >= 0.25:
            signals.append({"id": "contract_usage_overlap", "weight": 0.10, "hit": True,
                            "detail": f"{j2:.0%} overlap on top contracts + tokens used."})
            score += 0.10
        else:
            signals.append({"id": "contract_usage_overlap", "weight": 0.10, "hit": False,
                            "detail": f"{j2:.0%} overlap on top contracts + tokens used."})

    probability = min(0.99, max(0.01, score))
    return {
        "wallet_a": p1["wallet"], "wallet_b": p2["wallet"],
        "probability_same": round(probability, 3),
        "verdict": _verdict(probability),
        "signals": signals,
    }


# ---- Utilities ----

def _hour_hist(hours: list[int]) -> list[int]:
    hist = [0] * 24
    for h in hours:
        if 0 <= h < 24:
            hist[h] += 1
    return hist


def _cosine(a: list[int], b: list[int]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _verdict(p: float) -> str:
    if p >= 0.7:
        return "very_likely_same"
    if p >= 0.45:
        return "likely_same"
    if p >= 0.25:
        return "possible"
    return "likely_different"
