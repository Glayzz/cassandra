"""Map GoPlus token-security responses into Cassandra risk signals.

Returns a uniform dict: {score_delta, reasons, badges, meta, verdict_floor}.
Everything is defensive - missing fields are simply skipped.
"""
from __future__ import annotations


def _f(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _is1(gp: dict, key: str) -> bool:
    return str(gp.get(key, "0")) == "1"


def parse_evm_token(gp: dict) -> dict:
    reasons: list[str] = []
    badges: list[dict] = []
    score = 0
    floor = 0  # minimum risk score this evidence justifies

    honeypot = _is1(gp, "is_honeypot")
    if honeypot:
        score += 55; floor = max(floor, 85)
        reasons.append("GoPlus flags this as a HONEYPOT — you can buy but you cannot sell.")
        badges.append({"t": "honeypot", "sev": "bad"})
    if _is1(gp, "cannot_sell_all"):
        score += 25; reasons.append("Holders may be blocked from selling their full balance.")
    if _is1(gp, "cannot_buy"):
        score += 15; reasons.append("Buying is restricted by the contract.")

    bt = _f(gp.get("buy_tax")); st = _f(gp.get("sell_tax")); tt = _f(gp.get("transfer_tax"))
    if st is not None and st >= 0.5:
        score += 30; floor = max(floor, 70)
        reasons.append(f"Sell tax is {st*100:.0f}% — most of any sale is taken by the contract.")
    elif st is not None and st >= 0.1:
        score += 12; reasons.append(f"Sell tax is {st*100:.0f}%.")
    if bt is not None and bt >= 0.1:
        score += 6; reasons.append(f"Buy tax is {bt*100:.0f}%.")
    if bt is not None or st is not None:
        badges.append({"t": f"buy {(_f(gp.get('buy_tax')) or 0)*100:.0f}% / sell {(_f(gp.get('sell_tax')) or 0)*100:.0f}%",
                       "sev": "bad" if (st or 0) >= 0.1 else "neu"})

    if _is1(gp, "is_open_source") is False and "is_open_source" in gp:
        score += 15; reasons.append("Contract is not open-source / verified — its behaviour can't be reviewed.")
        badges.append({"t": "unverified", "sev": "bad"})
    if _is1(gp, "is_proxy"):
        score += 10; reasons.append("Proxy contract — the implementation can be swapped by its admin.")
        badges.append({"t": "proxy", "sev": "warn"})
    if _is1(gp, "is_mintable"):
        score += 12; reasons.append("Supply is mintable — the owner can create new tokens.")
        badges.append({"t": "mintable", "sev": "warn"})
    if _is1(gp, "owner_change_balance"):
        score += 22; floor = max(floor, 60)
        reasons.append("Owner can directly change your balance.")
        badges.append({"t": "owner can edit balances", "sev": "bad"})
    if _is1(gp, "hidden_owner"):
        score += 18; reasons.append("Contract has a hidden owner.")
    if _is1(gp, "can_take_back_ownership"):
        score += 12; reasons.append("Ownership can be re-claimed after being renounced.")
    if _is1(gp, "selfdestruct"):
        score += 20; reasons.append("Contract can self-destruct.")
    if _is1(gp, "transfer_pausable"):
        score += 12; reasons.append("Transfers can be paused by the owner (trading halt).")
        badges.append({"t": "pausable", "sev": "warn"})
    if _is1(gp, "is_blacklisted"):
        score += 12; reasons.append("Owner can blacklist addresses — a common way to block sells.")
    if _is1(gp, "slippage_modifiable"):
        score += 8; reasons.append("Tax/slippage can be changed by the owner at any time.")
    if _is1(gp, "trading_cooldown"):
        score += 5; reasons.append("Trading cooldown is enforced between transactions.")

    # holder concentration (top-10 provided)
    holders = gp.get("holders") or []
    top10 = 0.0
    for h in holders[:10]:
        p = _f(h.get("percent"))
        addr = (h.get("address") or "").lower()
        if p and addr != "0x000000000000000000000000000000000000dead":
            top10 += p
    if top10 >= 0.7:
        score += 15; reasons.append(f"Highly concentrated — top holders control {top10*100:.0f}% of supply.")
        badges.append({"t": f"top holders {top10*100:.0f}%", "sev": "bad"})
    elif top10 >= 0.4:
        score += 6; badges.append({"t": f"top holders {top10*100:.0f}%", "sev": "warn"})

    # LP lock (informational; only penalise clearly-unlocked DEX tokens)
    lp = gp.get("lp_holders") or []
    locked = sum((_f(h.get("percent")) or 0) for h in lp if str(h.get("is_locked", 0)) == "1")
    if _is1(gp, "is_in_dex") and lp and locked < 0.05:
        score += 8; reasons.append("Liquidity appears unlocked — the deployer could remove it.")
        badges.append({"t": "LP unlocked", "sev": "warn"})

    meta = {
        "goplus": {
            "is_honeypot": honeypot,
            "buy_tax": bt, "sell_tax": st, "transfer_tax": tt,
            "is_open_source": _is1(gp, "is_open_source"),
            "is_proxy": _is1(gp, "is_proxy"),
            "is_mintable": _is1(gp, "is_mintable"),
            "holder_count": gp.get("holder_count"),
            "top10_holder_pct": round(top10, 4),
            "lp_locked_pct": round(locked, 4),
            "in_cex": (gp.get("is_in_cex") or {}).get("listed") == "1",
        }
    }
    return {"score_delta": score, "reasons": reasons, "badges": badges, "meta": meta, "verdict_floor": floor}


def parse_solana_token(gp: dict) -> dict:
    reasons: list[str] = []
    badges: list[dict] = []
    score = 0
    floor = 0

    def status(key):
        return str((gp.get(key) or {}).get("status", "0")) == "1"

    if str(gp.get("non_transferable", "0")) == "1":
        score += 45; floor = max(floor, 80)
        reasons.append("Token is NON-TRANSFERABLE — you would not be able to move or sell it.")
        badges.append({"t": "non-transferable", "sev": "bad"})
    hook = gp.get("transfer_hook") or []
    if hook:
        score += 15; reasons.append("Transfer hook present — transfers can be intercepted or blocked by a program.")
        badges.append({"t": "transfer hook", "sev": "warn"})
    if gp.get("transfer_fee"):
        score += 8; reasons.append("Token charges a transfer fee (Token-2022 extension).")
    if status("mintable"):
        score += 20; reasons.append("Mint authority is active — supply can be inflated.")
    if status("freezable"):
        score += 22; floor = max(floor, 55)
        reasons.append("Freeze authority is active — your token account can be frozen so you can never sell.")
        badges.append({"t": "freezable", "sev": "bad"})
    if status("closable"):
        score += 10; reasons.append("Mint can be closed by its authority.")
    if status("metadata_mutable"):
        score += 6; reasons.append("Metadata is mutable — name/image/links can be changed after the fact.")
    # malicious authority?
    for field in ("mintable", "freezable", "metadata_mutable", "balance_mutable_authority"):
        for a in (gp.get(field) or {}).get("authority", []) or []:
            if str(a.get("malicious_address", 0)) == "1":
                score += 40; floor = max(floor, 85)
                reasons.append(f"An authority on this token is a FLAGGED malicious address ({field}).")

    trusted = str(gp.get("trusted_token", "0")) == "1"
    if trusted:
        score = max(0, score - 25)
        badges.append({"t": "trusted token", "sev": "ok"})

    holders = gp.get("holders") or []
    top10 = sum((_f(h.get("percent")) or 0) for h in holders[:10])
    if top10 >= 0.7 and not trusted:
        score += 12; badges.append({"t": f"top holders {top10*100:.0f}%", "sev": "bad"})

    meta = {"goplus": {
        "trusted_token": trusted,
        "mintable": status("mintable"), "freezable": status("freezable"),
        "non_transferable": str(gp.get("non_transferable", "0")) == "1",
        "transfer_hook": bool(hook),
        "holder_count": gp.get("holder_count"),
        "top10_holder_pct": round(top10, 4),
    }}
    return {"score_delta": score, "reasons": reasons, "badges": badges, "meta": meta, "verdict_floor": floor}
