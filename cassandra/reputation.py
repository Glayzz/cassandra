"""Address reputation - is this address a known scammer / drainer / sanctioned entity?

Combines two sources:
  1. Cassandra's built-in registry (fast, offline).
  2. GoPlus address-security (live coverage of phishing, drainers, sanctioned,
     laundering, mixers, honeypot operators, and more).

Defensive: GoPlus failures degrade to the registry-only result.
"""
from __future__ import annotations

from .heuristics.addresses import is_known_drainer
from .heuristics.solana_programs import KNOWN_SOL_DRAINERS

# GoPlus address_security flag -> human label. Each value is "0"/"1".
_FLAGS = {
    "stealing_attack": "wallet drainer",
    "phishing_activities": "phishing",
    "honeypot_related_address": "honeypot operator",
    "blacklist_doubt": "blacklisted",
    "sanctioned": "sanctioned",
    "money_laundering": "money laundering",
    "financial_crime": "financial crime",
    "cybercrime": "cybercrime",
    "blackmail_activities": "blackmail",
    "darkweb_transactions": "darkweb activity",
    "malicious_mining_activities": "malicious mining",
    "fake_kyc": "fake KYC",
    "fake_token": "fake token",
    "mixer": "mixer",
    "number_of_malicious_contracts_created": "deploys malicious contracts",
}


async def check(address: str, chain_id: int | None, goplus=None, solana: bool = False) -> dict:
    """Return {malicious, labels, sources}. Never raises."""
    labels: list[str] = []
    sources: list[str] = []

    if address:
        if solana:
            if address in KNOWN_SOL_DRAINERS:
                labels.append("known drainer"); sources.append("registry")
        elif is_known_drainer(address):
            labels.append("known drainer"); sources.append("registry")

    if goplus is not None and address and not solana:
        try:
            r = await goplus.address_security(address, chain_id or 1)
        except Exception:
            r = None
        if isinstance(r, dict):
            hit = False
            for flag, name in _FLAGS.items():
                v = str(r.get(flag, "0"))
                if flag == "number_of_malicious_contracts_created":
                    if v.isdigit() and int(v) > 0:
                        labels.append(name); hit = True
                elif v == "1":
                    labels.append(name); hit = True
            if hit:
                sources.append("goplus")

    # de-dup preserve order
    seen = set()
    labels = [x for x in labels if not (x in seen or seen.add(x))]
    return {"malicious": bool(labels), "labels": labels, "sources": sources}


import asyncio as _asyncio


async def check_wallet(address: str, chain_id: int, goplus) -> dict:
    """Reputation of a wallet address itself (sanctioned / drainer / launderer)."""
    return await check(address, chain_id, goplus)


async def enrich_signature(result: dict, chain_id: int, goplus) -> dict:
    """Escalate a signature verdict if the spender/operator is a flagged address."""
    if not isinstance(result, dict) or goplus is None:
        return result
    op = result.get("operation") or {}
    cands = set()
    for k in ("spender", "operator", "destination"):
        v = op.get(k)
        if isinstance(v, str) and v.startswith("0x"):
            cands.add(v)
    flagged = []
    for a in cands:
        r = await check(a, chain_id, goplus)
        if r["malicious"]:
            flagged.append((a, r["labels"]))
    if flagged:
        result.setdefault("findings", [])
        result.setdefault("fates", [])
        for a, labels in flagged:
            result["findings"].insert(0, {
                "kind": "malicious_address", "severity": "critical",
                "message": f"{a} is a flagged address ({', '.join(labels)}). Signing this hands your assets to a known bad actor.",
            })
            result["fates"].insert(0, f"{a} is a KNOWN {labels[0]} — do not sign.")
        result["verdict"] = "red"
        result.setdefault("intel", {})["flagged_addresses"] = [
            {"address": a, "labels": l} for a, l in flagged
        ]
    return result


async def enrich_approvals(result: dict, chain_id: int, goplus, max_checks: int = 30) -> dict:
    """Mark any approval whose spender is a flagged address (live GoPlus coverage)."""
    if not isinstance(result, dict) or goplus is None:
        return result
    rows = result.get("open_approvals") or []
    targets = rows[:max_checks]
    spenders = [a.get("spender") for a in targets]
    results = await _asyncio.gather(
        *[check(s, chain_id, goplus) if s else _noop() for s in spenders],
        return_exceptions=True,
    )
    any_mal = False
    for a, c in zip(targets, results):
        if isinstance(c, dict) and c.get("malicious"):
            a["spender_malicious"] = True
            a["spender_labels"] = c["labels"]
            a["spender_is_known_drainer"] = True
            any_mal = True
    if any_mal:
        rows.sort(key=lambda a: (
            0 if (a.get("spender_malicious") or a.get("spender_is_known_drainer")) else 1,
            -(a.get("exposure_usd") or 0),
        ))
        result["summary"] = "Flagged spender detected. " + result.get("summary", "")
    return result


async def _noop():
    return None
