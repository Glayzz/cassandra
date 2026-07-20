"""foresee_scan - the Wallet X-Ray.

One call, whole-wallet verdict. Runs the approval audit, then layers an aggregate
"safety score" (0-100) + letter grade + a prioritised list of the biggest risks.
This is the flagship "check my wallet in one click" tool - it turns four separate
oracles into a single health read.

EVM: open ERC-20 allowances + drainer exposure + unlimited-approval count.
Solana: open SPL delegates + drainer exposure.
"""
from __future__ import annotations

from .approvals import audit_approvals
from .solana import audit_solana_approvals
from ..chains.etherscan import Etherscan
from ..chains.rpc import Rpc
from ..chains.prices import Prices
from ..chains.solana import SolanaRpc
from .. import reputation as _rep


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def _score_from_approvals(rows: list[dict], total_exposure: float, sol: bool) -> tuple[int, list[dict]]:
    """Aggregate a 0-100 safety score + ranked risk list from an approvals result."""
    score = 100
    risks: list[dict] = []

    drainer_key = "delegate_is_known_drainer" if sol else "spender_is_known_drainer"
    spender_key = "delegate" if sol else "spender"
    token_key = "mint" if sol else "token"

    drainers = [a for a in rows if a.get(drainer_key)]
    unlimited = [a for a in rows if a.get("unlimited") and not a.get(drainer_key)]

    has_drainer = bool(drainers)
    if drainers:
        score -= min(75, 55 * len(drainers))
        risks.append({
            "severity": "critical",
            "title": f"{len(drainers)} approval(s) to a known drainer",
            "detail": "Revoke immediately - these addresses can take your tokens at will.",
            "items": [a.get(spender_key) for a in drainers],
        })
    if unlimited:
        score -= min(40, 8 * len(unlimited))
        risks.append({
            "severity": "high",
            "title": f"{len(unlimited)} unlimited approval(s) to unlabeled contracts",
            "detail": "Each is an open door to your entire balance of that token.",
            "items": [f"{a.get('token_symbol') or a.get(token_key)}" for a in unlimited],
        })

    if total_exposure >= 10000:
        score -= 15
        risks.append({"severity": "high", "title": f"~${total_exposure:,.0f} of live exposure",
                      "detail": "That's how much a malicious spender could take today.", "items": []})
    elif total_exposure >= 1000:
        score -= 8
        risks.append({"severity": "medium", "title": f"~${total_exposure:,.0f} of live exposure",
                      "detail": "Meaningful funds are reachable through open approvals.", "items": []})
    elif total_exposure >= 100:
        score -= 3

    open_count = len(rows)
    if open_count == 0:
        risks.append({"severity": "info", "title": "No open approvals found",
                      "detail": "Nothing is standing unlocked in the sampled window.", "items": []})

    if has_drainer:
        score = min(score, 25)  # any drainer approval caps the wallet in the red
    score = max(0, min(100, score))
    return score, risks


async def wallet_xray_evm(wallet: str, chain_id: int, etherscan: Etherscan,
                          rpc: Rpc, prices: Prices, goplus=None) -> dict:
    appr = await audit_approvals(wallet=wallet, chain_id=chain_id,
                                 etherscan=etherscan, rpc=rpc, prices=prices)
    if goplus is not None:
        try:
            await _rep.enrich_approvals(appr, chain_id, goplus)
        except Exception:
            pass
    rows = appr.get("open_approvals", [])
    exposure = appr.get("total_exposure_usd", 0) or 0
    score, risks = _score_from_approvals(rows, exposure, sol=False)
    verdict = "red" if score < 40 else ("yellow" if score < 75 else "green")
    out = {
        "wallet": wallet, "network": "evm", "chain_id": chain_id,
        "safety_score": score, "grade": _grade(score), "verdict": verdict,
        "total_exposure_usd": round(exposure, 2),
        "open_approvals_count": len(rows),
        "risks": risks,
        "headline": _headline(score, len(rows), exposure),
        "detail": appr,
    }
    if goplus is not None:
        try:
            wr = await _rep.check(wallet, chain_id, goplus)
            if wr.get("malicious"):
                out["risks"].insert(0, {"severity": "critical",
                    "title": "This wallet itself is flagged",
                    "detail": "Reputation feeds flag this address: " + ", ".join(wr["labels"]) + ".",
                    "items": wr["labels"]})
                out["safety_score"] = min(out.get("safety_score", 100), 20)
                out["grade"] = _grade(out["safety_score"]); out["verdict"] = "red"
        except Exception:
            pass
    return out


async def wallet_xray_solana(wallet: str, solana: SolanaRpc, prices: Prices) -> dict:
    appr = await audit_solana_approvals(wallet, solana, prices)
    rows = appr.get("open_approvals", [])
    exposure = appr.get("total_exposure_usd", 0) or 0
    score, risks = _score_from_approvals(rows, exposure, sol=True)
    verdict = "red" if score < 40 else ("yellow" if score < 75 else "green")
    return {
        "wallet": wallet, "network": "solana",
        "safety_score": score, "grade": _grade(score), "verdict": verdict,
        "total_exposure_usd": round(exposure, 2),
        "open_approvals_count": len(rows),
        "risks": risks,
        "headline": _headline(score, len(rows), exposure),
        "detail": appr,
    }


def _headline(score: int, open_count: int, exposure: float) -> str:
    if score >= 90:
        return f"This wallet looks healthy - {open_count} open approval(s), minimal exposure."
    if score >= 55:
        return f"Some housekeeping needed - {open_count} open approval(s), ~${exposure:,.0f} exposed."
    return f"This wallet is at risk - {open_count} open approval(s), ~${exposure:,.0f} reachable now."
