"""Solana implementations of the four foresee tools.

These mirror the EVM tools in spirit, but the mechanics are Solana-native:
  - signature: decode a base64 transaction/message into instructions + fates.
  - approvals: enumerate SPL token accounts whose delegate is set (the SOL analog
    of an ERC-20 allowance) + live USD exposure + a revoke instruction.
  - token: mint-account rug analysis (mint authority = infinite inflation, freeze
    authority = your tokens can be frozen) + Metaplex metadata when available.
  - identity: same-person probability from shared funder, direct transfers,
    counterparty overlap, and time-of-day rhythm using signature history.
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timezone

from ..chains.solana import SolanaRpc, TOKEN_PROGRAM, TOKEN_2022_PROGRAM
from ..chains.prices import Prices
from ..heuristics import solana_programs as SP


# =============================================================================
# 1. SIGNATURE
# =============================================================================

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _worse(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


def _color(sev: str) -> str:
    if sev in ("critical", "high"):
        return "red"
    if sev == "medium":
        return "yellow"
    return "green"


def analyze_solana_tx(tx_b64: str) -> dict:
    """Decode a base64 Solana transaction/message and narrate the fates.

    Pure decode - no network needed. Deterministic, sub-millisecond.
    """
    try:
        parsed = SP.parse_transaction(tx_b64)
    except Exception as e:
        return {
            "verdict": "error",
            "summary": f"Could not parse Solana transaction: {e}",
            "fates": [], "findings": [], "instructions": [],
        }

    instructions = parsed["instructions"]
    findings: list[dict] = []
    fates: list[str] = []
    severity_max = "info"
    decoded_ix: list[dict] = []

    approvals = 0
    transfers = 0
    unknown_programs = 0

    for i, ix in enumerate(instructions):
        c = SP.classify_instruction(ix)
        decoded_ix.append({"index": i, **{k: v for k, v in c.items() if k != "data"}})
        sev = c.get("severity", "info")
        severity_max = _worse(severity_max, sev)

        t = c.get("type")
        if t == "spl_approve":
            approvals += 1
            findings.append({
                "kind": "spl_approve", "severity": sev,
                "message": (f"Instruction #{i}: SPL Token Approve. "
                            f"Delegate {c.get('delegate')} would be able to move your tokens "
                            "until you revoke. This is the Solana equivalent of an unlimited "
                            "ERC-20 approval and the #1 SPL drainer vector."),
            })
            fates.append(f"Delegate {c.get('delegate')} gains the right to move your tokens.")
        elif t == "spl_set_authority":
            findings.append({
                "kind": "spl_set_authority", "severity": sev,
                "message": (f"Instruction #{i}: SetAuthority ({c.get('authority_type')}). "
                            + c.get("summary", "")),
            })
            if c.get("authority_type") == "AccountOwner":
                fates.append("Ownership of one of your token accounts would be handed to another address.")
        elif t == "spl_transfer":
            transfers += 1
            fates.append(c.get("summary", "Tokens leave your wallet."))
        elif t == "sol_transfer":
            transfers += 1
            fates.append(c.get("summary", "SOL leaves your wallet."))
        elif t == "spl_freeze":
            findings.append({"kind": "spl_freeze", "severity": sev, "message": c.get("summary", "")})
        elif t == "unknown_program":
            unknown_programs += 1
            findings.append({
                "kind": "unknown_program", "severity": sev,
                "message": (f"Instruction #{i} calls unrecognized program "
                            f"{c.get('program_id')}. Cassandra can't vouch for what it does."),
            })

    # aggregate drain heuristic
    if transfers >= 3:
        severity_max = _worse(severity_max, "high")
        findings.append({
            "kind": "bulk_transfer", "severity": "high",
            "message": (f"This single transaction contains {transfers} transfer instructions - "
                        "a common pattern for sweeping a wallet in one signature."),
        })
        fates.append("Multiple assets leave your wallet in one signature.")

    if not fates:
        fates.append("No asset-moving or authority-granting instructions were decoded. "
                     "Still verify the program list below before signing.")

    program_summary = Counter(
        (ix.get("program_label") or ix.get("program_id")) for ix in decoded_ix
    )

    return {
        "verdict": _color(severity_max),
        "network": "solana",
        "summary": (
            f"{parsed['parsed_as']} · {len(instructions)} instruction(s) · "
            f"{approvals} approve, {transfers} transfer, {unknown_programs} unknown-program"
        ),
        "fates": fates,
        "findings": findings,
        "instructions": decoded_ix,
        "programs": [{"program": k, "count": v} for k, v in program_summary.items()],
        "meta": {
            "version": parsed.get("version"),
            "accounts": len(parsed.get("accounts", [])),
            "parsed_as": parsed.get("parsed_as"),
        },
    }


# =============================================================================
# 2. APPROVALS
# =============================================================================

async def audit_solana_approvals(wallet: str, rpc: SolanaRpc, prices: Prices) -> dict:
    """Enumerate SPL token accounts with an active delegate (open approvals)."""
    open_approvals: list[dict] = []

    for program in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        try:
            accounts = await rpc.get_token_accounts_by_owner(wallet, program)
        except Exception:
            accounts = []
        for acct in accounts:
            info = (((acct or {}).get("account") or {}).get("data") or {}).get("parsed", {}).get("info", {})
            delegate = info.get("delegate")
            delegated = info.get("delegatedAmount") or {}
            amount = int(delegated.get("amount", 0) or 0)
            if not delegate or amount <= 0:
                continue
            mint = info.get("mint")
            decimals = (info.get("tokenAmount") or {}).get("decimals")
            if decimals is None:
                decimals = delegated.get("decimals", 0)
            open_approvals.append({
                "token_account": acct.get("pubkey"),
                "mint": mint,
                "delegate": delegate,
                "delegate_is_known_drainer": delegate in SP.KNOWN_SOL_DRAINERS,
                "delegated_amount_raw": str(amount),
                "decimals": decimals,
                "program": "Token-2022" if program == TOKEN_2022_PROGRAM else "SPL Token",
                "balance_raw": str(int((info.get("tokenAmount") or {}).get("amount", 0) or 0)),
            })

    # live USD exposure
    total_exposure = 0.0
    if open_approvals:
        mints = list({a["mint"] for a in open_approvals if a["mint"]})
        try:
            price_map = await prices.usd_prices_solana(mints)
        except Exception:
            price_map = {}
        for a in open_approvals:
            p = price_map.get(a["mint"])
            a["mint_usd_price"] = p
            dec = a.get("decimals") or 0
            spendable = min(int(a["delegated_amount_raw"]), int(a["balance_raw"]))
            a["exposure_usd"] = (spendable / (10 ** dec)) * p if p else None
            if isinstance(a["exposure_usd"], (int, float)):
                total_exposure += a["exposure_usd"]

    open_approvals.sort(key=lambda a: (
        0 if a["delegate_is_known_drainer"] else 1,
        -(a.get("exposure_usd") or 0),
    ))

    # revoke is an instruction, not calldata - describe it
    for a in open_approvals:
        a["revoke_instruction"] = {
            "program": "SPL Token (TokenkegQ…)",
            "instruction": "Revoke",
            "accounts": [a["token_account"], wallet],
            "note": "Send an SPL Token `Revoke` instruction on this token account to close the door.",
        }

    critical = [a for a in open_approvals if a["delegate_is_known_drainer"]]
    summary = (
        f"{len(open_approvals)} open SPL delegate(s), ~${total_exposure:,.2f} live exposure."
        + (f" {len(critical)} to flagged drainers." if critical else "")
        + ("" if open_approvals else " No active token-account delegates found.")
    )

    return {
        "wallet": wallet,
        "network": "solana",
        "open_approvals": open_approvals,
        "total_exposure_usd": round(total_exposure, 2),
        "summary": summary,
    }


# =============================================================================
# 3. TOKEN
# =============================================================================

async def analyze_solana_token(mint: str, rpc: SolanaRpc, prices: Prices, goplus=None) -> dict:
    reasons: list[str] = []
    score = 0

    acct = await rpc.get_account_info(mint, encoding="jsonParsed")
    if not acct:
        return {
            "token": mint, "network": "solana", "verdict": "error",
            "risk_score": None, "reasons": ["Mint account not found."],
        }

    parsed = ((acct.get("data") or {}).get("parsed") or {})
    info = parsed.get("info", {})
    owner_program = acct.get("owner")
    is_token_2022 = owner_program == TOKEN_2022_PROGRAM

    mint_authority = info.get("mintAuthority")
    freeze_authority = info.get("freezeAuthority")
    supply = info.get("supply")
    decimals = info.get("decimals")

    if mint_authority:
        score += 35
        reasons.append(
            f"Mint authority is still active ({mint_authority}). The holder can mint "
            "unlimited new tokens and dilute you to zero. Safe tokens renounce this."
        )
    else:
        reasons.append("Mint authority is renounced - supply cannot be inflated. Good sign.")

    if freeze_authority:
        score += 30
        reasons.append(
            f"Freeze authority is active ({freeze_authority}). The holder can freeze your "
            "token account so you can never sell. This is the classic SPL honeypot switch."
        )
    else:
        reasons.append("Freeze authority is renounced - your tokens can't be frozen. Good sign.")

    # Token-2022 extensions can hide transfer fees / transfer hooks
    if is_token_2022:
        score += 10
        reasons.append(
            "Token uses the Token-2022 program. Check its extensions - transfer fees and "
            "transfer hooks can tax or block sells in ways classic SPL tokens cannot."
        )

    # price
    price = None
    try:
        pmap = await prices.usd_prices_solana([mint])
        price = pmap.get(mint)
    except Exception:
        pass

    # metadata via Helius DAS (optional)
    name = symbol = None
    mutable = None
    das = await rpc.das_get_asset(mint)
    if das:
        content = das.get("content") or {}
        meta = content.get("metadata") or {}
        name = meta.get("name")
        symbol = meta.get("symbol")
        mutable = das.get("mutable")
        if mutable:
            score += 8
            reasons.append("Token metadata is still mutable - name/image/links can be changed after the fact.")

    security_badges: list = []
    goplus_meta: dict = {}
    if goplus is not None:
        try:
            gp = await goplus.solana_token_security(mint)
        except Exception:
            gp = None
        if isinstance(gp, dict):
            from ..heuristics.goplus_parse import parse_solana_token
            pg = parse_solana_token(gp)
            score = max(0, min(100, max(score, min(100, pg["score_delta"]), pg["verdict_floor"])))
            reasons = pg["reasons"] + reasons
            security_badges = pg["badges"]
            goplus_meta = pg["meta"].get("goplus", {})
            gmeta = gp.get("metadata") or {}
            if not symbol and gmeta.get("symbol"):
                symbol = gmeta.get("symbol")
            if not name and gmeta.get("name"):
                name = gmeta.get("name")

    score = max(0, min(100, score))
    verdict = "red" if score >= 55 else ("yellow" if score >= 25 else "green")

    return {
        "token": mint,
        "network": "solana",
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "metadata": {
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "supply_raw": supply,
            "usd_price": price,
            "program": "Token-2022" if is_token_2022 else "SPL Token",
            "mint_authority": mint_authority,
            "freeze_authority": freeze_authority,
            "metadata_mutable": mutable,
            "metadata_source": "helius_das" if das else "mint_account_only",
            "goplus": goplus_meta,
        },
        "security": security_badges,
        # On Solana there is no EOA "deployer family tree"; the authority addresses
        # are the human handles. Surface them as the analog.
        "authorities": [
            {"role": "mint", "address": mint_authority, "active": bool(mint_authority)},
            {"role": "freeze", "address": freeze_authority, "active": bool(freeze_authority)},
        ],
    }


# =============================================================================
# 4. IDENTITY
# =============================================================================

async def compare_solana_wallets(wallets: list[str], rpc: SolanaRpc,
                                  sig_sample: int = 100, tx_sample: int = 15) -> dict:
    if len(wallets) < 2 or len(wallets) > 5:
        return {"error": "provide 2-5 wallets"}

    profiles = [await _sol_profile(w, rpc, sig_sample, tx_sample) for w in wallets]

    pairs = []
    for i in range(len(wallets)):
        for j in range(i + 1, len(wallets)):
            pairs.append(_sol_compare(profiles[i], profiles[j]))

    overall = (pairs[0]["probability_same"] if len(wallets) == 2
               else min(p["probability_same"] for p in pairs))

    return {
        "wallets": wallets,
        "network": "solana",
        "overall_probability_same": overall,
        "verdict": _verdict(overall),
        "pairs": pairs,
        "profiles": [{
            "wallet": p["wallet"],
            "funder": p["funder"],
            "first_seen_ts": p["first_ts"],
            "sampled_signatures": p["sig_count"],
            "top_counterparties": [{"address": a, "count": c}
                                    for a, c in p["counterparties"].most_common(5)],
        } for p in profiles],
    }


async def _sol_profile(wallet: str, rpc: SolanaRpc, sig_sample: int, tx_sample: int) -> dict:
    sigs = await rpc.get_signatures_for_address(wallet, limit=sig_sample)
    hours: list[int] = []
    first_ts = None
    for s in sigs:
        bt = s.get("blockTime")
        if bt:
            hours.append(datetime.fromtimestamp(bt, tz=timezone.utc).hour)
            first_ts = bt  # list is newest-first, so last assignment = oldest in sample
    counterparties: Counter = Counter()
    fee_payers: Counter = Counter()

    # sample a handful of full transactions for counterparties + funder
    for s in sigs[:tx_sample]:
        sig = s.get("signature")
        if not sig:
            continue
        try:
            tx = await rpc.get_transaction(sig)
        except Exception:
            continue
        if not tx:
            continue
        acct_keys = (((tx.get("transaction") or {}).get("message") or {}).get("accountKeys") or [])
        for k in acct_keys:
            addr = k.get("pubkey") if isinstance(k, dict) else k
            if addr and addr != wallet:
                counterparties[addr] += 1
            if isinstance(k, dict) and k.get("signer") and k.get("pubkey") != wallet:
                fee_payers[k["pubkey"]] += 1

    funder = fee_payers.most_common(1)[0][0] if fee_payers else None

    return {
        "wallet": wallet,
        "funder": funder,
        "first_ts": first_ts,
        "sig_count": len(sigs),
        "hours": hours,
        "counterparties": counterparties,
    }


def _sol_compare(p1: dict, p2: dict) -> dict:
    signals = []
    score = 0.0

    # shared funder / co-signer
    if p1["funder"] and p1["funder"] == p2["funder"]:
        signals.append({"id": "shared_funder", "weight": 0.35, "hit": True,
                        "detail": f"Both wallets share a co-signer/fee-payer: {p1['funder']}."})
        score += 0.35
    else:
        signals.append({"id": "shared_funder", "weight": 0.35, "hit": False,
                        "detail": "No shared fee-payer/co-signer observed in the sample."})

    # direct interaction
    direct = p1["counterparties"].get(p2["wallet"], 0) + p2["counterparties"].get(p1["wallet"], 0)
    if direct > 0:
        signals.append({"id": "direct_transfers", "weight": 0.25, "hit": True,
                        "detail": f"{direct} transaction(s) directly involve both wallets."})
        score += 0.25
    else:
        signals.append({"id": "direct_transfers", "weight": 0.25, "hit": False,
                        "detail": "No transactions directly involve both wallets."})

    # counterparty overlap
    t1 = set(a for a, _ in p1["counterparties"].most_common(30))
    t2 = set(a for a, _ in p2["counterparties"].most_common(30))
    if t1 and t2:
        jacc = len(t1 & t2) / len(t1 | t2)
        if jacc >= 0.3:
            signals.append({"id": "counterparty_overlap", "weight": 0.25, "hit": True,
                            "detail": f"{jacc:.0%} overlap of interacted programs/accounts."})
            score += 0.25
        else:
            signals.append({"id": "counterparty_overlap", "weight": 0.25, "hit": False,
                            "detail": f"Only {jacc:.0%} counterparty overlap."})

    # hour rhythm
    h1 = _hist(p1["hours"]); h2 = _hist(p2["hours"])
    cos = _cosine(h1, h2)
    if cos >= 0.85:
        signals.append({"id": "hour_fingerprint", "weight": 0.15, "hit": True,
                        "detail": f"Time-of-day rhythm cosine similarity {cos:.2f}."})
        score += 0.15
    else:
        signals.append({"id": "hour_fingerprint", "weight": 0.15, "hit": False,
                        "detail": f"Time-of-day rhythm cosine similarity {cos:.2f}."})

    prob = min(0.99, max(0.01, score))
    return {
        "wallet_a": p1["wallet"], "wallet_b": p2["wallet"],
        "probability_same": round(prob, 3),
        "verdict": _verdict(prob),
        "signals": signals,
    }


def _hist(hours: list[int]) -> list[int]:
    h = [0] * 24
    for x in hours:
        if 0 <= x < 24:
            h[x] += 1
    return h


def _cosine(a: list[int], b: list[int]) -> float:
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
