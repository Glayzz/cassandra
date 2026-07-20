"""foresee_token - rug risk + deployer's family tree.

Two novelties over generic honeypot scanners:
1. `family_tree`: every prior contract the deployer wallet has shipped, ranked
   with a rugged/alive tag, so you see the human pattern behind the token.
2. `pattern_evidence`: source-level pattern hits (mint, blacklist, tax-mutable,
   ownership) with concrete line quotes when the contract is verified.
"""
from __future__ import annotations

import re
from typing import Any

from ..chains.etherscan import Etherscan
from ..chains.rpc import Rpc
from ..chains.prices import Prices
from ..heuristics.addresses import KNOWN_ROUTERS, label_for


# Patterns to grep in verified source. Each is a red flag when present.
_PATTERNS: list[tuple[str, str, str]] = [
    # (id, human_name, regex)
    ("mint_function",
     "Contract can mint new tokens (supply inflatable)",
     r"function\s+mint\s*\("),
    ("hidden_owner",
     "Ownership can be transferred or replaced",
     r"function\s+(transferOwnership|_transferOwnership)\s*\("),
    ("blacklist",
     "Owner can blacklist addresses (block sells)",
     r"\b(blacklist|_isBlacklisted|isBlackListed|isBot|_bots)\b"),
    ("fee_mutable",
     "Owner can change tax/fee at will",
     r"function\s+(setTaxFee|setBuyFee|setSellFee|setFee|setFees|updateFees|setSwapFee)\s*\("),
    ("pausable",
     "Contract can be paused (trading halted)",
     r"\b(_pause|whenNotPaused|Pausable)\b"),
    ("max_tx",
     "Owner can enforce a max-transaction size (block sells)",
     r"function\s+(setMaxTx|setMaxWallet|setMaxTransaction|_maxTxAmount)\s*"),
    ("owner_only_transfer",
     "Only-owner transfer branch found (rug switch)",
     r"require\s*\(\s*(msg\.sender\s*==\s*owner|_msgSender\(\)\s*==\s*owner|onlyOwner)"),
    ("no_liquidity_lock",
     "No visible LP lock in source (but source-only detection is weak)",
     r""),  # informational; verified by external LP check
    ("mev_reject",
     "Owner-controlled tx-origin gate (favors owner's own bots)",
     r"tx\.origin\s*==\s*(owner|_owner)"),
]


async def analyze_token(
    token: str,
    chain_id: int,
    etherscan: Etherscan,
    rpc: Rpc,
    prices: Prices,
    family_depth: int = 15,
    goplus=None,
) -> dict:
    token_l = token.lower()

    # 1. Contract source + metadata
    src = await etherscan.get_source(token, chain_id)
    contract_name = src.get("ContractName") if src else None
    is_verified = bool(src and src.get("SourceCode"))
    is_proxy = str(src.get("Proxy") or "0") == "1"
    impl = src.get("Implementation") if is_proxy else None
    compiler = src.get("CompilerVersion") if src else None
    source_code = src.get("SourceCode") if is_verified else ""

    # 2. Deployment info
    creation = await etherscan.get_contract_creation([token], chain_id)
    deployer = None
    creation_tx = None
    if creation and isinstance(creation, list) and creation:
        deployer = (creation[0].get("contractCreator") or "").lower()
        creation_tx = creation[0].get("txHash")

    # 3. Token supply + decimals + name via reads
    supply = decimals = 0
    symbol = None
    try:
        raw = await rpc.eth_call(chain_id, token, "0x18160ddd")  # totalSupply
        supply = int(raw, 16) if raw and raw != "0x" else 0
    except Exception:
        pass
    try:
        raw = await rpc.eth_call(chain_id, token, "0x313ce567")  # decimals
        decimals = int(raw, 16) if raw and raw != "0x" else 18
    except Exception:
        decimals = 18
    try:
        raw = await rpc.eth_call(chain_id, token, "0x95d89b41")  # symbol
        symbol = _decode_string(raw)
    except Exception:
        pass

    # 4. Live price
    price = None
    try:
        pmap = await prices.usd_prices([(chain_id, token)])
        price = pmap.get(token_l)
    except Exception:
        pass

    # 5. Source pattern hits
    pattern_hits: list[dict] = []
    if is_verified and source_code:
        clean = _extract_all_source(source_code)
        for pid, name, regex in _PATTERNS:
            if not regex:
                continue
            m = re.search(regex, clean, re.IGNORECASE)
            if m:
                pattern_hits.append({
                    "id": pid, "description": name,
                    "match_snippet": _context_around(clean, m.start(), m.end()),
                })

    # 6. Deployer family tree - list of prior contracts by this deployer + their fate
    family: list[dict] = []
    if deployer:
        family = await _deployer_family_tree(deployer, chain_id, etherscan, rpc, prices,
                                             depth=family_depth, exclude=token_l)

    # 7. Score
    score, verdict, reasons = _score(
        pattern_hits=pattern_hits,
        is_verified=is_verified,
        is_proxy=is_proxy,
        family=family,
    )

    # --- GoPlus Security enrichment (authoritative on token mechanics) ---
    security_badges: list = []
    goplus_meta: dict = {}
    if goplus is not None:
        try:
            gp = await goplus.evm_token_security(chain_id, token)
        except Exception:
            gp = None
        if isinstance(gp, dict):
            from ..heuristics.goplus_parse import parse_evm_token
            pg = parse_evm_token(gp)
            gp_score = min(100, pg["score_delta"])
            score = max(0, min(100, max(score, gp_score, pg["verdict_floor"])))
            reasons = pg["reasons"] + reasons
            security_badges = pg["badges"]
            goplus_meta = pg["meta"].get("goplus", {})
            verdict = "red" if score >= 60 else ("yellow" if score >= 30 else "green")
            if not symbol and gp.get("token_symbol"):
                symbol = gp.get("token_symbol")

    return {
        "token": token,
        "chain_id": chain_id,
        "verdict": verdict,
        "risk_score": score,  # 0=safe, 100=guaranteed rug
        "reasons": reasons,
        "metadata": {
            "name": contract_name,
            "symbol": symbol,
            "decimals": decimals,
            "total_supply_raw": str(supply),
            "usd_price": price,
            "is_verified": is_verified,
            "is_proxy": is_proxy,
            "implementation": impl,
            "compiler": compiler,
            "deployer": deployer,
            "creation_tx": creation_tx,
            "goplus": goplus_meta,
        },
        "security": security_badges,
        "pattern_evidence": pattern_hits,
        "deployer_family_tree": family,
    }


# ---- Family tree ----

async def _deployer_family_tree(
    deployer: str, chain_id: int, etherscan: Etherscan, rpc: Rpc, prices: Prices,
    depth: int, exclude: str,
) -> list[dict]:
    """Every contract this address has deployed + a fate summary for each."""
    # From txlist(deployer), a contract-creation tx is one with an empty `to`.
    txs = await etherscan.txlist(deployer, chain_id, page=1, offset=500, sort="desc")
    deployed = []
    for tx in txs:
        to = tx.get("to")
        contract_addr = (tx.get("contractAddress") or "").lower()
        if (not to or to == "" or to == "0x") and contract_addr and contract_addr != exclude:
            deployed.append({
                "address": contract_addr,
                "tx_hash": tx.get("hash"),
                "block": tx.get("blockNumber"),
                "timestamp": tx.get("timeStamp"),
            })
        if len(deployed) >= depth:
            break

    # For each deployment, determine fate
    for d in deployed:
        d.update(await _classify_fate(d["address"], chain_id, etherscan, rpc, prices))
    return deployed


async def _classify_fate(addr: str, chain_id: int, etherscan: Etherscan, rpc: Rpc,
                         prices: Prices) -> dict:
    """Best-effort: is this contract dead (0 activity), alive, or rugged (price crashed)?"""
    fate: dict = {"status": "unknown"}
    # Try totalSupply; if reverts, it's likely not an ERC-20
    try:
        raw = await rpc.eth_call(chain_id, addr, "0x18160ddd")
        supply = int(raw, 16) if raw and raw != "0x" else 0
        fate["total_supply_raw"] = str(supply)
        if supply == 0:
            fate["status"] = "empty_or_burned"
    except Exception:
        pass
    # Symbol
    try:
        raw = await rpc.eth_call(chain_id, addr, "0x95d89b41")
        s = _decode_string(raw)
        if s: fate["symbol"] = s
    except Exception:
        pass
    # Live price
    try:
        pmap = await prices.usd_prices([(chain_id, addr)])
        price = pmap.get(addr)
        if price is not None:
            fate["usd_price"] = price
            fate["status"] = "alive" if price >= 1e-8 else "rugged"
    except Exception:
        pass
    if fate["status"] == "unknown":
        # No price, but non-empty supply? Probably a dead token
        fate["status"] = "dead"
    return fate


# ---- Source parsing ----

def _extract_all_source(source_code: str) -> str:
    """Etherscan returns either raw source or a JSON stringified `standard-input`.
    Concatenate every file's content for regex scanning.
    """
    src = source_code.strip()
    if src.startswith("{"):
        # standard input JSON. Sometimes double-braced.
        try:
            import json
            if src.startswith("{{") and src.endswith("}}"):
                src = src[1:-1]
            parsed = json.loads(src)
            sources = parsed.get("sources", {})
            return "\n\n".join(v.get("content", "") for v in sources.values())
        except Exception:
            return source_code
    return source_code


def _context_around(s: str, start: int, end: int, window: int = 80) -> str:
    a = max(0, start - window)
    b = min(len(s), end + window)
    return s[a:b].replace("\n", " ")[:200]


def _decode_string(raw: str) -> str | None:
    if not raw or raw == "0x":
        return None
    b = bytes.fromhex(raw[2:])
    try:
        if len(b) >= 96:
            length = int.from_bytes(b[32:64], "big")
            return (b[64:64 + length].decode("utf-8", errors="replace").strip("\x00") or None)
        return b[:32].decode("utf-8", errors="replace").strip("\x00") or None
    except Exception:
        return None


# ---- Scoring ----

def _score(*, pattern_hits: list[dict], is_verified: bool, is_proxy: bool,
           family: list[dict]) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []
    if not is_verified:
        score += 30
        reasons.append("Contract source is NOT verified on Etherscan - you have no visibility into what it does.")
    if is_proxy:
        score += 15
        reasons.append("Target is a PROXY - the underlying code can be replaced by whoever holds admin.")
    # Pattern weights
    weights = {
        "mint_function": 15, "blacklist": 20, "fee_mutable": 15, "pausable": 10,
        "max_tx": 10, "owner_only_transfer": 20, "hidden_owner": 8, "mev_reject": 15,
    }
    for h in pattern_hits:
        w = weights.get(h["id"], 5)
        score += w
        reasons.append(f"[{h['id']}] {h['description']}")
    # Family tree signals
    if family:
        rugged = [f for f in family if f.get("status") == "rugged"]
        dead = [f for f in family if f.get("status") in ("dead", "empty_or_burned")]
        alive = [f for f in family if f.get("status") == "alive"]
        if len(family) >= 3 and (len(rugged) + len(dead)) / len(family) >= 0.8:
            score += 30
            reasons.append(
                f"Deployer has shipped {len(family)} prior contracts; "
                f"{len(rugged)} rugged and {len(dead)} went silent. Pattern of abandonment."
            )
        elif rugged:
            score += 20
            reasons.append(
                f"Deployer's prior contracts include {len(rugged)} rugged tokens."
            )
        elif alive and len(alive) >= 2:
            score = max(0, score - 10)
            reasons.append(
                f"Deployer has {len(alive)} still-live prior contracts, suggesting a real operator."
            )
    score = max(0, min(100, score))
    verdict = "red" if score >= 60 else ("yellow" if score >= 30 else "green")
    return score, verdict, reasons
