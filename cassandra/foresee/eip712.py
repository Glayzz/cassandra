"""Off-chain EIP-712 signature analysis - the modern drainer vector.

Most wallet drains in 2024-2026 do NOT come from a transaction you send; they
come from a typed-data message you SIGN. A malicious dApp shows a friendly
"Sign in" / "Verify wallet" prompt that is really a Permit2 PermitBatch
authorizing a drainer to move every token you hold. No transaction, no gas -
the loss happens the instant you sign.

This module decodes those messages and narrates the exact authorization being
granted. It is pure and synchronous - no network. It recognizes:

  - ERC-2612 Permit (and DAI-style boolean permit)
  - Permit2 PermitSingle / PermitBatch          (AllowanceTransfer)
  - Permit2 PermitTransferFrom / BatchTransferFrom (SignatureTransfer)
  - Seaport / marketplace orders (offer / consideration inversion)
  - Generic fallback that still flags authorization-shaped fields
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..heuristics.addresses import is_known_drainer, label_for

PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"

_UINT256_UNLIMITED = (1 << 255)
_UINT160_MAX = (1 << 160) - 1
_UINT160_UNLIMITED = (1 << 159)

_ITEM_TYPES = {
    0: "native ETH", 1: "ERC-20", 2: "NFT (ERC-721)", 3: "NFT (ERC-1155)",
    4: "NFT (ERC-721 criteria)", 5: "NFT (ERC-1155 criteria)",
}


# ---- small coercers -------------------------------------------------------

def _addr(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        v = "0x" + v.hex()
    s = str(v).strip()
    return s.lower() if s.startswith("0x") else s


def _int(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except Exception:
        return default


def _short(a: str | None) -> str:
    if not a:
        return "?"
    return a if len(a) < 12 else f"{a[:6]}…{a[-4:]}"


def _ts(v: Any) -> str | None:
    n = _int(v, 0)
    if n <= 0 or n > 32503680000:  # year ~3000 sanity bound
        return None
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return None


# ---- entrypoint -----------------------------------------------------------

def analyze_typed_data(typed_data: Any) -> dict:
    """Analyze an EIP-712 typed-data blob (what wallets show for signTypedData)."""
    if isinstance(typed_data, str):
        try:
            typed_data = json.loads(typed_data)
        except Exception:
            return _err("typed_data is not valid EIP-712 JSON.")
    if not isinstance(typed_data, dict):
        return _err("typed_data must be an EIP-712 object.")

    domain = typed_data.get("domain") or {}
    primary = str(typed_data.get("primaryType") or "")
    msg = typed_data.get("message") or {}
    if not isinstance(msg, dict):
        msg = {}
    dname_l = str(domain.get("name") or "").lower()
    verifying = _addr(domain.get("verifyingContract"))
    chain_id = _int(domain.get("chainId"), 0)

    is_permit2 = (verifying == PERMIT2) or ("permit2" in dname_l)

    # Permit2 AllowanceTransfer (standing allowance via signature)
    if primary == "PermitSingle" or (is_permit2 and isinstance(msg.get("details"), dict)):
        return _permit2_allowance(msg, verifying, batch=False)
    if primary == "PermitBatch" or (is_permit2 and isinstance(msg.get("details"), list)):
        return _permit2_allowance(msg, verifying, batch=True)

    # Permit2 SignatureTransfer (one-shot transfer authorization)
    if primary == "PermitTransferFrom" or (is_permit2 and isinstance(msg.get("permitted"), dict)):
        return _permit2_transfer(msg, verifying, batch=False)
    if primary == "PermitBatchTransferFrom" or (is_permit2 and isinstance(msg.get("permitted"), list)):
        return _permit2_transfer(msg, verifying, batch=True)

    # ERC-2612 (and DAI-style) permit
    if primary == "Permit" or ("spender" in msg and ("value" in msg or "allowed" in msg)):
        return _erc2612(msg, domain, verifying)

    # Seaport / marketplace order
    if (primary in ("OrderComponents", "OrderMessage", "BulkOrder")
            or "seaport" in dname_l
            or ("offer" in msg and "consideration" in msg)):
        return _seaport(msg, domain)

    return _generic(primary, str(domain.get("name") or ""), msg, verifying)


# ---- scheme analyzers -----------------------------------------------------

def _erc2612(msg: dict, domain: dict, verifying: str | None) -> dict:
    spender = _addr(msg.get("spender"))
    token_name = str(domain.get("name") or _short(verifying))

    dai_style = "allowed" in msg and "value" not in msg
    if dai_style:
        allowed = bool(msg.get("allowed"))
        if not allowed:
            return _result(
                scheme="erc2612_permit", severity="info",
                summary=f"DAI-style permit REVOKING allowance for {_short(spender)}.",
                fates=["This revokes a spender's allowance - a protective action. Nothing leaves your wallet."],
                findings=[],
                operation={"spender": spender, "token": verifying, "allowed": False, "unlimited": False},
            )
        value, unlimited = _UINT256_UNLIMITED, True
    else:
        value = _int(msg.get("value"))
        unlimited = value >= _UINT256_UNLIMITED

    deadline = _ts(msg.get("deadline"))
    drainer = is_known_drainer(spender or "")
    label = label_for(spender or "")
    severity = "critical" if drainer else "high"
    amt = "UNLIMITED" if unlimited else str(value)

    findings = [{
        "kind": "eip712_permit", "severity": severity,
        "message": (f"ERC-2612 gasless permit on {token_name}. Signing this OFF-CHAIN message lets "
                    f"{label or _short(spender)} spend {amt} of your {token_name} immediately - "
                    "no transaction, no gas, right now."),
    }]
    if drainer:
        findings.append({"kind": "drainer_spender", "severity": "critical",
                         "message": f"Spender {spender} is on Cassandra's drainer registry."})
    fates = [
        f"{label or _short(spender)} can pull {'ALL' if unlimited else amt} of your {token_name} "
        f"the instant you sign" + (f", until {deadline}." if deadline else ".")
    ]
    return _result(
        scheme="erc2612_permit", severity=severity,
        summary=f"ERC-2612 permit - {token_name} -> {label or _short(spender)} ({amt}). "
                "This is how most modern drains begin.",
        fates=fates, findings=findings,
        operation={"spender": spender, "token": verifying, "value": str(value),
                   "unlimited": unlimited, "deadline": msg.get("deadline")},
    )


def _permit2_allowance(msg: dict, verifying: str | None, batch: bool) -> dict:
    spender = _addr(msg.get("spender"))
    details = msg.get("details")
    items = details if isinstance(details, list) else [details]

    parsed, any_unlimited = [], False
    for d in items:
        if not isinstance(d, dict):
            continue
        amount = _int(d.get("amount"))
        unlimited = amount >= _UINT160_UNLIMITED
        any_unlimited = any_unlimited or unlimited
        parsed.append({
            "token": _addr(d.get("token")), "amount": str(amount), "unlimited": unlimited,
            "expiration": _ts(d.get("expiration")), "expiration_ts": d.get("expiration"),
        })

    drainer = is_known_drainer(spender or "")
    label = label_for(spender or "")
    severity = "critical" if (drainer or any_unlimited) else "high"
    n = len(parsed)
    tokens_desc = ", ".join(
        f"{_short(p['token'])}{' (UNLIMITED)' if p['unlimited'] else ''}" for p in parsed
    ) or "tokens"

    findings = [{
        "kind": "permit2_allowance", "severity": severity,
        "message": (f"Permit2 {'PermitBatch' if batch else 'PermitSingle'} authorizing "
                    f"{label or _short(spender)} to spend {n} token{'s' if n != 1 else ''} "
                    f"({tokens_desc}) through the Permit2 router. Permit2 signatures are the #1 EVM "
                    "phishing vector - the dApp shows only a signature prompt, but it grants standing "
                    "allowances exactly like an on-chain approve."),
    }]
    if drainer:
        findings.append({"kind": "drainer_spender", "severity": "critical",
                         "message": f"Spender {spender} is on Cassandra's drainer registry."})
    fates = [f"{label or _short(spender)} can pull the listed token{'s' if n != 1 else ''} from your "
             "wallet the moment you sign - no transaction required."]
    if any_unlimited:
        fates.append("At least one grant is UNLIMITED - the spender can take your entire balance of that token.")
    return _result(
        scheme="permit2_allowance", severity=severity,
        summary=(f"Permit2 {'batch ' if batch else ''}allowance -> {label or _short(spender)} over "
                 f"{n} token{'s' if n != 1 else ''}. Most modern drains use exactly this."),
        fates=fates, findings=findings,
        operation={"spender": spender, "verifying_contract": verifying, "router": "permit2",
                   "tokens": parsed, "unlimited": any_unlimited},
    )


def _permit2_transfer(msg: dict, verifying: str | None, batch: bool) -> dict:
    spender = _addr(msg.get("spender") or msg.get("to"))
    permitted = msg.get("permitted")
    items = permitted if isinstance(permitted, list) else [permitted]

    parsed = []
    for d in items:
        if not isinstance(d, dict):
            continue
        parsed.append({"token": _addr(d.get("token")), "amount": str(_int(d.get("amount")))})

    deadline = _ts(msg.get("deadline"))
    drainer = is_known_drainer(spender or "")
    label = label_for(spender or "")
    tokens_desc = ", ".join(f"{p['amount']} of {_short(p['token'])}" for p in parsed) or "tokens"

    findings = [{
        "kind": "permit2_transfer", "severity": "critical",
        "message": (f"Permit2 SignatureTransfer authorizing {label or _short(spender)} to transfer "
                    f"{tokens_desc} out of your wallet. Unlike an allowance, this is a direct "
                    "authorization to MOVE the tokens - signing it is equivalent to sending them."),
    }]
    if drainer:
        findings.append({"kind": "drainer_spender", "severity": "critical",
                         "message": f"Recipient {spender} is on Cassandra's drainer registry."})
    fates = [f"Signing sends {tokens_desc} to {label or _short(spender)}"
             + (f" (valid until {deadline})." if deadline else ".")]
    return _result(
        scheme="permit2_transfer", severity="critical",
        summary=f"Permit2 signature-transfer -> {label or _short(spender)}. Signing MOVES your tokens.",
        fates=fates, findings=findings,
        operation={"spender": spender, "verifying_contract": verifying, "router": "permit2",
                   "transfer": True, "tokens": parsed},
    )


def _seaport(msg: dict, domain: dict) -> dict:
    offer = msg.get("offer") or []
    consideration = msg.get("consideration") or []
    offerer = _addr(msg.get("offerer"))

    def _desc(items):
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            t = _int(it.get("itemType"))
            out.append(f"{it.get('startAmount', '?')} x {_ITEM_TYPES.get(t, 'item')} "
                       f"{_short(_addr(it.get('token')))}")
        return out

    gives = _desc(offer)
    back_to_offerer = [c for c in consideration
                       if isinstance(c, dict) and (not offerer or _addr(c.get("recipient")) == offerer)]
    gets = _desc(back_to_offerer)
    offer_has_nft = any(isinstance(it, dict) and _int(it.get("itemType")) >= 2 for it in offer)
    getting_nothing = not gets
    severity = "critical" if (offer_has_nft and getting_nothing) else "high"

    findings = [{
        "kind": "seaport_order", "severity": severity,
        "message": ("Seaport marketplace order. If you are the offerer, you GIVE everything in 'offer' and "
                    "RECEIVE only the 'consideration' routed back to you. Scam listings place your valuable "
                    "NFTs in 'offer' and route the payment elsewhere (or set it to ~0), so you hand over "
                    "assets for nothing."),
    }]
    if offer_has_nft and getting_nothing:
        findings.append({"kind": "seaport_inversion", "severity": "critical",
                         "message": "This order gives up NFT(s) while routing little or no payment back to "
                                    "you - a classic zero-consideration NFT theft."})
    fates = [
        f"You give up: {', '.join(gives) or 'nothing decoded'}",
        f"You receive: {', '.join(gets) or 'NOTHING routed back to you'}",
    ]
    return _result(
        scheme="seaport_order", severity=severity,
        summary=f"Seaport order on {domain.get('name') or 'marketplace'} - verify what leaves your wallet.",
        fates=fates, findings=findings,
        operation={"marketplace": domain.get("name"), "offerer": offerer, "gives": gives, "gets": gets},
    )


def _generic(primary: str, dname: str, msg: dict, verifying: str | None) -> dict:
    suspects = {}
    for k, v in (msg.items() if isinstance(msg, dict) else []):
        if str(k).lower() in ("spender", "operator", "to", "delegate", "allowed", "approved", "authorized"):
            suspects[k] = v
    severity = "high" if suspects else "medium"

    findings = [{
        "kind": "unknown_typed_data", "severity": "medium",
        "message": f"Unrecognized EIP-712 message: primaryType '{primary or '?'}' on domain '{dname or '?'}'.",
    }]
    fates = ["Cassandra doesn't recognize this typed-data schema. Do not sign unless you can read every "
             "field and you trust the site requesting it."]
    if suspects:
        findings.append({"kind": "suspicious_fields", "severity": "high",
                         "message": f"Message contains authorization-shaped fields: {list(suspects.keys())}. "
                                    "It may grant someone control over your assets."})
        fates.append(f"Possible authorization fields detected: {', '.join(map(str, suspects.keys()))}.")
    return _result(
        scheme="unknown", severity=severity,
        summary=f"Unrecognized EIP-712 request ({primary or 'unknown type'}).",
        fates=fates, findings=findings,
        operation={"primary_type": primary, "domain": dname, "verifying_contract": verifying},
    )


# ---- result builders ------------------------------------------------------

def _color(sev: str) -> str:
    return {"critical": "red", "high": "red", "medium": "yellow",
            "low": "green", "info": "green"}.get(sev, "green")


def _result(*, scheme: str, severity: str, summary: str, fates: list[str],
            findings: list[dict], operation: dict) -> dict:
    op = {"kind": "eip712", "scheme": scheme, **operation}
    target_addr = operation.get("token") or operation.get("verifying_contract")
    return {
        "verdict": _color(severity),
        "severity": severity,
        "network": "eip712",
        "summary": summary,
        "fates": fates,
        "findings": findings,
        "target": {"address": target_addr, "kind": "eip712", "scheme": scheme},
        "operation": op,
    }


def _err(msg: str) -> dict:
    return {"verdict": "error", "summary": msg, "fates": [], "findings": [],
            "target": None, "operation": None}
