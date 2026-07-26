"""Counterparty profiling - catch drainers that no blocklist knows about yet.

A blocklist can only recognise an address someone has already been robbed by.
Real drainer infrastructure is disposable: campaigns deploy a fresh, unverified
proxy (or use a brand-new EOA) per victim wave, so by the time an address lands
on a feed the campaign has moved on.

This module asks *structural* questions about whoever is being handed power over
your funds, none of which require prior knowledge of the address:

  1. Is the spender an EOA?  Legitimate spenders - routers, marketplaces,
     Permit2, lending pools - are ALWAYS contracts. An approval or permit whose
     spender is a plain wallet is the single strongest drainer tell there is.
  2. How old is it?  Drainer contracts are typically hours-to-days old.
  3. Is its source verified?  Real infrastructure is verified; drainers are not.
  4. Does a reputation feed already flag it?  (GoPlus - live, free.)

Every check degrades independently: an upstream failure yields `None`
("unknown"), never a false accusation. That distinction is load-bearing - a
security oracle that cries wolf gets ignored exactly when it is right.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from .. import reputation
from ..chains import sanctions
from ..heuristics.addresses import KNOWN_ROUTERS, label_for

# Permit2 is legitimate infrastructure but worth naming explicitly: it is both a
# real router and the rail most modern phishing rides on.
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"

# A contract younger than this, receiving spending power, is treated as hostile
# until proven otherwise. Drainer proxies are usually hours old.
_FRESH_CONTRACT_DAYS = 7
_YOUNG_CONTRACT_DAYS = 30

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _worse(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


async def _safe(coro, default=None):
    try:
        return await coro
    except Exception:
        return default


async def profile(
    address: str,
    chain_id: int,
    *,
    rpc=None,
    etherscan=None,
    goplus=None,
    role: str = "spender",
) -> dict:
    """Structural risk profile of an address about to be granted power.

    Returns {address, role, is_contract, is_verified, age_days, trusted_label,
             malicious, labels, signals[], severity, unknown[]}.
    Never raises; any check that cannot complete is reported as unknown.
    """
    addr = (address or "").strip()
    out: dict[str, Any] = {
        "address": addr, "role": role,
        "is_contract": None, "is_verified": None, "age_days": None,
        "trusted_label": None, "malicious": False, "labels": [],
        "signals": [], "unknown": [], "severity": "info",
    }
    if not addr.startswith("0x") or len(addr) != 42:
        return out

    addr_l = addr.lower()
    out["trusted_label"] = label_for(addr_l) or (
        "Uniswap Permit2" if addr_l == PERMIT2 else None
    )

    # All four probes are independent -> run them together.
    code, src, rep, ofac = await asyncio.gather(
        _safe(rpc.get_code(chain_id, addr)) if rpc else _safe(_none()),
        _safe(etherscan.get_source(addr, chain_id), {}) if etherscan else _safe(_none(), {}),
        _safe(reputation.check(addr, chain_id, goplus), {}) if goplus else _safe(_none(), {}),
        _safe(sanctions.is_sanctioned(rpc, chain_id, addr)) if rpc else _safe(_none()),
    )

    # --- 1. contract vs EOA -------------------------------------------------
    if code is None:
        out["unknown"].append("is_contract")
    else:
        out["is_contract"] = code not in ("0x", "0x0", "")

    # --- 2. verification + age ---------------------------------------------
    if isinstance(src, dict) and src:
        out["is_verified"] = bool(src.get("SourceCode"))
        if src.get("ContractName"):
            out["contract_name"] = src.get("ContractName")
    else:
        out["unknown"].append("is_verified")

    if etherscan and out.get("is_contract"):
        created = await _safe(etherscan.get_contract_creation([addr], chain_id), [])
        ts = None
        if isinstance(created, list) and created:
            ts = created[0].get("timestamp") or created[0].get("timeStamp")
        if ts:
            try:
                out["age_days"] = max(0.0, round((time.time() - int(ts)) / 86400.0, 1))
            except Exception:
                out["unknown"].append("age_days")
        else:
            out["unknown"].append("age_days")

    # --- 3. reputation feeds ------------------------------------------------
    if isinstance(rep, dict) and rep:
        out["malicious"] = bool(rep.get("malicious"))
        out["labels"] = rep.get("labels") or []

    # --- 3b. sanctions (authoritative, and its own category of problem) -----
    out["sanctioned"] = ofac if isinstance(ofac, bool) else None
    if out["sanctioned"] is None:
        out["unknown"].append("sanctioned")

    # --- 4. turn observations into ranked signals ---------------------------
    sev = "info"

    if out["sanctioned"]:
        sev = "critical"
        out["signals"].append(sanctions.finding(addr))

    if out["malicious"]:
        sev = "critical"
        out["signals"].append({
            "kind": "flagged_counterparty", "severity": "critical",
            "message": (f"{addr} is flagged by live reputation feeds as "
                        f"{', '.join(out['labels'])}. Do not grant it anything."),
        })

    if out["trusted_label"]:
        out["signals"].append({
            "kind": "known_infrastructure", "severity": "info",
            "message": f"{addr} is recognised infrastructure ({out['trusted_label']}).",
        })
    else:
        # The EOA test only means something for an unrecognised address.
        if out["is_contract"] is False:
            sev = _worse(sev, "critical")
            out["signals"].append({
                "kind": "spender_is_eoa", "severity": "critical",
                "message": (
                    f"The {role} {addr} is a plain wallet (EOA), not a contract. "
                    "Legitimate routers, marketplaces and lending pools are always "
                    "contracts - granting spending power to a personal wallet has no "
                    "honest use and is the clearest signature of a drainer."
                ),
            })
        elif out["is_contract"] is True:
            age = out["age_days"]
            if age is not None and age <= _FRESH_CONTRACT_DAYS:
                sev = _worse(sev, "critical")
                out["signals"].append({
                    "kind": "fresh_contract", "severity": "critical",
                    "message": (
                        f"The {role} contract was deployed {age} day(s) ago. Drainer "
                        "campaigns deploy a throwaway contract per wave; real "
                        "infrastructure you should be approving is not brand new."
                    ),
                })
            elif age is not None and age <= _YOUNG_CONTRACT_DAYS:
                sev = _worse(sev, "high")
                out["signals"].append({
                    "kind": "young_contract", "severity": "high",
                    "message": f"The {role} contract is only {age} days old - treat with caution.",
                })
            if out["is_verified"] is False:
                sev = _worse(sev, "high")
                out["signals"].append({
                    "kind": "unverified_contract", "severity": "high",
                    "message": (
                        f"The {role} contract's source is not verified, so nobody - "
                        "including you - can read what it does with your tokens."
                    ),
                })

    # Be explicit about what could NOT be established, so a caller never reads
    # silence as safety.
    if out["unknown"]:
        out["signals"].append({
            "kind": "incomplete_profile", "severity": "info",
            "message": ("Could not verify " + ", ".join(out["unknown"]) +
                        " for this address (upstream data unavailable). "
                        "Absence of a warning here is not proof of safety."),
        })

    out["severity"] = sev
    return out


async def _none():
    return None


def _candidate(result: dict) -> tuple[str | None, str]:
    """Pick the address that is actually being granted power by this operation."""
    op = result.get("operation") or {}
    for key, role in (("spender", "spender"), ("operator", "operator"),
                      ("delegate", "delegate"), ("destination", "recipient")):
        v = op.get(key)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            if int(v, 16) == 0:      # zero address = a revoke, not a grant
                return None, role
            return v, role
    return None, "spender"


async def enrich(result: dict, chain_id: int, *, rpc=None, etherscan=None, goplus=None) -> dict:
    """Profile whoever this signature empowers, and fold the result in.

    Safe on every input: a result with no counterparty (a plain transfer, a
    revoke, an error) passes straight through untouched.
    """
    if not isinstance(result, dict):
        return result
    addr, role = _candidate(result)
    if not addr:
        return result
    try:
        prof = await profile(addr, chain_id, rpc=rpc, etherscan=etherscan,
                             goplus=goplus, role=role)
    except Exception:
        return result
    return apply_to_result(result, prof)


def apply_to_result(result: dict, prof: dict) -> dict:
    """Fold a counterparty profile into a signature verdict, escalating if needed."""
    if not isinstance(result, dict) or not prof or not prof.get("address"):
        return result
    sev = prof.get("severity", "info")
    signals = [s for s in prof.get("signals", []) if s.get("severity") != "info"]

    result.setdefault("findings", [])
    result.setdefault("fates", [])
    for s in signals:
        result["findings"].insert(0, s)

    if sev in ("critical", "high"):
        result["verdict"] = "red"
        who = prof["address"]
        if prof.get("is_contract") is False:
            result["fates"].insert(0, f"{who} is a personal wallet, not a protocol - do not sign.")
        elif prof.get("age_days") is not None and prof["age_days"] <= _FRESH_CONTRACT_DAYS:
            result["fates"].insert(
                0, f"{who} was created {prof['age_days']} day(s) ago - do not sign.")

    if prof.get("sanctioned"):
        result["verdict"] = "red"
        result.setdefault("fates", []).insert(
            0, f"{prof['address']} is OFAC-sanctioned. Do not sign this.")

    result.setdefault("intel", {})["counterparty"] = {
        k: prof.get(k) for k in
        ("address", "role", "is_contract", "is_verified", "age_days",
         "trusted_label", "malicious", "labels", "sanctioned", "severity", "unknown")
    }
    return result
