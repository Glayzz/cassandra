"""Address-poisoning detection - the scam that abuses your own history.

The attack needs no approval, no signature, and no malicious contract. It works
like this:

  1. You regularly send funds to 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984.
  2. An attacker grinds a vanity address that matches the *visible* part of it -
     the first and last few hex characters - e.g. 0x1f9840...1F984, different in
     the middle where nobody looks.
  3. They send you a zero-value or dust transfer from it, purely so the address
     lands in your transaction history.
  4. Days later you pay that counterparty again, copy the address from your
     history, and the funds go to the attacker.

Nothing about the final transaction looks wrong: no approval, a plain transfer,
a recipient that appears in your own history. The only tell is that the address
*resembles* one you trust without being it - which is exactly what this module
checks, using history Cassandra already fetches.

Two entry points:
  * `check_recipient` - before you sign, is this recipient a lookalike of a
    counterparty you actually use?
  * `scan_history`   - has anyone already seeded a lookalike into this wallet's
    history, waiting to be copied?
"""
from __future__ import annotations

from typing import Any, Iterable

# How many hex characters at each end a wallet UI typically shows, and therefore
# how much of the address a human actually compares. Matching 4+4 is 32 bits of
# grind - cheap for an attacker, invisible to a reader.
_EDGE = 4
_STRONG_EDGE = 6

# A transfer at or below this USD value is treated as dust: it exists to appear
# in a history list, not to move money.
_DUST_USD = 1.0


def _norm(addr: Any) -> str:
    return str(addr or "").strip().lower()


def looks_alike(a: str, b: str, edge: int = _EDGE) -> bool:
    """True when two DIFFERENT addresses share their first and last `edge` hex chars."""
    a, b = _norm(a), _norm(b)
    if not a.startswith("0x") or not b.startswith("0x") or len(a) != 42 or len(b) != 42:
        return False
    if a == b:
        return False  # identical is not a lookalike
    body_a, body_b = a[2:], b[2:]
    return (body_a[:edge] == body_b[:edge]) and (body_a[-edge:] == body_b[-edge:])


def _match_strength(a: str, b: str) -> str | None:
    if looks_alike(a, b, _STRONG_EDGE):
        return "very_high"
    if looks_alike(a, b, _EDGE):
        return "high"
    return None


def _fmt(addr: str) -> str:
    a = _norm(addr)
    return f"{a[:8]}…{a[-6:]}" if len(a) == 42 else a


# ---- building the wallet's trusted counterparty set -------------------------

def _paid_counterparties(wallet: str, txlist: Iterable[dict],
                         transfers: Iterable[dict]) -> dict[str, int]:
    """Addresses this wallet has actually SENT value to, with a send count.

    Only outbound, non-zero movements count. An address that merely sent *to*
    the wallet is not trusted - that direction is free for an attacker.
    """
    w = _norm(wallet)
    out: dict[str, int] = {}

    for tx in txlist or []:
        if _norm(tx.get("from")) != w:
            continue
        to = _norm(tx.get("to"))
        if not to or len(to) != 42:
            continue
        try:
            value = int(tx.get("value") or 0)
        except Exception:
            value = 0
        if value > 0:
            out[to] = out.get(to, 0) + 1

    for t in transfers or []:
        if _norm(t.get("from")) != w:
            continue
        to = _norm(t.get("to"))
        if not to or len(to) != 42:
            continue
        try:
            value = int(t.get("value") or 0)
        except Exception:
            value = 0
        if value > 0:
            out[to] = out.get(to, 0) + 1

    return out


def _dust_senders(wallet: str, transfers: Iterable[dict]) -> set[str]:
    """Addresses that have only ever pushed zero-value/dust INTO this wallet.

    This is the poisoning fingerprint: an address appears in your history having
    given you nothing.
    """
    w = _norm(wallet)
    gave_dust: set[str] = set()
    gave_real: set[str] = set()
    for t in transfers or []:
        if _norm(t.get("to")) != w:
            continue
        frm = _norm(t.get("from"))
        if not frm or len(frm) != 42:
            continue
        try:
            value = int(t.get("value") or 0)
        except Exception:
            value = 0
        (gave_dust if value == 0 else gave_real).add(frm)
    return gave_dust - gave_real


# ---- entry point 1: before you sign ----------------------------------------

async def check_recipient(recipient: str, wallet: str, chain_id: int,
                          etherscan=None) -> dict | None:
    """Is `recipient` a lookalike of someone `wallet` actually pays?

    Returns a finding dict, or None when nothing suspicious was found (including
    when history is unavailable - absence of history is not evidence of safety).
    """
    recipient = _norm(recipient)
    wallet = _norm(wallet)
    if not etherscan or len(recipient) != 42 or len(wallet) != 42 or recipient == wallet:
        return None

    try:
        txlist = await etherscan.txlist(wallet, chain_id, page=1, offset=300)
    except Exception:
        txlist = []
    try:
        transfers = await etherscan.erc20_transfers(wallet, chain_id, page=1, offset=300)
    except Exception:
        transfers = []
    if not txlist and not transfers:
        return None

    trusted = _paid_counterparties(wallet, txlist, transfers)
    if recipient in trusted:
        return None  # you have paid this exact address before - not a lookalike

    for known, times in sorted(trusted.items(), key=lambda kv: -kv[1]):
        strength = _match_strength(recipient, known)
        if not strength:
            continue
        seeded = recipient in _dust_senders(wallet, transfers)
        return {
            "kind": "address_poisoning",
            "severity": "critical",
            "confidence": strength,
            "message": (
                f"The recipient {_fmt(recipient)} is NOT an address you have paid before, "
                f"but it closely resembles {_fmt(known)}, which you have paid "
                f"{times} time(s). The two differ only in the middle, where a wallet UI "
                "hides them. This is address poisoning - verify the full address "
                "character by character against the real one before sending."
                + (" That lookalike reached your history through a zero-value transfer, "
                   "which is how the trap is set." if seeded else "")
            ),
            "resembles": known,
            "resembles_paid_times": times,
            "seeded_by_dust_transfer": seeded,
        }
    return None


# ---- entry point 2: is the trap already set? -------------------------------

async def scan_history(wallet: str, chain_id: int, etherscan=None,
                       max_findings: int = 5) -> list[dict]:
    """Find lookalike addresses already sitting in this wallet's history."""
    wallet = _norm(wallet)
    if not etherscan or len(wallet) != 42:
        return []

    try:
        txlist = await etherscan.txlist(wallet, chain_id, page=1, offset=300)
    except Exception:
        txlist = []
    try:
        transfers = await etherscan.erc20_transfers(wallet, chain_id, page=1, offset=300)
    except Exception:
        transfers = []
    if not txlist and not transfers:
        return []

    trusted = _paid_counterparties(wallet, txlist, transfers)
    dust = _dust_senders(wallet, transfers)

    findings: list[dict] = []
    for impostor in dust:
        if impostor in trusted:
            continue
        for known, times in trusted.items():
            strength = _match_strength(impostor, known)
            if not strength:
                continue
            findings.append({
                "kind": "address_poisoning_seeded",
                "severity": "high",
                "confidence": strength,
                "title": "A lookalike address is sitting in your history",
                "message": (
                    f"{_fmt(impostor)} sent you a zero-value transfer and closely "
                    f"resembles {_fmt(known)}, an address you have paid {times} time(s). "
                    "It is in your history for one reason: so you copy it by mistake. "
                    "Never copy a recipient from your transaction history - use a saved "
                    "contact or the full address from the payee."
                ),
                "impostor": impostor,
                "resembles": known,
                "resembles_paid_times": times,
            })
            break
        if len(findings) >= max_findings:
            break
    return findings
