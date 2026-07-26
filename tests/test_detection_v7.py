"""Address poisoning, symbol impersonation, burn destinations, drainer lures.

Each of these fires without any blocklist, so the false-positive boundaries
matter as much as the detections themselves.
"""
from __future__ import annotations

import asyncio

from cassandra.foresee import poisoning
from cassandra.foresee.signature import _burn_destination
from cassandra.heuristics import selectors as S
from cassandra.heuristics.addresses import impersonation_check

WALLET = "0x1111111111111111111111111111111111111111"
REAL = "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"          # paid before
FAKE = "0x1f98cccccccccccccccccccccccccccccc01f984"          # same 4+4 edges
UNRELATED = "0xabcdef0123456789abcdef0123456789abcdef01"


class FakeEtherscan:
    def __init__(self, txlist=None, transfers=None):
        self._tx = txlist or []
        self._tr = transfers or []

    async def txlist(self, addr, chain_id, page=1, offset=100, sort="desc"):
        return self._tx

    async def erc20_transfers(self, addr, chain_id, page=1, offset=100):
        return self._tr


def _paid(to, value="1000000000000000000"):
    return {"from": WALLET, "to": to, "value": value}


def _dust_in(frm):
    return {"from": frm, "to": WALLET, "value": "0"}


# ---- lookalike primitive --------------------------------------------------

def test_looks_alike_matches_shared_edges():
    assert poisoning.looks_alike(REAL, FAKE)


def test_looks_alike_rejects_identical():
    assert not poisoning.looks_alike(REAL, REAL)


def test_looks_alike_rejects_unrelated():
    assert not poisoning.looks_alike(REAL, UNRELATED)


def test_looks_alike_rejects_malformed():
    assert not poisoning.looks_alike("0x123", REAL)
    assert not poisoning.looks_alike("", REAL)


# ---- check_recipient ------------------------------------------------------

def test_flags_lookalike_of_a_paid_counterparty():
    es = FakeEtherscan(txlist=[_paid(REAL), _paid(REAL)],
                       transfers=[_dust_in(FAKE)])
    hit = asyncio.run(poisoning.check_recipient(FAKE, WALLET, 1, etherscan=es))
    assert hit is not None
    assert hit["severity"] == "critical"
    assert hit["resembles"] == REAL
    assert hit["resembles_paid_times"] == 2
    assert hit["seeded_by_dust_transfer"] is True


def test_does_not_flag_the_address_you_actually_pay():
    """The real counterparty must never be flagged as its own impostor."""
    es = FakeEtherscan(txlist=[_paid(REAL)])
    assert asyncio.run(poisoning.check_recipient(REAL, WALLET, 1, etherscan=es)) is None


def test_does_not_flag_an_unrelated_new_recipient():
    es = FakeEtherscan(txlist=[_paid(REAL)])
    assert asyncio.run(poisoning.check_recipient(UNRELATED, WALLET, 1, etherscan=es)) is None


def test_inbound_only_address_is_not_trusted():
    """An address that only ever SENT to us must not become a trust anchor -
    otherwise an attacker seeds the anchor and the lookalike themselves."""
    es = FakeEtherscan(transfers=[_dust_in(REAL)])
    assert asyncio.run(poisoning.check_recipient(FAKE, WALLET, 1, etherscan=es)) is None


def test_no_history_yields_no_finding():
    es = FakeEtherscan()
    assert asyncio.run(poisoning.check_recipient(FAKE, WALLET, 1, etherscan=es)) is None


def test_missing_etherscan_is_silent():
    assert asyncio.run(poisoning.check_recipient(FAKE, WALLET, 1, etherscan=None)) is None


# ---- scan_history ---------------------------------------------------------

def test_scan_history_finds_seeded_lookalike():
    es = FakeEtherscan(txlist=[_paid(REAL)], transfers=[_dust_in(FAKE)])
    traps = asyncio.run(poisoning.scan_history(WALLET, 1, etherscan=es))
    assert len(traps) == 1
    assert traps[0]["impostor"] == FAKE
    assert traps[0]["resembles"] == REAL


def test_scan_history_ignores_dust_from_unrelated_address():
    es = FakeEtherscan(txlist=[_paid(REAL)], transfers=[_dust_in(UNRELATED)])
    assert asyncio.run(poisoning.scan_history(WALLET, 1, etherscan=es)) == []


def test_scan_history_ignores_real_payer_sending_dust():
    """An address that also sent real value isn't a pure poisoning seed."""
    es = FakeEtherscan(
        txlist=[_paid(REAL)],
        transfers=[_dust_in(FAKE), {"from": FAKE, "to": WALLET, "value": "500"}],
    )
    assert asyncio.run(poisoning.scan_history(WALLET, 1, etherscan=es)) == []


# ---- symbol impersonation -------------------------------------------------

def test_fake_usdc_is_flagged():
    hit = impersonation_check("USDC", "0xdeadbeef00000000000000000000000000000001", 1)
    assert hit is not None and hit["severity"] == "critical"
    assert hit["real_address"] == "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


def test_real_usdc_is_not_flagged():
    assert impersonation_check("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 1) is None


def test_unknown_symbol_is_not_flagged():
    assert impersonation_check("MYNEWCOIN", "0xdeadbeef00000000000000000000000000000001", 1) is None


def test_symbol_check_is_chain_scoped():
    """Base USDC lives at a different address; it must not be flagged on Base."""
    assert impersonation_check("USDC", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 8453) is None


def test_missing_symbol_is_not_flagged():
    assert impersonation_check(None, "0xdeadbeef00000000000000000000000000000001", 1) is None


# ---- burn destinations ----------------------------------------------------

def test_transfer_to_zero_address():
    f = _burn_destination("0x" + "0" * 40, token_contract=REAL, symbol="USDC")
    assert f and f["kind"] == "transfer_to_zero_address"


def test_transfer_to_dead_address():
    f = _burn_destination("0x000000000000000000000000000000000000dEaD", symbol="USDC")
    assert f and f["kind"] == "transfer_to_burn_address"


def test_transfer_to_token_itself():
    f = _burn_destination(REAL, token_contract=REAL, symbol="UNI")
    assert f and f["kind"] == "transfer_to_token_contract"


def test_ordinary_recipient_is_clean():
    assert _burn_destination(UNRELATED, token_contract=REAL, symbol="UNI") is None


# ---- drainer lure functions ----------------------------------------------

def test_security_update_is_a_known_lure():
    assert S.lure_name(S.sel("SecurityUpdate()")) == "SecurityUpdate()"


def test_claim_rewards_is_a_known_lure():
    assert S.lure_name(S.sel("ClaimRewards()")) == "ClaimRewards()"


def test_real_function_is_not_a_lure():
    assert S.lure_name(S.sel("transfer(address,uint256)")) is None
    assert S.lure_name(S.ERC20_APPROVE) is None


def test_lure_lookup_tolerates_garbage():
    assert S.lure_name("") is None
    assert S.lure_name("0xzzzz") is None
