"""Counterparty profiling + multicall unwrapping.

These cover the detections that do NOT depend on a blocklist, which is the whole
point of them: they must fire on an address nobody has ever reported.
"""
from __future__ import annotations

import asyncio
import time

import pytest

from cassandra.foresee import counterparty as cp
from cassandra.foresee.signature import _decode_inner_calls
from cassandra.heuristics import selectors as S


# ---- fakes ----------------------------------------------------------------

class FakeRpc:
    def __init__(self, code: str = "0x"):
        self._code = code

    async def get_code(self, chain_id, address):
        if self._code == "__raise__":
            raise RuntimeError("rpc down")
        return self._code


class FakeEtherscan:
    def __init__(self, source=None, created_ts=None):
        self._source = source if source is not None else {}
        self._ts = created_ts

    async def get_source(self, addr, chain_id):
        return self._source

    async def get_contract_creation(self, addrs, chain_id):
        return [{"timestamp": str(self._ts)}] if self._ts else []


class FakeGoPlus:
    """Only needs to be non-None; reputation.check tolerates its failures."""
    async def address_security(self, address, chain_id=1):
        return None


EOA = "0x1111111111111111111111111111111111111111"
CONTRACT = "0x2222222222222222222222222222222222222222"
UNISWAP_V2 = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"


# ---- EOA spender: the strongest blocklist-free signal ----------------------

def test_eoa_spender_is_critical():
    prof = asyncio.run(cp.profile(
        EOA, 1, rpc=FakeRpc("0x"), etherscan=FakeEtherscan(), goplus=FakeGoPlus(),
    ))
    assert prof["is_contract"] is False
    assert prof["severity"] == "critical"
    kinds = [s["kind"] for s in prof["signals"]]
    assert "spender_is_eoa" in kinds


def test_known_router_is_not_flagged():
    """A recognised router must never trip the EOA/fresh-contract rules."""
    prof = asyncio.run(cp.profile(
        UNISWAP_V2, 1, rpc=FakeRpc("0x60806040"), etherscan=FakeEtherscan(),
        goplus=FakeGoPlus(),
    ))
    assert prof["trusted_label"] == "Uniswap V2 Router"
    assert prof["severity"] == "info"


# ---- contract age ---------------------------------------------------------

def test_fresh_contract_is_critical():
    two_days_ago = int(time.time()) - (2 * 86400)
    prof = asyncio.run(cp.profile(
        CONTRACT, 1, rpc=FakeRpc("0x60806040"),
        etherscan=FakeEtherscan(source={"SourceCode": "contract X {}"},
                                created_ts=two_days_ago),
        goplus=FakeGoPlus(),
    ))
    assert prof["is_contract"] is True
    assert prof["age_days"] is not None and prof["age_days"] <= 7
    assert prof["severity"] == "critical"
    assert "fresh_contract" in [s["kind"] for s in prof["signals"]]


def test_old_verified_contract_is_clean():
    two_years_ago = int(time.time()) - (730 * 86400)
    prof = asyncio.run(cp.profile(
        CONTRACT, 1, rpc=FakeRpc("0x60806040"),
        etherscan=FakeEtherscan(source={"SourceCode": "contract X {}"},
                                created_ts=two_years_ago),
        goplus=FakeGoPlus(),
    ))
    assert prof["severity"] == "info"


def test_unverified_contract_is_high():
    two_years_ago = int(time.time()) - (730 * 86400)
    prof = asyncio.run(cp.profile(
        CONTRACT, 1, rpc=FakeRpc("0x60806040"),
        etherscan=FakeEtherscan(source={"ContractName": "X"}, created_ts=two_years_ago),
        goplus=FakeGoPlus(),
    ))
    assert prof["is_verified"] is False
    assert prof["severity"] == "high"


# ---- degradation: unknown must never become an accusation -----------------

def test_rpc_failure_yields_unknown_not_a_finding():
    prof = asyncio.run(cp.profile(
        CONTRACT, 1, rpc=FakeRpc("__raise__"), etherscan=FakeEtherscan(),
        goplus=FakeGoPlus(),
    ))
    assert prof["is_contract"] is None
    assert "is_contract" in prof["unknown"]
    # An unreachable probe must NOT escalate severity.
    assert prof["severity"] == "info"
    assert "spender_is_eoa" not in [s["kind"] for s in prof["signals"]]


# ---- enrich() plumbing ----------------------------------------------------

def test_enrich_escalates_verdict_for_eoa_spender():
    result = {"verdict": "green", "findings": [], "fates": [],
              "operation": {"name": "approve", "spender": EOA}}
    out = asyncio.run(cp.enrich(
        result, 1, rpc=FakeRpc("0x"), etherscan=FakeEtherscan(), goplus=FakeGoPlus(),
    ))
    assert out["verdict"] == "red"
    assert out["intel"]["counterparty"]["is_contract"] is False


def test_enrich_ignores_revoke_to_zero_address():
    zero = "0x" + "0" * 40
    result = {"verdict": "green", "findings": [], "fates": [],
              "operation": {"name": "approve", "spender": zero}}
    out = asyncio.run(cp.enrich(
        result, 1, rpc=FakeRpc("0x"), etherscan=FakeEtherscan(), goplus=FakeGoPlus(),
    ))
    assert out["verdict"] == "green"
    assert "intel" not in out


def test_enrich_passes_through_result_with_no_counterparty():
    result = {"verdict": "green", "operation": {"name": "transfer"}}
    out = asyncio.run(cp.enrich(
        result, 1, rpc=FakeRpc("0x"), etherscan=FakeEtherscan(), goplus=FakeGoPlus(),
    ))
    assert out == result


# ---- multicall unwrapping -------------------------------------------------

def _encode_approve(spender: str, amount: int) -> bytes:
    sel = bytes.fromhex(S.ERC20_APPROVE[2:])
    return sel + bytes.fromhex(spender[2:].rjust(64, "0")) + amount.to_bytes(32, "big")


def test_multicall_surfaces_hidden_unlimited_approval():
    """The drainer pattern: an approve buried inside a multicall bundle."""
    unlimited = (1 << 256) - 1
    inner = _decode_inner_calls([_encode_approve(EOA, unlimited)])
    assert len(inner) == 1
    assert inner[0]["type"] == "token_approve"
    assert inner[0]["severity"] == "critical"
    assert "UNLIMITED" in inner[0]["finding"]["message"]


def test_multicall_handles_garbage_payload_without_raising():
    inner = _decode_inner_calls([b"\x01\x02", "not-hex", 12345])
    assert len(inner) == 3
    assert all("name" in c for c in inner)


def test_multicall_ignores_non_list():
    assert _decode_inner_calls(None) == []
    assert _decode_inner_calls("0xdeadbeef") == []
