"""Chainalysis on-chain sanctions oracle.

The load-bearing property is that an unavailable oracle returns None, never
False: "not on the list" and "we couldn't ask" must never collapse into the
same answer.
"""
from __future__ import annotations

import asyncio

from cassandra.chains import sanctions

SANCTIONED = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"
CLEAN = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


class FakeRpc:
    """Returns a canned eth_call result, or raises."""

    def __init__(self, result="0x" + "0" * 64, raises=False):
        self._result = result
        self._raises = raises
        self.calls: list[tuple] = []

    async def eth_call(self, chain_id, to, data):
        self.calls.append((chain_id, to, data))
        if self._raises:
            raise RuntimeError("rpc down")
        return self._result


def _fresh():
    """Each test needs a clean cache - results are cached for an hour."""
    sanctions._cache = type(sanctions._cache)(ttl=3600.0)


def test_selector_is_correct():
    # keccak("isSanctioned(address)")[:4] - verified against the live contract
    assert sanctions._SELECTOR == "0xdf592f7d"


def test_positive_result_is_true():
    _fresh()
    rpc = FakeRpc("0x" + "0" * 63 + "1")
    assert asyncio.run(sanctions.is_sanctioned(rpc, 1, SANCTIONED)) is True


def test_negative_result_is_false():
    _fresh()
    rpc = FakeRpc("0x" + "0" * 64)
    assert asyncio.run(sanctions.is_sanctioned(rpc, 1, CLEAN)) is False


def test_rpc_failure_is_unknown_not_clean():
    _fresh()
    rpc = FakeRpc(raises=True)
    assert asyncio.run(sanctions.is_sanctioned(rpc, 1, SANCTIONED)) is None


def test_empty_return_is_unknown_not_clean():
    """No contract at the address on this chain -> unknown, never 'clean'."""
    _fresh()
    rpc = FakeRpc("0x")
    assert asyncio.run(sanctions.is_sanctioned(rpc, 1, SANCTIONED)) is None


def test_unsupported_chain_is_unknown_and_makes_no_call():
    _fresh()
    rpc = FakeRpc("0x" + "0" * 63 + "1")
    assert asyncio.run(sanctions.is_sanctioned(rpc, 8453, SANCTIONED)) is None
    assert rpc.calls == []          # never asked - Base isn't covered


def test_malformed_address_is_unknown():
    _fresh()
    rpc = FakeRpc()
    assert asyncio.run(sanctions.is_sanctioned(rpc, 1, "0x123")) is None
    assert asyncio.run(sanctions.is_sanctioned(rpc, 1, "")) is None


def test_missing_rpc_is_unknown():
    _fresh()
    assert asyncio.run(sanctions.is_sanctioned(None, 1, SANCTIONED)) is None


def test_call_targets_the_oracle_with_encoded_address():
    _fresh()
    rpc = FakeRpc("0x" + "0" * 64)
    asyncio.run(sanctions.is_sanctioned(rpc, 1, SANCTIONED))
    chain_id, to, data = rpc.calls[0]
    assert to == sanctions.ORACLE_ADDRESS
    assert data.startswith(sanctions._SELECTOR)
    assert SANCTIONED[2:].lower() in data.lower()


def test_result_is_cached():
    _fresh()
    rpc = FakeRpc("0x" + "0" * 64)
    asyncio.run(sanctions.is_sanctioned(rpc, 1, CLEAN))
    asyncio.run(sanctions.is_sanctioned(rpc, 1, CLEAN))
    assert len(rpc.calls) == 1


def test_finding_is_critical():
    f = sanctions.finding(SANCTIONED)
    assert f["severity"] == "critical"
    assert f["source"] == "chainalysis_sanctions_oracle"
