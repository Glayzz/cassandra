"""Offline smoke tests for the signature decoder (no network required)."""
from __future__ import annotations

import asyncio

from cassandra.foresee.signature import analyze_calldata, analyze_typed_data


USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
DRAINER = "0x000000db5c8b030ae20308ac975898e09741e70000"[:42]  # from KNOWN_DRAINERS
UNI_V3_ROUTER = "0xE592427A0AEce92De3Edee1F18E0157C05861564"


def _sync(coro):
    return asyncio.run(coro)


def test_unlimited_approve_to_drainer_is_red():
    # approve(spender=DRAINER, amount=UINT256_MAX)
    spender = DRAINER.replace("0x", "").rjust(64, "0")
    amount = "f" * 64
    data = "0x095ea7b3" + spender + amount
    out = _sync(analyze_calldata(to=USDC, data=data, chain_id=1))
    assert out["verdict"] == "red", out
    assert out["operation"]["name"] == "approve"
    assert out["operation"]["unlimited"] is True


def test_native_send_is_green():
    out = _sync(analyze_calldata(
        to="0x000000000000000000000000000000000000dEaD", data="0x",
        chain_id=1, value_wei=10**18,
    ))
    assert out["verdict"] == "green"


def test_setapproval_for_all_true_is_high_or_worse():
    # setApprovalForAll(operator=X, approved=true)
    op = "deadbeef".rjust(64, "0")
    approved = "1".rjust(64, "0")
    data = "0xa22cb465" + op + approved
    out = _sync(analyze_calldata(
        to="0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d", data=data, chain_id=1,
    ))
    assert out["verdict"] in ("red", "yellow"), out


def test_typed_data_permit2_is_red():
    typed = {
        "domain": {"name": "Permit2", "verifyingContract": "0x00…"},
        "primaryType": "PermitBatch",
        "message": {"spender": "0x1111111111111111111111111111111111111111",
                    "details": [{"token": USDC}]},
    }
    out = analyze_typed_data(typed)
    assert out["verdict"] == "red"


def test_uniswap_approve_yellow_or_green_no_drainer():
    spender = UNI_V3_ROUTER.replace("0x", "").lower().rjust(64, "0")
    amount = "f" * 64  # unlimited
    data = "0x095ea7b3" + spender + amount
    out = _sync(analyze_calldata(to=USDC, data=data, chain_id=1))
    # unlimited to a *known* router -> yellow (not red)
    assert out["verdict"] in ("yellow", "green"), out


if __name__ == "__main__":
    test_unlimited_approve_to_drainer_is_red()
    test_native_send_is_green()
    test_setapproval_for_all_true_is_high_or_worse()
    test_typed_data_permit2_is_red()
    test_uniswap_approve_yellow_or_green_no_drainer()
    print("all signature smoke tests passed")
