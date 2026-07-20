"""Offline tests for the product-grade upgrades: GoPlus parsing, reputation,
Permit2/NFT selectors. No network required."""
from __future__ import annotations

import asyncio

from cassandra.heuristics.goplus_parse import parse_evm_token, parse_solana_token
from cassandra.foresee import approvals_extra as X
from cassandra import reputation as R


def test_goplus_honeypot_flags_red():
    hp = {"is_honeypot": "1", "sell_tax": "0.99", "is_open_source": "0",
          "holders": [{"address": "0xa", "percent": "0.8"}], "lp_holders": [], "is_in_dex": "1"}
    r = parse_evm_token(hp)
    assert r["verdict_floor"] >= 85
    assert any("HONEYPOT" in x for x in r["reasons"])


def test_goplus_bluechip_stays_low():
    clean = {"is_honeypot": "0", "sell_tax": "0", "buy_tax": "0", "is_open_source": "1",
             "is_mintable": "0", "holders": [{"address": "0xf", "percent": "0.08"}],
             "lp_holders": [{"is_locked": "1", "percent": "0.9"}], "is_in_dex": "1"}
    r = parse_evm_token(clean)
    assert r["score_delta"] < 30 and r["verdict_floor"] == 0


def test_goplus_solana_freezable():
    sol = {"non_transferable": "0", "freezable": {"status": "1", "authority": []},
           "mintable": {"status": "0", "authority": []}, "transfer_hook": [],
           "trusted_token": "0", "holders": []}
    r = parse_solana_token(sol)
    assert r["verdict_floor"] >= 55


def test_permit2_and_nft_selectors():
    assert X._IS_APPROVED_FOR_ALL == "0xe985e9c5"
    assert X._PERMIT2_ALLOWANCE == "0x927da105"
    assert X.PERMIT2 == "0x000000000022d473030f116ddee9f6b43ac78ba3"


def test_reputation_static_drainer():
    # registry-only path, no goplus
    r = asyncio.run(R.check("0x0000db5c8b030ae20308ac975898e09741e70000", 1, None))
    assert isinstance(r, dict) and "malicious" in r


def test_reputation_enrich_signature_escalates():
    class FakeGP:
        async def address_security(self, addr, chain_id):
            return {"stealing_attack": "1"} if addr.lower() == "0xbad" else {"stealing_attack": "0"}
    res = {"verdict": "yellow", "operation": {"spender": "0xbad"}, "findings": [], "fates": []}
    out = asyncio.run(R.enrich_signature(res, 1, FakeGP()))
    assert out["verdict"] == "red"


if __name__ == "__main__":
    test_goplus_honeypot_flags_red()
    test_goplus_bluechip_stays_low()
    test_goplus_solana_freezable()
    test_permit2_and_nft_selectors()
    test_reputation_static_drainer()
    test_reputation_enrich_signature_escalates()
    print("all product-upgrade tests passed")
