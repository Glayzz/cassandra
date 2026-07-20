"""Offline tests for the v0.5 upgrades: EIP-712 analyzer + Lighthouse Shield."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cassandra.foresee.eip712 import analyze_typed_data
from cassandra.foresee.lighthouse import build_shield, LIGHTHOUSE_PROGRAM_ID

U256_MAX = str((1 << 256) - 1)
U160_MAX = str((1 << 160) - 1)
DRAINER = "0x0000000000000000000000000000000000dEaD01"

passed = 0
def ok(cond, msg):
    global passed
    assert cond, "FAIL: " + msg
    passed += 1
    print("  ok:", msg)


print("== ERC-2612 permit (unlimited) ==")
r = analyze_typed_data({
    "domain": {"name": "USD Coin", "chainId": 1,
               "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
    "primaryType": "Permit",
    "message": {"owner": "0x" + "1"*40, "spender": DRAINER,
                "value": U256_MAX, "deadline": "1893456000"},
})
ok(r["operation"]["scheme"] == "erc2612_permit", "scheme erc2612_permit")
ok(r["operation"]["unlimited"] is True, "detected unlimited")
ok(r["operation"]["spender"] == DRAINER.lower(), "spender exposed for reputation")
ok(r["verdict"] == "red", "verdict red")

print("== DAI-style permit revoke (safe) ==")
r = analyze_typed_data({
    "domain": {"name": "Dai Stablecoin", "chainId": 1,
               "verifyingContract": "0x6B175474E89094C44Da98b954EedeAC495271d0F"},
    "primaryType": "Permit",
    "message": {"holder": "0x"+"1"*40, "spender": "0x"+"2"*40,
                "nonce": "0", "expiry": "0", "allowed": False},
})
ok(r["verdict"] == "green", "dai revoke is green")
ok(r["operation"]["allowed"] is False, "allowed False")

print("== Permit2 PermitBatch (one unlimited) ==")
r = analyze_typed_data({
    "domain": {"name": "Permit2", "chainId": 1,
               "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
    "primaryType": "PermitBatch",
    "message": {"spender": "0x"+"a"*40, "details": [
        {"token": "0x"+"b"*40, "amount": U160_MAX, "expiration": "1893456000", "nonce": "0"},
        {"token": "0x"+"c"*40, "amount": "1000000", "expiration": "1893456000", "nonce": "1"},
    ]},
})
ok(r["operation"]["scheme"] == "permit2_allowance", "scheme permit2_allowance")
ok(len(r["operation"]["tokens"]) == 2, "two tokens")
ok(r["operation"]["unlimited"] is True, "any_unlimited True")
ok(r["verdict"] == "red", "verdict red")

print("== Permit2 SignatureTransfer (moves tokens) ==")
r = analyze_typed_data({
    "domain": {"name": "Permit2", "chainId": 1,
               "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
    "primaryType": "PermitTransferFrom",
    "message": {"permitted": {"token": "0x"+"d"*40, "amount": "5000000"},
                "spender": "0x"+"e"*40, "nonce": "7", "deadline": "1893456000"},
})
ok(r["operation"]["scheme"] == "permit2_transfer", "scheme permit2_transfer")
ok(r["operation"]["transfer"] is True, "transfer flag")
ok(r["verdict"] == "red", "verdict red")

print("== Seaport inversion (NFT out, payment elsewhere) ==")
r = analyze_typed_data({
    "domain": {"name": "Seaport", "chainId": 1, "verifyingContract": "0x"+"f"*40},
    "primaryType": "OrderComponents",
    "message": {"offerer": "0x"+"1"*40,
                "offer": [{"itemType": 2, "token": "0x"+"9"*40,
                           "identifierOrCriteria": "1234", "startAmount": "1", "endAmount": "1"}],
                "consideration": [{"itemType": 0, "token": "0x0", "startAmount": "1",
                                   "endAmount": "1", "recipient": "0x"+"7"*40}]},
})
ok(r["operation"]["scheme"] == "seaport_order", "scheme seaport_order")
ok(r["verdict"] == "red", "verdict red (zero-consideration to offerer)")

print("== Unknown typed data with auth-shaped field ==")
r = analyze_typed_data({
    "domain": {"name": "SomeApp", "chainId": 1},
    "primaryType": "Login",
    "message": {"statement": "Sign in", "operator": "0x"+"e"*40},
})
ok(r["operation"]["scheme"] == "unknown", "scheme unknown")
ok(r["verdict"] == "red", "escalated to red on operator field")

print("== Lighthouse Shield: invariants only (no simulation) ==")
sig = {"instructions": [
    {"index": 0, "type": "spl_approve", "accounts": ["TokAcctAAA", "DelegBBB"], "delegate": "DelegBBB"},
    {"index": 1, "type": "spl_set_authority", "accounts": ["TokAcctCCC"], "authority_type": "AccountOwner"},
], "signer": "SignerXYZ"}
sh = build_shield(sig)
ok(sh["program_id"] == LIGHTHOUSE_PROGRAM_ID, "correct program id")
ok(sh["protected"] is True, "protected with no simulation")
ok(sh["assertion_count"] == 2, "delegate + owner invariants")
kinds = [a["assertion"] for a in sh["assertions"]]
ok("TokenAccountAssertion::Delegate" in kinds, "delegate assertion present")
ok("TokenAccountAssertion::Owner" in kinds, "owner assertion present")

print("== Lighthouse Shield: with simulated floors ==")
sh = build_shield(sig, {
    "owner": "OwnerWallet", "signer": "SignerXYZ", "min_lamports": 1000000,
    "token_floors": [{"token_account": "TokAcctAAA", "min_amount": 90}],
})
ok(sh["assertion_count"] == 4, "invariants + lamports + amount floors")
targets = [a["target_account"] for a in sh["assertions"]]
ok("SignerXYZ" in targets, "lamports assertion targets signer")

print("== Lighthouse Shield: nothing to guard ==")
sh = build_shield({"instructions": [{"index": 0, "type": "sol_transfer", "accounts": ["a", "b"]}]})
ok(sh["protected"] is False, "no invariant guards when only a transfer")
ok("simulated post-balances" in " ".join(sh["notes"]), "suggests passing simulation")

print(f"\nALL PASSED ({passed} assertions)")
