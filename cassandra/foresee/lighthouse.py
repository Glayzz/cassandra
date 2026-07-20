"""Lighthouse Shield - turn a Solana signature analysis into revert guardrails.

Cassandra's Sign-Time oracle tells you what a transaction *would* do. The Shield
goes one step further: it produces Lighthouse assertion instructions you can
append to the same transaction so that, if the transaction tries to do MORE than
expected (drain a balance, install a delegate, hand off account ownership), the
Lighthouse program fails its assertion and the ENTIRE transaction reverts.

Lighthouse (https://lighthouse.voyage, program below) is an open, program-agnostic
assertion program: you append an instruction asserting on-chain state at runtime,
and a failed assertion aborts the transaction - no custom program required.

Division of labour: Cassandra decides the *policy* (which assertions protect this
specific transaction, and against what). The exact instruction bytes are produced
by the Lighthouse SDK (Rust builders or the kinobi JS client) from the plan
returned here - which keeps byte encoding authoritative and lets Cassandra remain
a pure, dependency-free analyzer.

Two classes of guard:
  1. Invariants that need NO simulation - if the tx installs a delegate or changes
     an authority, assert the account is undelegated / still owned by you at the
     end. These neutralize the classic SPL approval + authority-handoff drains.
  2. Balance floors - when the caller passes simulated post-balances
     (min_lamports, token_floors), emit assertions that fail on any overspend.
"""
from __future__ import annotations

# Lighthouse program (same address on mainnet-beta and devnet)
LIGHTHOUSE_PROGRAM_ID = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"


def build_shield(sig_result: dict, expected: dict | None = None) -> dict:
    """Given a foresee_signature (Solana) result, return a Lighthouse assertion plan.

    `expected` (all optional) lets a wallet that has simulated the tx tighten the
    guards:
        {
          "signer":       "<base58 pubkey>",   # fee payer / owner to protect
          "owner":        "<base58 pubkey>",   # expected token-account owner
          "min_lamports": 1234567,             # SOL floor for the signer
          "token_floors": [ {"token_account": "<pubkey>", "min_amount": 90} ]
        }
    """
    expected = expected or {}
    instructions = sig_result.get("instructions") or []
    signer = expected.get("signer") or sig_result.get("signer")
    owner = expected.get("owner")

    assertions: list[dict] = []

    # 1) Simulation-free invariants derived from the decoded instructions.
    for ix in instructions:
        t = ix.get("type")
        accts = ix.get("accounts") or []
        if t == "spl_approve":
            ta = accts[0] if accts else None
            if ta:
                assertions.append({
                    "type": "AssertTokenAccount",
                    "target_account": ta,
                    "assertion": "TokenAccountAssertion::Delegate",
                    "operator": "Equal",
                    "value": None,
                    "sdk": (f"AssertTokenAccountBuilder::new().target_account({ta})"
                            ".assertion(TokenAccountAssertion::Delegate {{ value: None, "
                            "operator: EquatableOperator::Equal }})"),
                    "why": ("This instruction sets a delegate on your token account. The assertion "
                            "fails the transaction unless the delegate is empty at the end - "
                            "neutralizing the approval a drainer just tried to install."),
                })
        elif t == "spl_set_authority":
            ta = accts[0] if accts else None
            if ta:
                assertions.append({
                    "type": "AssertTokenAccount",
                    "target_account": ta,
                    "assertion": "TokenAccountAssertion::Owner",
                    "operator": "Equal",
                    "value": owner,
                    "sdk": (f"AssertTokenAccountBuilder::new().target_account({ta})"
                            ".assertion(TokenAccountAssertion::Owner {{ value: <your_wallet>, "
                            "operator: EquatableOperator::Equal }})"),
                    "why": ("This instruction changes an account authority. The assertion fails the "
                            "transaction unless ownership is unchanged at the end."),
                })

    # 2) Balance floors (need caller-supplied simulation values).
    min_lamports = expected.get("min_lamports")
    if min_lamports is not None and signer:
        assertions.append({
            "type": "AssertAccountInfo",
            "target_account": signer,
            "assertion": "AccountInfoAssertion::Lamports",
            "operator": "GreaterThanOrEqual",
            "value": int(min_lamports),
            "sdk": (f"AssertAccountInfoBuilder::new().target_account({signer})"
                    f".assertion(AccountInfoAssertion::Lamports {{ value: {int(min_lamports)}, "
                    "operator: IntegerOperator::GreaterThanOrEqual }})"),
            "why": "Fails the transaction if your SOL balance ends below the expected floor.",
        })
    for tok in (expected.get("token_floors") or []):
        ta = tok.get("token_account")
        minv = tok.get("min_amount")
        if ta and minv is not None:
            assertions.append({
                "type": "AssertTokenAccount",
                "target_account": ta,
                "assertion": "TokenAccountAssertion::Amount",
                "operator": "GreaterThanOrEqual",
                "value": int(minv),
                "sdk": (f"AssertTokenAccountBuilder::new().target_account({ta})"
                        f".assertion(TokenAccountAssertion::Amount {{ value: {int(minv)}, "
                        "operator: IntegerOperator::GreaterThanOrEqual }})"),
                "why": "Fails the transaction if this token balance ends below the expected floor.",
            })

    protected = bool(assertions)
    has_sim = min_lamports is not None or bool(expected.get("token_floors"))

    notes: list[str] = []
    if protected:
        notes.append("Append these assertion instructions to the END of the transaction, then sign. "
                     "If the transaction does more than expected, Lighthouse reverts the whole thing.")
    else:
        notes.append("No approval or authority hand-off was detected to guard automatically.")
    if not has_sim:
        notes.append("For overspend protection too, pass your wallet's simulated post-balances "
                     "(min_lamports and/or token_floors) and Cassandra will add balance-floor assertions "
                     "on top of the invariant guards above.")

    return {
        "available": protected or has_sim,
        "protected": protected,
        "program_id": LIGHTHOUSE_PROGRAM_ID,
        "placement": "append_to_end",
        "assertion_count": len(assertions),
        "assertions": assertions,
        "notes": notes,
        "docs": "https://lighthouse.voyage",
        "how_it_works": ("Lighthouse is an on-chain assertion program. Appended assertion instructions read "
                         "live account state at the end of the transaction; if state violates an assertion, "
                         "the Lighthouse program returns an error and the Solana runtime reverts the entire "
                         "transaction. Encode the plan above with the Lighthouse SDK / kinobi client."),
    }
