# API Reference

Base URL (live): `https://cassandra-oracle.fly.dev`

Every oracle is available two ways:
- **REST** — `POST /foresee/<tool>` with a JSON body.
- **MCP** — the tool `foresee_<tool>` over Streamable HTTP at `/mcp`.

All tools accept a `chain` field: `ethereum`, `base`, `arbitrum`, `optimism`,
`polygon`, `bsc`, or `solana`. Default is `ethereum`.

Verdicts are `green` / `yellow` / `red` (or `error`).

---

## POST /foresee/scan — Wallet X-Ray

One-click whole-wallet health check.

```json
// request
{ "chain": "ethereum", "wallet": "0x…" }

// response (abridged)
{
  "wallet": "0x…", "network": "evm",
  "safety_score": 25, "grade": "F", "verdict": "red",
  "total_exposure_usd": 5231.40,
  "open_approvals_count": 6,
  "headline": "This wallet is at risk — revoke now.",
  "risks": [{ "severity": "critical", "title": "1 approval to a known drainer", "detail": "…", "items": ["0x…"] }],
  "detail": { "open_approvals": [ … ] }
}
```

## POST /foresee/signature — Sign-Time Oracle

Decode a pending signature before signing. Accepts EVM calldata, an **off-chain
EIP-712 message** (`typedData`), or a Solana transaction.

```json
// EVM calldata
{ "chain": "ethereum", "to": "0x…", "data": "0x095ea7b3…" }

// EVM off-chain signed message (permit / Permit2 / Seaport) — the modern drainer vector
{ "chain": "ethereum",
  "typedData": {
    "domain": { "name": "Permit2", "chainId": 1,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
    "primaryType": "PermitBatch",
    "message": { "spender": "0x…", "details": [ { "token": "0x…", "amount": "…" } ] }
  } }

// Solana — optionally pass simulated post-balances to tighten the Lighthouse Shield
{ "chain": "solana", "tx": "<base64 transaction>",
  "expected": { "signer": "<pubkey>", "owner": "<pubkey>",
                "min_lamports": 1000000,
                "token_floors": [ { "token_account": "<pubkey>", "min_amount": 90 } ] } }
```

Response:

```json
{ "verdict": "red", "summary": "…", "fates": ["…"],
  "findings": [{ "kind": "permit2_allowance", "severity": "critical", "message": "…" }],
  "operation": { "kind": "eip712", "scheme": "permit2_allowance", "spender": "0x…" },
  "instructions": [ … ],   // solana only
  "shield": {              // solana only — Lighthouse revert guardrails
    "program_id": "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95",
    "placement": "append_to_end",
    "assertions": [
      { "type": "AssertTokenAccount", "target_account": "<pubkey>",
        "assertion": "TokenAccountAssertion::Delegate", "operator": "Equal", "value": null,
        "sdk": "AssertTokenAccountBuilder::new()…", "why": "…" }
    ]
  }
}
```

`operation.scheme` is one of `erc2612_permit`, `permit2_allowance`, `permit2_transfer`,
`seaport_order`, or `unknown`. The `shield` block is present for Solana; encode its
`assertions` with the Lighthouse SDK and append them before signing.

## POST /foresee/approvals — Standing-Doors Audit

Open ERC-20 allowances + Permit2 + NFT operators (EVM), or SPL delegates (Solana).

```json
{ "chain": "ethereum", "wallet": "0x…" }

// response
{ "open_approvals": [
    { "kind": "erc20", "token": "0x…", "token_symbol": "USDC", "spender": "0x…",
      "unlimited": true, "exposure_usd": 4120.0, "revoke_calldata": "0x095ea7b3…",
      "spender_is_known_drainer": false },
    { "kind": "permit2", "token": "0x…", "spender": "0x…", "allowance_raw": "…",
      "revoke_instruction": { … } },
    { "kind": "nft_operator", "token": "0x…", "spender": "0x…", "revoke_calldata": "0xa22cb465…" }
  ],
  "total_exposure_usd": 4120.0, "summary": "…" }
```

## POST /foresee/token — Maker's Mark

Rug analysis. EVM: source patterns + deployer family tree + GoPlus security.
Solana: mint/freeze authority + GoPlus security.

```json
{ "chain": "ethereum", "token": "0x…" }

// response
{ "verdict": "red", "risk_score": 78, "reasons": ["…"],
  "security": [{ "t": "honeypot", "sev": "bad" }, { "t": "buy 5% / sell 99%", "sev": "bad" }],
  "metadata": { "symbol": "…", "is_verified": false, "goplus": { "is_honeypot": true, "sell_tax": 0.99, "top10_holder_pct": 0.8, "lp_locked_pct": 0.0 } },
  "deployer_family_tree": [{ "address": "0x…", "status": "rugged" }] }
```

## POST /foresee/identity — Same-Hand Detector

Are 2–5 wallets the same person?

```json
{ "chain": "ethereum", "wallets": ["0x…", "0x…"] }

// response
{ "overall_probability_same": 0.82, "verdict": "very_likely_same",
  "pairs": [{ "wallet_a": "0x…", "wallet_b": "0x…", "probability_same": 0.82,
    "signals": [{ "id": "shared_funder", "weight": 0.35, "hit": true, "detail": "…" }] }] }
```

---

## Utility endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness + version |
| `GET /ready` | readiness (clients constructed) |
| `GET /stats` | live capability counts + data sources + features |
| `GET /manifest.json` | machine-readable ASP manifest |
| `GET /mcp` | MCP Streamable-HTTP endpoint |

## Notes

- **Rate limit:** 90 requests / minute per IP on `/foresee/*` (HTTP 429 otherwise).
- **No auth, no keys, no signup** for callers. Reads are on public data only.
- Enrichment (GoPlus, reputation, trackers) is optional and additive; results may
  include an `intel` block or `security` badges when available.
