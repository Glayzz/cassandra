# Architecture

Cassandra is a single FastAPI application that speaks three ways at once:

- **A2MCP** — the five oracles are registered as MCP tools and served over
  Streamable HTTP at `/mcp`. Any A2MCP agent installs Cassandra with no wrapper.
- **REST** — the same logic is exposed as plain JSON at `/foresee/*` for humans
  and non-agent clients.
- **Web** — a landing page (`/`) and an interactive playground (`/demo`).

```
            ┌──────────────────────────── FastAPI app (cassandra/server.py) ────────────────────────────┐
  /mcp  ───►│  MCP tools ─┐                                                                              │
  /foresee ►│  REST      ─┼─►  networks.resolve(chain)  ─►  EVM pipeline    or    Solana pipeline         │
  / /demo  ►│  web        │                               │                       │                      │
            └─────────────┼───────────────────────────────┼───────────────────────┼──────────────────────┘
                          │                                │                       │
                          │        foresee/                │  chains/              │  integrations/
                          │  signature · approvals · token │  etherscan (v2)       │  tracker  (pluggable)
                          │  identity · scan (X-Ray)       │  rpc (Alchemy/public) │  reputation (GoPlus)
                          │  + solana.py (all five, SVM)   │  solana (RPC + DAS)   │  goplus (token sec)
                          │                                │  prices (DeFiLlama)   │
                          │                                │  cache (TTL)          │
                          └────────────────────────────────┴───────────────────────┘
```

## Request lifecycle

1. Every tool takes a `chain` string. `networks.resolve()` maps it to either an
   EVM `chain_id` or the Solana pipeline.
2. The oracle runs its analysis using the shared clients in `deps.py` (one
   long-lived instance each: Etherscan, RPC, Prices, Solana, GoPlus).
3. Enrichment layers run last and are always optional/defensive:
   - `reputation` — malicious-address intel (GoPlus + registry).
   - `goplus_parse` — authoritative token mechanics (honeypot, tax, LP, holders).
   - `integrations.tracker` — external provider data (attached under `intel`).
4. The result is a plain JSON dict, identical whether it came via MCP or REST.

## Module map

| Path | Responsibility |
|---|---|
| `cassandra/server.py` | FastAPI + FastMCP wiring, routes, rate limit, readiness |
| `cassandra/networks.py` | chain string → EVM(chain_id) \| Solana |
| `cassandra/deps.py` | shared long-lived clients |
| `cassandra/config.py` | env configuration |
| `cassandra/foresee/signature.py` | EVM calldata + EIP-712 decoder |
| `cassandra/foresee/approvals.py` | ERC-20 allowances + Permit2 + NFT operators |
| `cassandra/foresee/approvals_extra.py` | Permit2 + setApprovalForAll discovery |
| `cassandra/foresee/token.py` | EVM rug analysis + deployer family tree |
| `cassandra/foresee/identity.py` | same-person wallet correlation |
| `cassandra/foresee/scan.py` | Wallet X-Ray (aggregate safety score) |
| `cassandra/foresee/solana.py` | all five oracles, Solana-native |
| `cassandra/reputation.py` | malicious-address intel across oracles |
| `cassandra/chains/*` | Etherscan v2, JSON-RPC, Solana RPC, DeFiLlama, GoPlus, cache |
| `cassandra/heuristics/*` | selectors, address registry, Solana programs, GoPlus parse |
| `cassandra/integrations/tracker.py` | pluggable external-provider seam |

## Design principles

- **Defensive enrichment** — third-party data (GoPlus, trackers) is always
  wrapped in `try/except`; any failure degrades to the built-in heuristics. No
  external service can take the app down.
- **Stateless** — no database, no per-user state. Everything is a pure function
  of public on-chain data. The only state is an in-memory TTL cache.
- **Two worlds, one surface** — EVM's account model and Solana's program model
  are decoded natively but return the same shape.
