# Roadmap

Cassandra shipped as a hackathon project and is now a live product. What's next.

## Shipped (v0.5.0)

- **Off-chain signature-drainer analysis.** Sign-Time now reads EIP-712 typed
  messages, not just transactions: ERC-2612 / DAI permit, Permit2
  PermitSingle/PermitBatch (allowance) and PermitTransferFrom (transfer), and
  Seaport order inversion. This is the vector behind most modern wallet drains.
- **Lighthouse Shield (Solana).** Sign-Time returns ready-to-append
  [Lighthouse](https://lighthouse.voyage) assertion instructions so a risky
  transaction reverts instead of draining — a delegate/authority the tx tries to
  install must be gone at the end, and (with the caller's simulated post-balances)
  balances must stay above expected floors. Detection → prevention in one call.
- **Complete approval discovery.** Standing Doors now discovers ERC-20 allowances
  from `Approval` event logs (per token the wallet has touched), catching
  approvals set via routers/aggregators and older than the recent-tx window —
  Revoke.cash-grade coverage instead of a best-effort txlist scan.

## Shipped (v0.4.0)

- Five oracles across EVM + Solana (signature, approvals, token, identity, X-Ray).
- Pro token security via GoPlus (honeypot, taxes, LP lock, holder concentration).
- Malicious-address intel across every oracle (GoPlus address-security + registry).
- Permit2 + NFT `setApprovalForAll` approval coverage with revokes.
- Performance + reliability: TTL cache, per-IP rate limit, readiness probe, RPC fallback.
- A2MCP + REST + web, agent-native.

## Planned

### Show what you'll actually lose (simulation)
Best-effort EVM transaction simulation (asset-change tracing where the RPC
supports it) so Sign-Time reports the real balance deltas — "you will lose 1.2
ETH and all your USDC" — and feeds exact balance floors into the Lighthouse
Shield on Solana.

### Real-time monitoring
Same-second launch + tx monitoring (gRPC) surfaced as a `foresee_watch` endpoint
or scheduled alerts, powered by the pluggable tracker seam.

### Deeper intel
- Broader scam/drainer feeds (more sources) beyond GoPlus + registry.
- Wallet fleet/cluster forensics feeding Same-Hand (external tracker).
- Creator-history feeds for Maker's Mark.
- More chains (any Etherscan-v2 chain is a one-line add).

### Product
- Shareable verdict cards / permalinks.
- Optional API keys + usage tiers.
- Redis-backed cache for horizontal scaling.
