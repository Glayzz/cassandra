# Cassandra

**The wallet's pre-loss oracle.** Ask one question — _how do I lose money next?_ — and get a truthful answer before you sign.

![status](https://img.shields.io/badge/status-live-1f9d59) ![version](https://img.shields.io/badge/version-0.5.0-5a4be0) ![protocol](https://img.shields.io/badge/A2MCP-agent--native-4536c9) ![chains](https://img.shields.io/badge/EVM%20%2B%20Solana-7%20networks-b0862f) ![license](https://img.shields.io/badge/license-MIT-8a8a95)

> **Live:** https://cassandra-oracle.fly.dev · **MCP:** `/mcp` · **Playground:** `/demo`

Cassandra is a read-only security oracle for crypto wallets. It inspects the exact things that drain people — the transaction you're about to sign, the approvals you left open, the token you're about to buy, the wallet you're about to trust — and tells you the **consequence** in plain language, priced in USD, with the fix attached.

It works across seven EVM networks and Solana. It holds no keys, moves no funds, and never asks you to connect a wallet. You can call it three ways: as an **A2MCP endpoint** any AI agent can use, as a plain **REST API**, or through a **web playground** you click through yourself.

---

## Why it exists

Almost every crypto loss is *authorized by the victim.* You sign a transaction you can't read. You leave an unlimited approval open for two years and forget it. You buy a token whose deployer has already rugged four times. You send funds to a wallet that turns out to be the scammer's other hand. None of that is a "hack" — the wallet did exactly what it was told to do.

Most tools tell you *what* a transaction is: "this is an `approve` call." Cassandra tells you *what it does to you*: "this lets `0xModel…` move your entire USDC balance, forever, and that address is a flagged drainer — reject it." Same data, but turned toward the one question that actually matters at signing time.

---

## The five oracles

Each oracle answers a different way you can lose money. All are stateless, free, and work on both EVM and Solana.

| Oracle | The question it answers | What it does |
|---|---|---|
| **Wallet X-Ray** (`foresee_scan`) | _How exposed am I right now?_ | One call grades the whole wallet **A–F** with a live safety score, then hands back a ranked to-do list — the riskiest open door first. |
| **Sign-Time** (`foresee_signature`) | _What happens if I sign this?_ | Decodes raw calldata, **off-chain EIP-712 messages** (ERC-2612/DAI permit, Permit2 allowance & transfer, Seaport orders), or a Solana transaction, and narrates the outcome. On Solana it also returns a **Lighthouse Shield** — assertion instructions you append so an over-drain reverts the whole transaction. |
| **Standing Doors** (`foresee_approvals`) | _Who can already take my money?_ | Lists every open ERC-20 allowance, Permit2 delegation, NFT operator approval and SPL delegate — ranked by **live USD exposure**, each with the revoke ready to send. |
| **Maker's Mark** (`foresee_token`) | _Can this token rug me?_ | Reads the token's own rules (mint / blacklist / mutable-tax / pausable on EVM; mint & freeze authority on Solana) **plus** live honeypot, buy/sell-tax, LP-lock and holder-concentration intel, **plus** the EVM deployer's family tree of prior contracts tagged alive / dead / rugged. |
| **Same-Hand** (`foresee_identity`) | _Is this wallet secretly me — or secretly them?_ | Scores the probability that two addresses are the same operator, using shared funders, direct transfers, counterparty overlap and behavioral fingerprints — and shows the weight behind every signal. |

---

## What's new in v0.5.0

- **Off-chain signature-drainer detection.** Most wallets today are drained by a message you *sign*, not a transaction you send. Sign-Time now decodes EIP-712 typed data — ERC-2612 / DAI permit, Permit2 allowance and transfer, Seaport orders — and names exactly what signing authorizes.
- **Lighthouse Shield (Solana).** For a risky Solana transaction, Sign-Time returns ready-to-append [Lighthouse](https://lighthouse.voyage) assertion instructions so the transaction reverts instead of draining. Cassandra decides the guardrails; your wallet's Lighthouse client encodes them.
- **Complete approval discovery.** Standing Doors now finds ERC-20 approvals from `Approval` event logs, catching grants set via routers/aggregators and older approvals a transaction-history scan misses.

---

## How it works

Cassandra is stateless and read-only. There is no signup, no wallet connection, and no caller-side API key — you pass an address or some calldata, it reads public chain data and answers. Every risky finding ships with its remedy: the revoke calldata to send, the instruction to reject, or the reason to walk away.

It reads from free, public data sources: **Etherscan v2** (multichain EVM), **Solana RPC + Helius DAS**, **DeFiLlama** for live prices, and **GoPlus Security** for honeypot / malicious-address intelligence. When a live source is unavailable, each oracle degrades to its on-chain heuristics rather than failing — the answer gets less precise, never absent.

**Networks:** Ethereum, Base, Arbitrum, Optimism, Polygon, BNB Chain, and **Solana**. Pass `chain` on every call.

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # add ETHERSCAN_API_KEY (EVM); SOLANA_RPC_URL or HELIUS_API_KEY (Solana)
uvicorn cassandra.server:app --reload --host 0.0.0.0 --port 8000
```

Then open `/` for the landing page or `/demo` for the interactive playground. The MCP endpoint is at `/mcp` (Streamable HTTP), with a machine-readable summary at `/manifest.json` and a `/health` probe.

No keys? It still runs — GoPlus works anonymously and Solana falls back to the public RPC. Add `ETHERSCAN_API_KEY` and `HELIUS_API_KEY` (both free) for full-speed, fully-labeled results.

---

## Using it

**As a REST API** — check a token before you buy it:

```bash
curl -X POST https://cassandra-oracle.fly.dev/foresee/token \
  -H 'content-type: application/json' \
  -d '{"chain":"solana","mint":"<mint-address>"}'
```

**As a REST API** — see what a transaction will do before signing:

```bash
curl -X POST https://cassandra-oracle.fly.dev/foresee/signature \
  -H 'content-type: application/json' \
  -d '{"chain":"ethereum","to":"0xA0b8…","data":"0x095ea7b3…"}'
```

**As an MCP server** — point any A2MCP / MCP-capable agent at `https://cassandra-oracle.fly.dev/mcp`. The five oracles appear as tools (`foresee_scan`, `foresee_signature`, `foresee_approvals`, `foresee_token`, `foresee_identity`) the agent can call on the user's behalf — for example, an agentic wallet that runs `foresee_signature` automatically before every signature.

Full request/response shapes for every endpoint are in [docs/API.md](docs/API.md).

---

## Deploy

Cassandra is a plain Docker container that listens on `$PORT` — it runs on Fly.io, Render, Cloud Run, Railway, or anything that takes a container. Fly.io is recommended because a warm machine keeps the MCP handshake fast. Full instructions, environment variables and one-command recipes are in [docs/SELF_HOST.md](docs/SELF_HOST.md).

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — how it works, module map, request lifecycle
- [API reference](docs/API.md) — every endpoint, request and response
- [Self-hosting](docs/SELF_HOST.md) — environment variables + Fly / Render / Docker
- [Integration guide](INTEGRATION.md) — plug in an external intel provider (Helius, fleet forensics)
- [Roadmap](docs/ROADMAP.md) — what's next

---

## Security & disclaimer

Cassandra is **read-only**. It never has custody of funds, never asks you to connect a wallet, and never transmits a private key — it only reads public chain data. The revoke calldata and instructions it returns are yours to inspect and sign; Cassandra never signs anything.

It is a risk-assessment tool, not a guarantee. On-chain analysis can produce false positives and false negatives, and a "green" result is not a promise of safety. Nothing here is financial advice. Always verify before you sign.

---

## License

[MIT](LICENSE). Ship it.
