# Self-hosting

Cassandra is a plain Docker container that listens on `$PORT`. It runs anywhere.

## Environment

Copy `.env.example` to `.env`. The only key you truly need is Etherscan.

| Variable | Required | Purpose |
|---|---|---|
| `ETHERSCAN_API_KEY` | yes (EVM) | Etherscan v2, one key covers all EVM chains. Free. |
| `HELIUS_API_KEY` | recommended | Fast Solana RPC + DAS token metadata. Free. |
| `SOLANA_RPC_URL` | optional | Falls back to public RPC if no Helius key. |
| `GOPLUS_API_KEY` | optional | Higher GoPlus rate limits. Free tier works with no key. |
| `CASSANDRA_TRACKER` | optional | `module:Provider` to plug in an external tracker (see INTEGRATION.md). |

## Local

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env   # add ETHERSCAN_API_KEY
uvicorn cassandra.server:app --reload --port 8000
# open http://localhost:8000
```

Run the offline test suites (no network):

```bash
PYTHONPATH=. python tests/test_signature.py
PYTHONPATH=. python tests/test_solana.py
PYTHONPATH=. python tests/test_product.py
```

## Fly.io (recommended — keeps a warm machine for fast MCP handshakes)

```bash
flyctl launch --no-deploy --copy-config --name cassandra-oracle
flyctl secrets set ETHERSCAN_API_KEY=… HELIUS_API_KEY=…
flyctl deploy
```

## Render

Import the repo; `render.yaml` is the blueprint. Set the secrets in the dashboard.

## Any other host

```bash
docker build -t cassandra .
docker run -p 8000:8000 --env-file .env cassandra
```
Works on Cloud Run, App Runner, Railway, a VPS — anything that runs a container.

## Registering as an OKX.AI ASP

See the "Submitting to OKX.AI" section of the main README.
