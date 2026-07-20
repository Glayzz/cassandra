# Integrating the $MWOR DEV tracker stack

Cassandra has a pluggable intelligence seam so an external tracker — the
$MWOR DEV **fleet forensics + wallet tracker + creator tracker + funding traces**
stack (Helius-based) — can enrich the oracles **without touching Cassandra's core**.

It's off by default. Nothing changes until you set one env var, so it can't
affect a live deploy.

---

## How it maps

| Their capability | Cassandra method to implement | Enriches |
|---|---|---|
| Funding traces (per address, Helius) | `funding_trace(address, chain)` | `foresee_scan` (Wallet X-Ray) + `foresee_identity` |
| Fleet forensics / wallet clustering | `wallet_cluster(addresses, chain)` | `foresee_identity` (Same-Hand) |
| Creator tracking | `creator_history(token, chain)` | `foresee_token` (Maker's Mark) |
| gRPC same-second launch + tx monitor | *(streaming — see "Real-time" below)* | future `watch` endpoint / scheduled task |

Their Helius tx-fetching per address can also directly back Cassandra's Solana
reads (`cassandra/chains/solana.py`) — it's the same provider.

---

## Step 1 — Write a provider

Create a module (anywhere importable, e.g. `mwor_tracker.py`) that implements any
subset of the `Tracker` protocol. Every method is `async` and returns a
JSON-serialisable `dict` (or `None` to skip). `chain` is one of:
`ethereum, base, arbitrum, optimism, polygon, bsc, solana`.

```python
# mwor_tracker.py
class Provider:
    name = "mwor"

    def __init__(self):
        # spin up your Helius client, controller, tracking config, etc.
        ...

    async def funding_trace(self, address: str, chain: str) -> dict | None:
        # your existing funding-trace code
        return {
            "root_funders": [...],
            "hops": 3,
            "first_funded_by": "0x…",
            "flags": ["cex_hop", "mixer_adjacent"],
        }

    async def wallet_cluster(self, addresses: list[str], chain: str) -> dict | None:
        # your fleet-forensics clustering
        return {
            "same_operator_probability": 0.92,
            "shared_funders": [...],
            "cluster_members": [...],
        }

    async def creator_history(self, token: str, chain: str) -> dict | None:
        # your creator tracker
        return {
            "creator": "…",
            "prior_tokens": [{"mint": "…", "outcome": "rugged"}, ...],
            "rug_rate": 0.86,
        }
```

You can implement just one to start — e.g. `creator_history` alone still lights up
the Maker's Mark oracle.

## Step 2 — Point Cassandra at it

```bash
export CASSANDRA_TRACKER="mwor_tracker:Provider"
# format is  "module_path:ClassOrInstance"
```

On Fly.io:
```bash
fly secrets set CASSANDRA_TRACKER="mwor_tracker:Provider"
```
(make sure the module is in the image / on `PYTHONPATH`).

## Step 3 — See it

The provider's output is attached to the oracle response under `intel`:

```json
{
  "safety_score": 25,
  "grade": "F",
  "...": "...",
  "intel": {
    "funding": { "root_funders": [...], "hops": 3, "flags": ["mixer_adjacent"] }
  }
}
```

Verify the wiring end-to-end with the bundled stub first:
```bash
export CASSANDRA_TRACKER="cassandra.integrations.tracker:DemoTracker"
uvicorn cassandra.server:app --port 8000
# POST /foresee/identity → response now has result.intel.cluster
```

---

## Where the seam lives

- `cassandra/integrations/tracker.py` — the `Tracker` protocol, the loader
  (`get_tracker`), the `enrich_scan / enrich_identity / enrich_token` helpers,
  and `DemoTracker` (a stub for testing).
- `cassandra/server.py` — the three REST handlers call `enrich_*` after computing
  a result. Every call is wrapped so a tracker error can never break the response.

To also enrich the **MCP tools** (not just REST), wrap their return values the
same way — one line each in `foresee_scan / foresee_identity / foresee_token`.

## Rendering `intel` on the site (optional)

`web/demo.html` already prints the full JSON in the "Raw JSON response" drawer,
so `intel` shows up immediately. To give it a styled panel, read
`d.intel` in the relevant `render*` function and add a section — the design
tokens (`--surface-2`, `--hair`, `.section-label`, `.fam`) are all there.

## Real-time (gRPC launch / tx monitor)

Same-second launch + tx monitoring is a streaming concern that doesn't fit the
request/response A2MCP shape directly. Two clean options:

1. **Scheduled scanner** — run the monitor as its own process; when it flags a
   launch/rug, POST it into a Cassandra webhook or write to a shared store that a
   new `foresee_watch` endpoint reads. Good for alerts.
2. **Sidecar service** — keep the gRPC monitor as a separate service and let
   Cassandra call it via a `Tracker` method (e.g. `recent_launches(chain)`), so
   the oracle can annotate "this token launched 4s ago, deployer flagged".

Either way, the `Tracker` protocol is the one place to extend — add a method,
implement it, add a matching `enrich_*` helper.
