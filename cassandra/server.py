"""Cassandra ASP - FastMCP server + FastAPI shell.

Five MCP tools under one server, plus a plain-JSON REST facade for the demo
playground. Every tool takes a `chain` string and routes to the right pipeline:
EVM (Ethereum/Base/Arbitrum/Optimism/Polygon/BSC) or Solana.

Run:
    uvicorn cassandra.server:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    from fastmcp import FastMCP  # type: ignore
    _MCP_AVAILABLE = True
except Exception:  # pragma: no cover
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore
        _MCP_AVAILABLE = True
    except Exception:
        FastMCP = None  # type: ignore
        _MCP_AVAILABLE = False

from .deps import get_deps, shutdown
from .networks import resolve
from . import reputation
from .foresee.approvals import audit_approvals
from .foresee.identity import compare_wallets
from .foresee.signature import analyze_calldata
from .foresee.eip712 import analyze_typed_data
from .foresee import counterparty
from .foresee.lighthouse import build_shield
from .foresee.token import analyze_token
from .foresee.solana import (
    analyze_solana_tx,
    audit_solana_approvals,
    analyze_solana_token,
    compare_solana_wallets,
)
from .foresee.scan import wallet_xray_evm, wallet_xray_solana
from .integrations.tracker import enrich_scan, enrich_token, enrich_identity
from .heuristics.selectors import SELECTORS
from .heuristics.addresses import KNOWN_ROUTERS, KNOWN_DRAINERS
from .heuristics.solana_programs import KNOWN_PROGRAMS, KNOWN_SOL_DRAINERS

log = logging.getLogger("cassandra")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

_INSTRUCTIONS = (
    "Cassandra is the wallet's pre-loss oracle. It answers one question in five "
    "shapes: how do I lose money next? Works on EVM chains AND Solana.\n\n"
    "- foresee_signature: decode any signature request BEFORE the user signs - raw\n"
    "  calldata, off-chain EIP-712 messages (Permit/Permit2/Seaport), or a Solana\n"
    "  transaction. On Solana it also returns a Lighthouse Shield: assertion\n"
    "  instructions you can append so an over-drain reverts the whole transaction.\n"
    "- foresee_approvals: enumerate every open approval, ranked by live USD exposure.\n"
    "- foresee_token: rug-risk on a token.\n"
    "- foresee_identity: probability that 2-5 wallets belong to the same human.\n"
    "- foresee_scan: one-click Wallet X-Ray - an aggregate safety score (0-100) + "
    "letter grade + prioritised risks for a whole wallet.\n\n"
    "Pass `chain` as one of: ethereum, base, arbitrum, optimism, polygon, bsc, solana."
)

if _MCP_AVAILABLE:
    mcp = FastMCP(name="Cassandra", instructions=_INSTRUCTIONS)
    _tool = mcp.tool
else:  # pragma: no cover
    mcp = None

    def _tool():
        def _wrap(fn):
            return fn
        return _wrap


# ---- time budget -------------------------------------------------------------
# Every tool MUST return within the platform's task window even when an upstream
# data source hangs. On overrun we return a graceful, degraded verdict instead of
# leaving the caller waiting (the failure mode that got the listing rejected).
_TOOL_BUDGET = float(os.getenv("TOOL_BUDGET_SECONDS", "22"))


class _MissingField(ValueError):
    """A required caller input was not supplied (translated to a clean verdict)."""


async def _budget(coro, kind: str) -> dict:
    try:
        return await asyncio.wait_for(coro, timeout=_TOOL_BUDGET)
    except _MissingField as e:
        return {"verdict": "error", "summary": str(e)}
    except asyncio.TimeoutError:
        return {
            "verdict": "unknown",
            "degraded": True,
            "summary": (
                f"The {kind} analysis exceeded the {int(_TOOL_BUDGET)}s budget because an "
                "upstream data source was slow. Nothing conclusive was found - retry shortly."
            ),
        }


# ---- shared oracle cores (one implementation, used by MCP tools AND REST) -----
# `track=True` adds the optional external-tracker enrichment used by the demo REST
# facade; the MCP tools stay lean (track=False).

async def _core_signature(chain, to, data, value_wei, typed_data, tx, expected) -> dict:
    net = resolve(chain)
    if net.is_solana:
        if not tx:
            raise _MissingField("Solana requires `tx` (base64 transaction).")
        res = analyze_solana_tx(tx)
        res["shield"] = build_shield(res, expected)
        return res
    d = get_deps()
    if typed_data:
        res = analyze_typed_data(typed_data)
    elif to:
        res = await analyze_calldata(
            to=to, data=data, chain_id=net.chain_id, value_wei=value_wei,
            etherscan=d.etherscan, rpc=d.rpc,
        )
    else:
        raise _MissingField("EVM requires `to` (+ `data`) or `typed_data`.")
    res = await reputation.enrich_signature(res, net.chain_id, d.goplus)
    # Structural profile of whoever this signature empowers. Catches drainers no
    # blocklist has seen yet (fresh proxy contracts, EOA spenders).
    return await counterparty.enrich(
        res, net.chain_id, rpc=d.rpc, etherscan=d.etherscan, goplus=d.goplus,
    )


async def _core_approvals(wallet, chain) -> dict:
    net = resolve(chain)
    d = get_deps()
    if net.is_solana:
        return await audit_solana_approvals(wallet, d.solana, d.prices)
    res = await audit_approvals(
        wallet=wallet, chain_id=net.chain_id,
        etherscan=d.etherscan, rpc=d.rpc, prices=d.prices,
    )
    return await reputation.enrich_approvals(res, net.chain_id, d.goplus)


async def _core_token(token, chain, family_depth=8, *, track=False) -> dict:
    net = resolve(chain)
    d = get_deps()
    if net.is_solana:
        res = await analyze_solana_token(token, d.solana, d.prices, goplus=d.goplus)
    else:
        res = await analyze_token(
            token=token, chain_id=net.chain_id, etherscan=d.etherscan, rpc=d.rpc,
            prices=d.prices, family_depth=family_depth, goplus=d.goplus,
        )
    return await enrich_token(res, token, chain) if track else res


async def _core_identity(wallets, chain, *, track=False) -> dict:
    net = resolve(chain)
    d = get_deps()
    if net.is_solana:
        res = await compare_solana_wallets(wallets, d.solana)
    else:
        res = await compare_wallets(wallets=wallets, chain_id=net.chain_id, etherscan=d.etherscan)
    return await enrich_identity(res, wallets, chain) if track else res


async def _core_scan(wallet, chain, *, track=False) -> dict:
    net = resolve(chain)
    d = get_deps()
    if net.is_solana:
        res = await wallet_xray_solana(wallet, d.solana, d.prices)
    else:
        res = await wallet_xray_evm(wallet, net.chain_id, d.etherscan, d.rpc, d.prices, goplus=d.goplus)
    return await enrich_scan(res, wallet, chain) if track else res


# ---- MCP tools ----------------------------------------------------------------

# Each tool runs its real work under _budget() so the MCP caller ALWAYS gets a
# reply inside the platform's task window - the core cores below are shared with
# the REST facade further down.

@_tool()
async def foresee_signature(
    chain: str = "ethereum",
    to: str = "",
    data: str = "0x",
    value_wei: int = 0,
    typed_data: dict | None = None,
    tx: str = "",
    expected: dict | None = None,
) -> dict:
    """Decode a pending signature or transaction before the user signs.

    EVM: provide (to, data[, value_wei]) for raw calldata, OR `typed_data` for an
    EIP-712 signTypedData request.
    Solana: set chain="solana" and provide `tx` = base64 serialized transaction.
    """
    return await _budget(
        _core_signature(chain, to, data, value_wei, typed_data, tx, expected),
        "signature",
    )


@_tool()
async def foresee_approvals(wallet: str, chain: str = "ethereum") -> dict:
    """Enumerate every open approval a wallet has granted, ranked by live USD exposure."""
    return await _budget(_core_approvals(wallet, chain), "approvals")


@_tool()
async def foresee_token(token: str, chain: str = "ethereum", family_depth: int = 8) -> dict:
    """Rug-risk analysis on a token (EVM source + deployer tree; Solana mint/freeze authority)."""
    return await _budget(_core_token(token, chain, family_depth), "token")


@_tool()
async def foresee_identity(wallets: list[str], chain: str = "ethereum") -> dict:
    """Are these wallets the same person? Provide 2-5 addresses; returns probability + evidence."""
    return await _budget(_core_identity(wallets, chain), "identity")


@_tool()
async def foresee_scan(wallet: str, chain: str = "ethereum") -> dict:
    """Wallet X-Ray - one-click whole-wallet health check.

    Returns an aggregate safety_score (0-100), a letter grade, the total live USD
    exposure, and a prioritised list of the biggest risks (drainer approvals,
    unlimited allowances, exposure tiers). Works on EVM and Solana.
    """
    return await _budget(_core_scan(wallet, chain), "scan")


# ---- FastAPI shell around the MCP app -----------------------------------------

_mcp_app = None
_mcp_lifespan = None
if _MCP_AVAILABLE and mcp is not None:
    try:
        # stateless_http: no server-side session to lose between requests.
        # json_response: reply with plain JSON, not an SSE-only stream.
        # Together these let ANY MCP client (incl. the OKX review harness) call
        # the tools; the default stateful+SSE mode is what got the listing
        # rejected ("unable to receive a response ... task timed out").
        def _build_mcp(**kw):
            if hasattr(mcp, "http_app"):
                return mcp.http_app(**kw)
            if hasattr(mcp, "streamable_http_app"):
                return mcp.streamable_http_app(**kw)
            return None
        try:
            _mcp_app = _build_mcp(stateless_http=True, json_response=True)
        except TypeError:  # older fastmcp without these kwargs
            _mcp_app = _build_mcp()
        _mcp_lifespan = getattr(_mcp_app, "lifespan", None)
    except Exception:  # pragma: no cover
        log.exception("failed to build MCP app; REST facade still available")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    if _mcp_lifespan is not None:
        async with _mcp_lifespan(app):
            log.info("Cassandra ready (MCP active at /mcp).")
            yield
    else:
        log.info("Cassandra ready (REST + web only).")
        yield
    await shutdown()


app = FastAPI(
    title="Cassandra",
    description="The wallet's pre-loss oracle. Five /foresee tools across EVM + Solana.",
    version="0.6.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"],
)

# ---- simple in-memory per-IP rate limit on the /foresee endpoints ----
import time as _time
from fastapi.responses import JSONResponse as _JSONResponse

_RL: dict = {}
_RL_MAX = 90        # requests
_RL_WINDOW = 60.0   # seconds


@app.middleware("http")
async def _rate_limit(request, call_next):
    if request.url.path.startswith("/foresee"):
        ip = request.client.host if request.client else "?"
        now = _time.time()
        b = _RL.get(ip)
        if not b or now - b[1] > _RL_WINDOW:
            _RL[ip] = [1, now]
        else:
            b[0] += 1
            if b[0] > _RL_MAX:
                return _JSONResponse(status_code=429,
                    content={"detail": "Rate limit exceeded - slow down and try again shortly."})
        if len(_RL) > 20000:
            _RL.clear()
    return await call_next(request)


# ---- REST facade --------------------------------------------------------------

class SignatureReq(BaseModel):
    chain: str = "ethereum"
    to: str | None = None
    data: str = "0x"
    value_wei: int = Field(default=0, alias="valueWei")
    typed_data: dict | None = Field(default=None, alias="typedData")
    tx: str | None = None
    expected: dict | None = None
    model_config = {"populate_by_name": True}


class ApprovalsReq(BaseModel):
    wallet: str
    chain: str = "ethereum"
    model_config = {"populate_by_name": True}


class TokenReq(BaseModel):
    token: str
    chain: str = "ethereum"
    family_depth: int = Field(default=8, alias="familyDepth")
    model_config = {"populate_by_name": True}


class IdentityReq(BaseModel):
    wallets: list[str]
    chain: str = "ethereum"
    model_config = {"populate_by_name": True}


class ScanReq(BaseModel):
    wallet: str
    chain: str = "ethereum"
    model_config = {"populate_by_name": True}


# REST shares the exact same cores as the MCP tools, so a verdict is identical
# through either door. Missing inputs become a 400; a blown budget becomes a 504.

async def _rest(coro, kind: str):
    try:
        return await asyncio.wait_for(coro, timeout=_TOOL_BUDGET)
    except _MissingField as e:
        raise HTTPException(400, str(e))
    except asyncio.TimeoutError:
        raise HTTPException(504, f"{kind} analysis exceeded the {int(_TOOL_BUDGET)}s budget - retry shortly.")
    except HTTPException:
        raise
    except Exception as e:
        log.exception("%s error", kind)
        raise HTTPException(500, str(e))


@app.post("/foresee/signature")
async def rest_signature(req: SignatureReq):
    return await _rest(
        _core_signature(req.chain, req.to, req.data, req.value_wei,
                        req.typed_data, req.tx, req.expected),
        "signature",
    )


@app.post("/foresee/approvals")
async def rest_approvals(req: ApprovalsReq):
    return await _rest(_core_approvals(req.wallet, req.chain), "approvals")


@app.post("/foresee/token")
async def rest_token(req: TokenReq):
    return await _rest(_core_token(req.token, req.chain, req.family_depth, track=True), "token")


@app.post("/foresee/identity")
async def rest_identity(req: IdentityReq):
    return await _rest(_core_identity(req.wallets, req.chain, track=True), "identity")


@app.post("/foresee/scan")
async def rest_scan(req: ScanReq):
    return await _rest(_core_scan(req.wallet, req.chain, track=True), "scan")


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"status": "ok", "service": "cassandra", "version": "0.6.0", "mcp": _MCP_AVAILABLE}


@app.get("/ready")
async def ready():
    try:
        get_deps()
        return {"ready": True}
    except Exception as e:  # pragma: no cover
        raise HTTPException(503, str(e))


@app.get("/stats")
async def stats():
    """Live capability counts - what Cassandra actually knows, straight from the registries."""
    return {
        "tools": 5,
        "evm_chains": 6,
        "solana": True,
        "total_networks": 7,
        "selectors_tracked": len(SELECTORS),
        "programs_tracked": len(KNOWN_PROGRAMS),
        "routers_known": len(KNOWN_ROUTERS),
        "drainers_tracked": len(KNOWN_DRAINERS) + len(KNOWN_SOL_DRAINERS),
        "price_source": "DeFiLlama",
        "data_sources": ["Etherscan v2", "Solana RPC", "DeFiLlama", "Helius DAS", "GoPlus Security"],
        "features": [
            "eip712_signature_analysis", "lighthouse_shield", "approval_log_scan",
            "permit2", "nft_approvals", "token_security", "malicious_address_intel",
            "counterparty_profiling", "eoa_spender_detection", "fresh_contract_detection",
            "multicall_inner_call_decoding", "graceful_degradation", "bounded_latency",
            "stateless_mcp", "caching", "rate_limited",
        ],
        "tool_budget_seconds": _TOOL_BUDGET,
    }


@app.get("/manifest.json")
async def manifest():
    return {
        "name": "Cassandra",
        "tagline": "The wallet's pre-loss oracle.",
        "version": "0.6.0",
        "protocol": "A2MCP",
        "transport": {"type": "streamable-http", "stateless": True, "json_response": True},
        "pricing": "free",
        "endpoints": {
            "mcp": "/mcp",
            "rest": {
                "signature": "/foresee/signature",
                "approvals": "/foresee/approvals",
                "token": "/foresee/token",
                "identity": "/foresee/identity",
                "scan": "/foresee/scan",
            },
            "stats": "/stats",
        },
        "networks": {
            "evm": ["ethereum", "base", "arbitrum", "optimism", "polygon", "bsc"],
            "solana": ["solana"],
        },
        "categories": ["security", "wallet", "defi", "risk"],
    }


# ---- Landing / playground ----

_WEB_DIR = Path(__file__).resolve().parent.parent / "web"


@app.get("/", response_class=HTMLResponse)
async def index():
    idx = _WEB_DIR / "index.html"
    if idx.exists():
        return HTMLResponse(idx.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Cassandra</h1><p>The wallet's pre-loss oracle.</p>")


@app.get("/demo", response_class=HTMLResponse)
async def demo():
    d = _WEB_DIR / "demo.html"
    if d.exists():
        return HTMLResponse(d.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Demo page missing</h1>")


# ---- MCP mount (MUST be last) -------------------------------------------------
# mcp.http_app() already routes internally at /mcp, so mounting it at root ("/")
# serves MCP at exactly /mcp with no doubled segment. A root mount is a catch-all,
# so it is registered AFTER every FastAPI route above (/, /health, /ready, /demo,
# /stats, /manifest.json, /foresee/*) to ensure those match first and only
# unmatched paths (i.e. /mcp) fall through to the MCP app.
if _mcp_app is not None:
    app.mount("/", _mcp_app)

