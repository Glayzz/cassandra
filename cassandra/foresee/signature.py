"""foresee_signature - decode a sign request before you sign.

Input: raw tx calldata OR EIP-712 typed-data JSON.
Output: plain-English narration + red/yellow/green verdict + specific fates.

The critical insight: most wallet drains use permit / setApprovalForAll /
Permit2's PermitBatch. Recognizing those patterns is 80% of the win.
"""
from __future__ import annotations

from typing import Any

from eth_abi import decode as abi_decode
from eth_utils import is_hex, to_checksum_address

from ..heuristics import selectors as S
from ..heuristics.addresses import (
    KNOWN_ROUTERS,
    is_known_drainer,
    label_for,
    normalize,
)
from ..chains.etherscan import Etherscan
from ..chains.rpc import Rpc


# ---- Value formatting ----

_UNLIMITED_THRESHOLD = (1 << 255)  # anything above this we call "unlimited"


def _format_amount(v: int, decimals: int | None = None, symbol: str | None = None) -> str:
    if v == 0:
        return f"0 {symbol or 'tokens'}"
    if v >= _UNLIMITED_THRESHOLD:
        return f"UNLIMITED {symbol or 'tokens'}"
    if decimals is not None and decimals > 0:
        whole = v / (10 ** decimals)
        if whole >= 1:
            return f"{whole:,.4f} {symbol or ''}".strip()
        return f"{whole:.8g} {symbol or ''}".strip()
    return f"{v} raw units of {symbol or 'the token'}"


# ---- Selector decoding ----

def _split_calldata(hex_data: str) -> tuple[str, bytes] | None:
    hex_data = hex_data.strip()
    if not hex_data.startswith("0x"):
        hex_data = "0x" + hex_data
    if not is_hex(hex_data) or len(hex_data) < 10:
        return None
    return hex_data[:10].lower(), bytes.fromhex(hex_data[10:])


def _decode_selector(selector: str, args: bytes) -> dict | None:
    meta = S.SELECTORS.get(selector)
    if not meta:
        return {"selector": selector, "known": False}
    if meta["abi"] is None:
        return {"selector": selector, "known": True, "meta": meta, "args": None}
    try:
        decoded = abi_decode(meta["abi"], args)
    except Exception as e:
        return {"selector": selector, "known": True, "meta": meta,
                "args": None, "decode_error": str(e)}
    named = dict(zip(meta["arg_names"], decoded))
    return {"selector": selector, "known": True, "meta": meta, "args": named}


# ---- Token metadata (best-effort) ----

async def _token_metadata(rpc: Rpc, chain_id: int, token: str) -> dict:
    """symbol() + decimals() via eth_call. Silent-fail returns partial data."""
    out: dict = {"address": token}
    # decimals()  -> 0x313ce567
    try:
        raw = await rpc.eth_call(chain_id, token, "0x313ce567")
        out["decimals"] = int(raw, 16) if raw and raw != "0x" else None
    except Exception:
        out["decimals"] = None
    # symbol() -> 0x95d89b41
    try:
        raw = await rpc.eth_call(chain_id, token, "0x95d89b41")
        out["symbol"] = _decode_string_return(raw)
    except Exception:
        out["symbol"] = None
    return out


def _decode_string_return(raw: str) -> str | None:
    if not raw or raw == "0x":
        return None
    b = bytes.fromhex(raw[2:])
    # dynamic string encoding: 32-byte offset, 32-byte length, data
    try:
        if len(b) >= 96:
            length = int.from_bytes(b[32:64], "big")
            s = b[64:64 + length].decode("utf-8", errors="replace").strip("\x00")
            if s:
                return s
        # bytes32 fixed-string variant (older tokens like MKR)
        return b[:32].decode("utf-8", errors="replace").strip("\x00") or None
    except Exception:
        return None


# ---- Main entrypoint ----

async def analyze_calldata(
    to: str,
    data: str,
    chain_id: int,
    value_wei: int = 0,
    etherscan: Etherscan | None = None,
    rpc: Rpc | None = None,
) -> dict:
    """Analyze a raw transaction request.

    Returns a structured verdict dict.
    """
    findings: list[dict] = []
    fates: list[str] = []
    severity_max = "info"  # info | low | medium | high | critical

    to_norm = normalize(to)
    if not to_norm:
        return _err("Invalid `to` address")

    contract_label = label_for(to_norm) or None
    if is_known_drainer(to_norm):
        findings.append({
            "kind": "known_drainer",
            "severity": "critical",
            "message": f"Destination {to_norm} is on Cassandra's drainer registry.",
        })
        fates.append("Signing this will send your assets to a known scammer.")
        severity_max = "critical"

    # Empty data => plain ETH send
    if not data or data in ("0x", "0x0"):
        note = f"Plain native transfer of {value_wei / 1e18:.6f} ETH to {to_norm}"
        if contract_label:
            note += f" ({contract_label})"
        return {
            "verdict": _color(severity_max),
            "summary": note,
            "fates": fates or [f"{value_wei / 1e18:.6f} ETH leaves your wallet."],
            "findings": findings,
            "target": {"address": to_norm, "label": contract_label},
            "operation": {"name": "native_transfer", "type": "transfer"},
        }

    parsed = _split_calldata(data)
    if not parsed:
        return _err("Invalid calldata (not hex or too short).")
    selector, arg_bytes = parsed

    decoded = _decode_selector(selector, arg_bytes)
    if not decoded or not decoded.get("known"):
        # Before treating this as merely unrecognised, check whether the function
        # NAME is one of the pretexts drainers use. This fires on contracts no
        # feed has seen, because it keys off the lure rather than the address.
        lure = S.lure_name(selector)
        if lure:
            severity_max = _worse(severity_max, "critical")
            findings.append({
                "kind": "drainer_lure_function",
                "severity": "critical",
                "message": (
                    f"This calls `{lure}` on {to_norm}. No token, DEX or NFT standard "
                    "defines that function - it exists to give a phishing page a "
                    "plausible button to press. Contracts exposing it are overwhelmingly "
                    "wallet drainers."
                ),
            })
            fates.append(
                f"`{lure}` is a phishing pretext, not a real protocol action. "
                "Whatever it does, you did not intend it - reject this."
            )
            return _final(
                summary=f"`{lure}` on {to_norm} - a known wallet-drainer pretext.",
                fates=fates, findings=findings, verdict="red",
                target={"address": to_norm, "label": contract_label},
                operation={"name": lure, "type": "drainer_lure", "selector": selector},
            )

        # unknown selector - not necessarily bad, but user should know
        findings.append({
            "kind": "unknown_selector",
            "severity": "medium",
            "message": (
                f"Selector {selector} isn't in Cassandra's known-function registry. "
                "The wallet cannot verify what this call does without contract source."
            ),
        })
        severity_max = _worse(severity_max, "medium")
        # Try to look up ABI on Etherscan to give a hint
        hint = None
        if etherscan:
            try:
                abi = await etherscan.get_abi(to_norm, chain_id)
                hint = "(ABI available on Etherscan - decode manually before signing)" if abi else None
            except Exception:
                pass
            src = None
            try:
                src = await etherscan.get_source(to_norm, chain_id)
            except Exception:
                pass
            if src and src.get("ContractName"):
                findings.append({
                    "kind": "contract_name",
                    "severity": "info",
                    "message": f"Contract identifies as `{src['ContractName']}`.",
                })
            if src and src.get("Proxy") == "1":
                findings.append({
                    "kind": "proxy",
                    "severity": "medium",
                    "message": (
                        "Target is a proxy - the implementation contract can be swapped "
                        f"by its admin. Actual code today lives at {src.get('Implementation')}."
                    ),
                })
                severity_max = _worse(severity_max, "medium")
        summary = (
            f"Unknown function on contract {to_norm}"
            + (f" ({contract_label})" if contract_label else "")
            + ". Cassandra cannot vouch for what happens next."
        )
        return {
            "verdict": _color(severity_max),
            "summary": summary,
            "fates": fates or [
                "You are signing a transaction whose behavior isn't decoded.",
                "If the contract is malicious, worst case is total loss of any tokens or NFTs "
                "you've ever approved to it (or via Permit2).",
            ],
            "findings": findings,
            "target": {"address": to_norm, "label": contract_label},
            "operation": {"name": "unknown", "selector": selector, "hint": hint},
        }

    meta = decoded["meta"]
    op_type = meta["type"]

    # The selector is recognised but its arguments did not decode - truncated,
    # padded wrong, or deliberately malformed. Every branch below indexes into
    # `args`, so bail out here with a verdict instead of raising: calldata comes
    # from whoever is asking for the signature, and a hostile caller must not be
    # able to turn bad input into a crash.
    if meta.get("abi") is not None and decoded.get("args") is None:
        severity_max = _worse(severity_max, "high")
        findings.append({
            "kind": "malformed_calldata",
            "severity": "high",
            "message": (
                f"This call claims to be `{meta['name']}` but its arguments do not "
                "decode against that function's signature"
                + (f" ({decoded['decode_error']})." if decoded.get("decode_error") else ".")
                + " Cassandra cannot tell you what it would do, and a wallet cannot "
                "either. Malformed arguments on a recognised selector are a common "
                "way to slip past naive decoders."
            ),
        })
        return _final(
            summary=f"`{meta['name']}` on {to_norm} with undecodable arguments.",
            fates=fates or ["The effect of this call cannot be determined. Do not sign it."],
            findings=findings, verdict=_color(severity_max),
            target={"address": to_norm, "label": contract_label},
            operation={"name": meta["name"], "type": "malformed", "selector": selector},
        )

    # ---- Case analysis ----
    if op_type == "token_approve":
        spender = _to_addr(decoded["args"]["spender"])
        amount = int(decoded["args"]["amount"])
        token_meta = {}
        if rpc:
            try:
                token_meta = await _token_metadata(rpc, chain_id, to_norm)
            except Exception:
                pass
        symbol = token_meta.get("symbol")
        decimals = token_meta.get("decimals")
        spender_label = label_for(spender)
        drainer = is_known_drainer(spender)
        unlimited = amount >= _UNLIMITED_THRESHOLD

        if drainer:
            severity_max = _worse(severity_max, "critical")
            findings.append({
                "kind": "drainer_spender",
                "severity": "critical",
                "message": f"Spender {spender} is a known drainer.",
            })
            fates.append(f"Signing lets {spender} steal your entire {symbol or 'token'} balance forever.")
        elif unlimited and not spender_label:
            severity_max = _worse(severity_max, "high")
            findings.append({
                "kind": "unlimited_unknown",
                "severity": "high",
                "message": (
                    f"You are granting UNLIMITED spending of {symbol or 'this token'} "
                    f"to {spender}, which Cassandra doesn't recognize as a mainstream router."
                ),
            })
            fates.append(
                f"{spender} can move your entire {symbol or 'token'} balance whenever it wants."
            )
        elif unlimited and spender_label:
            severity_max = _worse(severity_max, "medium")
            findings.append({
                "kind": "unlimited_known",
                "severity": "medium",
                "message": (
                    f"Unlimited approval to {spender_label}. Normal for trading, but "
                    "you should revoke afterward if you don't plan to keep using it."
                ),
            })
            fates.append(f"{spender_label} can move any {symbol or 'token'} you hold in this wallet.")
        else:
            severity_max = _worse(severity_max, "low")
            fates.append(
                f"You approve up to {_format_amount(amount, decimals, symbol)} to be spent by "
                f"{spender_label or spender}."
            )

        return _final(
            summary=(
                f"ERC-20 approve on {symbol or to_norm}: spender={spender_label or spender}, "
                f"amount={'UNLIMITED' if unlimited else _format_amount(amount, decimals, symbol)}"
            ),
            fates=fates, findings=findings, verdict=_color(severity_max),
            target={"address": to_norm, "label": symbol or contract_label, "kind": "erc20_token"},
            operation={
                "name": "approve", "type": op_type,
                "spender": spender, "amount": str(amount), "unlimited": unlimited,
                "token": {"address": to_norm, "symbol": symbol, "decimals": decimals},
            },
        )

    if op_type == "gasless_approve":
        # ERC-2612 permit
        owner = _to_addr(decoded["args"]["owner"])
        spender = _to_addr(decoded["args"]["spender"])
        value = int(decoded["args"]["value"])
        deadline = int(decoded["args"]["deadline"])
        token_meta = await _token_metadata(rpc, chain_id, to_norm) if rpc else {}
        symbol = token_meta.get("symbol"); decimals = token_meta.get("decimals")
        unlimited = value >= _UNLIMITED_THRESHOLD

        severity_max = _worse(severity_max, "critical")
        drainer = is_known_drainer(spender)
        findings.append({
            "kind": "permit",
            "severity": "critical" if drainer or unlimited else "high",
            "message": (
                "This is a GASLESS APPROVAL (EIP-2612 permit). Signing this off-chain message "
                f"lets `{spender}` move up to "
                f"{_format_amount(value, decimals, symbol)} of your {symbol or 'tokens'} "
                "instantly, with no on-chain confirmation."
            ),
        })
        fates.append(
            f"{spender} gains {'UNLIMITED' if unlimited else _format_amount(value, decimals, symbol)} "
            f"spending rights over your {symbol or 'tokens'} the moment you sign - not later, now."
        )
        return _final(
            summary=(
                f"EIP-2612 permit on {symbol or to_norm}. "
                "This is the mechanism used by most modern wallet drains."
            ),
            fates=fates, findings=findings, verdict=_color(severity_max),
            target={"address": to_norm, "label": symbol or contract_label, "kind": "erc20_token"},
            operation={
                "name": "permit", "type": op_type,
                "owner": owner, "spender": spender, "value": str(value),
                "unlimited": unlimited, "deadline": deadline,
            },
        )

    if op_type == "nft_approve_all":
        operator = _to_addr(decoded["args"]["operator"])
        approved = bool(decoded["args"]["approved"])
        if not approved:
            # revoke - safe
            return _final(
                summary=f"Revoking setApprovalForAll on {to_norm} for operator {operator}.",
                fates=["Nothing leaves your wallet; you are REVOKING a previous permission."],
                findings=findings, verdict="green",
                target={"address": to_norm, "kind": "nft_collection"},
                operation={"name": "setApprovalForAll", "operator": operator, "approved": False},
            )
        operator_label = label_for(operator)
        drainer = is_known_drainer(operator)
        severity_max = _worse(severity_max, "critical" if drainer else "high")
        findings.append({
            "kind": "approve_for_all",
            "severity": "critical" if drainer else "high",
            "message": (
                f"You are granting `{operator}` the ability to transfer EVERY NFT you own "
                f"in collection {to_norm}, including any you buy in the future."
            ),
        })
        fates.append(
            f"{operator_label or operator} can move any NFT from this collection out of your wallet, "
            "forever - until you revoke."
        )
        return _final(
            summary=f"setApprovalForAll on NFT collection {to_norm} to {operator_label or operator}.",
            fates=fates, findings=findings, verdict=_color(severity_max),
            target={"address": to_norm, "kind": "nft_collection"},
            operation={"name": "setApprovalForAll", "operator": operator, "approved": True},
        )

    if op_type == "multicall":
        # Decode every wrapped call. This is where drainers hide: the wallet
        # renders one innocuous "multicall" prompt while a permit + transferFrom
        # sit inside it. Surfacing the inner calls is the whole point.
        raw_calls = (decoded.get("args") or {}).get("calls") or []
        inner = _decode_inner_calls(raw_calls)

        severity_max = _worse(severity_max, "high")
        findings.append({
            "kind": "multicall",
            "severity": "high",
            "message": (
                f"This `multicall` wraps {len(inner)} inner call(s). Wallets show only the "
                "outer call, so drainers bundle a `permit` + `transferFrom` inside one prompt."
            ),
        })

        for c in inner:
            if c.get("severity"):
                severity_max = _worse(severity_max, c["severity"])
            if c.get("finding"):
                findings.append(c["finding"])
            if c.get("fate"):
                fates.append(c["fate"])

        names = ", ".join(c["name"] for c in inner) or "undecodable payloads"
        if not fates:
            fates.append("Any of the inner calls could be an approval or transfer you didn't see.")
        return _final(
            summary=f"multicall on {to_norm} wrapping {len(inner)} call(s): {names}.",
            fates=fates, findings=findings, verdict=_color(severity_max),
            target={"address": to_norm, "label": contract_label},
            operation={"name": meta["name"], "type": op_type,
                       "inner_calls_count": len(inner),
                       "inner_calls": [
                           {k: v for k, v in c.items() if k in ("name", "type", "selector", "detail")}
                           for c in inner
                       ]},
        )

    if op_type == "swap":
        args = decoded["args"]
        return _final(
            summary=f"Uniswap V2 swap via {contract_label or to_norm}.",
            fates=[
                f"You spend up to {args.get('amountIn')} of the input token, receiving at "
                f"least {args.get('amountOutMin')} of the output token."
            ],
            findings=findings, verdict="green",
            target={"address": to_norm, "label": contract_label},
            operation={"name": meta["name"], "type": op_type},
        )

    if op_type == "token_transfer":
        args = decoded["args"]
        recipient = _to_addr(args["recipient"])
        amount = int(args["amount"])
        token_meta = await _token_metadata(rpc, chain_id, to_norm) if rpc else {}
        symbol = token_meta.get("symbol"); decimals = token_meta.get("decimals")
        pretty = _format_amount(amount, decimals, symbol)

        # Destinations that burn the funds with no way back.
        burn = _burn_destination(recipient, token_contract=to_norm, symbol=symbol)
        if burn:
            findings.append(burn)
            severity_max = _worse(severity_max, "critical")
            fates.append(burn["fate"])

        return _final(
            summary=f"ERC-20 transfer of {pretty} to {recipient}",
            fates=fates or [f"{pretty} leaves your wallet."],
            findings=findings, verdict=_color(severity_max),
            target={"address": to_norm, "label": symbol or contract_label, "kind": "erc20_token"},
            # `recipient` is exposed so the counterparty and address-poisoning
            # checks downstream have something to inspect.
            operation={"name": "transfer", "type": op_type, "recipient": recipient,
                       "amount": str(amount), "token": to_norm, "symbol": symbol},
        )

    # Generic decoded case
    return _final(
        summary=f"{meta['name']} on {contract_label or to_norm}.",
        fates=fates or [f"Executes `{meta['name']}` on the target contract."],
        findings=findings, verdict=_color(severity_max),
        target={"address": to_norm, "label": contract_label},
        operation={"name": meta["name"], "type": op_type, "args": _stringify_args(decoded["args"])},
    )


# ---- irreversible destinations ----

_ZERO = "0x" + "0" * 40
_DEAD = "0x000000000000000000000000000000000000dead"


def _burn_destination(recipient: str, *, token_contract: str | None = None,
                      symbol: str | None = None) -> dict | None:
    """Flag transfers whose destination destroys the funds.

    None of these revert - the transaction succeeds and the money is simply gone,
    which is why they belong in a pre-loss oracle rather than a linter.
    """
    r = (recipient or "").lower()
    name = symbol or "these tokens"

    if r == _ZERO:
        return {
            "kind": "transfer_to_zero_address", "severity": "critical",
            "message": ("The recipient is the zero address. This transaction will "
                        "succeed and the tokens will be permanently destroyed."),
            "fate": f"{name} are burned forever - this cannot be undone.",
        }
    if r == _DEAD:
        return {
            "kind": "transfer_to_burn_address", "severity": "critical",
            "message": ("The recipient is the standard burn address (0x…dEaD). The "
                        "tokens will be permanently destroyed."),
            "fate": f"{name} are burned forever - this cannot be undone.",
        }
    if token_contract and r == token_contract.lower():
        return {
            "kind": "transfer_to_token_contract", "severity": "critical",
            "message": (
                "The recipient is the token's own contract address. Sending a token "
                "to itself is one of the most common irreversible mistakes - almost "
                "no token implements a way to recover it."
            ),
            "fate": f"{name} are almost certainly unrecoverable.",
        }
    return None


# ---- multicall unwrapping ----

def _decode_inner_calls(raw_calls: Any) -> list[dict]:
    """Decode each payload wrapped in a multicall into a named, rated finding.

    Pure and synchronous: it only reads the calldata already in front of us, so
    unwrapping never adds a network round-trip to the signing path.
    """
    out: list[dict] = []
    if not isinstance(raw_calls, (list, tuple)):
        return out

    for idx, blob in enumerate(raw_calls[:20]):  # bound the work; 20 is generous
        if isinstance(blob, (bytes, bytearray)):
            hexed = "0x" + blob.hex()
        elif isinstance(blob, str):
            hexed = blob if blob.startswith("0x") else "0x" + blob
        else:
            out.append({"name": "undecodable", "type": "unknown", "selector": None,
                        "detail": "inner payload was not bytes"})
            continue

        parsed = _split_calldata(hexed)
        if not parsed:
            out.append({"name": "undecodable", "type": "unknown", "selector": None,
                        "detail": "inner payload is not valid calldata"})
            continue

        sel_, arg_bytes = parsed
        dec = _decode_selector(sel_, arg_bytes)
        if not dec or not dec.get("known"):
            out.append({
                "name": f"unknown({sel_})", "type": "unknown", "selector": sel_,
                "detail": "selector not in Cassandra's registry",
                "severity": "medium",
                "finding": {
                    "kind": "multicall_unknown_inner", "severity": "medium",
                    "message": (f"Inner call #{idx + 1} uses unrecognised selector {sel_} - "
                                "its effect cannot be verified before you sign."),
                },
            })
            continue

        m = dec["meta"]
        args = dec.get("args") or {}
        entry: dict = {"name": m["name"], "type": m["type"], "selector": sel_}

        if m["type"] in ("token_approve", "gasless_approve"):
            spender = _safe_addr(args.get("spender"))
            amount = int(args.get("amount") or args.get("value") or 0)
            unlimited = amount >= _UNLIMITED_THRESHOLD
            entry["detail"] = f"spender={spender}, amount={'UNLIMITED' if unlimited else amount}"
            entry["severity"] = "critical"
            entry["finding"] = {
                "kind": "multicall_hidden_approval", "severity": "critical",
                "message": (
                    f"Inner call #{idx + 1} is a hidden {m['name']}: it grants "
                    f"{'UNLIMITED' if unlimited else str(amount)} spending power to {spender}. "
                    "This is buried inside the multicall - your wallet will not show it."
                ),
            }
            entry["fate"] = (f"{spender} gains {'UNLIMITED' if unlimited else str(amount)} "
                             "spending rights over your tokens.")
        elif m["type"] == "nft_approve_all" and args.get("approved"):
            operator = _safe_addr(args.get("operator"))
            entry["detail"] = f"operator={operator}"
            entry["severity"] = "critical"
            entry["finding"] = {
                "kind": "multicall_hidden_approval", "severity": "critical",
                "message": (f"Inner call #{idx + 1} hides a setApprovalForAll granting "
                            f"{operator} every NFT in the collection."),
            }
            entry["fate"] = f"{operator} can take every NFT you own in that collection."
        elif m["type"] in ("token_transferFrom", "token_transfer", "nft_transfer",
                           "nft_transfer_batch"):
            recipient = _safe_addr(args.get("to") or args.get("recipient"))
            entry["detail"] = f"to={recipient}"
            entry["severity"] = "high"
            entry["finding"] = {
                "kind": "multicall_hidden_transfer", "severity": "high",
                "message": (f"Inner call #{idx + 1} moves assets to {recipient} as part of "
                            "this bundle."),
            }
            entry["fate"] = f"Assets move to {recipient}."
        else:
            entry["detail"] = m["name"]

        out.append(entry)
    return out


def _safe_addr(v: Any) -> str:
    try:
        return _to_addr(v)
    except Exception:
        return "0x?"


# ---- EIP-712 typed data ----

def analyze_typed_data(typed_data: dict) -> dict:
    """Analyze an EIP-712 typed data blob (what wallets show for signTypedData).

    We especially care about:
    - Permit / Permit2 (drainers' favorite)
    - Seaport orders (NFT scams that ask you to sign a bid = you SELL an NFT for 0.001 ETH)
    """
    findings: list[dict] = []
    fates: list[str] = []
    severity_max = "info"
    domain = typed_data.get("domain") or {}
    primary_type = typed_data.get("primaryType") or ""
    message = typed_data.get("message") or {}

    dname = str(domain.get("name") or "").lower()

    # ---- Permit (EIP-2612) ----
    if primary_type == "Permit":
        spender = _to_addr(message.get("spender", "0x"))
        value = int(message.get("value", 0))
        unlimited = value >= _UNLIMITED_THRESHOLD
        drainer = is_known_drainer(spender)
        severity_max = "critical" if (drainer or unlimited) else "high"
        findings.append({
            "kind": "eip712_permit",
            "severity": severity_max,
            "message": (
                f"EIP-2612 Permit for token `{domain.get('name')}` "
                f"(contract {domain.get('verifyingContract')}). Spender: {spender}. "
                f"Amount: {'UNLIMITED' if unlimited else value}."
            ),
        })
        fates.append(
            f"Signing this OFF-CHAIN grants {spender} the right to pull "
            f"{'ALL' if unlimited else value} of your `{domain.get('name')}` tokens immediately."
        )
        return _final_typed(
            summary=f"EIP-2612 Permit signature request on {domain.get('name')}",
            fates=fates, findings=findings, verdict=_color(severity_max),
        )

    # ---- Permit2 batch (Uniswap Permit2 - the drainer favorite in 2024+) ----
    if primary_type in ("PermitBatch", "PermitSingle") or "permit2" in dname:
        severity_max = "critical"
        details = message.get("details") or [message.get("details")] or []
        tokens = []
        if isinstance(details, dict):
            tokens = [details.get("token")]
        elif isinstance(details, list):
            tokens = [d.get("token") for d in details if isinstance(d, dict)]
        spender = _to_addr(message.get("spender", "0x"))
        findings.append({
            "kind": "permit2",
            "severity": "critical",
            "message": (
                f"Permit2 signature grants {spender} the right to move tokens: {tokens}. "
                "Permit2 is the #1 phishing vector on Ethereum in the last 18 months."
            ),
        })
        fates.append(
            f"{spender} can pull the listed tokens from your wallet the instant you sign. "
            "No on-chain transaction is needed."
        )
        return _final_typed(
            summary="Permit2 signature - this is how most modern wallet drains happen.",
            fates=fates, findings=findings, verdict="red",
        )

    # ---- Seaport / marketplace orders ----
    if primary_type in ("OrderComponents", "OrderMessage") or "seaport" in dname:
        offer = message.get("offer") or []
        consideration = message.get("consideration") or []
        offer_desc = ", ".join(f"{o.get('startAmount', '?')} of {o.get('token', '?')}" for o in offer)
        cons_desc = ", ".join(
            f"{c.get('startAmount', '?')} of {c.get('token', '?')} to {c.get('recipient', '?')}"
            for c in consideration
        )
        severity_max = "high"  # sign carefully - many scams here
        findings.append({
            "kind": "seaport_order",
            "severity": "high",
            "message": (
                "Signing a Seaport order. If YOU are the offerer, you are SELLING what's in `offer` "
                "for what's in `consideration`. Scammers commonly craft orders where the "
                "consideration is tiny and the offer is your valuable NFTs."
            ),
        })
        fates.append(f"You give up: {offer_desc}")
        fates.append(f"You receive: {cons_desc}")
        return _final_typed(
            summary=f"Seaport order signature on {domain.get('name')}",
            fates=fates, findings=findings, verdict=_color(severity_max),
        )

    # Unknown typed-data primary type
    return _final_typed(
        summary=f"EIP-712 signature request: {primary_type} on {dname or 'unknown domain'}",
        fates=[
            "Cassandra doesn't recognize this typed-data schema. "
            "Do not sign unless you can read every field.",
        ],
        findings=[{
            "kind": "unknown_typed_data",
            "severity": "medium",
            "message": f"Unknown EIP-712 primary type `{primary_type}`.",
        }],
        verdict="yellow",
    )


# ---- Helpers ----

def _to_addr(v: Any) -> str:
    if isinstance(v, (bytes, bytearray)):
        v = "0x" + v.hex()
    return to_checksum_address(v) if v else "0x0"


def _stringify_args(args: dict | None) -> dict:
    if not args:
        return {}
    out = {}
    for k, v in args.items():
        if isinstance(v, (bytes, bytearray)):
            out[k] = "0x" + v.hex()
        elif isinstance(v, int):
            out[k] = str(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [_stringify_scalar(x) for x in v]
        else:
            out[k] = str(v)
    return out


def _stringify_scalar(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + v.hex()
    if isinstance(v, int):
        return str(v)
    return v


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _worse(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


def _color(sev: str) -> str:
    if sev in ("critical", "high"):
        return "red"
    if sev == "medium":
        return "yellow"
    return "green"


def _err(msg: str) -> dict:
    return {"verdict": "error", "summary": msg, "fates": [], "findings": [], "target": None,
            "operation": None}


def _final(*, summary: str, fates: list[str], findings: list[dict], verdict: str,
           target: dict, operation: dict) -> dict:
    return {
        "verdict": verdict, "summary": summary, "fates": fates, "findings": findings,
        "target": target, "operation": operation,
    }


def _final_typed(*, summary: str, fates: list[str], findings: list[dict], verdict: str) -> dict:
    return {
        "verdict": verdict, "summary": summary, "fates": fates, "findings": findings,
        "target": None, "operation": {"kind": "eip712"},
    }
