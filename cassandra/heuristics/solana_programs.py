"""Solana transaction decoding + program/instruction registry.

Pure-Python, no heavy deps. Handles:
  - base58 encode/decode
  - shortvec (compact-u16) decode
  - legacy + v0 (versioned) transaction & message parsing
  - SPL Token / Token-2022 instruction classification (the drainer-relevant ones)

The signing danger surface on Solana is different from EVM, but the spirit is the
same: an off-hand signature can hand a stranger your tokens. The instructions that
matter most are Approve / ApproveChecked (delegate authority) and SetAuthority
(AccountOwner / MintTokens / FreezeAccount handover).
"""
from __future__ import annotations

import base64

# ---- base58 (Bitcoin/Solana alphabet) ----

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    # leading zero bytes -> leading '1's
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise ValueError(f"invalid base58 char: {c!r}")
        n = n * 58 + _B58_INDEX[c]
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def is_base58_pubkey(s: str) -> bool:
    if not s or len(s) < 32 or len(s) > 44:
        return False
    try:
        return len(b58decode(s)) == 32
    except Exception:
        return False


# ---- shortvec (compact-u16) ----

def decode_shortvec(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("shortvec overran buffer")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift > 21:
            raise ValueError("shortvec too long")
    return value, offset


# ---- known program IDs ----

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
METAPLEX_METADATA = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
RAYDIUM_AMM = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"

KNOWN_PROGRAMS: dict[str, str] = {
    SYSTEM_PROGRAM: "System Program",
    TOKEN_PROGRAM: "SPL Token",
    TOKEN_2022_PROGRAM: "SPL Token-2022",
    ASSOCIATED_TOKEN_PROGRAM: "Associated Token Account Program",
    COMPUTE_BUDGET: "Compute Budget",
    MEMO_PROGRAM: "Memo",
    METAPLEX_METADATA: "Metaplex Token Metadata",
    JUPITER_V6: "Jupiter Aggregator v6",
    RAYDIUM_AMM: "Raydium AMM v4",
}

# A conservative starter set of flagged drainer program addresses. Expandable at runtime.
KNOWN_SOL_DRAINERS: set[str] = set()

# SPL Token instruction index -> name (subset that matters for risk)
SPL_IX = {
    0: "InitializeMint",
    1: "InitializeAccount",
    3: "Transfer",
    4: "Approve",
    5: "Revoke",
    6: "SetAuthority",
    7: "MintTo",
    8: "Burn",
    9: "CloseAccount",
    10: "FreezeAccount",
    11: "ThawAccount",
    12: "TransferChecked",
    13: "ApproveChecked",
    14: "MintToChecked",
    15: "BurnChecked",
}

SET_AUTHORITY_TYPES = {
    0: "MintTokens",
    1: "FreezeAccount",
    2: "AccountOwner",
    3: "CloseAccount",
}

SYSTEM_IX = {
    0: "CreateAccount",
    1: "Assign",
    2: "Transfer",
    3: "CreateAccountWithSeed",
    8: "Allocate",
}


# ---- transaction / message parsing ----

def _parse_message(raw: bytes, off: int) -> dict:
    """Parse a message body starting at `off`. Returns dict + consumed flag."""
    version = "legacy"
    if off < len(raw) and (raw[off] & 0x80):
        version = raw[off] & 0x7F
        off += 1

    if off + 3 > len(raw):
        raise ValueError("truncated header")
    num_req_sigs = raw[off]
    num_ro_signed = raw[off + 1]
    num_ro_unsigned = raw[off + 2]
    off += 3

    acct_count, off = decode_shortvec(raw, off)
    if acct_count > 256:
        raise ValueError(f"absurd account count {acct_count}")
    accounts: list[str] = []
    for _ in range(acct_count):
        if off + 32 > len(raw):
            raise ValueError("truncated account key")
        accounts.append(b58encode(raw[off:off + 32]))
        off += 32

    if off + 32 > len(raw):
        raise ValueError("truncated blockhash")
    blockhash = b58encode(raw[off:off + 32])
    off += 32

    ix_count, off = decode_shortvec(raw, off)
    if ix_count > 256:
        raise ValueError(f"absurd instruction count {ix_count}")
    instructions = []
    for _ in range(ix_count):
        prog_idx = raw[off]
        off += 1
        n_accts, off = decode_shortvec(raw, off)
        acct_idx = list(raw[off:off + n_accts])
        off += n_accts
        data_len, off = decode_shortvec(raw, off)
        ix_data = raw[off:off + data_len]
        off += data_len
        program_id = accounts[prog_idx] if prog_idx < len(accounts) else None
        instructions.append({
            "program_id_index": prog_idx,
            "program_id": program_id,
            "account_indices": acct_idx,
            "accounts": [accounts[i] for i in acct_idx if i < len(accounts)],
            "data": ix_data,
        })

    # v0 address table lookups (we don't resolve them, just count)
    lookups = 0
    if version == 0 and off < len(raw):
        try:
            lut_count, off2 = decode_shortvec(raw, off)
            lookups = lut_count
        except Exception:
            pass

    return {
        "version": version,
        "num_required_signatures": num_req_sigs,
        "num_readonly_signed": num_ro_signed,
        "num_readonly_unsigned": num_ro_unsigned,
        "accounts": accounts,
        "recent_blockhash": blockhash,
        "instructions": instructions,
        "address_table_lookups": lookups,
    }


def parse_transaction(b64_or_bytes: str | bytes) -> dict:
    """Parse a base64 serialized transaction OR message. Robust to both."""
    if isinstance(b64_or_bytes, str):
        s = b64_or_bytes.strip()
        try:
            raw = base64.b64decode(s, validate=False)
        except Exception as e:
            raise ValueError(f"input is not valid base64: {e}")
    else:
        raw = b64_or_bytes

    # Attempt 1: full transaction (compact-array of signatures, then message)
    try:
        sig_count, off = decode_shortvec(raw, 0)
        if sig_count <= 20:  # sanity: no real tx has >20 sigs
            candidate_off = off + sig_count * 64
            if candidate_off < len(raw):
                msg = _parse_message(raw, candidate_off)
                return {"parsed_as": "transaction", "signature_count": sig_count, **msg}
    except Exception:
        pass

    # Attempt 2: bare message (starts at header or version byte)
    msg = _parse_message(raw, 0)
    return {"parsed_as": "message", "signature_count": 0, **msg}


# ---- instruction classification ----

def classify_instruction(ix: dict) -> dict:
    """Turn a raw parsed instruction into a risk-annotated description."""
    prog = ix.get("program_id")
    data: bytes = ix.get("data") or b""
    accts: list[str] = ix.get("accounts") or []
    label = KNOWN_PROGRAMS.get(prog, None)

    base = {
        "program_id": prog,
        "program_label": label,
        "known_program": label is not None,
    }

    if prog in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        if not data:
            return {**base, "type": "spl_unknown", "severity": "medium",
                    "summary": "SPL Token instruction with empty data."}
        ix_index = data[0]
        name = SPL_IX.get(ix_index, f"Unknown({ix_index})")

        if ix_index == 4:  # Approve
            amount = int.from_bytes(data[1:9], "little") if len(data) >= 9 else None
            delegate = accts[1] if len(accts) > 1 else None
            return {**base, "type": "spl_approve", "name": name, "severity": "critical",
                    "delegate": delegate, "amount": amount,
                    "summary": (f"Grants delegate {delegate} the right to move "
                                f"{'an amount of' if amount is None else amount} your tokens.")}
        if ix_index == 13:  # ApproveChecked
            amount = int.from_bytes(data[1:9], "little") if len(data) >= 9 else None
            delegate = accts[2] if len(accts) > 2 else None
            return {**base, "type": "spl_approve", "name": name, "severity": "critical",
                    "delegate": delegate, "amount": amount,
                    "summary": f"Grants delegate {delegate} authority over your token account."}
        if ix_index == 6:  # SetAuthority
            auth_type = SET_AUTHORITY_TYPES.get(data[1], f"type {data[1]}") if len(data) > 1 else "?"
            sev = "critical" if auth_type in ("AccountOwner", "MintTokens") else "high"
            return {**base, "type": "spl_set_authority", "name": name, "severity": sev,
                    "authority_type": auth_type,
                    "summary": (f"Changes the {auth_type} authority. "
                                + ("This can hand ownership of your token account to someone else."
                                   if auth_type == "AccountOwner" else
                                   "This changes a control authority on the token/mint."))}
        if ix_index in (3, 12):  # Transfer / TransferChecked
            amount = int.from_bytes(data[1:9], "little") if len(data) >= 9 else None
            dest = accts[1] if ix_index == 3 and len(accts) > 1 else (
                accts[2] if len(accts) > 2 else None)
            return {**base, "type": "spl_transfer", "name": name, "severity": "medium",
                    "amount": amount, "destination": dest,
                    "summary": f"Transfers tokens{'' if amount is None else f' ({amount} base units)'}."}
        if ix_index == 5:  # Revoke
            return {**base, "type": "spl_revoke", "name": name, "severity": "info",
                    "summary": "Revokes a delegate. This is a safe, protective action."}
        if ix_index == 9:  # CloseAccount
            return {**base, "type": "spl_close", "name": name, "severity": "medium",
                    "summary": "Closes a token account and reclaims its rent (destination gets the SOL)."}
        if ix_index == 10:  # FreezeAccount
            return {**base, "type": "spl_freeze", "name": name, "severity": "high",
                    "summary": "Freezes a token account."}
        return {**base, "type": "spl_other", "name": name, "severity": "low",
                "summary": f"SPL Token: {name}."}

    if prog == SYSTEM_PROGRAM:
        if len(data) >= 4:
            ix_index = int.from_bytes(data[0:4], "little")
            name = SYSTEM_IX.get(ix_index, f"Unknown({ix_index})")
            if ix_index == 2:  # Transfer (lamports)
                lamports = int.from_bytes(data[4:12], "little") if len(data) >= 12 else None
                dest = accts[1] if len(accts) > 1 else None
                sol = (lamports / 1e9) if lamports is not None else None
                return {**base, "type": "sol_transfer", "name": name, "severity": "medium",
                        "lamports": lamports, "sol": sol, "destination": dest,
                        "summary": f"Transfers {sol if sol is not None else '?'} SOL to {dest}."}
            return {**base, "type": "system_other", "name": name, "severity": "low",
                    "summary": f"System Program: {name}."}
        return {**base, "type": "system_other", "severity": "low",
                "summary": "System Program instruction."}

    if prog == COMPUTE_BUDGET:
        return {**base, "type": "compute_budget", "severity": "info",
                "summary": "Sets compute unit price/limit. Harmless."}

    if prog == MEMO_PROGRAM:
        try:
            memo = data.decode("utf-8", errors="replace")
        except Exception:
            memo = None
        return {**base, "type": "memo", "severity": "info",
                "summary": f"Attaches a memo: {memo!r}" if memo else "Attaches a memo."}

    # unknown program
    return {**base, "type": "unknown_program", "severity": "medium",
            "summary": ("Interacts with a program Cassandra does not recognize. "
                        "If your token accounts are writable in this instruction, "
                        "it could move your assets.")}
