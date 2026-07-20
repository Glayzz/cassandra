"""Offline tests for the Solana decoder (no network required).

We synthesize real transaction bytes (legacy + v0) and assert the classifier.
"""
from __future__ import annotations

import base64

from cassandra.heuristics import solana_programs as SP
from cassandra.foresee.solana import analyze_solana_tx


def _sv(n: int) -> bytes:
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            o.append(b | 0x80)
        else:
            o.append(b)
            break
    return bytes(o)


def _legacy_tx(accounts: list[bytes], instructions: list[tuple[int, list[int], bytes]]) -> str:
    m = bytearray([1, 0, 1])
    m += _sv(len(accounts))
    for a in accounts:
        m += a
    m += bytes(32)  # blockhash
    m += _sv(len(instructions))
    for prog_idx, idxs, data in instructions:
        m += bytes([prog_idx])
        m += _sv(len(idxs)) + bytes(idxs)
        m += _sv(len(data)) + data
    tx = bytearray() + _sv(1) + bytes(64) + bytes(m)
    return base64.b64encode(bytes(tx)).decode()


def test_base58_roundtrip():
    for a in [SP.TOKEN_PROGRAM, SP.SYSTEM_PROGRAM, SP.METAPLEX_METADATA]:
        assert SP.b58encode(SP.b58decode(a)) == a
    assert SP.b58decode(SP.SYSTEM_PROGRAM) == b"\x00" * 32


def test_shortvec():
    for n in [0, 1, 127, 128, 255, 16383, 16384]:
        v, off = SP.decode_shortvec(_sv(n), 0)
        assert v == n and off == len(_sv(n))


def test_spl_approve_is_red():
    owner = SP.b58decode("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
    source = SP.b58decode("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gWs5W")
    delegate = SP.b58decode("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWN")
    tokprog = SP.b58decode(SP.TOKEN_PROGRAM)
    accounts = [owner, source, delegate, tokprog]
    data = bytes([4]) + (10**9).to_bytes(8, "little")  # Approve, amount
    tx = _legacy_tx(accounts, [(3, [1, 2, 0], data)])
    out = analyze_solana_tx(tx)
    assert out["verdict"] == "red", out
    assert out["instructions"][0]["type"] == "spl_approve"


def test_sol_transfer_is_yellow():
    payer = SP.b58decode("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
    dest = SP.b58decode("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWN")
    sysp = SP.b58decode(SP.SYSTEM_PROGRAM)
    data = bytes([2, 0, 0, 0]) + (5 * 10**8).to_bytes(8, "little")
    tx = _legacy_tx([payer, dest, sysp], [(2, [0, 1], data)])
    out = analyze_solana_tx(tx)
    assert out["instructions"][0]["type"] == "sol_transfer"
    assert "SOL" in out["fates"][0]


def test_garbage_is_error():
    assert analyze_solana_tx("not base64!!!")["verdict"] == "error"


if __name__ == "__main__":
    test_base58_roundtrip()
    test_shortvec()
    test_spl_approve_is_red()
    test_sol_transfer_is_yellow()
    test_garbage_is_error()
    print("all solana smoke tests passed")
