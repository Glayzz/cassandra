"""Function selectors for common operations we want to recognize.

A selector is the first 4 bytes of keccak(signature).
We list every high-risk / high-frequency function we care about.
"""
from __future__ import annotations

from eth_hash.auto import keccak


def sel(sig: str) -> str:
    return "0x" + keccak(sig.encode()).hex()[:8]


# --- ERC-20 ---
ERC20_TRANSFER = sel("transfer(address,uint256)")
ERC20_TRANSFER_FROM = sel("transferFrom(address,address,uint256)")
ERC20_APPROVE = sel("approve(address,uint256)")

# --- ERC-2612 permit (gasless approvals; the primary drainer vector today) ---
ERC20_PERMIT = sel("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")

# --- ERC-721 ---
ERC721_APPROVE = sel("approve(address,uint256)")  # same 4-byte as ERC-20 approve; disambiguate by context
ERC721_SET_APPROVAL_FOR_ALL = sel("setApprovalForAll(address,bool)")
ERC721_TRANSFER_FROM = sel("transferFrom(address,address,uint256)")
ERC721_SAFE_TRANSFER_FROM = sel("safeTransferFrom(address,address,uint256)")

# --- ERC-1155 ---
ERC1155_SAFE_TRANSFER = sel("safeTransferFrom(address,address,uint256,uint256,bytes)")
ERC1155_SAFE_BATCH = sel("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)")

# --- Seaport (OpenSea) ---
SEAPORT_FULFILL_ORDER = "0xb3a34c4c"
SEAPORT_FULFILL_ADVANCED = "0xe7acab24"
SEAPORT_MATCH_ORDERS = "0xa8174404"

# --- Uniswap ---
UNI_V2_SWAP_EXACT_TOKENS_FOR_TOKENS = sel(
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
)
UNI_V3_EXACT_INPUT = sel("exactInput((bytes,address,uint256,uint256,uint256))")
UNI_V3_MULTICALL = sel("multicall(uint256,bytes[])")

# --- Common drainer / wallet-drain patterns ---
# Multicall from a random contract with several transfer/permit inner calls
MULTICALL_1 = sel("multicall(bytes[])")
MULTICALL_2 = sel("multicall(uint256,bytes[])")
AGGREGATE = sel("aggregate((address,bytes)[])")

# ERC-20 increaseAllowance - can also unlimited-approve silently
ERC20_INCREASE_ALLOWANCE = sel("increaseAllowance(address,uint256)")

# Delegate-style takeover
EXEC_TRANSACTION = sel(
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
)

# Common bridge / withdrawal
WITHDRAW = sel("withdraw(uint256)")

# --- Look-up table ---
SELECTORS: dict[str, dict] = {
    ERC20_APPROVE: {
        "name": "approve",
        "type": "token_approve",
        "abi": ["address", "uint256"],
        "arg_names": ["spender", "amount"],
        "severity": "high",
    },
    ERC20_INCREASE_ALLOWANCE: {
        "name": "increaseAllowance",
        "type": "token_approve",
        "abi": ["address", "uint256"],
        "arg_names": ["spender", "added"],
        "severity": "high",
    },
    ERC20_PERMIT: {
        "name": "permit",
        "type": "gasless_approve",
        "abi": ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
        "arg_names": ["owner", "spender", "value", "deadline", "v", "r", "s"],
        "severity": "critical",
    },
    ERC721_SET_APPROVAL_FOR_ALL: {
        "name": "setApprovalForAll",
        "type": "nft_approve_all",
        "abi": ["address", "bool"],
        "arg_names": ["operator", "approved"],
        "severity": "critical",
    },
    ERC20_TRANSFER: {
        "name": "transfer",
        "type": "token_transfer",
        "abi": ["address", "uint256"],
        "arg_names": ["recipient", "amount"],
        "severity": "medium",
    },
    ERC721_TRANSFER_FROM: {
        "name": "transferFrom",
        "type": "token_transferFrom",
        "abi": ["address", "address", "uint256"],
        "arg_names": ["from", "to", "tokenId_or_amount"],
        "severity": "medium",
    },
    ERC1155_SAFE_TRANSFER: {
        "name": "safeTransferFrom (ERC-1155)",
        "type": "nft_transfer",
        "abi": ["address", "address", "uint256", "uint256", "bytes"],
        "arg_names": ["from", "to", "id", "value", "data"],
        "severity": "medium",
    },
    ERC1155_SAFE_BATCH: {
        "name": "safeBatchTransferFrom (ERC-1155)",
        "type": "nft_transfer_batch",
        "abi": ["address", "address", "uint256[]", "uint256[]", "bytes"],
        "arg_names": ["from", "to", "ids", "values", "data"],
        "severity": "medium",
    },
    MULTICALL_1: {
        "name": "multicall(bytes[])",
        "type": "multicall",
        "abi": ["bytes[]"],
        "arg_names": ["calls"],
        "severity": "high",  # bag of wrapped calls, needs recursion
    },
    MULTICALL_2: {
        "name": "multicall(uint256,bytes[])",
        "type": "multicall",
        "abi": ["uint256", "bytes[]"],
        "arg_names": ["deadline", "calls"],
        "severity": "high",
    },
    EXEC_TRANSACTION: {
        "name": "execTransaction (Safe)",
        "type": "safe_exec",
        "abi": ["address", "uint256", "bytes", "uint8", "uint256",
                "uint256", "uint256", "address", "address", "bytes"],
        "arg_names": ["to", "value", "data", "operation", "safeTxGas",
                      "baseGas", "gasPrice", "gasToken", "refundReceiver", "signatures"],
        "severity": "high",
    },
    SEAPORT_FULFILL_ORDER: {
        "name": "fulfillOrder (Seaport)",
        "type": "marketplace_trade",
        "abi": None,  # complex tuple, skip decoding for MVP
        "arg_names": [],
        "severity": "medium",
    },
    SEAPORT_FULFILL_ADVANCED: {
        "name": "fulfillAdvancedOrder (Seaport)",
        "type": "marketplace_trade",
        "abi": None,
        "arg_names": [],
        "severity": "medium",
    },
    UNI_V2_SWAP_EXACT_TOKENS_FOR_TOKENS: {
        "name": "swapExactTokensForTokens (Uni V2)",
        "type": "swap",
        "abi": ["uint256", "uint256", "address[]", "address", "uint256"],
        "arg_names": ["amountIn", "amountOutMin", "path", "to", "deadline"],
        "severity": "low",
    },
    WITHDRAW: {
        "name": "withdraw",
        "type": "withdraw",
        "abi": ["uint256"],
        "arg_names": ["amount"],
        "severity": "low",
    },
}


UINT256_MAX = (1 << 256) - 1
