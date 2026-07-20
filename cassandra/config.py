"""Runtime config, sourced from env."""
from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    etherscan_api_key: str = ""
    alchemy_api_key: str = ""
    anthropic_api_key: str = ""

    # Solana. Public RPC works but is heavily rate-limited; set a Helius / QuickNode
    # / Alchemy Solana URL for the demo. Helius also unlocks the DAS API for token
    # metadata (name/symbol/authorities), used by foresee_token on Solana.
    solana_rpc_url: str = "https://api.mainnet-beta.solana.com"
    helius_api_key: str = ""

    # GoPlus Security (optional). Free tier works without a key; set one to raise
    # rate limits. https://gopluslabs.io
    goplus_api_key: str = ""

    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    default_chain_id: int = 1

    # Etherscan v2 unified endpoint (multichain).
    etherscan_base: str = "https://api.etherscan.io/v2/api"

    def solana_url(self) -> str:
        if self.helius_api_key:
            return f"https://mainnet.helius-rpc.com/?api-key={self.helius_api_key}"
        return self.solana_rpc_url

    def helius_das_url(self) -> str | None:
        if self.helius_api_key:
            return f"https://mainnet.helius-rpc.com/?api-key={self.helius_api_key}"
        return None

    # Alchemy per-chain URL builder
    def alchemy_url(self, chain_id: int) -> str | None:
        if not self.alchemy_api_key:
            return None
        net = {
            1: "eth-mainnet",
            8453: "base-mainnet",
            10: "opt-mainnet",
            42161: "arb-mainnet",
            137: "polygon-mainnet",
        }.get(chain_id)
        if net is None:
            return None
        return f"https://{net}.g.alchemy.com/v2/{self.alchemy_api_key}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
