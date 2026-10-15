import tomllib
from pathlib import Path
from pydantic import BaseModel

DEFAULT_DNS_SERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
CONFIG_DIR = Path.home() / ".config" / "huntera2"
CONFIG_FILE = CONFIG_DIR / "config.toml"


class Config(BaseModel):
    timeout: int = 10
    user_agent: str = "HunterA2/0.1"
    log_level: str = "INFO"


def load_config() -> Config:
    if not CONFIG_FILE.exists():
        return Config()
    with CONFIG_FILE.open("rb") as f:
        data = tomllib.load(f)
    return Config(**data)
