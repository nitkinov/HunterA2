"""Централизованное логирование HunterA 2."""
import logging
from pathlib import Path

LOG_DIR = Path.home() / ".cache" / "huntera2"
LOG_FILE = LOG_DIR / "app.log"

_logger = None


def get_logger() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("huntera2")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        logger.addHandler(fh)

    _logger = logger
    return logger
