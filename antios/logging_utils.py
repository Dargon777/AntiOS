from __future__ import annotations

import logging
from pathlib import Path


LOGGER_NAME = "antios"


def configure_logging(level: str = "INFO", file_path: str = "") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if file_path:
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(target, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
        logger.addHandler(handler)
    else:
        logger.addHandler(logging.NullHandler())

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
