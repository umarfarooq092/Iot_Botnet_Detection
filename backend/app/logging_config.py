"""Structured logging configuration for the backend.

Control: LOG-001 (Logging & Monitoring)

This module configures JSON structured logs written to `backend/logs/app.log` using
a rotating file handler. It is intended as a local, append-only (append mode) logger
for demo purposes. Production systems should ship logs to a centralized immutable store.
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from pythonjsonlogger import jsonlogger


def setup_logging(log_path: str | Path | None = None) -> logging.Logger:
    log_dir = Path(__file__).parents[1] / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = Path(log_path) if log_path else log_dir / "app.log"

    handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8", mode="a")
    formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)

    logger = logging.getLogger("ssd_app")
    logger.setLevel(logging.INFO)
    # Avoid adding duplicate handlers on repeated imports
    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        logger.addHandler(handler)

    # Console logging (human-friendly) for local developer convenience
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        logger.addHandler(console)

    # Example: logger.info("Logging initialized")
    return logger
