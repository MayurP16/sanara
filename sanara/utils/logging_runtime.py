from __future__ import annotations

import logging
import os
import sys


def _normalize_level(value: str | None) -> int:
    raw = (value or "").strip().upper()
    if not raw:
        return logging.INFO
    return getattr(logging, raw, logging.INFO)


def configure_logging() -> None:
    level = _normalize_level(
        os.environ.get("SANARA_LOG_LEVEL") or os.environ.get("INPUT_LOG_LEVEL")
    )
    stream = getattr(sys, "__stderr__", None) or sys.stderr
    logging.basicConfig(
        level=level,
        stream=stream,
        force=True,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
