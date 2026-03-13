from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import validate

from sanara.utils.io import read_json


class SchemaValidationError(RuntimeError):
    pass


def validate_payload(schema_path: Path, payload: Any) -> None:
    schema = read_json(schema_path)
    try:
        validate(instance=payload, schema=schema)
    except Exception as exc:  # pragma: no cover
        raise SchemaValidationError(
            f"schema validation failed for {schema_path.name}: {exc}"
        ) from exc
