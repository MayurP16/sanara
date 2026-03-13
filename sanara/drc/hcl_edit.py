from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sanara.drc.models import DrcError

try:  # pragma: no cover - optional import in constrained envs
    import hcl2
except Exception:  # pragma: no cover
    hcl2 = None

RESOURCE_RE = re.compile(r'resource\s+"(?P<rtype>[^"]+)"\s+"(?P<rname>[^"]+)"\s*\{')
ASSIGNMENT_RE = re.compile(r"^(?P<indent>\s*)(?P<name>[a-zA-Z0-9_]+)\s*=\s*(?P<value>.+)$")
LITERAL_EXPR_RE = re.compile(r'^(true|false|"[^"]*"|[0-9]+)$')


@dataclass
class ResourceBlock:
    file_path: Path
    resource_type: str
    resource_name: str
    start: int
    end: int
    body_start: int
    body_end: int
    text: str


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    in_string = False
    while i < len(text):
        ch = text[i]
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_string = not in_string
        if not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise DrcError("NO_TARGET_RESOURCE", "Unclosed resource block")


def _parse_resources(path: Path) -> list[ResourceBlock]:
    text = path.read_text(encoding="utf-8")
    blocks: list[ResourceBlock] = []
    for m in RESOURCE_RE.finditer(text):
        body_open = m.end() - 1
        body_close = _find_matching_brace(text, body_open)
        start = m.start()
        end = body_close + 1
        blocks.append(
            ResourceBlock(
                file_path=path,
                resource_type=m.group("rtype"),
                resource_name=m.group("rname"),
                start=start,
                end=end,
                body_start=body_open + 1,
                body_end=body_close,
                text=text[start:end],
            )
        )
    return blocks


def _parse_resource_keys_with_hcl2(path: Path) -> list[tuple[str, str]]:
    if hcl2 is None:
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            parsed = hcl2.load(f)
    except Exception:
        return []
    resources = parsed.get("resource", [])
    out: list[tuple[str, str]] = []
    for item in resources:
        if not isinstance(item, dict):
            continue
        for rtype, by_name in item.items():
            if not isinstance(by_name, dict):
                continue
            for rname in by_name.keys():
                out.append((str(rtype), str(rname)))
    return out


def _find_resource_ranges(
    path: Path, resource_type: str, resource_name: str
) -> list[tuple[int, int, str]]:
    text = path.read_text(encoding="utf-8")
    out: list[tuple[int, int, str]] = []
    header = re.compile(
        rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"\s*\{{'
    )
    for m in header.finditer(text):
        body_open = m.end() - 1
        body_close = _find_matching_brace(text, body_open)
        out.append((m.start(), body_close + 1, text[m.start() : body_close + 1]))
    return out


def find_resource_block(paths: list[Path], resource_type: str, resource_name: str) -> ResourceBlock:
    parser_candidates: list[Path] = []
    for path in paths:
        keys = _parse_resource_keys_with_hcl2(path)
        if keys:
            if (resource_type, resource_name) in keys:
                parser_candidates.append(path)
            continue
        # Fallback when parser unavailable/unable to parse.
        for block in _parse_resources(path):
            if block.resource_type == resource_type and block.resource_name == resource_name:
                parser_candidates.append(path)
                break

    if not parser_candidates:
        raise DrcError("NO_TARGET_RESOURCE", f"No resource {resource_type}.{resource_name}")

    hits: list[ResourceBlock] = []
    for path in parser_candidates:
        for start, end, text in _find_resource_ranges(path, resource_type, resource_name):
            hits.append(
                ResourceBlock(
                    file_path=path,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    start=start,
                    end=end,
                    body_start=0,
                    body_end=0,
                    text=text,
                )
            )

    if len(hits) == 0:
        raise DrcError("NO_TARGET_RESOURCE", f"No resource {resource_type}.{resource_name}")
    if len(hits) > 1:
        raise DrcError("AMBIGUOUS_TARGET", f"Ambiguous resource {resource_type}.{resource_name}")
    return hits[0]


def find_resource_blocks(paths: list[Path], resource_type: str) -> list[ResourceBlock]:
    hits: list[ResourceBlock] = []
    for path in paths:
        for block in _parse_resources(path):
            if block.resource_type != resource_type:
                continue
            for start, end, text in _find_resource_ranges(
                path, block.resource_type, block.resource_name
            ):
                hits.append(
                    ResourceBlock(
                        file_path=path,
                        resource_type=block.resource_type,
                        resource_name=block.resource_name,
                        start=start,
                        end=end,
                        body_start=0,
                        body_end=0,
                        text=text,
                    )
                )
    return hits


def replace_block(block: ResourceBlock, new_text: str) -> None:
    full = block.file_path.read_text(encoding="utf-8")
    patched = full[: block.start] + new_text + full[block.end :]
    block.file_path.write_text(patched, encoding="utf-8")


def _split_block(block_text: str) -> tuple[str, list[str], str]:
    lines = block_text.splitlines()
    if len(lines) < 2:
        return block_text, [], ""
    header = lines[0]
    footer = lines[-1]
    body = lines[1:-1]
    return header, body, footer


def _is_literal(value: str) -> bool:
    if "${" in value:
        return False
    if value.startswith("var.") or value.startswith("local.") or value.startswith("data."):
        return False
    return bool(LITERAL_EXPR_RE.match(value.strip()))


def ensure_attribute_literal(block_text: str, attr: str, value: str) -> tuple[str, bool]:
    header, body_lines, footer = _split_block(block_text)
    depth = 0
    indent = "  "
    changed = False
    found = False

    for idx, line in enumerate(body_lines):
        stripped = line.strip()
        depth += stripped.count("{") - stripped.count("}") if stripped else 0
        if depth != 0:
            continue
        m = ASSIGNMENT_RE.match(line)
        if not m or m.group("name") != attr:
            continue

        found = True
        indent = m.group("indent") or indent
        rhs = m.group("value").strip()
        if not _is_literal(rhs):
            raise DrcError("NON_LITERAL_ATTR", f"{attr} is non-literal")
        if rhs != value and rhs != value.strip('"'):
            body_lines[idx] = f"{indent}{attr} = {value}"
            changed = True
        break

    if not found:
        body_lines.append(f"{indent}{attr} = {value}")
        changed = True

    out = "\n".join([header, *body_lines, footer])
    return out, changed


def ensure_nested_block(block_text: str, nested: str) -> tuple[str, bool]:
    nested_name = nested.split("{", 1)[0].strip()
    header, body_lines, footer = _split_block(block_text)

    depth = 0
    for line in body_lines:
        stripped = line.strip()
        if depth == 0 and stripped.startswith(nested_name + " "):
            if "enabled = false" in line and nested_name == "point_in_time_recovery":
                raise DrcError(
                    "NON_LITERAL_ATTR", "point_in_time_recovery.enabled is false or expression"
                )
            return block_text, False
        depth += stripped.count("{") - stripped.count("}") if stripped else 0

    nested_lines = ["  " + x for x in nested.strip().splitlines()]
    out = "\n".join([header, *body_lines, *nested_lines, footer])
    return out, True


def append_resource(file_path: Path, resource_text: str) -> None:
    existing = file_path.read_text(encoding="utf-8") if file_path.exists() else ""
    prefix = existing.rstrip()
    out = f"{prefix}\n\n{resource_text.strip()}\n" if prefix else f"{resource_text.strip()}\n"
    file_path.write_text(out, encoding="utf-8")
