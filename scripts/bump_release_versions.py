#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ReleaseVersions:
    git_tag: str
    package_version: str
    rule_pack_version: str | None


def _pep440_from_git_tag(tag: str) -> str:
    """
    Convert a git tag like:
      v0.1.0           -> 0.1.0
      v0.1.0-alpha.1   -> 0.1.0a1
      v0.1.0-beta.2    -> 0.1.0b2
      v0.1.0-rc.3      -> 0.1.0rc3
    """
    m = re.fullmatch(r"v(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?", tag.strip())
    if not m:
        raise ValueError(f"Unsupported tag format: {tag!r}")
    base, pre, n = m.groups()
    if not pre:
        return base
    suffix = {"alpha": "a", "beta": "b", "rc": "rc"}[pre]
    return f"{base}{suffix}{n}"


def _replace_one(path: Path, pattern: str, repl: str) -> bool:
    text = path.read_text(encoding="utf-8")
    new_text, count = re.subn(pattern, repl, text, flags=re.MULTILINE)
    if count:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def _replace_literal(path: Path, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return False
    path.write_text(text.replace(old, new), encoding="utf-8")
    return True


def _current_versions() -> ReleaseVersions:
    init_py = (ROOT / "sanara/__init__.py").read_text(encoding="utf-8")
    m_pkg = re.search(r'^__version__ = "([^"]+)"$', init_py, flags=re.MULTILINE)
    m_rule = re.search(r'^RULE_PACK_VERSION = "([^"]+)"$', init_py, flags=re.MULTILINE)
    if not m_pkg or not m_rule:
        raise RuntimeError("Could not parse sanara/__init__.py versions")
    pkg = m_pkg.group(1)
    rule = m_rule.group(1)

    # Best-effort inverse for docs replacement. Supports only the tag styles we emit.
    if m := re.fullmatch(r"(\d+\.\d+\.\d+)(a|b|rc)(\d+)", pkg):
        base, pre, n = m.groups()
        label = {"a": "alpha", "b": "beta", "rc": "rc"}[pre]
        tag = f"v{base}-{label}.{n}"
    else:
        tag = f"v{pkg}"
    return ReleaseVersions(git_tag=tag, package_version=pkg, rule_pack_version=rule)


def _update_versions(target: ReleaseVersions, dry_run: bool = False) -> list[str]:
    changed: list[str] = []

    edits: list[tuple[Path, str, str, str]] = [
        (
            ROOT / "pyproject.toml",
            r'^version = ".*"$',
            f'version = "{target.package_version}"',
            "regex",
        ),
        (
            ROOT / "sanara/__init__.py",
            r'^__version__ = ".*"$',
            f'__version__ = "{target.package_version}"',
            "regex",
        ),
        (ROOT / "VERSION_LOCK", r"^sanara=.*$", f"sanara={target.package_version}", "regex"),
    ]

    if target.rule_pack_version is not None:
        edits.extend(
            [
                (
                    ROOT / "sanara/__init__.py",
                    r'^RULE_PACK_VERSION = ".*"$',
                    f'RULE_PACK_VERSION = "{target.rule_pack_version}"',
                    "regex",
                ),
                (
                    ROOT / "templates/policy.yml",
                    r"^rule_pack_version: .*$",
                    f"rule_pack_version: {target.rule_pack_version}",
                    "regex",
                ),
                (
                    ROOT / "rules/mappings/checkov_to_sanara.v0.1.json",
                    r'"rule_pack_version": ".*?"',
                    f'"rule_pack_version": "{target.rule_pack_version}"',
                    "regex",
                ),
                (
                    ROOT / "rules/repair_profiles/checkov_repair_profiles.v0.1.json",
                    r'"rule_pack_version": ".*?"',
                    f'"rule_pack_version": "{target.rule_pack_version}"',
                    "regex",
                ),
                (
                    ROOT / "sanara/policy/models.py",
                    r'rule_pack_version: str = ".*?"',
                    f'rule_pack_version: str = "{target.rule_pack_version}"',
                    "regex",
                ),
                (
                    ROOT / "sanara/policy/loader.py",
                    r'rule_pack_version=data.get\("rule_pack_version", ".*?"\)',
                    f'rule_pack_version=data.get("rule_pack_version", "{target.rule_pack_version}")',
                    "regex",
                ),
                (
                    ROOT / "tests/test_mapping_table.py",
                    r'assert data\["rule_pack_version"\] == ".*?"',
                    f'assert data["rule_pack_version"] == "{target.rule_pack_version}"',
                    "regex",
                ),
                (
                    ROOT / "tests/test_finding_policy.py",
                    r"^rule_pack_version: .*$",
                    f"rule_pack_version: {target.rule_pack_version}",
                    "regex",
                ),
            ]
        )

    for path, pat, repl, kind in edits:
        if dry_run:
            text = path.read_text(encoding="utf-8")
            if re.search(pat, text, flags=re.MULTILINE):
                changed.append(str(path.relative_to(ROOT)))
            continue
        did = _replace_one(path, pat, repl)
        if did:
            changed.append(str(path.relative_to(ROOT)))

    return sorted(set(changed))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bump Sanara package/release versions across common files (rule pack optional)."
    )
    ap.add_argument("--tag", required=True, help="Git tag version, e.g. v0.1.0-alpha.1 or v0.1.0")
    ap.add_argument(
        "--package-version",
        help="Optional explicit PEP440 package version (defaults derived from --tag)",
    )
    ap.add_argument(
        "--rule-pack-version",
        help="Optional explicit rule_pack_version (not changed unless provided)",
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="Print files that would change without writing"
    )
    args = ap.parse_args()

    package_version = args.package_version or _pep440_from_git_tag(args.tag)
    rule_pack_version = args.rule_pack_version
    target = ReleaseVersions(
        git_tag=args.tag, package_version=package_version, rule_pack_version=rule_pack_version
    )

    changed = _update_versions(target, dry_run=args.dry_run)
    mode = "Would update" if args.dry_run else "Updated"
    print(f"{mode} {len(changed)} files")
    for p in changed:
        print(f"- {p}")
    print(f"package_version={target.package_version}")
    print(f"git_tag={target.git_tag}")
    if target.rule_pack_version is not None:
        print(f"rule_pack_version={target.rule_pack_version}")
    else:
        print("rule_pack_version=<unchanged>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
