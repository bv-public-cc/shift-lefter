"""Reject private-lab identifiers and common credential material before release."""

from __future__ import annotations

import re
import sys
from pathlib import Path

FORBIDDEN = (
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile("chiefs" + r"cloud\.local", re.IGNORECASE),
    re.compile("hp" + "desktop", re.IGNORECASE),
    re.compile("/opt/" + "agent-" + "platform", re.IGNORECASE),
    re.compile(r"\bagent[ _-]" + "platform" + r"\b", re.IGNORECASE),
    re.compile(r"glpat-[A-Za-z0-9_-]{10,}"),
)
SAFE_SYNTHETIC_LITERALS = ("glpat-EXAMPLE_REPLACE_TOKEN",)


def main(root: Path) -> int:
    hits: list[str] = []
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or ".git" in path.parts
            or "__pycache__" in path.parts
            or path.suffix in {".pyc", ".pyo"}
        ):
            continue
        data = path.read_text(encoding="utf-8", errors="ignore")
        for literal in SAFE_SYNTHETIC_LITERALS:
            data = data.replace(literal, "[synthetic-placeholder]")
        if any(pattern.search(data) for pattern in FORBIDDEN):
            hits.append(path.as_posix())
    if hits:
        print("public-safety check failed:", *sorted(hits), sep="\n  ")
        return 2
    print("public-safety check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()))
