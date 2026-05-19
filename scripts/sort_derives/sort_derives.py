#!/usr/bin/env python3
"""Sort `#[derive(...)]` trait lists alphabetically across the workspace.

Handles:
  - `#[derive(A, B, C)]`
  - Multi-line `#[derive(\n    A,\n    B,\n)]`
  - `#[cfg_attr(..., derive(A, B), ...)]` (including multi-line forms)

By default rewrites files in place. With `--check` only reports files that
would change and exits non-zero if any are found (used by CI).

Generated proto files under `crates/iota-sdk-grpc-types/src/proto/` are
skipped — they must never be hand-edited.
"""

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES_DIR = REPO_ROOT / "crates"
SKIP_DIRS = (
    REPO_ROOT / "crates" / "iota-sdk-grpc-types" / "src" / "proto",
)

# Match `derive(` preceded by a word boundary; this catches both `#[derive(`
# and `derive(` inside `#[cfg_attr(..., derive(...), ...)]`.
DERIVE_RE = re.compile(r"\bderive\s*\(")


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("no matching paren")


def format_derive(body: str) -> str:
    """Reorder traits inside a `derive(...)` body alphabetically while preserving
    the original whitespace layout (single-line vs multi-line, indentation, and
    trailing comma).

    Each top-level comma-separated segment is split into a leading-whitespace
    prefix and the trait expression. We sort the trait expressions and re-emit
    them paired with the original prefixes at each position. This is idempotent
    against rustfmt's re-flow (which may collapse short multi-line derives onto
    a single content line surrounded by newlines).
    """
    depth = 0
    comma_positions: list[int] = []
    for i, c in enumerate(body):
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            depth -= 1
        elif c == "," and depth == 0:
            comma_positions.append(i)

    segments: list[str] = []
    prev = 0
    for pos in comma_positions:
        segments.append(body[prev:pos])
        prev = pos + 1
    trailing = body[prev:]

    has_trailing_comma = bool(comma_positions) and not trailing.strip()
    if not has_trailing_comma:
        if not segments and not trailing.strip():
            return body  # empty derive()
        segments.append(trailing)
        trailing = ""

    leadings: list[str] = []
    traits: list[str] = []
    for seg in segments:
        i = 0
        while i < len(seg) and seg[i] in " \t\n":
            i += 1
        leadings.append(seg[:i])
        traits.append(seg[i:].rstrip())

    if len([t for t in traits if t]) <= 1:
        return body

    sorted_traits = sorted(traits, key=lambda t: t.lower())
    new_segments = [leadings[i] + sorted_traits[i] for i in range(len(traits))]
    result = ",".join(new_segments)
    if has_trailing_comma:
        result += ","
    return result + trailing


def rewrite(text: str) -> str:
    out: list[str] = []
    last = 0
    i = 0
    while True:
        m = DERIVE_RE.search(text, i)
        if not m:
            out.append(text[last:])
            break
        open_idx = m.end() - 1
        close_idx = find_matching_paren(text, open_idx)
        body = text[open_idx + 1 : close_idx]
        new_body = format_derive(body)
        out.append(text[last : open_idx + 1])
        out.append(new_body)
        last = close_idx
        i = close_idx + 1
    return "".join(out)


def is_skipped(path: Path) -> bool:
    return any(str(path).startswith(str(skip)) for skip in SKIP_DIRS)


def iter_rust_files() -> list[Path]:
    return [p for p in CRATES_DIR.rglob("*.rs") if not is_skipped(p)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report files that would change and exit non-zero; do not write.",
    )
    args = parser.parse_args()

    files = iter_rust_files()
    changed: list[Path] = []
    for f in files:
        original = f.read_text()
        new = rewrite(original)
        if new != original:
            changed.append(f)
            if not args.check:
                f.write_text(new)

    if args.check:
        if changed:
            print(
                "The following files have unsorted #[derive(...)] lists:",
                file=sys.stderr,
            )
            for f in changed:
                print(f"  {f.relative_to(REPO_ROOT)}", file=sys.stderr)
            print(
                "\nRun `make sort-derives` to fix.",
                file=sys.stderr,
            )
            return 1
        print(f"All {len(files)} files have sorted #[derive(...)] lists.")
        return 0

    for f in changed:
        print(f"sorted: {f.relative_to(REPO_ROOT)}")
    print(f"\nRewrote {len(changed)}/{len(files)} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
