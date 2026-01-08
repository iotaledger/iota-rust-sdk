#!/usr/bin/env python3
"""
Post-process the generated Kotlin bindings to split a chunk of methods
out of `UniffiLib` into `UniffiLibBatch2`, reducing interface size to
avoid JNA proxy MethodTooLargeException. Run this after `make kotlin`.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def find_block(lines: list[str], start_line: int) -> int:
    """Return the line index of the matching closing brace for a block starting at start_line."""
    depth = 0
    for i in range(start_line, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        if depth == 0:
            return i
    raise ValueError("Did not find matching brace for block starting at line %d" % start_line)


def parse_methods(lines: list[str], start: int, end: int) -> list[tuple[int, str]]:
    """Collect method declarations directly inside the interface block."""
    methods: list[tuple[int, str]] = []
    for i in range(start + 1, end):
        if re.match(r"^\s*fun\s", lines[i]):
            methods.append((i, lines[i]))
    return methods


def main() -> None:
    parser = argparse.ArgumentParser(description="Split large UniffiLib interface into batches.")
    parser.add_argument(
        "--file",
        default="bindings/kotlin/lib/iota_sdk/iota_sdk_ffi.kt",
        help="Path to generated Kotlin bindings file.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="How many methods to move from UniffiLib into UniffiLibBatch2 (from the end).",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    try:
        interface_start = next(
            i for i, line in enumerate(lines) if line.strip().startswith("internal interface UniffiLib : Library")
        )
    except StopIteration:
        raise SystemExit("Could not find `internal interface UniffiLib : Library {` in the file.")

    interface_end = find_block(lines, interface_start)
    methods = parse_methods(lines, interface_start, interface_end)

    if not methods:
        raise SystemExit("No methods found in UniffiLib interface; nothing to split.")

    move_count = min(args.batch_size, len(methods))
    moved = methods[-move_count:]
    moved_names = []
    for idx, _ in moved:
        signature = lines[idx]
        m = re.match(r"^\s*fun\s+([A-Za-z0-9_`]+)\s*\(", signature)
        if not m:
            raise SystemExit(f"Could not parse method name from line {idx+1}: {signature}")
        moved_names.append(m.group(1))
        lines[idx] = None  # Mark for removal

    # Remove marked lines from UniffiLib block
    lines = [ln for ln in lines if ln is not None]

    # Recompute text for replacements
    text = "\n".join(lines) + "\n"

    # Replace call sites to use the new batch interface
    for name in moved_names:
        pattern = re.compile(rf"\bUniffiLib\.INSTANCE\.{re.escape(name)}\b")
        text, n = pattern.subn(f"UniffiLibBatch2.INSTANCE.{name}", text)
        if n == 0:
            # Best-effort: warn but continue
            print(f"Warning: did not rewrite any call sites for {name}")

    # Build the new interface block
    moved_signatures = [sig for _, sig in moved]
    batch_block = [
        "",
        "internal interface UniffiLibBatch2 : Library {",
        "    companion object {",
        "        internal val INSTANCE: UniffiLibBatch2 by lazy {",
        '            val componentName = "iota_sdk_ffi"',
        "            loadIndirect<UniffiLibBatch2>(componentName)",
        "        }",
        "    }",
        "",
        *moved_signatures,
        "}",
        "",
    ]
    insertion_text = "\n".join(batch_block)

    # Insert after the original UniffiLib block
    # Re-find positions after modifications
    new_lines = text.splitlines()
    try:
        start_idx = next(
            i for i, line in enumerate(new_lines) if line.strip().startswith("internal interface UniffiLib : Library")
        )
    except StopIteration:
        raise SystemExit("Failed to re-find UniffiLib interface after edits.")
    end_idx = find_block(new_lines, start_idx)
    insertion_point = end_idx + 1
    new_lines[insertion_point:insertion_point] = insertion_text.splitlines()

    new_text = "\n".join(new_lines) + "\n"
    path.write_text(new_text, encoding="utf-8")

    print(
        f"Moved {len(moved_names)} methods into UniffiLibBatch2; "
        f"rewired call sites. Output written to {path}"
    )


if __name__ == "__main__":
    main()
