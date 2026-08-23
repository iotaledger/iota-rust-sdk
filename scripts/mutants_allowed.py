#!/usr/bin/env python3
"""Reconcile cargo-mutants survivors against the argued allowlist.

Reads mutants.out/missed.txt and mutants.out/timeout.txt, prints every
survivor as allowed or UNREGISTERED, and exits 0 only when every one is
allowed. Timeouts are reconciled the same way as misses because
cargo-mutants reports a timeout in preference to a miss (exit 3 beats
exit 2), so a run with even one unargued timeout stays red regardless
of its misses.

Allowlist entries that matched nothing are reported informationally: on a
diff-scoped run most entries are simply out of scope, but on a whole-tree
sweep that note is the removal reminder.
"""

import pathlib
import re
import sys

LINE_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):\d+: (?P<desc>.*)$")


def read_lines(path: pathlib.Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def main(out_dir: str, allowlist_path: str) -> int:
    entries = [
        line.strip()
        for line in read_lines(pathlib.Path(allowlist_path))
        if not line.lstrip().startswith("#")
    ]
    out = pathlib.Path(out_dir)
    survivors = [("missed", m) for m in read_lines(out / "missed.txt")]
    survivors += [("timeout", t) for t in read_lines(out / "timeout.txt")]

    used = set()
    unregistered = []
    for kind, survivor in survivors:
        match = LINE_RE.match(survivor)
        key = None
        if match:
            broad = f"{match['file']}: {match['desc']}"
            narrow = f"{match['file']}:{match['line']}: {match['desc']}"
            key = next((e for e in (survivor, narrow, broad) if e in entries), None)
        if key is None:
            unregistered.append((kind, survivor))
        else:
            used.add(key)
            print(f"allowed {kind}:  {survivor}")

    for entry in entries:
        if entry not in used:
            print(f"note: allowlist entry matched nothing this run: {entry}")

    if unregistered:
        for kind, survivor in unregistered:
            print(f"UNREGISTERED {kind}: {survivor}")
        print(
            f"mutants-allowed: {len(unregistered)} unregistered survivor(s); "
            "kill them or argue them into scripts/mutants-allowlist.txt"
        )
        return 1
    print(f"mutants-allowed: all {len(survivors)} survivor(s) are argued residuals")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: mutants_allowed.py <mutants.out dir> <allowlist>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
