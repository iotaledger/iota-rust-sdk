#!/usr/bin/env python3
"""Reconcile cargo-mutants survivors against the argued allowlist.

Reads mutants.out/missed.txt and mutants.out/timeout.txt, prints every
survivor as allowed or UNREGISTERED, and exits 0 only when every miss is
allowed and no timeouts occurred. Timeouts are never allowlistable: a hang
is new information regardless of any argument recorded for a miss of the
same mutant, so a run with even one timeout stays red.

This script only runs after cargo-mutants reported survivors (exit 2 or 3),
so an unreadable output file or an empty survivor set means the run is
being misread (a relocated output directory, a truncated artifact) and is a
hard error, never a green exit.

Allowlist entries that matched nothing are reported informationally: on a
diff-scoped run most entries are simply out of scope, but on a whole-tree
sweep that note is the removal reminder. An entry matching more than one
survivor is an error: identical mutants at different sites need one
line-anchored entry each.
"""

import collections
import pathlib
import re
import sys

LINE_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+):\d+: (?P<desc>.*)$")


def read_lines(path: pathlib.Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        sys.exit(f"mutants-allowed: cannot read {path}: {err}")
    return [line.strip() for line in text.splitlines() if line.strip()]


def main(out_dir: str, allowlist_path: str) -> int:
    entries = [
        line.strip()
        for line in read_lines(pathlib.Path(allowlist_path))
        if not line.lstrip().startswith("#")
    ]
    out = pathlib.Path(out_dir)
    missed = read_lines(out / "missed.txt")
    timeouts = read_lines(out / "timeout.txt")
    if not missed and not timeouts:
        sys.exit(
            "mutants-allowed: cargo-mutants reported survivors but none are "
            f"readable under {out}; refusing to reconcile"
        )

    used = collections.Counter()
    unregistered = [("timeout", t) for t in timeouts]
    for survivor in missed:
        keys = [survivor]
        match = LINE_RE.match(survivor)
        if match:
            keys.append(f"{match['file']}:{match['line']}: {match['desc']}")
            keys.append(f"{match['file']}: {match['desc']}")
        key = next((k for k in keys if k in entries), None)
        if key is None:
            unregistered.append(("missed", survivor))
        else:
            used[key] += 1
            print(f"allowed missed:  {survivor}")

    for entry in entries:
        if entry not in used:
            print(f"note: allowlist entry matched nothing this run: {entry}")

    problems = 0
    for kind, survivor in unregistered:
        print(f"UNREGISTERED {kind}: {survivor}")
        problems += 1
    for entry, count in used.items():
        if count > 1:
            print(f"OVERMATCHED ({count} survivors; anchor one entry per line): {entry}")
            problems += 1
    if problems:
        print(
            f"mutants-allowed: {problems} problem(s); kill the mutants with "
            "tests or argue misses into scripts/mutants-allowlist.txt"
        )
        return 1
    print(f"mutants-allowed: all {len(missed)} missed survivor(s) are argued residuals")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: mutants_allowed.py <mutants.out dir> <allowlist>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
