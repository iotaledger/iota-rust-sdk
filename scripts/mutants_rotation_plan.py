#!/usr/bin/env python3
"""Build the nightly whole-tree mutation matrix.

The tree is split into TOTAL_SHARDS contiguous slices; each night runs
SHARDS_PER_NIGHT of them, picked by a monotonic UTC day index, so the
whole scope is covered on a rolling cycle with no state to keep and no
discontinuity at New Year. A missed night means those slices wait one
cycle.

Sizing (measured 2026-08-23): the mutation scope is 2,930 mutants, and
comparable code measures ~3.5 mutants/min at 4 jobs on a 4-core runner,
so 16 shards of ~180 mutants put one shard around an hour. Retune
TOTAL_SHARDS from the slowest shard in the workflow's step summary, not
the average: slices are contiguous file ranges, so their per-mutant cost
differs widely.
"""

import json
import sys

TOTAL_SHARDS = 16
SHARDS_PER_NIGHT = 4
if TOTAL_SHARDS % SHARDS_PER_NIGHT:
    raise ValueError(
        "TOTAL_SHARDS must be a multiple of SHARDS_PER_NIGHT: "
        "a remainder would silently leave the trailing shards out of every night"
    )
ROTATION_NIGHTS = TOTAL_SHARDS // SHARDS_PER_NIGHT


def rotation_plan(utc_day_index: int, requested: str) -> tuple[int, list[int]]:
    if utc_day_index < 0:
        raise ValueError("UTC day index must not be negative")

    value = requested.strip()
    if value:
        if not value.isascii() or not value.isdecimal():
            raise ValueError("shard must be a decimal integer")
        shard = int(value)
        if not 0 <= shard < TOTAL_SHARDS:
            raise ValueError(f"shard must be between 0 and {TOTAL_SHARDS - 1}")
        return TOTAL_SHARDS, [shard]

    first = (utc_day_index % ROTATION_NIGHTS) * SHARDS_PER_NIGHT
    return TOTAL_SHARDS, list(range(first, first + SHARDS_PER_NIGHT))


def github_outputs(utc_day_index: int, requested: str) -> str:
    count, matrix = rotation_plan(utc_day_index, requested)
    return f"count={count}\nmatrix={json.dumps(matrix, separators=(',', ':'))}\n"


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 3:
        raise SystemExit("usage: mutants_rotation_plan.py <utc-day-index> [shard]")
    try:
        utc_day_index = int(argv[1])
        output = github_outputs(utc_day_index, argv[2] if len(argv) == 3 else "")
    except ValueError as error:
        raise SystemExit(f"mutants-rotation-plan: {error}") from error
    print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
