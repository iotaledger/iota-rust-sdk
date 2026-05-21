# Sort Derives

Sorts the trait list inside every `#[derive(...)]` (and `#[cfg_attr(..., derive(...))]`)
across the workspace alphabetically (case-insensitive). Files under
`crates/iota-sdk-grpc-types/src/proto/` are skipped because they are generated.

## Usage

```bash
# Rewrite files in place
make sort-derives

# Or directly
python3 scripts/sort_derives/sort_derives.py

# Check only (CI mode): exit non-zero if any file would change
make check-sort-derives
python3 scripts/sort_derives/sort_derives.py --check
```

Multi-line derives keep their per-trait layout; single-line derives stay single-line.
Run `make fmt` afterwards — rustfmt may re-flow short derive lists onto a single
line, but it never reorders the traits.

## Enforcement

The `sort-derives` job in `.github/workflows/lints.yml` runs `make check-sort-derives`
on every PR.
