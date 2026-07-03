# Cargo Sort

Cargo.toml dependency management tool with two modes:

1. **Sort Mode** (default): Sort dependencies into internal/external groups with comments
2. **Consolidate Mode**: Analyze and consolidate/distribute workspace dependencies

## Sort Mode (Default)

Scans all `Cargo.toml` files and:

- Separates internal (workspace) and external dependencies with comments
- Sorts dependencies alphabetically within each group

### Usage

```bash
./run_sort.sh [options]

# Or directly:
python cargo_sort.py [options]
```

### Options

```
--target TARGET    Target directory to search in (relative or absolute). Default: ../../
--ignore FOLDER    Folder patterns to ignore (can be specified multiple times)
--skip-dprint      Skip running dprint fmt
--skip-sort        Skip sort mode (useful with --consolidate-deps to only consolidate)
--debug            Show debug prints
```

## Consolidate Mode

Analyzes all dependencies across the workspace and:

- If an external dependency is used by **multiple crates**: adds it to root `[workspace.dependencies]` and updates crates to use `package.workspace = true`
- If an external dependency is used by **only one crate**: removes it from root and gives the crate the full version spec

**Note:** Sort mode runs automatically after consolidate mode (use `--skip-sort` to disable).

### Usage

```bash
./run_consolidate.sh [options]

# Or directly:
python cargo_sort.py --consolidate-deps [options]
```

### Options

```
--consolidate-deps     Enable consolidate mode
--target TARGET        Target directory to search in (relative or absolute). Default: ../../
--ignore FOLDER        Folder patterns to ignore (can be specified multiple times)
--min-usage N          Minimum usages to consolidate (default: 2)
--skip-dprint          Skip running dprint fmt
--skip-sort            Skip sort mode after consolidating
```

### Features

- **Version conflict resolution**: Picks the highest version when crates use different versions (with SemVer-compatible specs)
- **Feature merging**: Combines features from all usages into workspace definition
- **Version constraint validation**: Detects and errors on incompatible version constraints:

  | Constraint Type | Example               | Behavior                                         |
  | --------------- | --------------------- | ------------------------------------------------ |
  | Exact pins      | `=1.0.0`              | **ERROR** if higher version exists elsewhere     |
  | Upper bounds    | `<2.0.0`, `<=1.5.0`   | **ERROR** if higher version exists elsewhere     |
  | Bounded ranges  | `>=1.0, <2.0`         | **ERROR** if range conflicts with higher version |
  | Exclusions      | `!=1.5.0`             | **ERROR** if highest version is excluded         |
  | Wildcards       | `*`, `1.*`            | Skipped (very permissive)                        |
  | SemVer specs    | `1.0`, `^1.0`, `~1.0` | **WARN** and use highest version                 |

- **Conflict handling**:
  - RED error + **panic** for exact pins or upper bounds conflicting with higher versions
  - RED error + **panic** for mixed version/git specifications
  - RED error + **panic** for conflicting git revisions
  - YELLOW warning for multiple SemVer versions (uses highest)
  - YELLOW warning for conflicting `default-features` settings
- **Special section handling**: `build-dependencies` and `target.'cfg(...)'.dependencies` don't drive consolidation (but can still use workspace refs)

### Examples

```bash
# Run consolidate mode (will also sort after)
./run_consolidate.sh

# Consolidate with custom minimum usage threshold
./run_consolidate.sh --min-usage 3

# Only consolidate, don't sort
python cargo_sort.py --consolidate-deps --skip-sort
```

## Maintenance

When modifying the workspace (adding/removing crates, changing dependencies), the following
configuration points may need updating:

### Internal crate aliases (`cargo_sort.py`)

The `internal_crates_dict` in `cargo_sort.py` is auto-populated by scanning all `Cargo.toml`
files in the workspace for their `[package] name`. However, some crates are referenced by an
**alias** — a dependency name that differs from the actual package name. For example, if a
crate declares `name = "iota-sdk-crypto"` but other crates depend on it as `iota-crypto` (via
`package = "iota-sdk-crypto"` renaming), the sort tool won't automatically recognize
`iota-crypto` as an internal crate.

**When to update:** When a workspace crate is depended on using a different name than its
`[package] name`, add the alias to the manual `internal_crates_dict` entries in `cargo_sort.py`.
Without this, the sort tool will misclassify the dependency as external.

### Strict-ignore rules (`run_consolidate.sh`)

The `--strict-ignore` flags in `run_consolidate.sh` suppress strict-mode errors for known,
acceptable version conflicts. Strict mode (`--strict`) exits with an error if any dependency has
conflicting versions across workspace crates.

Ignore rules use the format:

- `"dep_name"` — ignore all version conflicts for that dependency
- `"dep_name:crate/path"` — ignore conflicts only for that dependency in a specific crate
- `"*:crate/path"` — ignore all dependency conflicts in a specific crate

**When to add entries:** When a dependency legitimately requires different versions in different
crates (e.g., a crate pins an older version for platform compatibility) and this conflict should
not block CI.

**When to remove entries:** When the underlying version conflict has been resolved (e.g., all
crates now use the same version), the ignore rule is no longer needed and should be removed.
