#!/usr/bin/env python3
"""Report which publishable crates changed since their last release.

Every workspace crate without `publish = false` is compared against the tag of
the version in its Cargo.toml (`<crate>-v<version>`), which the release
workflow creates when a release PR is merged. A crate is due for a release
when, since that tag:

- a file that `cargo package` ships changed (the commits are listed), or
- a `[workspace.dependencies]` entry it inherits moved out of the caret range
  of the published requirement, so the published crate can't follow the bump.

Cargo resolves a caret requirement to the newest compatible version, so a
compatible dependency bump reaches consumers of the published crate on its
own; a pre-release bump such as `1.0.0-rc.1` to `1.0.0-rc.2` is compatible
too, while a pre-release of another version, such as `1.1.0-rc.1`, is not.
A dependent that needed adapting to a dependency change shows that as a
change of its own; an unchanged dependent ships the source the workspace
already builds against the new dependency.

Crates are printed in publish order.
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Files cargo generates into the package; they have no counterpart in git.
GENERATED = {".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml.orig"}
# Leading version of a requirement such as `1.0.0-rc.1`, `0.3` or `^1`, with
# its pre-release tag when it has one.
VERSION = re.compile(r"(\d+(?:\.\d+){0,2})(-[0-9A-Za-z.-]+)?")
# Makes `--sort=v:refname` order pre-releases before the final version.
VERSIONSORT = [
    "-c",
    "versionsort.suffix=-alpha",
    "-c",
    "versionsort.suffix=-beta",
    "-c",
    "versionsort.suffix=-rc",
]


def run(*cmd: str) -> str:
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"`{' '.join(cmd)}` failed:\n{result.stderr.strip()}")
    return result.stdout


def git(*args: str) -> str:
    return run("git", *args)


def pull() -> None:
    """Fast-forward the checkout so the versions compared are the ones on the
    remote. Release tags sit on the fetched branch, so the fetch follows them."""
    result = subprocess.run(
        ["git", "pull", "--ff-only", "--quiet"], cwd=ROOT, capture_output=True, text=True
    )
    if result.returncode != 0:
        print(
            "warning: `git pull --ff-only` failed, comparing a possibly stale checkout:\n"
            f"{result.stderr.strip()}",
            file=sys.stderr,
        )


@dataclass
class Crate:
    name: str
    version: str
    # Relative to the workspace root.
    dir: str
    # In-workspace, non-dev dependencies by package name.
    deps: set[str]

    tag: str | None = None
    tag_date: str | None = None
    version_tagged: bool = True
    # Changed files that ship in the package, relative to the crate root.
    changed: list[str] = field(default_factory=list)
    # Changed files that don't ship (nested packages, excluded paths).
    unpackaged: list[str] = field(default_factory=list)
    # (short hash, subject) of the commits touching `changed`.
    commits: list[tuple[str, str]] = field(default_factory=list)
    # Inherited `[workspace.dependencies]` entries that changed: a summary and
    # whether the published crate still resolves to the new version.
    manifest: dict[str, tuple[str, bool]] = field(default_factory=dict)
    # In-workspace dependencies that are due for a release themselves.
    deps_due: list[str] = field(default_factory=list)

    @property
    def manifest_incompatible(self) -> bool:
        return any(not compatible for _, compatible in self.manifest.values())

    @property
    def due(self) -> bool:
        return self.tag is None or bool(self.commits or self.manifest_incompatible)

    @property
    def reasons(self) -> list[str]:
        reasons = []
        if self.tag is None:
            reasons.append("never released")
        if self.commits:
            reasons.append("source")
        if self.manifest_incompatible:
            reasons.append("manifest")
        if reasons:
            return reasons
        ignored = []
        if self.unpackaged:
            ignored.append("unpackaged changes")
        if self.manifest or self.deps_due:
            ignored.append("compatible bumps")
        return [" and ".join(ignored) + " only"] if ignored else []


def load_crates() -> dict[str, Crate]:
    meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps"))
    root = Path(meta["workspace_root"])
    # `publish = false` shows up as an empty registry list.
    packages = [p for p in meta["packages"] if p["publish"] != []]
    names = {p["name"] for p in packages}
    crates = {}
    for p in packages:
        deps = {d["name"] for d in p["dependencies"] if d["name"] in names and d["kind"] != "dev"}
        crate_dir = Path(p["manifest_path"]).parent.relative_to(root).as_posix()
        crates[p["name"]] = Crate(p["name"], p["version"], crate_dir, deps)
    return crates


def publish_order(crates: dict[str, Crate]) -> list[str]:
    order: list[str] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        for dep in sorted(crates[name].deps):
            visit(dep)
        order.append(name)

    for name in sorted(crates):
        visit(name)
    return order


def release_tag(crate: Crate) -> tuple[str | None, bool]:
    """The tag of the crate's current version, else its latest release tag."""
    tag = f"{crate.name}-v{crate.version}"
    if git("tag", "-l", tag).strip():
        return tag, True
    tags = git(*VERSIONSORT, "tag", "-l", f"{crate.name}-v*", "--sort=-v:refname").split()
    return (tags[0] if tags else None), False


def packaged_files(name: str) -> set[str]:
    listing = run("cargo", "package", "--list", "--allow-dirty", "-p", name)
    return {f for f in listing.split() if f not in GENERATED}


def nested_package_dirs(ref: str, crate_dir: str) -> list[str]:
    """Directories under the crate that held their own package at `ref`."""
    tree = git("ls-tree", "-r", "--name-only", ref, "--", crate_dir).splitlines()
    manifests = [p for p in tree if p.endswith("/Cargo.toml") and p != f"{crate_dir}/Cargo.toml"]
    return [Path(m).parent.relative_to(crate_dir).as_posix() + "/" for m in manifests]


@functools.cache
def workspace_deps(ref: str) -> dict:
    manifest = tomllib.loads(git("show", f"{ref}:Cargo.toml"))
    return manifest.get("workspace", {}).get("dependencies", {})


def inherited_deps(ref: str, crate: Crate) -> set[str]:
    """Non-dev dependency keys the crate declares with `workspace = true`."""
    manifest = tomllib.loads(git("show", f"{ref}:{crate.dir}/Cargo.toml"))
    tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {})]
    for target in manifest.get("target", {}).values():
        tables += [target.get("dependencies", {}), target.get("build-dependencies", {})]
    return {
        key
        for table in tables
        for key, dep in table.items()
        if isinstance(dep, dict) and dep.get("workspace")
    }


def requirement(dep) -> str:
    return dep if isinstance(dep, str) else dep.get("version", "")


def parse_version(requirement: str) -> tuple[list[int], bool] | None:
    """The major, minor and patch of a requirement, and whether it names a
    pre-release."""
    match = VERSION.search(requirement)
    if not match:
        return None
    parts = [int(n) for n in match.group(1).split(".")]
    return parts + [0] * (3 - len(parts)), match.group(2) is not None


def compatible(old: str, new: str) -> bool:
    """Whether `new` lies in the caret range of `old`, as Cargo resolves it:
    same first non-zero component and everything before it, and a pre-release
    only when `old` already names a pre-release of that same version."""
    old_parsed, new_parsed = parse_version(old), parse_version(new)
    if old_parsed is None or new_parsed is None:
        return False
    (old_parts, old_pre), (new_parts, new_pre) = old_parsed, new_parsed
    if new_pre:
        return old_pre and old_parts == new_parts
    pinned = next((i for i, n in enumerate(old_parts) if n), 2) + 1
    return old_parts[:pinned] == new_parts[:pinned]


def describe_change(old, new) -> tuple[str, bool]:
    """A summary of a `[workspace.dependencies]` entry change and whether the
    published crate's requirement still resolves to the new entry."""
    if old is None:
        return "added", True
    if new is None:
        return "removed", True
    old_version, new_version = requirement(old), requirement(new)
    if old_version == new_version:
        return "changed", True
    if compatible(old_version, new_version):
        return f"{old_version} -> {new_version} (compatible)", True
    return f"{old_version} -> {new_version} (incompatible)", False


def inspect_crate(crate: Crate, rev: str, crates: dict[str, Crate]) -> None:
    crate.tag, crate.version_tagged = release_tag(crate)
    if crate.tag is None:
        return
    crate.tag_date = git("log", "-1", "--format=%cs", crate.tag).strip()

    packaged = packaged_files(crate.name)
    nested = tuple(nested_package_dirs(crate.tag, crate.dir))
    diff = git("diff", "--name-status", "--no-renames", crate.tag, rev, "--", crate.dir)
    for line in diff.splitlines():
        status, path = line.split("\t", 1)
        rel = path[len(crate.dir) + 1 :]
        # A deleted file is not in today's package listing, so fall back to
        # whether it lived in a nested package at the tag.
        shipped = not rel.startswith(nested) if status == "D" else rel in packaged
        (crate.changed if shipped else crate.unpackaged).append(rel)
    if crate.changed:
        paths = [f"{crate.dir}/{rel}" for rel in crate.changed]
        log = git("log", "--format=%h %s", f"{crate.tag}..{rev}", "--", *paths)
        crate.commits = [tuple(line.split(" ", 1)) for line in log.splitlines()]

    old, new = workspace_deps(crate.tag), workspace_deps(rev)
    for key in sorted(inherited_deps(rev, crate)):
        if old.get(key) != new.get(key):
            crate.manifest[key] = describe_change(old.get(key), new.get(key))

    # Dependencies are inspected first (publish order), so their verdict is final.
    crate.deps_due = [dep for dep in sorted(crate.deps) if crates[dep].due]


def report(crates: dict[str, Crate], order: list[str], rev: str, quiet: bool) -> None:
    short = git("rev-parse", "--short", rev).strip()
    print(f"Changes since each crate's release tag, up to {rev} ({short})\n")
    name_width = max(len(name) for name in order)
    version_width = max(len(c.version) for c in crates.values())
    for name in order:
        crate = crates[name]
        verdict = "RELEASE" if crate.due else "ok"
        columns = [
            f"{name:<{name_width}}",
            f"{crate.version:<{version_width}}",
            f"{crate.tag_date or '-':<10}",
            f"{verdict:<7}",
            ", ".join(crate.reasons),
        ]
        print("  ".join(columns).rstrip())
        if quiet:
            continue
        if crate.tag and not crate.version_tagged:
            print(
                f"    no tag for {crate.version}, compared against {crate.tag}"
                " (the release is in flight)"
            )
        for sha, subject in crate.commits:
            print(f"    {sha} {subject}")
        for key, (change, _) in crate.manifest.items():
            print(f"    workspace dependency {key}: {change}")
        if crate.deps_due:
            print(f"    depends on crates due for release: {', '.join(crate.deps_due)}")
        if crate.unpackaged:
            print(f"    not shipped, ignored: {', '.join(crate.unpackaged)}")
    due = [name for name in order if crates[name].due]
    print(f"\nRelease order: {', '.join(due) if due else 'nothing to release'}")


def to_json(crates: dict[str, Crate], order: list[str]) -> list[dict]:
    entries = []
    for name in order:
        crate = crates[name]
        entries.append(
            {
                "name": name,
                "version": crate.version,
                "tag": crate.tag,
                "tag_date": crate.tag_date,
                "version_tagged": crate.version_tagged,
                "due": crate.due,
                "reasons": crate.reasons,
                "commits": [{"sha": sha, "subject": subject} for sha, subject in crate.commits],
                "changed": crate.changed,
                "unpackaged": crate.unpackaged,
                "workspace_dependencies": {
                    key: {"change": change, "compatible": compatible}
                    for key, (change, compatible) in crate.manifest.items()
                },
                "dependencies_due": crate.deps_due,
            }
        )
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--rev", default="HEAD", help="revision to compare the release tags against (default: HEAD)"
    )
    parser.add_argument("--quiet", action="store_true", help="one line per crate, no commits or files")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()

    pull()
    crates = load_crates()
    order = publish_order(crates)
    for name in order:
        inspect_crate(crates[name], args.rev, crates)

    if args.json:
        print(json.dumps(to_json(crates, order), indent=2))
    else:
        report(crates, order, args.rev, args.quiet)


if __name__ == "__main__":
    main()
