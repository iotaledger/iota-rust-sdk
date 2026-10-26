# Release Status

Lists which publishable crates need a release, in publish order, so the
end-of-sprint release round doesn't have to be worked out by hand.

Each crate is compared against the tag of the version in its `Cargo.toml`
(`<crate>-v<version>`), which `.github/workflows/release.yml` creates when the
release PR is merged. A crate is marked `RELEASE` when, since that tag:

- `source`: a file that `cargo package` ships changed. The commits are listed.
- `manifest`: a `[workspace.dependencies]` entry the crate inherits moved out
  of the caret range of the published requirement, such as a major bump or a
  pre-release of another version, so the published crate can't follow it.

Everything else is reported but ignored. Cargo resolves a caret requirement to
the newest compatible version, so a compatible dependency bump reaches
consumers of the already published crate on its own; a pre-release bump such
as `1.0.0-rc.1` to `1.0.0-rc.2` is compatible too. A dependent that had to be
adapted to a dependency change shows that as a change of its own, and an
unchanged dependent ships the very source the workspace already builds against
the new dependency. Files that don't ship, such as the nested example packages,
don't count either. Re-run after each release lands.

## Usage

```bash
make release-status

# Or directly
python3 scripts/release_status/release_status.py
python3 scripts/release_status/release_status.py --rev origin/develop
python3 scripts/release_status/release_status.py --quiet
python3 scripts/release_status/release_status.py --json
```

Requires Python 3.11+. The script fast-forwards the checkout first, which also
fetches the release tags; a checkout that can't be fast-forwarded is compared
as is, with a warning. Only committed changes count. `cargo package --list`
reads the working tree, so compare from a checkout of the revision passed to
`--rev`.
