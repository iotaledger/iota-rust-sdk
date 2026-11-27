"""Reshapes typedoc-plugin-markdown output into the layout the docs site uses.

typedoc emits ``<Kind>.<Name>.md`` files next to ``index.md``; the docs site
wants the same shape as the other languages, one page per type under
``types/`` with an overview at the top. Pages for UniFFI plumbing are dropped,
as in the other bindings, along with pages for deprecated declarations — the
bindings carry a deprecated alias per renamed type, and a page holding only
"use X instead" is not worth a sidebar entry.

A namespace holds the functions of the type it shares its name with (e.g.
``IntentVersion.toDisplayString`` for the ``IntentVersion`` enum). typedoc
emits it as ``Namespace.<Name>.md`` plus ``<Name>.<Kind>.<Member>.md`` per
member; the members are listed on that type's page instead, so neither the
namespace nor its members get a page of their own.

Usage: postprocess_wasm.py <typedoc-output-dir>
"""

import posixpath
import re
import sys
from pathlib import Path

import common

PAGE_RE = re.compile(r"^(?P<kind>[A-Za-z]+)\.(?P<name>[^.]+)\.md$")
MEMBER_RE = re.compile(
    r"^(?P<namespace>[^.]+)\.(?P<kind>[A-Za-z]+)\.(?P<name>[^.]+)\.md$"
)
HEADING_RE = re.compile(r"^(#+) ", re.M)
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
# Source positions point into the generated .d.ts, which readers cannot open.
DEFINED_IN_RE = re.compile(r"^Defined in: .*$\n?", re.M)


def heading_anchor(title):
    """Anchor Docusaurus gives a heading, e.g. "toBcs()" -> "tobcs"."""
    return re.sub(r"[^\w\- ]", "", title).strip().lower().replace(" ", "-")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = Path(sys.argv[1])

    names = {}
    kinds = {}
    members = {}
    for path in sorted(root.glob("*.md")):
        if path.name == "index.md":
            continue
        match = MEMBER_RE.match(path.name)
        if match:
            if match.group("kind") != "Function":
                sys.exit(f"unexpected namespace member: {path.name}")
            members.setdefault(match.group("namespace"), []).append(path.name)
            continue
        match = PAGE_RE.match(path.name)
        if not match:
            sys.exit(f"unexpected typedoc output file: {path.name}")
        names[path.name] = match.group("name")
        kinds[path.name] = match.group("kind")

    def deprecated(filename):
        # typedoc strikes through the heading of a deprecated declaration.
        with (root / filename).open() as page:
            return page.readline().startswith("# ~~")

    dropped = {
        f
        for f, name in names.items()
        if common.PLUMBING_RE.match(name) or deprecated(f)
    }

    # Namespace page -> page of the type it shares its name with.
    hosts = {}
    for f, name in names.items():
        if kinds[f] != "Namespace":
            continue
        candidates = [h for h, n in names.items() if n == name and h != f]
        if len(candidates) != 1:
            sys.exit(f"namespace {name} does not share its name with exactly one type")
        hosts[f] = candidates[0]
    orphans = set(members) - {names[f] for f in hosts}
    if orphans:
        sys.exit(f"members of unknown namespaces: {', '.join(sorted(orphans))}")

    # Namespace or member page -> (host page, anchor on the host page).
    folded = {}
    # Host page -> section listing the namespace's members.
    functions = {}
    for namespace, host in hosts.items():
        member_files = members.get(names[namespace], [])
        if host in dropped or namespace in dropped:
            dropped |= {namespace, *member_files}
            continue
        folded[namespace] = (host, "")
        sections = []
        for member in member_files:
            heading, _, body = (root / member).read_text().partition("\n")
            title = heading.split(": ", 1)[-1]
            sections.append(f"### {title}\n" + HEADING_RE.sub(r"\1## ", body))
            folded[member] = (host, heading_anchor(title))
        if sections:
            functions[host] = "\n## Functions\n\n" + "\n".join(sections)

    taken = {}
    mapping = {
        f: f"types/{common.page_stem(taken, name)}.md"
        for f, name in names.items()
        if f not in dropped and f not in folded
    }

    def relink(text, new_file):
        def repl(match):
            target = match.group(1)
            if "://" in target or target.startswith("#"):
                return match.group(0)
            path, _, anchor = target.partition("#")
            if path in dropped:
                return "]()"
            if path in folded:
                path, host_anchor = folded[path]
                anchor = anchor or host_anchor
            if path == "index.md":
                new_path = posixpath.relpath("index.md", posixpath.dirname(new_file))
            elif path in mapping:
                new_path = posixpath.relpath(
                    mapping[path], posixpath.dirname(new_file) or "."
                )
            else:
                return match.group(0)
            return f"]({new_path}#{anchor})" if anchor else f"]({new_path})"

        return common.strip_empty_links(LINK_RE.sub(repl, text))

    (root / "types").mkdir(exist_ok=True)
    for old, new in mapping.items():
        text = (root / old).read_text() + functions.get(old, "")
        text = DEFINED_IN_RE.sub("", text)
        (root / new).write_text(relink(text, new))
        (root / old).unlink()
    for name in dropped | set(folded):
        (root / name).unlink()

    index = root / "index.md"
    text = DEFINED_IN_RE.sub("", index.read_text())
    text = re.sub(r"^# .*", "# @iota/sdk-wasm", text, count=1, flags=re.M)
    unlisted = dropped | set(folded)
    if unlisted:
        targets = "|".join(re.escape(name) for name in sorted(unlisted))
        text = re.sub(rf"^- \[[^\]]*\]\((?:{targets})\)\n", "", text, flags=re.M)
        # A section listing only removed pages is left without entries.
        text = re.sub(r"^## [^\n]*\n\n+(?=##|\Z)", "", text, flags=re.M)
    index.write_text(relink(text, "index.md"))

    common.write_category(root / "types", "Types", 2)
    print(f"wasm reference: {len(mapping)} type pages, {len(dropped)} dropped")


if __name__ == "__main__":
    main()
