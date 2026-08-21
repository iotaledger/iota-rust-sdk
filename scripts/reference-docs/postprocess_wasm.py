"""Reshapes typedoc-plugin-markdown output into the layout the docs site uses.

typedoc emits ``<Kind>.<Name>.md`` files next to ``index.md``; the docs site
wants the same shape as the other languages, one page per type under
``types/`` with an overview at the top. Pages for UniFFI plumbing are dropped,
as in the other bindings, along with pages for deprecated declarations — the
bindings carry a deprecated alias per renamed type, and a page holding only
"use X instead" is not worth a sidebar entry.

Usage: postprocess_wasm.py <typedoc-output-dir>
"""

import posixpath
import re
import sys
from pathlib import Path

import common

PAGE_RE = re.compile(r"^(?P<kind>[A-Za-z]+)\.(?P<name>.+)\.md$")
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
# Source positions point into the generated .d.ts, which readers cannot open.
DEFINED_IN_RE = re.compile(r"^Defined in: .*$\n?", re.M)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = Path(sys.argv[1])

    names = {}
    for path in sorted(root.glob("*.md")):
        if path.name == "index.md":
            continue
        match = PAGE_RE.match(path.name)
        if not match:
            sys.exit(f"unexpected typedoc output file: {path.name}")
        names[path.name] = match.group("name")

    def deprecated(filename):
        # typedoc strikes through the heading of a deprecated declaration.
        with (root / filename).open() as page:
            return page.readline().startswith("# ~~")

    dropped = {
        f
        for f, name in names.items()
        if common.PLUMBING_RE.match(name) or deprecated(f)
    }
    taken = {}
    mapping = {
        f: f"types/{common.page_stem(taken, name)}.md"
        for f, name in names.items()
        if f not in dropped
    }

    def relink(text, new_file):
        def repl(match):
            target = match.group(1)
            if "://" in target or target.startswith("#"):
                return match.group(0)
            path, _, anchor = target.partition("#")
            if path in dropped:
                return "]()"
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
        text = DEFINED_IN_RE.sub("", (root / old).read_text())
        (root / new).write_text(relink(text, new))
        (root / old).unlink()
    for name in dropped:
        (root / name).unlink()

    index = root / "index.md"
    text = DEFINED_IN_RE.sub("", index.read_text())
    text = re.sub(r"^# .*", "# @iota/sdk-wasm", text, count=1, flags=re.M)
    if dropped:
        targets = "|".join(re.escape(name) for name in sorted(dropped))
        text = re.sub(rf"^- \[[^\]]*\]\((?:{targets})\)\n", "", text, flags=re.M)
        # A section listing only plumbing is left without entries.
        text = re.sub(r"^## [^\n]*\n\n(?=##|\Z)", "", text, flags=re.M)
    index.write_text(relink(text, "index.md"))

    common.write_category(root / "types", "Types", 2)
    print(f"wasm reference: {len(mapping)} type pages, {len(dropped)} dropped")


if __name__ == "__main__":
    main()
