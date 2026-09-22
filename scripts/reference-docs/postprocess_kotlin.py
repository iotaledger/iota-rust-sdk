#!/usr/bin/env python3
"""Make Dokka's GFM output consumable by Docusaurus.

Dokka encodes uppercase letters in file and directory names as a dash
followed by the lowercase letter (``TransactionBuilder`` becomes
``-transaction-builder``) and names the default package ``[root]``.
Square brackets are invalid in Docusaurus routes and the dash encoding
produces unreadable URLs and sidebar labels, so this script renames
every path segment back to its real name and rewrites all relative
links accordingly.

Dokka also emits one page per member (thousands of files for this
module), which makes the Docusaurus build run out of memory. Each
type's ``index.md`` already lists every member with its signature and
documentation, so only the ``index.md`` pages are kept and links to the
dropped member pages are replaced by their text.

Companion object members are inlined into the parent type's page (as
kotlinlang.org and the Android reference do) instead of living on a
separate nested ``Companion`` page.

Finally the tree is flattened for the docs sidebar: the bindings expose
a single module with a single package, so the ``<module>/<package>/``
directory chain carries no information, and a per-type directory would
render as a sidebar category wrapping just one page. The output is one
``types/<Type>.md`` page per type plus an ``index.md`` overview, with
nested declarations (enum entries, sealed variants) folded into their
parent type's page under an anchor.

Usage: postprocess_kotlin.py <dokka-gfm-dir> <output-dir>
"""

import posixpath
import re
import shutil
import sys
from pathlib import Path

import common

LINK_RE = re.compile(r"\]\(([^)\s]+)\)")

# Module directories keep their literal name (Dokka only dash-encodes
# class/member names, and a module name may contain a real dash). Filled
# in from the top-level directories of the Dokka output.
module_dirs = set()


def decode_segment(segment: str) -> str:
    """Reverse Dokka's dash-encoding of uppercase letters in one path segment."""
    if segment == "[root]":
        return "root"
    if segment in module_dirs:
        return segment
    out = []
    upper_next = False
    for ch in segment:
        if ch == "-":
            if upper_next:
                # A literal dash was encoded as "--".
                out.append("-")
                upper_next = False
            else:
                upper_next = True
        elif upper_next:
            out.append(ch.upper())
            upper_next = False
        else:
            out.append(ch)
    return "".join(out)


def decode_path(path: str) -> str:
    return "/".join(decode_segment(seg) for seg in path.split("/"))


def rewrite_links(text: str) -> str:
    def repl(match):
        target = match.group(1)
        if "://" in target or target.startswith("#") or target.startswith("mailto:"):
            return match.group(0)
        # Anchors are Dokka-internal numeric IDs that don't exist in the
        # GFM output, so they are always dropped.
        path = target.split("#", 1)[0]
        # Links to dropped member pages keep their text only (the target is
        # emptied here and the brackets removed in a second pass). Only links
        # whose basename is exactly index.md survive — endswith would wrongly
        # match member pages like state-index.md.
        if path.split("/")[-1] != "index.md":
            return "]()"
        return f"]({decode_path(path)})"

    return common.strip_empty_links(LINK_RE.sub(repl, text))


def strip_platform_labels(text: str) -> str:
    """Drop Dokka's ``[jvm]`` platform labels. They only disambiguate
    targets in multiplatform projects; these bindings are JVM-only."""
    text = text.replace("[jvm]<br>", "")
    lines = [line for line in text.splitlines() if line.strip() not in ("[jvm]", "[jvm]\\")]
    return "\n".join(lines) + "\n"


def strip_breadcrumbs(text: str) -> str:
    """Drop Dokka's leading ``//[module](...)`` breadcrumb line; the site
    renders its own breadcrumbs."""
    lines = text.splitlines()
    if lines and lines[0].startswith("//["):
        lines = lines[1:]
        while lines and not lines[0].strip():
            lines = lines[1:]
    return "\n".join(lines) + "\n"


COMPANION_ROW_RE = re.compile(r"^\|\s*\[Companion\]\(Companion/index\.md\)\s*\|.*\|\s*$")


def sections(text: str) -> list[tuple[str, str]]:
    """Split a page into its ``## `` sections as (heading, body) pairs."""
    result = []
    for part in text.split("\n## ")[1:]:
        heading, _, body = part.partition("\n")
        result.append((heading.strip(), body.strip("\n")))
    return result


def companion_sections(text: str) -> list[str]:
    """Extract a companion page's member sections, retitled and with links
    adjusted for living one directory level higher."""
    out = []
    for heading, body in sections(text):
        if not body:
            continue
        # The moved content sits in the parent's directory, so links lose
        # one leading "../" (companions have no nested pages of their own).
        body = body.replace("](../", "](")
        out.append(f"## Companion object {heading.lower()}\n\n{body}")
    return out


def remove_companion_type_row(text: str) -> str:
    """Drop the ``Companion`` row from the parent's Types table, and the
    whole Types section if that row was its only entry."""
    lines = [line for line in text.splitlines() if not COMPANION_ROW_RE.match(line)]
    out = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == "## Types":
            j = i + 1
            while j < len(lines) and not lines[j].startswith("## "):
                j += 1
            block = lines[i + 1 : j]
            if not any(re.match(r"^\|\s*\[", line) for line in block):
                i = j
                continue
        out.append(lines[i])
        i += 1
    return "\n".join(out) + "\n"


def merge_companions(pages: dict[str, str]) -> dict[str, str]:
    """Fold each ``<Type>/Companion/index.md`` page into ``<Type>/index.md``."""
    out = dict(pages)
    for path, text in pages.items():
        parts = path.split("/")
        if len(parts) < 3 or parts[-2:] != ["Companion", "index.md"]:
            continue
        parent = "/".join(parts[:-2]) + "/index.md"
        if parent not in out:
            continue
        merged = remove_companion_type_row(out[parent]).rstrip("\n")
        for section in companion_sections(text):
            merged += f"\n\n{section}"
        out[parent] = merged + "\n"
        del out[path]
    return out


def demote_headings(text: str) -> str:
    return re.sub(r"^(#+) ", r"#\1 ", text, flags=re.M)


def flatten(pages: dict[str, str]) -> dict[str, str]:
    """Collapse the module/package chain and per-type directories into
    ``index.md`` plus one ``types/<Type>.md`` page per type."""
    package_indexes = [p for p in pages if len(p.split("/")) == 3]
    if len(package_indexes) != 1:
        sys.exit(
            f"expected exactly one package, found {package_indexes}; "
            "the flattened layout in postprocess_kotlin.py needs updating"
        )

    # Where every old page lands: (new file, anchor within it or None).
    mapping = {}
    for path in pages:
        parts = path.split("/")
        if len(parts) <= 3:
            mapping[path] = ("index.md", None)
        elif len(parts) == 4:
            mapping[path] = (f"types/{parts[2]}.md", None)
        elif len(parts) == 5:
            # Nested declarations are folded into the parent type's page
            # under a heading whose Docusaurus anchor is the lowercased name.
            mapping[path] = (f"types/{parts[2]}.md", parts[3].lower())
        else:
            sys.exit(f"unexpected nesting depth: {path}")

    def relink(text: str, old_path: str, new_file: str) -> str:
        def repl(match):
            target = match.group(1)
            if "://" in target or target.startswith("#") or target.startswith("mailto:"):
                return match.group(0)
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(old_path), target))
            if resolved not in mapping:
                return "]()"
            target_file, anchor = mapping[resolved]
            if anchor and target_file == new_file:
                return f"](#{anchor})"
            rel = posixpath.relpath(target_file, posixpath.dirname(new_file) or ".")
            return f"]({rel}#{anchor})" if anchor else f"]({rel})"

        return common.strip_empty_links(LINK_RE.sub(repl, text))

    module_index = pages.get("index.md", "")
    module_title = module_index.partition("\n")[0].removeprefix("# ").strip()

    out = {}
    for path, text in pages.items():
        parts = path.split("/")
        if path == "index.md" or len(parts) == 5:
            continue
        new_file, _ = mapping[path]
        text = relink(text, path, new_file)
        if len(parts) == 3 and module_title:
            # The package index becomes the landing page; title it after
            # the module (its own H1 is "Package-level declarations").
            text = re.sub(r"^# .*", f"# {module_title}", text, count=1, flags=re.M)
        out[new_file] = text
    for path in sorted(p for p in pages if len(p.split("/")) == 5):
        new_file, _ = mapping[path]
        out[new_file] = (
            out[new_file].rstrip("\n")
            + "\n\n"
            + demote_headings(relink(pages[path], path, new_file)).strip("\n")
            + "\n"
        )
    return out


def main():
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    module_dirs.update(p.name for p in src.iterdir() if p.is_dir())
    pages = {
        decode_path(str(path.relative_to(src))): strip_platform_labels(
            strip_breadcrumbs(rewrite_links(path.read_text()))
        )
        for path in sorted(src.rglob("index.md"))
    }
    if dst.exists():
        shutil.rmtree(dst)
    for rel, text in flatten(merge_companions(pages)).items():
        out_path = dst / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text)
    common.write_category(dst / "types", "Types", 2)


if __name__ == "__main__":
    main()
