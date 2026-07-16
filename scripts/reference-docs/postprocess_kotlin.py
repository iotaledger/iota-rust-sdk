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

Usage: postprocess_kotlin.py <dokka-gfm-dir> <output-dir>
"""

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


def main():
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    module_dirs.update(p.name for p in src.iterdir() if p.is_dir())
    if dst.exists():
        shutil.rmtree(dst)
    for path in sorted(src.rglob("index.md")):
        rel = path.relative_to(src)
        out_path = dst / decode_path(str(rel))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            strip_platform_labels(strip_breadcrumbs(rewrite_links(path.read_text())))
        )


if __name__ == "__main__":
    main()
