#!/usr/bin/env python3
"""Split the single-file gomarkdoc output into Docusaurus pages.

gomarkdoc renders the whole Go package as one markdown file (tens of
thousands of lines), which Docusaurus cannot present as a single page.
This script splits it into an index page, a constants/variables page, a
functions page, and one page per type (so every type is findable by
name in the sidebar), and rewrites gomarkdoc's intra-page anchor links
(``[X](<#anchor>)``) into cross-page links that use Docusaurus heading
slugs, so the site's broken-anchor check passes.

Usage: split_go_api.py <go_api.md> <output-dir>
"""

import posixpath
import re
import sys
from pathlib import Path

import common

ANCHOR_RE = re.compile(r'^<a name="([^"]+)"></a>(.*)$')
HEADING_RE = re.compile(r"^(#{2,4}) (.+)$")
# gomarkdoc link form: [text](<#anchor>) — also matches without angle brackets.
LINK_RE = re.compile(r"\]\(<?#([A-Za-z0-9_.]+)>?\)")
MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")

PLUMBING_RE = re.compile(rf"^(func|type) \[?{common.PLUMBING_NAMES}")


def plain_heading(heading_text: str) -> str:
    """Heading text as rendered: link markup replaced by its text."""
    return MD_LINK_RE.sub(r"\1", heading_text).replace("\\", "")


def github_slug(heading_text: str, taken: dict) -> str:
    """Replicate github-slugger for the character set gomarkdoc emits."""
    text = plain_heading(heading_text)
    slug = "".join(c for c in text.lower() if c.isalnum() or c in " -_")
    slug = slug.replace(" ", "-")
    if slug in taken:
        taken[slug] += 1
        return f"{slug}-{taken[slug]}"
    taken[slug] = 0
    return slug


class Section:
    def __init__(self, heading: str):
        self.heading = heading  # text of the `## ` heading
        self.lines = []  # all lines including the heading line
        self.anchors = []  # anchor names defined inside this section

    def name(self) -> str:
        """Symbol name: the second word of "func X" / "type X" headings."""
        words = plain_heading(self.heading).split()
        return words[1] if len(words) > 1 else words[0]


def parse_sections(lines):
    """Split the file into a preamble and a list of top-level sections."""
    preamble = []
    sections = []
    current = None
    pending_anchor = None
    for line in lines:
        anchor_match = ANCHOR_RE.match(line)
        if anchor_match:
            # Drop the raw <a name> tag (heading slugs replace it) but keep
            # any prose gomarkdoc put on the same line.
            pending_anchor = anchor_match.group(1)
            trailing = anchor_match.group(2).strip()
            if not trailing:
                continue
            line = trailing
        heading_match = HEADING_RE.match(line)
        if heading_match and len(heading_match.group(1)) == 2:
            current = Section(heading_match.group(2))
            sections.append(current)
        if current is None:
            preamble.append(line)
        else:
            current.lines.append(line)
            if pending_anchor and heading_match:
                current.anchors.append((pending_anchor, heading_match.group(2)))
        if heading_match:
            pending_anchor = None
    return preamble, sections


def main():
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = src.read_text().splitlines()

    preamble, sections = parse_sections(lines)

    # Drop UniFFI plumbing that go users never call directly.
    sections = [s for s in sections if not PLUMBING_RE.match(plain_heading(s.heading))]

    variables = [s for s in sections if s.heading in ("Variables", "Constants")]
    functions = sorted(
        (s for s in sections if s.heading.startswith("func ")),
        key=lambda s: s.name().lower(),
    )
    types = sorted(
        (s for s in sections if s.heading.startswith("type ")),
        key=lambda s: s.name().lower(),
    )

    # (path relative to out_dir, title, sections, sidebar position)
    pages = []
    if variables:
        pages.append(("variables.md", "Constants and Variables", variables, 2))
    if functions:
        pages.append(("functions.md", "Functions", functions, 3))
    taken = {}
    for section in types:
        stem = common.page_stem(taken, section.name())
        pages.append((f"types/{stem}.md", section.name(), [section], None))

    # Map every anchor to (page path, heading slug) for link rewriting.
    anchor_map = {}
    for page_path, _title, page_sections, _pos in pages:
        taken = {}
        for section in page_sections:
            for line in section.lines:
                heading_match = HEADING_RE.match(line)
                if not heading_match:
                    continue
                slug = github_slug(heading_match.group(2), taken)
                for anchor, anchor_heading in section.anchors:
                    if anchor_heading == heading_match.group(2):
                        anchor_map.setdefault(anchor, (page_path, slug))

    def rewrite_links(text: str, from_dir: str) -> str:
        def rewrite(match):
            anchor = match.group(1)
            if anchor in anchor_map:
                target, slug = anchor_map[anchor]
                return f"]({posixpath.relpath(target, from_dir)}#{slug})"
            # Anchors gomarkdoc references but this script cannot resolve
            # (e.g. into the dropped Index) degrade to plain text.
            return "]()"

        return common.strip_empty_links(LINK_RE.sub(rewrite, text))

    common.write_category(out_dir / "types", "Types", 4)
    for page_path, title, page_sections, position in pages:
        body_lines = []
        for section in page_sections:
            body_lines.extend(section.lines)
            body_lines.append("")
        common.write_page(
            out_dir / page_path,
            title,
            rewrite_links("\n".join(body_lines), posixpath.dirname(page_path)),
            position,
        )

    # Index page: package preamble (minus gomarkdoc's own H1, which the
    # frontmatter title replaces, and its "generated" comment) plus links
    # to the non-type pages; the sidebar lists the types.
    intro = "\n".join(
        line
        for line in preamble
        if not line.startswith("<!--") and not line.startswith("# ")
    )
    common.write_index(
        out_dir / "index.md",
        "Go API",
        rewrite_links(intro, ""),
        [(p, t) for p, t, _s, _pos in pages if not p.startswith("types/")],
    )


if __name__ == "__main__":
    main()
