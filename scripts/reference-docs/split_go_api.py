#!/usr/bin/env python3
"""Split the single-file gomarkdoc output into Docusaurus-sized pages.

gomarkdoc renders the whole Go package as one markdown file (tens of
thousands of lines), which Docusaurus cannot present as a single page.
This script splits it into an index page plus alphabetically grouped
pages for functions and types, and rewrites gomarkdoc's intra-page
anchor links (``[X](<#anchor>)``) into cross-page links that use
Docusaurus heading slugs, so the site's broken-anchor check passes.

Usage: split_go_api.py <go_api.md> <output-dir>
"""

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


def sort_key(section: Section) -> str:
    text = plain_heading(section.heading)
    for prefix in ("func ", "type "):
        if text.startswith(prefix):
            return text[len(prefix) :].lower()
    return text.lower()


def main():
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = src.read_text().splitlines()

    preamble, sections = parse_sections(lines)

    # Drop UniFFI plumbing that go users never call directly.
    sections = [s for s in sections if not PLUMBING_RE.match(plain_heading(s.heading))]

    variables = [s for s in sections if s.heading in ("Variables", "Constants")]
    functions = sorted(
        (s for s in sections if s.heading.startswith("func ")), key=sort_key
    )
    types = sorted((s for s in sections if s.heading.startswith("type ")), key=sort_key)

    section_size = lambda s: len(s.lines)
    pages = []
    if variables:
        pages.append(("variables.md", "Constants and Variables", variables))
    pages += common.pack(functions, "functions", "Functions", sort_key, section_size)
    pages += common.pack(types, "types", "Types", sort_key, section_size)

    # Map every anchor to (page file, heading slug) for link rewriting.
    anchor_map = {}
    for filename, _title, page_sections in pages:
        taken = {}
        for section in page_sections:
            for line in section.lines:
                heading_match = HEADING_RE.match(line)
                if not heading_match:
                    continue
                slug = github_slug(heading_match.group(2), taken)
                for anchor, anchor_heading in section.anchors:
                    if anchor_heading == heading_match.group(2):
                        anchor_map.setdefault(anchor, (filename, slug))

    def rewrite(match):
        anchor = match.group(1)
        if anchor in anchor_map:
            filename, slug = anchor_map[anchor]
            return f"]({filename}#{slug})"
        # Anchors gomarkdoc references but this script cannot resolve
        # (e.g. into the dropped Index) degrade to plain text.
        return "]()"

    def rewrite_links(text: str) -> str:
        return common.strip_empty_links(LINK_RE.sub(rewrite, text))

    for filename, title, page_sections in pages:
        body_lines = []
        for section in page_sections:
            body_lines.extend(section.lines)
            body_lines.append("")
        common.write_page(out_dir / filename, title, rewrite_links("\n".join(body_lines)))

    # Index page: package preamble (minus gomarkdoc's own H1, which the
    # frontmatter title replaces, and its "generated" comment) plus links
    # to the generated pages.
    intro = "\n".join(
        line
        for line in preamble
        if not line.startswith("<!--") and not line.startswith("# ")
    )
    common.write_index(out_dir / "index.md", "Go API", rewrite_links(intro), pages)


if __name__ == "__main__":
    main()
