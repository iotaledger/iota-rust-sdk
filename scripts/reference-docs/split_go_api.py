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

# Upper bound per generated page. Pages are packed greedily with whole
# sections, so a page can exceed this only if a single section does.
MAX_PAGE_LINES = 6000

ANCHOR_RE = re.compile(r'^<a name="([^"]+)"></a>(.*)$')
HEADING_RE = re.compile(r"^(#{2,4}) (.+)$")
# gomarkdoc link form: [text](<#anchor>) — also matches without angle brackets.
LINK_RE = re.compile(r"\]\(<?#([A-Za-z0-9_.]+)>?\)")
MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")


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


def pack(sections, page_stem, label):
    """Greedily pack sections into pages, labeled by first-letter range."""
    pages = []
    current, current_lines = [], 0
    for section in sections:
        if current and current_lines + len(section.lines) > MAX_PAGE_LINES:
            pages.append(current)
            current, current_lines = [], 0
        current.append(section)
        current_lines += len(section.lines)
    if current:
        pages.append(current)

    out = []
    for i, page_sections in enumerate(pages):
        first = sort_key(page_sections[0])[:1].upper()
        last = sort_key(page_sections[-1])[:1].upper()
        letters = first if first == last else f"{first}–{last}"
        if len(pages) == 1:
            filename, title = f"{page_stem}.md", label
        else:
            filename = f"{page_stem}-{i + 1:02d}.md"
            title = f"{label} ({letters})"
        out.append((filename, title, page_sections))
    return out


def main():
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = src.read_text().splitlines()

    preamble, sections = parse_sections(lines)

    # Drop UniFFI plumbing that go users never call directly.
    plumbing = re.compile(
        r"^(func|type) \[?(FfiConverter|FfiDestroyer|RustBuffer|Uniffi|uniffi)"
    )
    sections = [s for s in sections if not plumbing.match(plain_heading(s.heading))]

    variables = [s for s in sections if s.heading in ("Variables", "Constants")]
    functions = sorted(
        (s for s in sections if s.heading.startswith("func ")), key=sort_key
    )
    types = sorted((s for s in sections if s.heading.startswith("type ")), key=sort_key)

    pages = []
    if variables:
        pages.append(("variables.md", "Constants and Variables", variables))
    pages += pack(functions, "functions", "Functions")
    pages += pack(types, "types", "Types")

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
        # (e.g. into the dropped Index) fall back to a plain-text link
        # target removal by keeping the closing bracket only.
        return "]()"

    def render(filename, title, page_sections):
        body_lines = []
        for section in page_sections:
            body_lines.extend(section.lines)
            body_lines.append("")
        body = "\n".join(body_lines)
        body = LINK_RE.sub(rewrite, body)
        # Drop links whose target could not be resolved: [text]() -> text
        body = re.sub(r"\[([^\]]*)\]\(\)", r"\1", body)
        front = f"---\ntitle: {title}\nsidebar_label: {title}\n---\n\n"
        (out_dir / filename).write_text(front + body)

    for filename, title, page_sections in pages:
        render(filename, title, page_sections)

    # Index page: package preamble (minus gomarkdoc's own giant index)
    # plus links to the generated pages.
    intro = []
    for line in preamble:
        # The frontmatter title replaces the H1, and gomarkdoc's own
        # "generated" comment is dropped.
        if line.startswith("<!--") or line.startswith("# "):
            continue
        intro.append(line)
    toc = "\n".join(
        f"- [{title}]({filename})" for filename, title, _sections in pages
    )
    index = (
        "---\ntitle: Go API\nsidebar_label: Overview\nsidebar_position: 1\n---\n\n"
        + "\n".join(intro).strip()
        + "\n\n## Pages\n\n"
        + toc
        + "\n"
    )
    (out_dir / "index.md").write_text(index)


if __name__ == "__main__":
    main()
