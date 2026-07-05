"""Helpers shared by the reference-docs generation scripts."""

import re

# Upper bound per generated page. Pages are packed greedily with whole
# sections, so a page can exceed this only if a single section does.
MAX_PAGE_LINES = 6000

# UniFFI scaffolding symbol prefixes that must not appear in published
# references, in every binding language.
PLUMBING_NAMES = r"(FfiConverter|FfiDestroyer|RustBuffer|RustCallStatus|Uniffi|uniffi)"
PLUMBING_RE = re.compile(rf"^{PLUMBING_NAMES}")

_EMPTY_LINK_RE = re.compile(r"\[([^\]]*)\]\(\)")


def strip_empty_links(text: str) -> str:
    """Replace links whose target was emptied out ("[text]()") by their text."""
    return _EMPTY_LINK_RE.sub(r"\1", text)


def pack(sections, stem, label, name_of, size_of):
    """Greedily pack sections into pages, labeled by first-letter range.

    Returns a list of (filename, title, page_sections) tuples where
    page_sections preserves the input section objects.
    """
    pages, current, count = [], [], 0
    for section in sections:
        if current and count + size_of(section) > MAX_PAGE_LINES:
            pages.append(current)
            current, count = [], 0
        current.append(section)
        count += size_of(section)
    if current:
        pages.append(current)

    out = []
    for i, page in enumerate(pages):
        first = name_of(page[0])[:1].upper()
        last = name_of(page[-1])[:1].upper()
        letters = first if first == last else f"{first}–{last}"
        if len(pages) == 1:
            filename, title = f"{stem}.md", label
        else:
            filename, title = f"{stem}-{i + 1:02d}.md", f"{label} ({letters})"
        out.append((filename, title, page))
    return out


def write_page(path, title, body: str):
    front = f"---\ntitle: {title}\nsidebar_label: {title}\n---\n\n"
    path.write_text(front + body.strip() + "\n")


def write_index(path, title, intro: str, pages):
    """Write the overview page linking each generated page.

    ``pages`` is a list of (filename, title, ...) tuples.
    """
    toc = "\n".join(f"- [{page_title}]({filename})" for filename, page_title, *_ in pages)
    path.write_text(
        f"---\ntitle: {title}\nsidebar_label: Overview\nsidebar_position: 1\n---\n\n"
        + (intro.strip() + "\n\n" if intro.strip() else "")
        + "## Pages\n\n"
        + toc
        + "\n"
    )
