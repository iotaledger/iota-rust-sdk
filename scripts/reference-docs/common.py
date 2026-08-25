"""Helpers shared by the reference-docs generation scripts."""

import re

# UniFFI scaffolding symbol prefixes that must not appear in published
# references, in every binding language.
PLUMBING_NAMES = r"(FfiConverter|FfiDestroyer|RustBuffer|RustCallStatus|Uniffi|uniffi)"
PLUMBING_RE = re.compile(rf"^{PLUMBING_NAMES}")

_EMPTY_LINK_RE = re.compile(r"\[([^\]]*)\]\(\)")


def strip_empty_links(text: str) -> str:
    """Replace links whose target was emptied out ("[text]()") by their text."""
    return _EMPTY_LINK_RE.sub(r"\1", text)


def page_stem(taken: dict, name: str) -> str:
    """Filename stem for a per-type page.

    Names differing only in case (e.g. Input vs INPUT) get distinct stems
    so the tree also extracts safely on case-insensitive filesystems.
    """
    stem = name
    while taken.setdefault(stem.lower(), name) != name:
        stem += "_"
    return stem


def write_category(directory, label, position):
    """Mark a directory as a Docusaurus sidebar category."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "_category_.json").write_text(
        f'{{"label": "{label}", "position": {position}}}\n'
    )


def write_page(path, title, body: str, position=None):
    front = f"---\ntitle: {title}\nsidebar_label: {title}\n"
    if position is not None:
        front += f"sidebar_position: {position}\n"
    front += "---\n\n"
    path.write_text(front + body.strip() + "\n")


def write_index(path, title, intro: str, pages):
    """Write the overview page linking each generated page.

    ``pages`` is a list of (filename, title) pairs.
    """
    toc = "\n".join(f"- [{page_title}]({filename})" for filename, page_title in pages)
    path.write_text(
        f"---\ntitle: {title}\nsidebar_label: Overview\nsidebar_position: 1\n---\n\n"
        + (intro.strip() + "\n\n" if intro.strip() else "")
        + "## Pages\n\n"
        + toc
        + "\n"
    )
