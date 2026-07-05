#!/usr/bin/env python3
"""Render a Swift symbol graph as Docusaurus markdown pages.

Consumes the JSON emitted by ``swift package dump-symbol-graph`` and
produces one page per symbol-kind group (classes, structs, enums,
protocols, functions, ...), split into alphabetical chunks like the Go
reference. UniFFI plumbing symbols are dropped.

Usage: symbolgraph_to_md.py <Module.symbols.json> <output-dir>
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

MAX_PAGE_LINES = 6000

PLUMBING_RE = re.compile(r"^(FfiConverter|FfiDestroyer|RustBuffer|RustCallStatus|Uniffi|uniffi)")

# Top-level kinds and the page group they render into.
KIND_GROUPS = {
    "swift.class": ("classes", "Classes"),
    "swift.struct": ("structs", "Structs"),
    "swift.enum": ("enums", "Enums"),
    "swift.protocol": ("protocols", "Protocols"),
    "swift.func": ("functions", "Functions"),
    "swift.typealias": ("typealiases", "Type Aliases"),
    "swift.var": ("globals", "Globals"),
}

# Member kinds rendered underneath their parent type, in this order.
MEMBER_KIND_ORDER = [
    "swift.init",
    "swift.enum.case",
    "swift.property",
    "swift.type.property",
    "swift.method",
    "swift.type.method",
    "swift.subscript",
    "swift.func.op",
]


def declaration(symbol):
    fragments = symbol.get("declarationFragments", [])
    return "".join(f.get("spelling", "") for f in fragments)


def doc_comment(symbol):
    lines = symbol.get("docComment", {}).get("lines", [])
    return "\n".join(l.get("text", "") for l in lines).strip()


def title(symbol):
    return symbol.get("names", {}).get("title", "?")


def render_member(symbol):
    out = [f"#### `{title(symbol)}`", ""]
    decl = declaration(symbol)
    if decl:
        out += ["```swift", decl, "```", ""]
    doc = doc_comment(symbol)
    if doc:
        out += [doc, ""]
    return out


def render_type(symbol, members):
    out = [f"## {title(symbol)}", ""]
    decl = declaration(symbol)
    if decl:
        out += ["```swift", decl, "```", ""]
    doc = doc_comment(symbol)
    if doc:
        out += [doc, ""]
    ordered = sorted(
        members,
        key=lambda s: (
            MEMBER_KIND_ORDER.index(s["kind"]["identifier"])
            if s["kind"]["identifier"] in MEMBER_KIND_ORDER
            else len(MEMBER_KIND_ORDER),
            title(s),
        ),
    )
    for member in ordered:
        out += render_member(member)
    return out


def paginate(rendered, stem, label):
    """Split (name, lines) chunks into pages under MAX_PAGE_LINES."""
    pages, current, count = [], [], 0
    for name, lines in rendered:
        if current and count + len(lines) > MAX_PAGE_LINES:
            pages.append(current)
            current, count = [], 0
        current.append((name, lines))
        count += len(lines)
    if current:
        pages.append(current)

    out = []
    for i, page in enumerate(pages):
        first, last = page[0][0][:1].upper(), page[-1][0][:1].upper()
        letters = first if first == last else f"{first}–{last}"
        if len(pages) == 1:
            filename, page_title = f"{stem}.md", label
        else:
            filename, page_title = f"{stem}-{i + 1:02d}.md", f"{label} ({letters})"
        body = []
        for _name, lines in page:
            body += lines
        out.append((filename, page_title, body))
    return out


def main():
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    graph = json.loads(src.read_text())
    module = graph.get("module", {}).get("name", "IotaSDK")

    symbols = {s["identifier"]["precise"]: s for s in graph.get("symbols", [])}
    members = defaultdict(list)
    children = set()
    for rel in graph.get("relationships", []):
        if rel.get("kind") == "memberOf":
            source, target = rel.get("source"), rel.get("target")
            if source in symbols and target in symbols:
                members[target].append(symbols[source])
                children.add(source)

    groups = defaultdict(list)
    for precise, symbol in symbols.items():
        if precise in children:
            continue
        if symbol.get("accessLevel") not in (None, "public", "open"):
            continue
        name = title(symbol)
        if PLUMBING_RE.match(name):
            continue
        kind = symbol.get("kind", {}).get("identifier", "")
        if kind in KIND_GROUPS:
            groups[kind].append(symbol)

    pages = []
    for kind, (stem, label) in KIND_GROUPS.items():
        group = sorted(groups.get(kind, []), key=lambda s: title(s).lower())
        if not group:
            continue
        rendered = [
            (
                title(symbol),
                render_type(
                    symbol,
                    [
                        m
                        for m in members.get(symbol["identifier"]["precise"], [])
                        if m.get("accessLevel") in (None, "public", "open")
                        and not PLUMBING_RE.match(title(m))
                    ],
                ),
            )
            for symbol in group
        ]
        pages += paginate(rendered, stem, label)

    for filename, page_title, body in pages:
        front = f"---\ntitle: {page_title}\nsidebar_label: {page_title}\n---\n\n"
        (out_dir / filename).write_text(front + "\n".join(body) + "\n")

    toc = "\n".join(f"- [{t}]({f})" for f, t, _b in pages)
    (out_dir / "index.md").write_text(
        "---\ntitle: Swift API\nsidebar_label: Overview\nsidebar_position: 1\n---\n\n"
        f"API reference for the `{module}` Swift module.\n\n## Pages\n\n{toc}\n"
    )


if __name__ == "__main__":
    main()
