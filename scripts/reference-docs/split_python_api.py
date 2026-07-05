#!/usr/bin/env python3
"""Split the single-file pydoc-markdown output into Docusaurus-sized pages.

pydoc-markdown renders the whole generated ``iota_sdk`` module as one
markdown file (tens of thousands of lines). This script splits it into
an index page, alphabetically grouped class pages, and function pages.

Classes are delimited by ``## <Name> Objects`` headings. Module-level
functions render exactly like methods, so the generated Python source
is consulted to tell them apart: every ``#### name`` matching a
top-level ``def`` in the module, found after the last class's methods,
starts the functions part.

Usage: split_python_api.py <iota_sdk.md> <iota_sdk.py> <output-dir>
"""

import ast
import re
import sys
from pathlib import Path

MAX_PAGE_LINES = 6000

CLASS_RE = re.compile(r"^## (.+) Objects$")
MEMBER_RE = re.compile(r"^#### (.+)$")


def pack(sections, page_stem, label):
    """Greedily pack (name, lines) sections into letter-labeled pages."""
    pages, current, count = [], [], 0
    for section in sections:
        if current and count + len(section[1]) > MAX_PAGE_LINES:
            pages.append(current)
            current, count = [], 0
        current.append(section)
        count += len(section[1])
    if current:
        pages.append(current)

    out = []
    for i, page in enumerate(pages):
        first, last = page[0][0][:1].upper(), page[-1][0][:1].upper()
        letters = first if first == last else f"{first}–{last}"
        if len(pages) == 1:
            filename, title = f"{page_stem}.md", label
        else:
            filename, title = f"{page_stem}-{i + 1:02d}.md", f"{label} ({letters})"
        out.append((filename, title, [l for _n, lines in page for l in lines]))
    return out


def main():
    src, module_py, out_dir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)

    module_functions = {
        node.name
        for node in ast.parse(module_py.read_text()).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    lines = src.read_text().splitlines()
    # Drop the pydoc-markdown front matter; each page gets its own.
    if lines and lines[0] == "---":
        lines = lines[lines.index("---", 1) + 1 :]

    preamble, classes = [], []
    current = None  # (name, lines) of the class being collected
    function_lines = []
    in_functions = False
    for line in lines:
        class_match = CLASS_RE.match(line)
        member_match = MEMBER_RE.match(line)
        if in_functions:
            function_lines.append(line)
            continue
        if class_match:
            current = (class_match.group(1).replace("\\", ""), [line])
            classes.append(current)
            continue
        if member_match and member_match.group(1).replace("\\", "") in module_functions:
            in_functions = True
            function_lines.append(line)
            continue
        if current is None:
            preamble.append(line)
        else:
            current[1].append(line)

    classes.sort(key=lambda c: c[0].lower())
    pages = pack(classes, "classes", "Classes")
    if function_lines:
        functions = []
        name = "functions"
        block = []
        for line in function_lines:
            member_match = MEMBER_RE.match(line)
            if member_match:
                if block:
                    functions.append((name, block))
                name, block = member_match.group(1).replace("\\", ""), []
            block.append(line)
        if block:
            functions.append((name, block))
        functions.sort(key=lambda f: f[0].lower())
        pages += pack(functions, "functions", "Functions")

    for filename, title, body in pages:
        front = f"---\ntitle: {title}\nsidebar_label: {title}\n---\n\n"
        (out_dir / filename).write_text(front + "\n".join(body).strip() + "\n")

    toc = "\n".join(f"- [{title}]({filename})" for filename, title, _body in pages)
    intro = "\n".join(preamble).strip()
    (out_dir / "index.md").write_text(
        "---\ntitle: Python API\nsidebar_label: Overview\nsidebar_position: 1\n---\n\n"
        + (intro + "\n\n" if intro else "")
        + "## Pages\n\n"
        + toc
        + "\n"
    )


if __name__ == "__main__":
    main()
