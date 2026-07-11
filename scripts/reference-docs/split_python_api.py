#!/usr/bin/env python3
"""Split the single-file pydoc-markdown output into Docusaurus-sized pages.

pydoc-markdown renders the whole generated ``iota_sdk`` module as one
markdown file (tens of thousands of lines). This script splits it into
an index page, one page per class (so every class is findable by name
in the sidebar), and a functions page.

Classes are delimited by ``## <Name> Objects`` headings. Module-level
functions render exactly like methods, so the generated Python source
is consulted to tell them apart: a ``#### name`` block is a module
function iff the name is a top-level ``def`` in the module and not also
a method of any class (a colliding name stays in the preceding block,
which only costs the function its copy on the Functions page).

Usage: split_python_api.py <iota_sdk.md> <iota_sdk.py> <output-dir>
"""

import ast
import sys
from pathlib import Path

import common

CLASS_MARKER = " Objects"


def module_function_names(module_py: Path) -> set:
    tree = ast.parse(module_py.read_text())
    top_level = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    methods = {
        member.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        for member in node.body
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return top_level - methods


def main():
    src, module_py, out_dir = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)

    module_functions = module_function_names(module_py)

    lines = src.read_text().splitlines()
    # Drop the pydoc-markdown front matter; each page gets its own.
    if lines and lines[0] == "---" and "---" in lines[1:]:
        lines = lines[lines.index("---", 1) + 1 :]

    preamble = []
    classes = []  # (name, lines)
    functions = []  # (name, lines)
    # Lines are appended to the most recently opened block: a class block
    # opens on `## X Objects`, a function block on a `#### name` whose name
    # is a module-level function. Everything else follows its predecessor,
    # so a class section stays intact even after the first module function.
    active = preamble
    for line in lines:
        if line.startswith("## ") and line.endswith(CLASS_MARKER):
            name = line[3 : -len(CLASS_MARKER)].replace("\\", "")
            classes.append((name, []))
            active = classes[-1][1]
        elif line.startswith("#### "):
            name = line[5:].replace("\\", "")
            if name in module_functions:
                functions.append((name, []))
                active = functions[-1][1]
        active.append(line)

    if not classes:
        sys.exit(f"no class sections found in {src}")

    classes.sort(key=lambda c: c[0].lower())
    functions.sort(key=lambda f: f[0].lower())

    common.write_category(out_dir / "classes", "Classes", 3)
    taken = {}
    for name, class_lines in classes:
        stem = common.page_stem(taken, name)
        common.write_page(out_dir / "classes" / f"{stem}.md", name, "\n".join(class_lines))

    function_body = "\n".join(line for _name, lines in functions for line in lines)
    common.write_page(out_dir / "functions.md", "Functions", function_body, position=2)

    common.write_index(
        out_dir / "index.md",
        "Python API",
        "\n".join(preamble),
        [("functions.md", "Functions")],
    )


if __name__ == "__main__":
    main()
