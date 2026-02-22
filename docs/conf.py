# Configuration file for the Sphinx documentation builder.
#
# rfc9180-py documentation

import os
import sys

# Add project root and src to path so autodoc can import rfc9180
_root = os.path.abspath("..")
sys.path.insert(0, _root)
sys.path.insert(0, os.path.abspath("../src"))


def _read_version() -> str:
    """Read version from pyproject.toml (single source of truth)."""
    pyproject = os.path.join(_root, "pyproject.toml")
    if os.path.isfile(pyproject):
        with open(pyproject, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("version ") or line.startswith("version="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "0.0.0"


project = "rfc9180"
copyright = "rfc9180-py Contributors"
author = "rfc9180-py Contributors"
release = _read_version()
version = ".".join(release.split(".")[:2])  # e.g. 0.2 for 0.2.0

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
]
try:
    import sphinx_autodoc_typehints  # noqa: F401

    extensions.append("sphinx_autodoc_typehints")
except ImportError:
    pass

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Use Read the Docs theme if installed (e.g. uv sync --extra docs), else default
try:
    import sphinx_rtd_theme  # noqa: F401

    html_theme = "sphinx_rtd_theme"
except ImportError:
    html_theme = "alabaster"
html_static_path = ["_static"]
html_show_sphinx = False

# Napoleon settings for NumPy-style docstrings
napoleon_google_docstring = False
napoleon_numpy_docstring = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_param = True
napoleon_use_rtype = True


# Autodoc
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}
# When sphinx_autodoc_typehints is installed
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
}
