Installation
============

Requirements
------------

- Python 3.9 or newer
- ``cryptography`` >= 41.0.0

Install from PyPI
-----------------

.. code-block:: bash

   pip install rfc9180-py

Install from source
-------------------

.. code-block:: bash

   git clone https://github.com/MFDI-hub/rfc9180-py.git
   cd rfc9180-py
   pip install -e .

Development and documentation
-----------------------------

To install with development tools (pytest, mypy, ruff):

.. code-block:: bash

   pip install -e ".[dev]"

To build the documentation (Sphinx, theme, type hints):

.. code-block:: bash

   pip install -e ".[docs]"
   cd docs && sphinx-build -b html . _build/html

Then open ``docs/_build/html/index.html`` in a browser.

With **uv** and **Hatch** (dev deps installed):

.. code-block:: bash

   uv run hatch run docs

How the docs work
-----------------

- **In GitHub**: Only the *source* of the docs lives in the repo (``docs/*.rst``, ``docs/conf.py``).
  The built HTML (``docs/_build/``) is not committed (it is in ``.gitignore``).
- **Building**: Sphinx reads those ``.rst`` files and your Python docstrings (autodoc) and
  generates HTML into ``docs/_build/html``. You run that build locally or in CI.
- **Publishing**: To have the API docs on the web, either build in CI and publish
  (e.g. GitHub Pages from ``docs/_build/html``) or use a host like Read the Docs that
  builds from your repo. Hatch is only a shortcut to run the Sphinx build
  (``hatch run docs``); you can instead run ``sphinx-build -b html docs docs/_build/html`` yourself.
