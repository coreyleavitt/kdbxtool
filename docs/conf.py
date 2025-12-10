"""Sphinx configuration for kdbxtool documentation."""

project = "kdbxtool"
copyright = "2025, Corey Leavitt"
author = "Corey Leavitt"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "myst_parser",
]

# Autosummary settings
autosummary_generate = True

templates_path = ["_templates"]
exclude_patterns = ["_build"]

html_theme = "furo"
html_title = "kdbxtool"

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "show-inheritance": True,
}
autodoc_typehints = "description"

# Napoleon settings for Google-style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True

# Intersphinx for linking to Python docs
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

# MyST settings
myst_enable_extensions = ["colon_fence", "deflist"]

# Inject version switcher into sidebar (versions loaded dynamically via JS)
html_sidebars = {
    "**": [
        "sidebar/brand.html",
        "version-switcher.html",
        "sidebar/search.html",
        "sidebar/scroll-start.html",
        "sidebar/navigation.html",
        "sidebar/scroll-end.html",
    ]
}
