import os
import sys

sys.path.insert(0, os.path.abspath('..'))

extensions = [
    'sphinx-prompt',
    'nbsphinx',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
]
autodoc_default_flags = [
    'show-inheritance',
    'undoc-members',
]
autodoc_member_order = 'groupwise'
autosummary_generate = True
napoleon_numpy_docstring = False  # Force consistency, leave only Google
napoleon_use_rtype = False

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = 'stix2'
copyright = '2017, OASIS Open'
author = 'OASIS Open'

version = '0.2.0'
release = '0.2.0'

language = None
exclude_patterns = ['_build', '_templates', 'Thumbs.db', '.DS_Store', '.ipynb_checkpoints']
pygments_style = 'sphinx'
todo_include_todos = False

html_theme = 'alabaster'
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',
        'searchbox.html',
    ]
}

latex_elements = {}
latex_documents = [
    (master_doc, 'stix2.tex', 'stix2 Documentation', 'OASIS', 'manual'),
]
