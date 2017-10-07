import os
import sys

sys.path.insert(0, os.path.abspath('..'))

extensions = [
    'sphinx-prompt',
    'nbsphinx',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',
]
autodoc_default_flags = [
    'undoc-members',
]
autodoc_member_order = 'groupwise'
autosummary_generate = True
napoleon_numpy_docstring = False  # Force consistency, leave only Google
napoleon_use_rtype = False
add_module_names = False

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = 'stix2'
copyright = '2017, OASIS Open'
author = 'OASIS Open'

version = '0.3.0'
release = '0.3.0'

language = None
exclude_patterns = ['_build', '_templates', 'Thumbs.db', '.DS_Store', 'guide/.ipynb_checkpoints']
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
