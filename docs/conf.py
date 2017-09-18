extensions = [
    'sphinx-prompt',
    'nbsphinx',
]
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = 'stix2'
copyright = '2017, OASIS Open'
author = 'OASIS Open'

version = '0.2.0'
release = '0.2.0'

language = None
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
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
