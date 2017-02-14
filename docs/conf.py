extensions = []
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = 'stix2'
copyright = '2017, OASIS Open'
author = 'OASIS Open'

version = '0.0.1'
release = '0.0.1'

language = None
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
pygments_style = 'sphinx'
todo_include_todos = False

html_theme = 'alabaster'

latex_elements = {}
latex_documents = [
    (master_doc, 'stix2.tex', 'stix2 Documentation', 'OASIS', 'manual'),
]
