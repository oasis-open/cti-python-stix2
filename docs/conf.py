import os
import re
import sys

from six import class_types
from sphinx.ext.autodoc import ClassDocumenter

from stix2.base import _STIXBase

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

version = '0.4.0'
release = '0.4.0'

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

def get_property_type(prop):
    try:
        prop_class = prop.__name__
    except AttributeError:
        prop_class = prop.__class__.__name__
    prop_class = prop_class.split('Property')[0]
    split_camelcase = re.sub('(?!^)([A-Z][a-z]+)', r' \1', prop_class).split()
    prop_class = ' '.join(split_camelcase)
    return prop_class

class STIXAttributeDocumenter(ClassDocumenter):
    '''Custom Sphinx extension to auto-document STIX properties.

    Needed because descendants of _STIXBase use `_properties` dictionaries
    instead of instance variables for STIX 2 objects' properties.

    '''
    objtype = 'stixattr'
    directivetype = 'class'
    priority = 999

    @classmethod
    def can_document_member(cls, member, membername, isattr, parent):
        return isinstance(member, class_types) and \
               issubclass(member, _STIXBase) and \
               hasattr(member, '_properties')

    def add_content(self, more_content, no_docstring=False):
        ClassDocumenter.add_content(self, more_content, no_docstring)

        obj = self.object
        self.add_line(':Properties:', '<stixattr>')
        for prop_name, prop in obj._properties.items():
            # Add metadata about the property
            prop_type = get_property_type(prop)
            if prop_type == 'List':
                prop_type = 'List of %ss' % get_property_type(prop.contained)
            if prop.required:
                prop_type += ', required'
            prop_str = '**%s** (*%s*)' % (prop_name, prop_type)
            self.add_line('    - %s' % prop_str, '<stixattr>')
        self.add_line('', '<stixattr>')

def setup(app):
    app.add_autodocumenter(STIXAttributeDocumenter)
