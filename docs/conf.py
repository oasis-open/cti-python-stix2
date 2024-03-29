import datetime
import json
import os
import re
import sys

from sphinx.ext.autodoc import ClassDocumenter

from stix2.base import _STIXBase
from stix2.equivalence.object import WEIGHTS
from stix2.version import __version__

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
copyright = '{}, OASIS Open'.format(datetime.date.today().year)
author = 'OASIS Open'

version = __version__
release = __version__

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
    ],
}

latex_elements = {}
latex_documents = [
    (master_doc, 'stix2.tex', 'stix2 Documentation', 'OASIS', 'manual'),
]

# Add a formatted version of environment.WEIGHTS
object_default_sem_eq_weights = json.dumps(WEIGHTS, indent=4, default=lambda o: o.__name__)
object_default_sem_eq_weights = object_default_sem_eq_weights.replace('\n', '\n    ')
object_default_sem_eq_weights = object_default_sem_eq_weights.replace('               "', '               ')
object_default_sem_eq_weights = object_default_sem_eq_weights.replace('"\n', '\n')
with open('similarity_weights.rst', 'w') as f:
    f.write(".. code-block:: python\n\n   {}\n\n".format(object_default_sem_eq_weights))


def get_property_type(prop):
    """Convert property classname into pretty string name of property.

    """
    try:
        prop_class = prop.__name__
    except AttributeError:
        prop_class = prop.__class__.__name__
    # Remove 'Property' from the string
    prop_class = prop_class.split('Property')[0]
    # Split camelcase with spaces
    split_camelcase = re.sub('(?!^)([A-Z][a-z]+)', r' \1', prop_class).split()
    prop_class = ' '.join(split_camelcase)
    return prop_class


class STIXPropertyDocumenter(ClassDocumenter):
    """Custom Sphinx extension to auto-document STIX properties.

    Needed because descendants of _STIXBase use `_properties` dictionaries
    instead of instance variables for STIX 2 objects' properties.

    """
    objtype = 'stixattr'
    directivetype = 'class'
    priority = 999

    @classmethod
    def can_document_member(cls, member, membername, isattr, parent):
        return isinstance(member, type) and \
               issubclass(member, _STIXBase) and \
               hasattr(member, '_properties')

    def add_content(self, more_content):
        ClassDocumenter.add_content(self, more_content)

        obj = self.object
        self.add_line(':Properties:', '<stixattr>')
        for prop_name, prop in obj._properties.items():
            # Skip 'type'
            if prop_name == 'type':
                continue

            # Add metadata about the property
            prop_type = get_property_type(prop)
            if prop_type == 'List':
                prop_type = 'List of %ss' % get_property_type(prop.contained)
            if prop.required:
                prop_type += ', required'
            if 'Timestamp' in prop_type and hasattr(prop, 'default'):
                prop_type += ', default: current date/time'
            prop_str = '**%s** (*%s*)' % (prop_name, prop_type)
            self.add_line('    - %s' % prop_str, '<stixattr>')

        self.add_line('', '<stixattr>')


def autodoc_skipper(app, what, name, obj, skip, options):
    """Customize Sphinx to skip some member we don't want documented.

    Skips anything containing ':autodoc-skip:' in its docstring.
    """
    if obj.__doc__ and ':autodoc-skip:' in obj.__doc__:
        return skip or True
    return skip


def setup(app):
    app.add_autodocumenter(STIXPropertyDocumenter)
    app.connect('autodoc-skip-member', autodoc_skipper)
