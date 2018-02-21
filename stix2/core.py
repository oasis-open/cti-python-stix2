"""STIX 2.0 Objects that are neither SDOs nor SROs."""

from collections import OrderedDict
import importlib
import pkgutil

import stix2

from . import exceptions
from .base import _STIXBase
from .properties import IDProperty, ListProperty, Property, TypeProperty
from .utils import get_class_hierarchy_names, get_dict


class STIXObjectProperty(Property):

    def __init__(self, allow_custom=False):
        self.allow_custom = allow_custom
        super(STIXObjectProperty, self).__init__()

    def clean(self, value):
        # Any STIX Object (SDO, SRO, or Marking Definition) can be added to
        # a bundle with no further checks.
        if any(x in ('STIXDomainObject', 'STIXRelationshipObject', 'MarkingDefinition')
               for x in get_class_hierarchy_names(value)):
            return value
        try:
            dictified = get_dict(value)
        except ValueError:
            raise ValueError("This property may only contain a dictionary or object")
        if dictified == {}:
            raise ValueError("This property may only contain a non-empty dictionary or object")
        if 'type' in dictified and dictified['type'] == 'bundle':
            raise ValueError('This property may not contain a Bundle object')

        if self.allow_custom:
            parsed_obj = parse(dictified, allow_custom=True)
        else:
            parsed_obj = parse(dictified)
        return parsed_obj


class Bundle(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part1-stix-core/stix-v2.0-cs01-part1-stix-core.html#_Toc496709293>`__.
    """

    _type = 'bundle'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('spec_version', Property(fixed="2.0")),
        ('objects', ListProperty(STIXObjectProperty)),
    ])

    def __init__(self, *args, **kwargs):
        # Add any positional arguments to the 'objects' kwarg.
        if args:
            if isinstance(args[0], list):
                kwargs['objects'] = args[0] + list(args[1:]) + kwargs.get('objects', [])
            else:
                kwargs['objects'] = list(args) + kwargs.get('objects', [])

        allow_custom = kwargs.get('allow_custom', False)
        if allow_custom:
            self._properties['objects'] = ListProperty(STIXObjectProperty(True))

        super(Bundle, self).__init__(**kwargs)


STIX2_OBJ_MAPS = {}


def parse(data, allow_custom=False, version=None):
    """Deserialize a string or file-like object into a STIX object.

    Args:
        data (str, dict, file-like object): The STIX 2 content to be parsed.
        allow_custom (bool): Whether to allow custom properties or not.
            Default: False.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    Returns:
        An instantiated Python STIX object.

    """
    if not version:
        # Use latest version
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')
    else:
        v = 'v' + version.replace('.', '')

    OBJ_MAP = STIX2_OBJ_MAPS[v]
    obj = get_dict(data)

    if 'type' not in obj:
        raise exceptions.ParseError("Can't parse object with no 'type' property: %s" % str(obj))

    try:
        obj_class = OBJ_MAP[obj['type']]
    except KeyError:
        raise exceptions.ParseError("Can't parse unknown object type '%s'! For custom types, use the CustomObject decorator." % obj['type'])
    return obj_class(allow_custom=allow_custom, **obj)


def _register_type(new_type, version=None):
    """Register a custom STIX Object type.

    Args:
        new_type (class): A class to register in the Object map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.
    """
    if not version:
        # Use latest version
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')
    else:
        v = 'v' + version.replace('.', '')

    OBJ_MAP = STIX2_OBJ_MAPS[v]
    OBJ_MAP[new_type._type] = new_type


def _collect_stix2_obj_maps():
    """Navigate the package once and retrieve all OBJ_MAP dicts for each v2X
    package."""
    if not STIX2_OBJ_MAPS:
        top_level_module = importlib.import_module('stix2')
        path = top_level_module.__path__
        prefix = str(top_level_module.__name__) + '.'

        for module_loader, name, is_pkg in pkgutil.walk_packages(path=path,
                                                                 prefix=prefix):
            if name.startswith('stix2.v2') and is_pkg:
                mod = importlib.import_module(name, str(top_level_module.__name__))
                STIX2_OBJ_MAPS[name.split('.')[-1]] = mod.OBJ_MAP
