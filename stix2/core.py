"""STIX 2.0 Objects that are neither SDOs nor SROs."""

from collections import OrderedDict
import importlib
import pkgutil

import stix2

from . import exceptions
from .base import _STIXBase
from .properties import IDProperty, ListProperty, Property, TypeProperty
from .utils import _get_dict, get_class_hierarchy_names


class STIXObjectProperty(Property):

    def __init__(self, allow_custom=False, *args, **kwargs):
        self.allow_custom = allow_custom
        super(STIXObjectProperty, self).__init__(*args, **kwargs)

    def clean(self, value):
        # Any STIX Object (SDO, SRO, or Marking Definition) can be added to
        # a bundle with no further checks.
        if any(x in ('STIXDomainObject', 'STIXRelationshipObject', 'MarkingDefinition')
               for x in get_class_hierarchy_names(value)):
            return value
        try:
            dictified = _get_dict(value)
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

        self.__allow_custom = kwargs.get('allow_custom', False)
        self._properties['objects'].contained.allow_custom = kwargs.get('allow_custom', False)

        super(Bundle, self).__init__(**kwargs)


STIX2_OBJ_MAPS = {}


def parse(data, allow_custom=False, version=None):
    """Convert a string, dict or file-like object into a STIX object.

    Args:
        data (str, dict, file-like object): The STIX 2 content to be parsed.
        allow_custom (bool): Whether to allow custom properties as well unknown
            custom objects. Note that unknown custom objects cannot be parsed
            into STIX objects, and will be returned as is. Default: False.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    Returns:
        An instantiated Python STIX object.

    WARNING: 'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types (both STIX2
        domain objects or defined custom STIX2 objects); NO validation is done. This is
        done to allow the processing of possibly unknown custom STIX objects (example
        scenario: I need to query a third-party TAXII endpoint that could provide custom
        STIX objects that I dont know about ahead of time)

    """
    # convert STIX object to dict, if not already
    obj = _get_dict(data)

    # convert dict to full python-stix2 obj
    obj = dict_to_stix2(obj, allow_custom, version)

    return obj


def dict_to_stix2(stix_dict, allow_custom=False, version=None):
    """convert dictionary to full python-stix2 object

        Args:
            stix_dict (dict): a python dictionary of a STIX object
                that (presumably) is semantically correct to be parsed
                into a full python-stix2 obj
            allow_custom (bool): Whether to allow custom properties as well unknown
                custom objects. Note that unknown custom objects cannot be parsed
                into STIX objects, and will be returned as is. Default: False.

        Returns:
            An instantiated Python STIX object

        WARNING: 'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types (both STIX2
        domain objects or defined custom STIX2 objects); NO validation is done. This is
        done to allow the processing of possibly unknown custom STIX objects (example
        scenario: I need to query a third-party TAXII endpoint that could provide custom
        STIX objects that I dont know about ahead of time)

    """
    if not version:
        # Use latest version
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')
    else:
        v = 'v' + version.replace('.', '')

    OBJ_MAP = STIX2_OBJ_MAPS[v]

    if 'type' not in stix_dict:
        raise exceptions.ParseError("Can't parse object with no 'type' property: %s" % str(stix_dict))

    try:
        obj_class = OBJ_MAP[stix_dict['type']]
    except KeyError:
        if allow_custom:
            # flag allows for unknown custom objects too, but will not
            # be parsed into STIX object, returned as is
            return stix_dict
        raise exceptions.ParseError("Can't parse unknown object type '%s'! For custom types, use the CustomObject decorator." % stix_dict['type'])

    return obj_class(allow_custom=allow_custom, **stix_dict)


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
