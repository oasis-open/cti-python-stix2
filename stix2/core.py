import importlib
import pkgutil

import stix2

from . import exceptions
from .utils import _get_dict

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
            version: If version can't be determined from stix_dict, use this
                version of the STIX spec.  If None, use the latest supported
                version.  Default: None

        Returns:
            An instantiated Python STIX object

        WARNING: 'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types (both STIX2
        domain objects or defined custom STIX2 objects); NO validation is done. This is
        done to allow the processing of possibly unknown custom STIX objects (example
        scenario: I need to query a third-party TAXII endpoint that could provide custom
        STIX objects that I dont know about ahead of time)

    """
    if 'type' not in stix_dict:
        raise exceptions.ParseError("Can't parse object with no 'type' property: %s" % str(stix_dict))

    if "spec_version" in stix_dict:
        # For STIX 2.0, applies to bundles only.
        # For STIX 2.1+, applies to SDOs, SROs, and markings only.
        v = 'v' + stix_dict["spec_version"].replace('.', '')
    elif stix_dict["type"] == "bundle":
        # bundles without spec_version are ambiguous.
        if version:
            v = 'v' + version.replace('.', '')
        else:
            v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')
    else:
        v = 'v20'

    OBJ_MAP = STIX2_OBJ_MAPS[v]

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
