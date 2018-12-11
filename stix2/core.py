"""STIX2 Core Objects and Methods."""

import copy
import importlib
import pkgutil
import re

import stix2

from .base import _STIXBase
from .exceptions import CustomContentError, ParseError
from .markings import _MarkingsMixin
from .utils import _get_dict

STIX2_OBJ_MAPS = {}


class STIXDomainObject(_STIXBase, _MarkingsMixin):
    pass


class STIXRelationshipObject(_STIXBase, _MarkingsMixin):
    pass


def parse(data, allow_custom=False, version=None):
    """Convert a string, dict or file-like object into a STIX object.

    Args:
        data (str, dict, file-like object): The STIX 2 content to be parsed.
        allow_custom (bool): Whether to allow custom properties as well unknown
            custom objects. Note that unknown custom objects cannot be parsed
            into STIX objects, and will be returned as is. Default: False.
        version (str): If present, it forces the parser to use the version
            provided. Otherwise, the library will make the best effort based
            on checking the "spec_version" property. If none of the above are
            possible, it will use the default version specified by the library.

    Returns:
        An instantiated Python STIX object.

    Warnings:
        'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types
        (both STIX2 domain objects or defined custom STIX2 objects); NO
        validation is done. This is done to allow the processing of possibly
        unknown custom STIX objects (example scenario: I need to query a
        third-party TAXII endpoint that could provide custom STIX objects that
        I don't know about ahead of time)

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
        allow_custom (bool): Whether to allow custom properties as well
            unknown custom objects. Note that unknown custom objects cannot
            be parsed into STIX objects, and will be returned as is.
            Default: False.
        version (str): If present, it forces the parser to use the version
            provided. Otherwise, the library will make the best effort based
            on checking the "spec_version" property. If none of the above are
            possible, it will use the default version specified by the library.

    Returns:
        An instantiated Python STIX object

    Warnings:
        'allow_custom=True' will allow for the return of any supplied STIX
        dict(s) that cannot be found to map to any known STIX object types
        (both STIX2 domain objects or defined custom STIX2 objects); NO
        validation is done. This is done to allow the processing of
        possibly unknown custom STIX objects (example scenario: I need to
        query a third-party TAXII endpoint that could provide custom STIX
        objects that I don't know about ahead of time)

    """
    if 'type' not in stix_dict:
        raise ParseError("Can't parse object with no 'type' property: %s" % str(stix_dict))

    if version:
        # If the version argument was passed, override other approaches.
        v = 'v' + version.replace('.', '')
    elif 'spec_version' in stix_dict:
        # For STIX 2.0, applies to bundles only.
        # For STIX 2.1+, applies to SDOs, SROs, and markings only.
        v = 'v' + stix_dict['spec_version'].replace('.', '')
    elif stix_dict['type'] == 'bundle':
        # bundles without spec_version are ambiguous.
        if any('spec_version' in x for x in stix_dict['objects']):
            # Only on 2.1 we are allowed to have 'spec_version' in SDOs/SROs.
            v = 'v21'
        else:
            v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')
    else:
        # The spec says that SDO/SROs without spec_version will default to a
        # '2.0' representation.
        v = 'v20'

    OBJ_MAP = STIX2_OBJ_MAPS[v]['objects']

    try:
        obj_class = OBJ_MAP[stix_dict['type']]
    except KeyError:
        if allow_custom:
            # flag allows for unknown custom objects too, but will not
            # be parsed into STIX object, returned as is
            return stix_dict
        raise ParseError("Can't parse unknown object type '%s'! For custom types, use the CustomObject decorator." % stix_dict['type'])

    return obj_class(allow_custom=allow_custom, **stix_dict)


def parse_observable(data, _valid_refs=None, allow_custom=False, version=None):
    """Deserialize a string or file-like object into a STIX Cyber Observable
    object.

    Args:
        data (str, dict, file-like object): The STIX2 content to be parsed.
        _valid_refs: A list of object references valid for the scope of the
            object being parsed. Use empty list if no valid refs are present.
        allow_custom (bool): Whether to allow custom properties or not.
            Default: False.
        version (str): If present, it forces the parser to use the version
            provided. Otherwise, the default version specified by the library
            will be used.

    Returns:
        An instantiated Python STIX Cyber Observable object.

    """
    obj = _get_dict(data)
    # get deep copy since we are going modify the dict and might
    # modify the original dict as _get_dict() does not return new
    # dict when passed a dict
    obj = copy.deepcopy(obj)

    obj['_valid_refs'] = _valid_refs or []

    if version:
        # If the version argument was passed, override other approaches.
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    if 'type' not in obj:
        raise ParseError("Can't parse observable with no 'type' property: %s" % str(obj))
    try:
        OBJ_MAP_OBSERVABLE = STIX2_OBJ_MAPS[v]['observables']
        obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
    except KeyError:
        if allow_custom:
            # flag allows for unknown custom objects too, but will not
            # be parsed into STIX observable object, just returned as is
            return obj
        raise CustomContentError("Can't parse unknown observable type '%s'! For custom observables, "
                                 "use the CustomObservable decorator." % obj['type'])

    EXT_MAP = STIX2_OBJ_MAPS[v]['observable-extensions']

    if 'extensions' in obj and obj['type'] in EXT_MAP:
        for name, ext in obj['extensions'].items():
            try:
                ext_class = EXT_MAP[obj['type']][name]
            except KeyError:
                if not allow_custom:
                    raise CustomContentError("Can't parse unknown extension type '%s'"
                                             "for observable type '%s'!" % (name, obj['type']))
            else:  # extension was found
                obj['extensions'][name] = ext_class(allow_custom=allow_custom, **obj['extensions'][name])

    return obj_class(allow_custom=allow_custom, **obj)


def _register_object(new_type, version=None):
    """Register a custom STIX Object type.

    Args:
        new_type (class): A class to register in the Object map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP = STIX2_OBJ_MAPS[v]['objects']
    OBJ_MAP[new_type._type] = new_type


def _register_marking(new_marking, version=None):
    """Register a custom STIX Marking Definition type.

    Args:
        new_marking (class): A class to register in the Marking map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP_MARKING = STIX2_OBJ_MAPS[v]['markings']
    OBJ_MAP_MARKING[new_marking._type] = new_marking


def _register_observable(new_observable, version=None):
    """Register a custom STIX Cyber Observable type.

    Args:
        new_observable (class): A class to register in the Observables map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP_OBSERVABLE = STIX2_OBJ_MAPS[v]['observables']
    OBJ_MAP_OBSERVABLE[new_observable._type] = new_observable


def _register_observable_extension(observable, new_extension, version=None):
    """Register a custom extension to a STIX Cyber Observable type.

    Args:
        observable: An observable object
        new_extension (class): A class to register in the Observables
            Extensions map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    try:
        observable_type = observable._type
    except AttributeError:
        raise ValueError(
            "Unknown observable type. Custom observables must be "
            "created with the @CustomObservable decorator.",
        )

    OBJ_MAP_OBSERVABLE = STIX2_OBJ_MAPS[v]['observables']
    EXT_MAP = STIX2_OBJ_MAPS[v]['observable-extensions']

    try:
        EXT_MAP[observable_type][new_extension._type] = new_extension
    except KeyError:
        if observable_type not in OBJ_MAP_OBSERVABLE:
            raise ValueError(
                "Unknown observable type '%s'. Custom observables "
                "must be created with the @CustomObservable decorator."
                % observable_type,
            )
        else:
            EXT_MAP[observable_type] = {new_extension._type: new_extension}


def _collect_stix2_mappings():
    """Navigate the package once and retrieve all object mapping dicts for each
    v2X package. Includes OBJ_MAP, OBJ_MAP_OBSERVABLE, EXT_MAP."""
    if not STIX2_OBJ_MAPS:
        top_level_module = importlib.import_module('stix2')
        path = top_level_module.__path__
        prefix = str(top_level_module.__name__) + '.'

        for module_loader, name, is_pkg in pkgutil.walk_packages(path=path, prefix=prefix):
            ver = name.split('.')[1]
            if re.match(r'^stix2\.v2[0-9]$', name) and is_pkg:
                mod = importlib.import_module(name, str(top_level_module.__name__))
                STIX2_OBJ_MAPS[ver] = {}
                STIX2_OBJ_MAPS[ver]['objects'] = mod.OBJ_MAP
                STIX2_OBJ_MAPS[ver]['observables'] = mod.OBJ_MAP_OBSERVABLE
                STIX2_OBJ_MAPS[ver]['observable-extensions'] = mod.EXT_MAP
            elif re.match(r'^stix2\.v2[0-9]\.common$', name) and is_pkg is False:
                mod = importlib.import_module(name, str(top_level_module.__name__))
                STIX2_OBJ_MAPS[ver]['markings'] = mod.OBJ_MAP_MARKING
