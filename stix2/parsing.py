"""STIX2 Core Objects and Methods."""

import copy
import importlib
import pkgutil
import re

import stix2

from .base import _DomainObject, _Observable
from .exceptions import DuplicateRegistrationError, ParseError
from .utils import PREFIX_21_REGEX, _get_dict, get_class_hierarchy_names

STIX2_OBJ_MAPS = {}


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


def _detect_spec_version(stix_dict):
    """
    Given a dict representing a STIX object, try to detect what spec version
    it is likely to comply with.

    :param stix_dict: A dict with some STIX content.  Must at least have a
        "type" property.
    :return: A string in "vXX" format, where "XX" indicates the spec version,
        e.g. "v20", "v21", etc.
    """

    obj_type = stix_dict["type"]

    if 'spec_version' in stix_dict:
        # For STIX 2.0, applies to bundles only.
        # For STIX 2.1+, applies to SCOs, SDOs, SROs, and markings only.
        v = 'v' + stix_dict['spec_version'].replace('.', '')
    elif "id" not in stix_dict:
        # Only 2.0 SCOs don't have ID properties
        v = "v20"
    elif obj_type == 'bundle':
        # Bundle without a spec_version property: must be 2.1.  But to
        # future-proof, use max version over all contained SCOs, with 2.1
        # minimum.
        v = max(
            "v21",
            max(
                _detect_spec_version(obj) for obj in stix_dict["objects"]
            ),
        )
    elif obj_type in STIX2_OBJ_MAPS["v21"]["observables"]:
        # Non-bundle object with an ID and without spec_version.  Could be a
        # 2.1 SCO or 2.0 SDO/SRO/marking.  Check for 2.1 SCO...
        v = "v21"
    else:
        # Not a 2.1 SCO; must be a 2.0 object.
        v = "v20"

    return v


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
    else:
        v = _detect_spec_version(stix_dict)

    OBJ_MAP = dict(STIX2_OBJ_MAPS[v]['objects'], **STIX2_OBJ_MAPS[v]['observables'])

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

    if 'type' not in obj:
        raise ParseError("Can't parse observable with no 'type' property: %s" % str(obj))

    # get deep copy since we are going modify the dict and might
    # modify the original dict as _get_dict() does not return new
    # dict when passed a dict
    obj = copy.deepcopy(obj)

    obj['_valid_refs'] = _valid_refs or []

    if version:
        # If the version argument was passed, override other approaches.
        v = 'v' + version.replace('.', '')
    else:
        v = _detect_spec_version(obj)

    try:
        OBJ_MAP_OBSERVABLE = STIX2_OBJ_MAPS[v]['observables']
        obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
    except KeyError:
        if allow_custom:
            # flag allows for unknown custom objects too, but will not
            # be parsed into STIX observable object, just returned as is
            return obj
        raise ParseError("Can't parse unknown observable type '%s'! For custom observables, "
                         "use the CustomObservable decorator." % obj['type'])

    return obj_class(allow_custom=allow_custom, **obj)


def _register_object(new_type, version=stix2.DEFAULT_VERSION):
    """Register a custom STIX Object type.

    Args:
        new_type (class): A class to register in the Object map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    Raises:
        ValueError: If the class being registered wasn't created with the
            @CustomObject decorator.
        DuplicateRegistrationError: If the class has already been registered.

    """

    if not issubclass(new_type, _DomainObject):
        raise ValueError(
            "'%s' must be created with the @CustomObject decorator." %
            new_type.__name__,
        )

    properties = new_type._properties

    if version == "2.1":
        for prop_name, prop in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character" % prop_name)

    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP = STIX2_OBJ_MAPS[v]['objects']
    if new_type._type in OBJ_MAP.keys():
        raise DuplicateRegistrationError("STIX Object", new_type._type)
    OBJ_MAP[new_type._type] = new_type


def _register_marking(new_marking, version=stix2.DEFAULT_VERSION):
    """Register a custom STIX Marking Definition type.

    Args:
        new_marking (class): A class to register in the Marking map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """

    mark_type = new_marking._type
    properties = new_marking._properties

    stix2.properties._validate_type(mark_type, version)

    if version == "2.1":
        for prop_name, prop_value in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)

    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP_MARKING = STIX2_OBJ_MAPS[v]['markings']
    if mark_type in OBJ_MAP_MARKING.keys():
        raise DuplicateRegistrationError("STIX Marking", mark_type)
    OBJ_MAP_MARKING[mark_type] = new_marking


def _register_observable(new_observable, version=stix2.DEFAULT_VERSION):
    """Register a custom STIX Cyber Observable type.

    Args:
        new_observable (class): A class to register in the Observables map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
            None, use latest version.

    """
    properties = new_observable._properties

    if version == "2.0":
        # If using STIX2.0, check properties ending in "_ref/s" are ObjectReferenceProperties
        for prop_name, prop in properties.items():
            if prop_name.endswith('_ref') and ('ObjectReferenceProperty' not in get_class_hierarchy_names(prop)):
                raise ValueError(
                    "'%s' is named like an object reference property but "
                    "is not an ObjectReferenceProperty." % prop_name,
                )
            elif (prop_name.endswith('_refs') and ('ListProperty' not in get_class_hierarchy_names(prop) or
                                                   'ObjectReferenceProperty' not in get_class_hierarchy_names(prop.contained))):
                raise ValueError(
                    "'%s' is named like an object reference list property but "
                    "is not a ListProperty containing ObjectReferenceProperty." % prop_name,
                )
    else:
        # If using STIX2.1 (or newer...), check properties ending in "_ref/s" are ReferenceProperties
        for prop_name, prop in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)
            elif prop_name.endswith('_ref') and ('ReferenceProperty' not in get_class_hierarchy_names(prop)):
                raise ValueError(
                    "'%s' is named like a reference property but "
                    "is not a ReferenceProperty." % prop_name,
                )
            elif (prop_name.endswith('_refs') and ('ListProperty' not in get_class_hierarchy_names(prop) or
                                                   'ReferenceProperty' not in get_class_hierarchy_names(prop.contained))):
                raise ValueError(
                    "'%s' is named like a reference list property but "
                    "is not a ListProperty containing ReferenceProperty." % prop_name,
                )

    if version:
        v = 'v' + version.replace('.', '')
    else:
        # Use default version (latest) if no version was provided.
        v = 'v' + stix2.DEFAULT_VERSION.replace('.', '')

    OBJ_MAP_OBSERVABLE = STIX2_OBJ_MAPS[v]['observables']
    if new_observable._type in OBJ_MAP_OBSERVABLE.keys():
        raise DuplicateRegistrationError("Cyber Observable", new_observable._type)
    OBJ_MAP_OBSERVABLE[new_observable._type] = new_observable


def _register_observable_extension(
    observable, new_extension, version=stix2.DEFAULT_VERSION,
):
    """Register a custom extension to a STIX Cyber Observable type.

    Args:
        observable: An observable class or instance
        new_extension (class): A class to register in the Observables
            Extensions map.
        version (str): Which STIX2 version to use. (e.g. "2.0", "2.1").
            Defaults to the latest supported version.

    """
    obs_class = observable if isinstance(observable, type) else \
        type(observable)
    ext_type = new_extension._type
    properties = new_extension._properties

    if not issubclass(obs_class, _Observable):
        raise ValueError("'observable' must be a valid Observable class!")

    stix2.properties._validate_type(ext_type, version)

    if not new_extension._properties:
        raise ValueError(
            "Invalid extension: must define at least one property: " +
            ext_type,
        )

    if version == "2.1":
        if not ext_type.endswith('-ext'):
            raise ValueError(
                "Invalid extension type name '%s': must end with '-ext'." %
                ext_type,
            )

        for prop_name, prop_value in properties.items():
            if not re.match(PREFIX_21_REGEX, prop_name):
                raise ValueError("Property name '%s' must begin with an alpha character." % prop_name)

    v = 'v' + version.replace('.', '')

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
        if ext_type in EXT_MAP[observable_type].keys():
            raise DuplicateRegistrationError("Observable Extension", ext_type)
        EXT_MAP[observable_type][ext_type] = new_extension
    except KeyError:
        if observable_type not in OBJ_MAP_OBSERVABLE:
            raise ValueError(
                "Unknown observable type '%s'. Custom observables "
                "must be created with the @CustomObservable decorator."
                % observable_type,
            )
        else:
            EXT_MAP[observable_type] = {ext_type: new_extension}


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
