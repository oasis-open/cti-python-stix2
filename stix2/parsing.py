"""STIX2 Core parsing methods."""

import copy

from . import registry
from .exceptions import ParseError
from .utils import _get_dict


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
    elif obj_type in registry.STIX2_OBJ_MAPS["v21"]["observables"]:
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

    OBJ_MAP = dict(
        registry.STIX2_OBJ_MAPS[v]['objects'],
        **registry.STIX2_OBJ_MAPS[v]['observables']
    )

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
        OBJ_MAP_OBSERVABLE = registry.STIX2_OBJ_MAPS[v]['observables']
        obj_class = OBJ_MAP_OBSERVABLE[obj['type']]
    except KeyError:
        if allow_custom:
            # flag allows for unknown custom objects too, but will not
            # be parsed into STIX observable object, just returned as is
            return obj
        raise ParseError(
            "Can't parse unknown observable type '%s'! For custom observables, "
            "use the CustomObservable decorator." % obj['type'],
        )

    return obj_class(allow_custom=allow_custom, **obj)
