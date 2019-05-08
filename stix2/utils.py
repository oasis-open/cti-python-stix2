"""Utility functions and classes for the STIX2 library."""

from collections import Mapping
import copy
import datetime as dt
import json

from dateutil import parser
import pytz

import stix2.base

from .exceptions import (
    InvalidValueError, RevokeError, UnmodifiablePropertyError,
)

# Sentinel value for properties that should be set to the current time.
# We can't use the standard 'default' approach, since if there are multiple
# timestamps in a single object, the timestamps will vary by a few microseconds.
NOW = object()

# STIX object properties that cannot be modified
STIX_UNMOD_PROPERTIES = ['created', 'created_by_ref', 'id', 'type']

TYPE_REGEX = r'^\-?[a-z0-9]+(-[a-z0-9]+)*\-?$'


class STIXdatetime(dt.datetime):
    def __new__(cls, *args, **kwargs):
        precision = kwargs.pop('precision', None)
        if isinstance(args[0], dt.datetime):  # Allow passing in a datetime object
            dttm = args[0]
            args = (
                dttm.year, dttm.month, dttm.day, dttm.hour, dttm.minute,
                dttm.second, dttm.microsecond, dttm.tzinfo,
            )
        # self will be an instance of STIXdatetime, not dt.datetime
        self = dt.datetime.__new__(cls, *args, **kwargs)
        self.precision = precision
        return self

    def __repr__(self):
        return "'%s'" % format_datetime(self)


def deduplicate(stix_obj_list):
    """Deduplicate a list of STIX objects to a unique set.

    Reduces a set of STIX objects to unique set by looking
    at 'id' and 'modified' fields - as a unique object version
    is determined by the combination of those fields

    Note: Be aware, as can be seen in the implementation
    of deduplicate(),that if the "stix_obj_list" argument has
    multiple STIX objects of the same version, the last object
    version found in the list will be the one that is returned.

    Args:
        stix_obj_list (list): list of STIX objects (dicts)

    Returns:
        A list with a unique set of the passed list of STIX objects.

    """
    unique_objs = {}

    for obj in stix_obj_list:
        try:
            unique_objs[(obj['id'], obj['modified'])] = obj
        except KeyError:
            # Handle objects with no `modified` property, e.g. marking-definition
            unique_objs[(obj['id'], obj['created'])] = obj

    return list(unique_objs.values())


def get_timestamp():
    """Return a STIX timestamp of the current date and time."""
    return STIXdatetime.now(tz=pytz.UTC)


def format_datetime(dttm):
    """Convert a datetime object into a valid STIX timestamp string.

    1. Convert to timezone-aware
    2. Convert to UTC
    3. Format in ISO format
    4. Ensure correct precision
       a. Add subsecond value if non-zero and precision not defined
    5. Add "Z"

    """

    if dttm.tzinfo is None or dttm.tzinfo.utcoffset(dttm) is None:
        # dttm is timezone-naive; assume UTC
        zoned = pytz.utc.localize(dttm)
    else:
        zoned = dttm.astimezone(pytz.utc)
    ts = zoned.strftime('%Y-%m-%dT%H:%M:%S')
    ms = zoned.strftime('%f')
    precision = getattr(dttm, 'precision', None)
    if precision == 'second':
        pass  # Already precise to the second
    elif precision == 'millisecond':
        ts = ts + '.' + ms[:3]
    elif zoned.microsecond > 0:
        ts = ts + '.' + ms.rstrip('0')
    return ts + 'Z'


def parse_into_datetime(value, precision=None):
    """Parse a value into a valid STIX timestamp object.
    """
    if isinstance(value, dt.date):
        if hasattr(value, 'hour'):
            ts = value
        else:
            # Add a time component
            ts = dt.datetime.combine(value, dt.time(0, 0, tzinfo=pytz.utc))
    else:
        # value isn't a date or datetime object so assume it's a string
        try:
            parsed = parser.parse(value)
        except (TypeError, ValueError):
            # Unknown format
            raise ValueError(
                "must be a datetime object, date object, or "
                "timestamp string in a recognizable format.",
            )
        if parsed.tzinfo:
            ts = parsed.astimezone(pytz.utc)
        else:
            # Doesn't have timezone info in the string; assume UTC
            ts = pytz.utc.localize(parsed)

    # Ensure correct precision
    if not precision:
        return STIXdatetime(ts, precision=precision)
    ms = ts.microsecond
    if precision == 'second':
        ts = ts.replace(microsecond=0)
    elif precision == 'millisecond':
        ms_len = len(str(ms))
        if ms_len > 3:
            # Truncate to millisecond precision
            factor = 10 ** (ms_len - 3)
            ts = ts.replace(microsecond=(ts.microsecond // factor) * factor)
        else:
            ts = ts.replace(microsecond=0)
    return STIXdatetime(ts, precision=precision)


def _get_dict(data):
    """Return data as a dictionary.

    Input can be a dictionary, string, or file-like object.
    """

    if type(data) is dict:
        return data
    else:
        try:
            return json.loads(data)
        except TypeError:
            pass
        try:
            return json.load(data)
        except AttributeError:
            pass
        try:
            return dict(data)
        except (ValueError, TypeError):
            raise ValueError("Cannot convert '%s' to dictionary." % str(data))


def _find(seq, val):
    """
    Search sequence 'seq' for val.  This behaves like str.find(): if not found,
    -1 is returned instead of throwing an exception.

    Args:
        seq: The sequence to search
        val: The value to search for

    Returns:
        int: The index of the value if found, or -1 if not found
    """
    try:
        return seq.index(val)
    except ValueError:
        return -1


def _find_property_in_seq(seq, search_key, search_value):
    """
    Helper for find_property_index(): search for the property in all elements
    of the given sequence.

    Args:
        seq: The sequence
        search_key: Property name to find
        search_value: Property value to find

    Returns:
        int: A property index, or -1 if the property was not found
    """
    idx = -1
    for elem in seq:
        idx = find_property_index(elem, search_key, search_value)
        if idx >= 0:
            break

    return idx


def find_property_index(obj, search_key, search_value):
    """
    Search (recursively) for the given key and value in the given object.
    Return an index for the key, relative to whatever object it's found in.

    Args:
        obj: The object to search (list, dict, or stix object)
        search_key: A search key
        search_value: A search value

    Returns:
        int: An index; -1 if the key and value aren't found
    """
    from .base import _STIXBase

    # Special-case keys which are numbers-as-strings, e.g. for cyber-observable
    # mappings.  Use the int value of the key as the index.
    if search_key.isdigit():
        return int(search_key)

    if isinstance(obj, _STIXBase):
        if search_key in obj and obj[search_key] == search_value:
            idx = _find(obj.object_properties(), search_key)
        else:
            idx = _find_property_in_seq(obj.values(), search_key, search_value)
    elif isinstance(obj, dict):
        if search_key in obj and obj[search_key] == search_value:
            idx = _find(sorted(obj), search_key)
        else:
            idx = _find_property_in_seq(obj.values(), search_key, search_value)
    elif isinstance(obj, list):
        idx = _find_property_in_seq(obj, search_key, search_value)
    else:
        # Don't know how to search this type
        idx = -1

    return idx


def new_version(data, **kwargs):
    """Create a new version of a STIX object, by modifying properties and
    updating the ``modified`` property.
    """

    if not isinstance(data, Mapping):
        raise ValueError(
            "cannot create new version of object of this type! "
            "Try a dictionary or instance of an SDO or SRO class.",
        )

    unchangable_properties = []
    if data.get('revoked'):
        raise RevokeError("new_version")
    try:
        new_obj_inner = copy.deepcopy(data._inner)
    except AttributeError:
        new_obj_inner = copy.deepcopy(data)
    properties_to_change = kwargs.keys()

    # Make sure certain properties aren't trying to change
    for prop in STIX_UNMOD_PROPERTIES:
        if prop in properties_to_change:
            unchangable_properties.append(prop)
    if unchangable_properties:
        raise UnmodifiablePropertyError(unchangable_properties)

    cls = type(data)
    if 'modified' not in kwargs:
        kwargs['modified'] = get_timestamp()
    elif 'modified' in data:
        old_modified_property = parse_into_datetime(data.get('modified'), precision='millisecond')
        new_modified_property = parse_into_datetime(kwargs['modified'], precision='millisecond')
        if new_modified_property <= old_modified_property:
            raise InvalidValueError(
                cls, 'modified',
                "The new modified datetime cannot be before than or equal to the current modified datetime."
                "It cannot be equal, as according to STIX 2 specification, objects that are different "
                "but have the same id and modified timestamp do not have defined consumer behavior.",
            )
    new_obj_inner.update(kwargs)
    # Exclude properties with a value of 'None' in case data is not an instance of a _STIXBase subclass
    return cls(**{k: v for k, v in new_obj_inner.items() if v is not None})


def revoke(data):
    """Revoke a STIX object.

    Returns:
        A new version of the object with ``revoked`` set to ``True``.
    """
    if not isinstance(data, Mapping):
        raise ValueError(
            "cannot revoke object of this type! Try a dictionary "
            "or instance of an SDO or SRO class.",
        )

    if data.get('revoked'):
        raise RevokeError("revoke")
    return new_version(data, revoked=True, allow_custom=True)


def get_class_hierarchy_names(obj):
    """Given an object, return the names of the class hierarchy."""
    names = []
    for cls in obj.__class__.__mro__:
        names.append(cls.__name__)
    return names


def remove_custom_stix(stix_obj):
    """Remove any custom STIX objects or properties.

    Warnings:
        This function is a best effort utility, in that it will remove custom
        objects and properties based on the type names; i.e. if "x-" prefixes
        object types, and "x\\_" prefixes property types. According to the
        STIX2 spec, those naming conventions are a SHOULDs not MUSTs, meaning
        that valid custom STIX content may ignore those conventions and in
        effect render this utility function invalid when used on that STIX
        content.

    Args:
        stix_obj (dict OR python-stix obj): a single python-stix object
                                             or dict of a STIX object

    Returns:
        A new version of the object with any custom content removed
    """

    if stix_obj['type'].startswith('x-'):
        # if entire object is custom, discard
        return None

    custom_props = []
    for prop in stix_obj.items():
        if prop[0].startswith('x_'):
            # for every custom property, record it and set value to None
            # (so we can pass it to new_version() and it will be dropped)
            custom_props.append((prop[0], None))

    if custom_props:
        # obtain set of object properties that can be transferred
        # to a new object version. This is 1)custom props with their
        # values set to None, and 2)any properties left that are not
        # unmodifiable STIX properties or the "modified" property

        # set of properties that are not supplied to new_version()
        # to be used for updating properties. This includes unmodifiable
        # properties (properties that new_version() just re-uses from the
        # existing STIX object) and the "modified" property. We dont supply the
        # "modified" property so that new_version() creates a new datetime
        # value for this property
        non_supplied_props = STIX_UNMOD_PROPERTIES + ['modified']

        props = [(prop, stix_obj[prop]) for prop in stix_obj if prop not in non_supplied_props]

        # add to set the custom properties we want to get rid of (with their value=None)
        props.extend(custom_props)

        new_obj = new_version(stix_obj, **(dict(props)))

        while parse_into_datetime(new_obj['modified']) == parse_into_datetime(stix_obj['modified']):
            # Prevents bug when fast computation allows multiple STIX object
            # versions to be created in single unit of time
            new_obj = new_version(stix_obj, **(dict(props)))

        return new_obj

    else:
        return stix_obj


def get_type_from_id(stix_id):
    return stix_id.split('--', 1)[0]


def is_marking(obj_or_id):
    """Determines whether the given object or object ID is/is for a marking
    definition.

    :param obj_or_id: A STIX object or object ID as a string.
    :return: True if a marking definition, False otherwise.
    """

    if isinstance(obj_or_id, (stix2.base._STIXBase, dict)):
        result = obj_or_id["type"] == "marking-definition"
    else:
        # it's a string ID
        result = obj_or_id.startswith("marking-definition--")

    return result
