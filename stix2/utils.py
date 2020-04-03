"""Utility functions and classes for the STIX2 library."""

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping
import copy
import datetime as dt
import enum
import json
import re

from dateutil import parser
import pytz
import six

import stix2

from .exceptions import (
    InvalidValueError, RevokeError, UnmodifiablePropertyError,
)

# Sentinel value for properties that should be set to the current time.
# We can't use the standard 'default' approach, since if there are multiple
# timestamps in a single object, the timestamps will vary by a few microseconds.
NOW = object()

# STIX object properties that cannot be modified
STIX_UNMOD_PROPERTIES = ['created', 'created_by_ref', 'id', 'type']

TYPE_REGEX = re.compile(r'^\-?[a-z0-9]+(-[a-z0-9]+)*\-?$')
TYPE_21_REGEX = re.compile(r'^([a-z][a-z0-9]*)+(-[a-z0-9]+)*\-?$')
PREFIX_21_REGEX = re.compile(r'^[a-z].*')


class Precision(enum.Enum):
    """
    Timestamp format precisions.
    """
    # auto() wasn't introduced until Python 3.6.
    ANY = 1
    SECOND = 2
    MILLISECOND = 3


class PrecisionConstraint(enum.Enum):
    """
    Timestamp precision constraints.  These affect how the Precision
    values are applied when formatting a timestamp.

    These constraints don't really make sense with the ANY precision, so they
    have no effect in that case.
    """
    EXACT = 1  # format must have exactly the given precision
    MIN = 2  # format must have at least the given precision
    #  no need for a MAX constraint yet


def _to_enum(value, enum_type, enum_default=None):
    """
    Detect and convert strings to enums and None to a default enum.  This
    allows use of strings and None in APIs, while enforcing the enum type: if
    you use a string, it must name a valid enum value.  This implementation is
    case-insensitive.

    :param value: A value to be interpreted as an enum (string, Enum instance,
        or None).  If an Enum instance, it must be an instance of enum_type.
    :param enum_type: The enum type which strings will be interpreted against
    :param enum_default: The default enum to use if value is None.  Must be
        an instance of enum_type, or None.  If None, you are disallowing a
        default and requiring that value be non-None.
    :return: An instance of enum_type
    :raises TypeError: If value was neither an instance of enum_type, None, nor
        a string
    :raises KeyError: If value was a string which couldn't be interpreted as an
        enum value from enum_type
    """
    assert enum_default is None or isinstance(enum_default, enum_type)

    if not isinstance(value, enum_type):
        if value is None and enum_default is not None:
            value = enum_default
        elif isinstance(value, six.string_types):
            value = enum_type[value.upper()]
        else:
            raise TypeError("Not a valid {}: {}".format(
                enum_type.__name__, value,
            ))

    return value


class STIXdatetime(dt.datetime):
    """
    Bundle a datetime with some format-related metadata, so that JSON
    serialization has the info it needs to produce compliant timestamps.
    """

    def __new__(cls, *args, **kwargs):
        precision = _to_enum(
            kwargs.pop("precision", Precision.ANY),
            Precision,
        )
        precision_constraint = _to_enum(
            kwargs.pop("precision_constraint", PrecisionConstraint.EXACT),
            PrecisionConstraint,
        )

        if isinstance(args[0], dt.datetime):  # Allow passing in a datetime object
            dttm = args[0]
            args = (
                dttm.year, dttm.month, dttm.day, dttm.hour, dttm.minute,
                dttm.second, dttm.microsecond, dttm.tzinfo,
            )
        # self will be an instance of STIXdatetime, not dt.datetime
        self = dt.datetime.__new__(cls, *args, **kwargs)
        self.precision = precision
        self.precision_constraint = precision_constraint
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
       a. Add subsecond value if warranted, according to precision settings
    5. Add "Z"

    """

    if dttm.tzinfo is None or dttm.tzinfo.utcoffset(dttm) is None:
        # dttm is timezone-naive; assume UTC
        zoned = pytz.utc.localize(dttm)
    else:
        zoned = dttm.astimezone(pytz.utc)
    ts = zoned.strftime('%Y-%m-%dT%H:%M:%S')
    precision = getattr(dttm, 'precision', Precision.ANY)
    precision_constraint = getattr(
        dttm, 'precision_constraint', PrecisionConstraint.EXACT,
    )

    frac_seconds_str = ""
    if precision == Precision.ANY:
        # No need to truncate; ignore constraint
        if zoned.microsecond:
            frac_seconds_str = "{:06d}".format(zoned.microsecond).rstrip("0")

    elif precision == Precision.SECOND:
        if precision_constraint == PrecisionConstraint.MIN:
            # second precision, or better.  Winds up being the same as ANY:
            # just use all our digits
            if zoned.microsecond:
                frac_seconds_str = "{:06d}".format(zoned.microsecond)\
                    .rstrip("0")
        # exact: ignore microseconds entirely

    else:
        # precision == millisecond
        if precision_constraint == PrecisionConstraint.EXACT:
            # can't rstrip() here or we may lose precision
            frac_seconds_str = "{:06d}".format(zoned.microsecond)[:3]

        else:
            # millisecond precision, or better.  So we can rstrip() zeros, but
            # only to a length of at least 3 digits (ljust() adds zeros back,
            # if it stripped too far.)
            frac_seconds_str = "{:06d}"\
                .format(zoned.microsecond)\
                .rstrip("0")\
                .ljust(3, "0")

    ts = "{}{}{}Z".format(
        ts,
        "." if frac_seconds_str else "",
        frac_seconds_str,
    )

    return ts


def parse_into_datetime(
    value, precision=Precision.ANY,
    precision_constraint=PrecisionConstraint.EXACT,
):
    """
    Parse a value into a valid STIX timestamp object.  Also, optionally adjust
    precision of fractional seconds.  This allows alignment with JSON
    serialization requirements, and helps ensure we're not using extra
    precision which would be lost upon JSON serialization.  The precision
    info will be embedded in the returned object, so that JSON serialization
    will format it correctly.

    :param value: A datetime.datetime or datetime.date instance, or a string
    :param precision: A precision value: either an instance of the Precision
        enum, or a string naming one of the enum values (case-insensitive)
    :param precision_constraint: A precision constraint value: either an
        instance of the PrecisionConstraint enum, or a string naming one of
        the enum values (case-insensitive)
    :return: A STIXdatetime instance, which is a datetime but also carries the
        precision info necessary to properly JSON-serialize it.
    """
    precision = _to_enum(precision, Precision)
    precision_constraint = _to_enum(precision_constraint, PrecisionConstraint)

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
    if precision == Precision.SECOND:
        if precision_constraint == PrecisionConstraint.EXACT:
            ts = ts.replace(microsecond=0)
        # else, no need to modify fractional seconds

    elif precision == Precision.MILLISECOND:
        if precision_constraint == PrecisionConstraint.EXACT:
            us = (ts.microsecond // 1000) * 1000
            ts = ts.replace(microsecond=us)
        # else: at least millisecond precision: the constraint will affect JSON
        # formatting, but there's nothing we need to do here.

    # else, precision == Precision.ANY: nothing for us to do.

    return STIXdatetime(
        ts, precision=precision, precision_constraint=precision_constraint,
    )


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
    # Special-case keys which are numbers-as-strings, e.g. for cyber-observable
    # mappings.  Use the int value of the key as the index.
    if search_key.isdigit():
        return int(search_key)

    if isinstance(obj, stix2.base._STIXBase):
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


def _fudge_modified(old_modified, new_modified, use_stix21):
    """
    Ensures a new modified timestamp is newer than the old.  When they are
    too close together, new_modified must be pushed further ahead to ensure
    it is distinct and later, after JSON serialization (which may mean it's
    actually being pushed a little ways into the future).  JSON serialization
    can remove precision, which can cause distinct timestamps to accidentally
    become equal, if we're not careful.

    :param old_modified: A previous "modified" timestamp, as a datetime object
    :param new_modified: A candidate new "modified" timestamp, as a datetime
        object
    :param use_stix21: Whether to use STIX 2.1+ versioning timestamp precision
        rules (boolean).  This is important so that we are aware of how
        timestamp precision will be truncated, so we know how close together
        the timestamps can be, and how far ahead to potentially push the new
        one.
    :return: A suitable new "modified" timestamp.  This may be different from
        what was passed in, if it had to be pushed ahead.
    """
    if use_stix21:
        # 2.1+: we can use full precision
        if new_modified <= old_modified:
            new_modified = old_modified + dt.timedelta(microseconds=1)
    else:
        # 2.0: we must use millisecond precision
        one_ms = dt.timedelta(milliseconds=1)
        if new_modified - old_modified < one_ms:
            new_modified = old_modified + one_ms

    return new_modified


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

    # Different versioning precision rules in STIX 2.0 vs 2.1, so we need
    # to know which rules to apply.
    is_21 = "spec_version" in data
    precision_constraint = "min" if is_21 else "exact"

    cls = type(data)
    if 'modified' not in kwargs:
        old_modified = parse_into_datetime(
            data["modified"], precision="millisecond",
            precision_constraint=precision_constraint,
        )

        new_modified = get_timestamp()
        new_modified = _fudge_modified(old_modified, new_modified, is_21)

        kwargs['modified'] = new_modified

    elif 'modified' in data:
        old_modified_property = parse_into_datetime(
            data.get('modified'), precision='millisecond',
            precision_constraint=precision_constraint,
        )
        new_modified_property = parse_into_datetime(
            kwargs['modified'], precision='millisecond',
            precision_constraint=precision_constraint,
        )
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
