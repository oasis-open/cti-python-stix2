"""Utility functions and classes for the STIX2 library."""

import datetime as dt
import enum
import json
import re

import pytz
import six

import stix2

# Sentinel value for properties that should be set to the current time.
# We can't use the standard 'default' approach, since if there are multiple
# timestamps in a single object, the timestamps will vary by a few microseconds.
NOW = object()

PREFIX_21_REGEX = re.compile(r'^[a-z].*')

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_TIMESTAMP_FORMAT_FRAC = "%Y-%m-%dT%H:%M:%S.%fZ"


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
        ver = obj.get("modified") or obj.get("created")

        if ver is None:
            unique_objs[obj["id"]] = obj
        else:
            unique_objs[(obj['id'], ver)] = obj

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
        fmt = _TIMESTAMP_FORMAT_FRAC if "." in value else _TIMESTAMP_FORMAT
        try:
            parsed = dt.datetime.strptime(value, fmt)
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


def get_class_hierarchy_names(obj):
    """Given an object, return the names of the class hierarchy."""
    names = []
    for cls in obj.__class__.__mro__:
        names.append(cls.__name__)
    return names


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
