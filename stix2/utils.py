"""Utility functions and classes for the stix2 library."""

import datetime as dt
import json

from dateutil import parser
import pytz

# Sentinel value for properties that should be set to the current time.
# We can't use the standard 'default' approach, since if there are multiple
# timestamps in a single object, the timestamps will vary by a few microseconds.
NOW = object()


class STIXdatetime(dt.datetime):
    def __new__(cls, *args, **kwargs):
        precision = kwargs.pop('precision', None)
        if isinstance(args[0], dt.datetime):  # Allow passing in a datetime object
            dttm = args[0]
            args = (dttm.year, dttm.month, dttm.day, dttm.hour, dttm.minute,
                    dttm.second, dttm.microsecond, dttm.tzinfo)
        # self will be an instance of STIXdatetime, not dt.datetime
        self = dt.datetime.__new__(cls, *args, **kwargs)
        self.precision = precision
        return self

    def __repr__(self):
        return "'%s'" % format_datetime(self)


def get_timestamp():
    return STIXdatetime.now(tz=pytz.UTC)


def format_datetime(dttm):
    # 1. Convert to timezone-aware
    # 2. Convert to UTC
    # 3. Format in ISO format
    # 4. Ensure correct precision
    # 4a. Add subsecond value if non-zero and precision not defined
    # 5. Add "Z"

    if dttm.tzinfo is None or dttm.tzinfo.utcoffset(dttm) is None:
        # dttm is timezone-naive; assume UTC
        zoned = pytz.utc.localize(dttm)
    else:
        zoned = dttm.astimezone(pytz.utc)
    ts = zoned.strftime("%Y-%m-%dT%H:%M:%S")
    ms = zoned.strftime("%f")
    precision = getattr(dttm, "precision", None)
    if precision == 'second':
        pass  # Alredy precise to the second
    elif precision == "millisecond":
        ts = ts + '.' + ms[:3]
    elif zoned.microsecond > 0:
        ts = ts + '.' + ms.rstrip("0")
    return ts + "Z"


def parse_into_datetime(value, precision=None):
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
            raise ValueError("must be a datetime object, date object, or "
                             "timestamp string in a recognizable format.")
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


def get_dict(data):
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


def find_property_index(obj, properties, tuple_to_find):
    """Recursively find the property in the object model, return the index
    according to the _properties OrderedDict. If its a list look for
    individual objects.
    """
    from .base import _STIXBase
    try:
        if tuple_to_find[1] in obj._inner.values():
            return properties.index(tuple_to_find[0])
        raise ValueError
    except ValueError:
        for pv in obj._inner.values():
            if isinstance(pv, list):
                for item in pv:
                    if isinstance(item, _STIXBase):
                        val = find_property_index(item,
                                                  item.object_properties(),
                                                  tuple_to_find)
                        if val is not None:
                            return val
            elif isinstance(pv, dict):
                if pv.get(tuple_to_find[0]) is not None:
                    try:
                        return int(tuple_to_find[0])
                    except ValueError:
                        return len(tuple_to_find[0])
                for item in pv.values():
                    if isinstance(item, _STIXBase):
                        val = find_property_index(item,
                                                  item.object_properties(),
                                                  tuple_to_find)
                        if val is not None:
                            return val
