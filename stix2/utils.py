"""Utility functions and classes for the stix2 library."""

import datetime as dt
import pytz

# Sentinel value for fields that should be set to the current time.
# We can't use the standard 'default' approach, since if there are multiple
# timestamps in a single object, the timestamps will vary by a few microseconds.
NOW = object()


def get_timestamp():
    return dt.datetime.now(tz=pytz.UTC)


def format_datetime(dttm):
    # 1. Convert to timezone-aware
    # 2. Convert to UTC
    # 3. Format in ISO format
    # 4. Add subsecond value if non-zero
    # 5. Add "Z"

    try:
        zoned = dttm.astimezone(pytz.utc)
    except ValueError:
        # dttm is timezone-naive; assume UTC
        pytz.utc.localize(dttm)
    ts = zoned.strftime("%Y-%m-%dT%H:%M:%S")
    if zoned.microsecond > 0:
        ms = zoned.strftime("%f")
        ts = ts + '.' + ms.rstrip("0")
    return ts + "Z"
