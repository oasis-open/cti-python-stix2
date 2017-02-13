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
    # TODO: how to handle naive datetime

    # 1. Convert to UTC
    # 2. Format in ISO format
    # 3. Strip off "+00:00"
    # 4. Add "Z"

    # TODO: how to handle timestamps with subsecond 0's
    return dttm.astimezone(pytz.utc).isoformat()[:-6] + "Z"
