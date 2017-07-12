import datetime as dt
from io import StringIO

import pytest
import pytz

import stix2.utils

amsterdam = pytz.timezone('Europe/Amsterdam')
eastern = pytz.timezone('US/Eastern')


@pytest.mark.parametrize('dttm,timestamp', [
    (dt.datetime(2017, 1, 1, tzinfo=pytz.utc), '2017-01-01T00:00:00Z'),
    (amsterdam.localize(dt.datetime(2017, 1, 1)), '2016-12-31T23:00:00Z'),
    (eastern.localize(dt.datetime(2017, 1, 1, 12, 34, 56)), '2017-01-01T17:34:56Z'),
    (eastern.localize(dt.datetime(2017, 7, 1)), '2017-07-01T04:00:00Z'),
    (dt.datetime(2017, 7, 1), '2017-07-01T00:00:00Z'),
    (dt.datetime(2017, 7, 1, 0, 0, 0, 1), '2017-07-01T00:00:00.000001Z'),
    (stix2.utils.STIXdatetime(2017, 7, 1, 0, 0, 0, 1, precision='millisecond'), '2017-07-01T00:00:00.000Z'),
    (stix2.utils.STIXdatetime(2017, 7, 1, 0, 0, 0, 1, precision='second'), '2017-07-01T00:00:00Z'),
])
def test_timestamp_formatting(dttm, timestamp):
    assert stix2.utils.format_datetime(dttm) == timestamp


@pytest.mark.parametrize('timestamp, dttm', [
    (dt.datetime(2017, 1, 1, 0, tzinfo=pytz.utc), dt.datetime(2017, 1, 1, 0, 0, 0, tzinfo=pytz.utc)),
    (dt.date(2017, 1, 1), dt.datetime(2017, 1, 1, 0, 0, 0, tzinfo=pytz.utc)),
    ('2017-01-01T00:00:00Z', dt.datetime(2017, 1, 1, 0, 0, 0, tzinfo=pytz.utc)),
    ('2017-01-01T02:00:00+2:00', dt.datetime(2017, 1, 1, 0, 0, 0, tzinfo=pytz.utc)),
    ('2017-01-01T00:00:00', dt.datetime(2017, 1, 1, 0, 0, 0, tzinfo=pytz.utc)),
])
def test_parse_datetime(timestamp, dttm):
    assert stix2.utils.parse_into_datetime(timestamp) == dttm


@pytest.mark.parametrize('timestamp, dttm, precision', [
    ('2017-01-01T01:02:03.000001', dt.datetime(2017, 1, 1, 1, 2, 3, 0, tzinfo=pytz.utc), 'millisecond'),
    ('2017-01-01T01:02:03.001', dt.datetime(2017, 1, 1, 1, 2, 3, 1000, tzinfo=pytz.utc), 'millisecond'),
    ('2017-01-01T01:02:03.1', dt.datetime(2017, 1, 1, 1, 2, 3, 100000, tzinfo=pytz.utc), 'millisecond'),
    ('2017-01-01T01:02:03.45', dt.datetime(2017, 1, 1, 1, 2, 3, 450000, tzinfo=pytz.utc), 'millisecond'),
    ('2017-01-01T01:02:03.45', dt.datetime(2017, 1, 1, 1, 2, 3, tzinfo=pytz.utc), 'second'),
])
def test_parse_datetime_precision(timestamp, dttm, precision):
    assert stix2.utils.parse_into_datetime(timestamp, precision) == dttm


@pytest.mark.parametrize('ts', [
    'foobar',
    1,
])
def test_parse_datetime_invalid(ts):
    with pytest.raises(ValueError):
        stix2.utils.parse_into_datetime('foobar')


@pytest.mark.parametrize('data', [
    {"a": 1},
    '{"a": 1}',
    StringIO(u'{"a": 1}'),
    [("a", 1,)],
])
def test_get_dict(data):
    assert stix2.utils.get_dict(data)


@pytest.mark.parametrize('data', [
    1,
    [1],
    ['a', 1],
    "foobar",
])
def test_get_dict_invalid(data):
    with pytest.raises(ValueError):
        stix2.utils.get_dict(data)
