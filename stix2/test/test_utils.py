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
])
def test_timestamp_formatting(dttm, timestamp):
    assert stix2.utils.format_datetime(dttm) == timestamp


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
