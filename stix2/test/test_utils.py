import datetime as dt

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
