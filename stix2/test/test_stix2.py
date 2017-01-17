"""Tests for the stix2 library"""

import datetime

import pytest
import pytz

import stix2

amsterdam = pytz.timezone('Europe/Amsterdam')
eastern = pytz.timezone('US/Eastern')


@pytest.mark.parametrize('dt,timestamp', [
    (datetime.datetime(2017, 1, 1, tzinfo=pytz.utc), '2017-01-01T00:00:00Z'),
    (amsterdam.localize(datetime.datetime(2017, 1, 1)), '2016-12-31T23:00:00Z'),
    (eastern.localize(datetime.datetime(2017, 1, 1, 12, 34, 56)), '2017-01-01T17:34:56Z'),
    (eastern.localize(datetime.datetime(2017, 7, 1)), '2017-07-01T04:00:00Z'),
])
def test_timestamp_formatting(dt, timestamp):
    assert stix2.format_datetime(dt) == timestamp


def test_basic_indicator():
    indicator = stix2.Indicator()
    assert indicator.id.startswith("indicator")


EXPECTED = """{
    "created": "2017-01-01T00:00:00Z",
    "id": "indicator--01234567-89ab-cdef-0123-456789abcdef",
    "labels": [
        "malicious-activity"
    ],
    "modified": "2017-01-01T00:00:00Z",
    "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
    "type": "indicator",
    "valid_from": "1970-01-01T00:00:00Z"
}"""


def test_indicator_with_all_required_fields():
    now = datetime.datetime(2017, 1, 1, 0, 0, 0, tzinfo=pytz.utc)
    epoch = datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=pytz.utc)

    indicator = stix2.Indicator(
        type="indicator",
        id="indicator--01234567-89ab-cdef-0123-456789abcdef",
        created=now,
        modified=now,
        labels=['malicious-activity'],
        pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        valid_from=epoch,
    )

    assert str(indicator) == EXPECTED
