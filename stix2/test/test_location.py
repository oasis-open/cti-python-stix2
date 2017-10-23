import datetime as dt
import re

import pytest
import pytz

import stix2

from .constants import LOCATION_ID


EXPECTED_LOCATION_1 = """{
    "type": "location",
    "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "latitude": 48.8566,
    "longitude": 2.3522
}"""

EXPECTED_LOCATION_1_REPR = "Location(" + " ".join("""
    type='location',
    id='location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64',
    created='2016-04-06T20:03:00.000Z',
    modified='2016-04-06T20:03:00.000Z',
    latitude=48.8566,
    longitude=2.3522""".split()) + ")"

EXPECTED_LOCATION_2 = """{
    "type": "location",
    "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "region": "north-america"
}
"""

EXPECTED_LOCATION_2_REPR = "Location(" + " ".join("""
    type='location',
    id='location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64',
    created='2016-04-06T20:03:00.000Z',
    modified='2016-04-06T20:03:00.000Z',
    region='north-america'""".split()) + ")"


def test_location_with_some_required_properties():
    now = dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)

    loc = stix2.Location(
        type="location",
        id=LOCATION_ID,
        created=now,
        modified=now,
        latitude=48.8566,
        longitude=2.3522
    )

    assert str(loc) == EXPECTED_LOCATION_1
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(loc))
    assert rep == EXPECTED_LOCATION_1_REPR


@pytest.mark.parametrize("data", [
    EXPECTED_LOCATION_2,
    {
        "type": "location",
        "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "region": "north-america"
    }
])
def test_parse_location(data):
    location = stix2.parse(data)

    assert location.type == 'location'
    assert location.id == LOCATION_ID
    assert location.created == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert location.modified == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert location.region == 'north-america'
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(location))
    assert rep == EXPECTED_LOCATION_2_REPR
