import datetime as dt
import re

import pytest
import pytz

import stix2

from .constants import LOCATION_ID

EXPECTED_LOCATION_1 = """{
    "type": "location",
    "spec_version": "2.1",
    "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "latitude": 48.8566,
    "longitude": 2.3522
}"""

EXPECTED_LOCATION_1_REPR = "Location(" + " ".join("""
    type='location',
    spec_version='2.1',
    id='location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64',
    created='2016-04-06T20:03:00.000Z',
    modified='2016-04-06T20:03:00.000Z',
    latitude=48.8566,
    longitude=2.3522""".split()) + ")"

EXPECTED_LOCATION_2 = """{
    "type": "location",
    "spec_version": "2.1",
    "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "region": "north-america"
}
"""

EXPECTED_LOCATION_2_REPR = "Location(" + " ".join("""
    type='location',
    spec_version='2.1',
    id='location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64',
    created='2016-04-06T20:03:00.000Z',
    modified='2016-04-06T20:03:00.000Z',
    region='north-america'""".split()) + ")"


def test_location_with_some_required_properties():
    now = dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)

    loc = stix2.v21.Location(
        id=LOCATION_ID,
        created=now,
        modified=now,
        latitude=48.8566,
        longitude=2.3522,
    )

    assert str(loc) == EXPECTED_LOCATION_1
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(loc))
    assert rep == EXPECTED_LOCATION_1_REPR


@pytest.mark.parametrize(
    "data", [
        EXPECTED_LOCATION_2,
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "region": "north-america",
        },
    ],
)
def test_parse_location(data):
    location = stix2.parse(data, version="2.1")

    assert location.type == 'location'
    assert location.spec_version == '2.1'
    assert location.id == LOCATION_ID
    assert location.created == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert location.modified == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert location.region == 'north-america'
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(location))
    assert rep == EXPECTED_LOCATION_2_REPR


@pytest.mark.parametrize(
    "data", [
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "latitude": 90.01,
            "longitude": 0.0,
        },
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "latitude": -90.1,
            "longitude": 0.0,
        },
    ],
)
def test_location_bad_latitude(data):
    with pytest.raises(ValueError) as excinfo:
        stix2.parse(data)

    assert "Invalid value for Location 'latitude'" in str(excinfo.value)


@pytest.mark.parametrize(
    "data", [
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "latitude": 80,
            "longitude": 180.1,
        },
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "latitude": 80,
            "longitude": -180.1,
        },
    ],
)
def test_location_bad_longitude(data):
    with pytest.raises(ValueError) as excinfo:
        stix2.parse(data)

    assert "Invalid value for Location 'longitude'" in str(excinfo.value)


@pytest.mark.parametrize(
    "data", [
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "longitude": 175.7,
            "precision": 20,
        },
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "latitude": 80,
            "precision": 20,
        },
    ],
)
def test_location_properties_missing_when_precision_is_present(data):
    with pytest.raises(stix2.exceptions.DependentPropertiesError) as excinfo:
        stix2.parse(data)

    assert any(x in str(excinfo.value) for x in ("(latitude, precision)", "(longitude, precision)"))


@pytest.mark.parametrize(
    "data", [
        {
            "type": "location",
            "spec_version": "2.1",
            "id": LOCATION_ID,
            "created": "2016-04-06T20:03:00.000Z",
            "modified": "2016-04-06T20:03:00.000Z",
            "latitude": 18.468842,
            "longitude": -66.120711,
            "precision": -100.0,
        },
    ],
)
def test_location_negative_precision(data):
    with pytest.raises(ValueError) as excinfo:
        stix2.parse(data)

    assert "Invalid value for Location 'precision'" in str(excinfo.value)


@pytest.mark.parametrize(
    "data,msg", [
        (
            {
                "type": "location",
                "spec_version": "2.1",
                "id": LOCATION_ID,
                "created": "2016-04-06T20:03:00.000Z",
                "modified": "2016-04-06T20:03:00.000Z",
                "latitude": 18.468842,
                "precision": 5.0,
            },
            "(longitude, precision) are not met.",
        ),
        (
            {
                "type": "location",
                "spec_version": "2.1",
                "id": LOCATION_ID,
                "created": "2016-04-06T20:03:00.000Z",
                "modified": "2016-04-06T20:03:00.000Z",
                "longitude": 160.7,
                "precision": 5.0,
            },
            "(latitude, precision) are not met.",
        ),
    ],
)
def test_location_latitude_dependency_missing(data, msg):
    with pytest.raises(stix2.exceptions.DependentPropertiesError) as excinfo:
        stix2.parse(data)

    assert msg in str(excinfo.value)


@pytest.mark.parametrize(
    "data,msg", [
        (
            {
                "type": "location",
                "spec_version": "2.1",
                "id": LOCATION_ID,
                "created": "2016-04-06T20:03:00.000Z",
                "modified": "2016-04-06T20:03:00.000Z",
                "latitude": 18.468842,
            },
            "(longitude, latitude) are not met.",
        ),
        (
            {
                "type": "location",
                "spec_version": "2.1",
                "id": LOCATION_ID,
                "created": "2016-04-06T20:03:00.000Z",
                "modified": "2016-04-06T20:03:00.000Z",
                "longitude": 160.7,
            },
            "(latitude, longitude) are not met.",
        ),
    ],
)
def test_location_lat_or_lon_dependency_missing(data, msg):
    with pytest.raises(stix2.exceptions.DependentPropertiesError) as excinfo:
        stix2.parse(data)

    assert msg in str(excinfo.value)


def test_google_map_url_long_lat_provided():
    expected_url = "https://www.google.com/maps/search/?api=1&query=41.862401%2C-87.616001"

    loc = stix2.v21.Location(
        latitude=41.862401,
        longitude=-87.616001,
    )

    loc_url = loc.to_maps_url()
    assert loc_url == expected_url


def test_google_map_url_multiple_props_no_long_lat_provided():
    expected_url = "https://www.google.com/maps/search/?api=1&query=1410+Museum+Campus+Drive%2C+Chicago%2C+IL+60605%2CUnited+States+of+America%2CNorth+America"
    now = dt.datetime(2019, 2, 7, 12, 34, 56, tzinfo=pytz.utc)

    loc = stix2.v21.Location(
        type="location",
        id=LOCATION_ID,
        created=now,
        modified=now,
        region="North America",
        country="United States of America",
        street_address="1410 Museum Campus Drive, Chicago, IL 60605",
    )

    loc_url = loc.to_maps_url()
    assert loc_url == expected_url


def test_google_map_url_multiple_props_and_long_lat_provided():
    expected_url = "https://www.google.com/maps/search/?api=1&query=41.862401%2C-87.616001"

    loc = stix2.v21.Location(
        region="North America",
        country="United States of America",
        street_address="1410 Museum Campus Drive, Chicago, IL 60605",
        latitude=41.862401,
        longitude=-87.616001,
    )

    loc_url = loc.to_maps_url()
    assert loc_url == expected_url


def test_map_url_invalid_map_engine_provided():
    loc = stix2.v21.Location(
        latitude=41.862401,
        longitude=-87.616001,
    )

    with pytest.raises(ValueError) as excinfo:
        loc.to_maps_url("Fake Maps")

    assert "is not a valid or currently-supported map engine" in str(excinfo.value)


def test_bing_map_url_long_lat_provided():
    expected_url = "https://bing.com/maps/default.aspx?where1=41.862401%2C-87.616001&lvl=16"

    loc = stix2.v21.Location(
        latitude=41.862401,
        longitude=-87.616001,
    )

    loc_url = loc.to_maps_url("Bing Maps")
    assert loc_url == expected_url


def test_bing_map_url_multiple_props_no_long_lat_provided():
    expected_url = "https://bing.com/maps/default.aspx?where1=1410+Museum+Campus+Drive%2C+Chicago%2C+IL+60605%2CUnited+States+of+America%2CNorth+America&lvl=16"

    loc = stix2.v21.Location(
        region="North America",
        country="United States of America",
        street_address="1410 Museum Campus Drive, Chicago, IL 60605",
    )

    loc_url = loc.to_maps_url("Bing Maps")
    assert loc_url == expected_url


def test_bing_map_url_multiple_props_and_long_lat_provided():
    expected_url = "https://bing.com/maps/default.aspx?where1=41.862401%2C-87.616001&lvl=16"

    loc = stix2.v21.Location(
        region="North America",
        country="United States of America",
        street_address="1410 Museum Campus Drive, Chicago, IL 60605",
        latitude=41.862401,
        longitude=-87.616001,
    )

    loc_url = loc.to_maps_url("Bing Maps")
    assert loc_url == expected_url
