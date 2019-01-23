import datetime as dt

import pytest
import pytz

import stix2

from .constants import IDENTITY_ID

EXPECTED = """{
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2015-12-21T19:59:11.000Z",
    "modified": "2015-12-21T19:59:11.000Z",
    "name": "John Smith",
    "identity_class": "individual"
}"""


def test_identity_example():
    identity = stix2.v21.Identity(
        id=IDENTITY_ID,
        created="2015-12-21T19:59:11.000Z",
        modified="2015-12-21T19:59:11.000Z",
        name="John Smith",
        identity_class="individual",
    )

    assert str(identity) == EXPECTED


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "created": "2015-12-21T19:59:11.000Z",
            "id": IDENTITY_ID,
            "identity_class": "individual",
            "modified": "2015-12-21T19:59:11.000Z",
            "name": "John Smith",
            "spec_version": "2.1",
            "type": "identity",
        },
    ],
)
def test_parse_identity(data):
    identity = stix2.parse(data, version="2.1")

    assert identity.type == 'identity'
    assert identity.spec_version == '2.1'
    assert identity.id == IDENTITY_ID
    assert identity.created == dt.datetime(2015, 12, 21, 19, 59, 11, tzinfo=pytz.utc)
    assert identity.modified == dt.datetime(2015, 12, 21, 19, 59, 11, tzinfo=pytz.utc)
    assert identity.name == "John Smith"


def test_parse_no_type():
    with pytest.raises(stix2.exceptions.ParseError):
        stix2.parse(
            """
        {
            "id": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
            "created": "2015-12-21T19:59:11.000Z",
            "modified": "2015-12-21T19:59:11.000Z",
            "name": "John Smith",
            "identity_class": "individual"
        }""", version="2.1",
        )


def test_identity_with_custom():
    identity = stix2.v21.Identity(
        name="John Smith",
        identity_class="individual",
        custom_properties={'x_foo': 'bar'},
    )

    assert identity.x_foo == "bar"
    assert "x_foo" in identity.object_properties()

# TODO: Add other examples
