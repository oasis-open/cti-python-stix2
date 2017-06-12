import datetime as dt

import pytest
import pytz

import stix2

from .constants import IDENTITY_ID


EXPECTED = """{
    "created": "2015-12-21T19:59:11Z",
    "id": "identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
    "identity_class": "individual",
    "modified": "2015-12-21T19:59:11Z",
    "name": "John Smith",
    "type": "identity"
}"""


def test_identity_example():
    identity = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
    )

    assert str(identity) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "created": "2015-12-21T19:59:11Z",
        "id": "identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        "identity_class": "individual",
        "modified": "2015-12-21T19:59:11Z",
        "name": "John Smith",
        "type": "identity"
    },
])
def test_parse_identity(data):
    identity = stix2.parse(data)

    assert identity.type == 'identity'
    assert identity.id == IDENTITY_ID
    assert identity.created == dt.datetime(2015, 12, 21, 19, 59, 11, tzinfo=pytz.utc)
    assert identity.modified == dt.datetime(2015, 12, 21, 19, 59, 11, tzinfo=pytz.utc)
    assert identity.name == "John Smith"


def test_identity_custom_property():
    with pytest.raises(ValueError):
        stix2.Identity(
            id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties="foobar",
        )

    identity = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
        custom_properties={
            "foo": "bar",
        },
    )

    assert identity.foo == "bar"


def test_identity_custom_property_invalid():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.Identity(
            id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            x_foo="bar",
        )


def test_identity_custom_property_allowed():
    identity = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
        x_foo="bar",
        allow_custom=True,
    )
    assert identity.x_foo == "bar"


@pytest.mark.parametrize("data", [
    """{
        "type": "identity",
        "id": "identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        "created": "2015-12-21T19:59:11Z",
        "modified": "2015-12-21T19:59:11Z",
        "name": "John Smith",
        "identity_class": "individual",
        "foo": "bar"
    }""",
])
def test_parse_identity_custom_property(data):
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        identity = stix2.parse(data)

    identity = stix2.parse(data, allow_custom=True)
    assert identity.foo == "bar"


def test_parse_no_type():
    with pytest.raises(stix2.exceptions.ParseError):
        stix2.parse("""
        {
            "id": "identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            "created": "2015-12-21T19:59:11Z",
            "modified": "2015-12-21T19:59:11Z",
            "name": "John Smith",
            "identity_class": "individual"
        }""")

# TODO: Add other examples
