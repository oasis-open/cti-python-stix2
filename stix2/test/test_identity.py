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
    report = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
    )

    assert str(report) == EXPECTED


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

# TODO: Add other examples
