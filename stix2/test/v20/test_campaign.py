import datetime as dt

import pytest
import pytz

import stix2

from .constants import CAMPAIGN_ID, CAMPAIGN_MORE_KWARGS, IDENTITY_ID

EXPECTED = """{
    "type": "campaign",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Green Group Attacks Against Finance",
    "description": "Campaign by Green Group against a series of targets in the financial services sector."
}"""


def test_campaign_example():
    campaign = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    assert str(campaign) == EXPECTED


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "type": "campaign",
            "id": CAMPAIGN_ID,
            "created": "2016-04-06T20:03:00Z",
            "modified": "2016-04-06T20:03:00Z",
            "created_by_ref": IDENTITY_ID,
            "description": "Campaign by Green Group against a series of targets in the financial services sector.",
            "name": "Green Group Attacks Against Finance",
        },
    ],
)
def test_parse_campaign(data):
    cmpn = stix2.parse(data, version="2.0")

    assert cmpn.type == 'campaign'
    assert cmpn.id == CAMPAIGN_ID
    assert cmpn.created == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert cmpn.modified == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert cmpn.created_by_ref == IDENTITY_ID
    assert cmpn.description == "Campaign by Green Group against a series of targets in the financial services sector."
    assert cmpn.name == "Green Group Attacks Against Finance"

# TODO: Add other examples
