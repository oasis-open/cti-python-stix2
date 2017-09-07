import datetime as dt

import pytest
import pytz

import stix2

from .constants import CAMPAIGN_ID


EXPECTED = """{
    "type": "campaign",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Green Group Attacks Against Finance",
    "description": "Campaign by Green Group against a series of targets in the financial services sector."
}"""


def test_campaign_example():
    campaign = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00Z",
        modified="2016-04-06T20:03:00Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    assert str(campaign) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "type": "campaign",
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:00Z",
        "modified": "2016-04-06T20:03:00Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "description": "Campaign by Green Group against a series of targets in the financial services sector.",
        "name": "Green Group Attacks Against Finance",
    },
])
def test_parse_campaign(data):
    cmpn = stix2.parse(data)

    assert cmpn.type == 'campaign'
    assert cmpn.id == CAMPAIGN_ID
    assert cmpn.created == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert cmpn.modified == dt.datetime(2016, 4, 6, 20, 3, 0, tzinfo=pytz.utc)
    assert cmpn.created_by_ref == "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    assert cmpn.description == "Campaign by Green Group against a series of targets in the financial services sector."
    assert cmpn.name == "Green Group Attacks Against Finance"

# TODO: Add other examples
