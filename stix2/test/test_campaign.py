import stix2

EXPECTED = """{
    "created": "2016-04-06T20:03:00.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "description": "Campaign by Green Group against a series of targets in the financial services sector.",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Green Group Attacks Against Finance",
    "type": "campaign"
}"""


def test_campaign_example():
    campaign = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    assert str(campaign) == EXPECTED

# TODO: Add other examples
