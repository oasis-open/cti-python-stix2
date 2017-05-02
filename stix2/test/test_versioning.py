import stix2
import pytest

EXPECTED = """{
    "created": "2016-04-06T20:03:00.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "description": "Campaign by Green Group against a series of targets in the financial services sector.",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Green Group Attacks Against Finance",
    "type": "campaign"
}"""


def test_making_new_version():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    campaign_v2 = campaign_v1.new_version(name="fred")

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name != campaign_v2.name
    assert campaign_v2.name == "fred"
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified


def test_revoke():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    campaign_v2 = campaign_v1.revoke()

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified

    assert campaign_v2.revoked


def test_versioning_error_invalid_property():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    with pytest.raises(stix2.exceptions.VersioningError) as excinfo:
        campaign_v2 = campaign_v1.new_version(type="threat-actor")

    str(excinfo.value) == "These properties cannot be changed when making a new version: type"


def test_versioning_error_new_version_of_revoked():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    campaign_v2 = campaign_v1.revoke()

    with pytest.raises(stix2.exceptions.VersioningError) as excinfo:
        campaign_v3 = campaign_v2.new_version(name="barney")

    str(excinfo.value) == "Cannot create a new version of a revoked object"


def test_versioning_error_revoke_of_revoked():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    campaign_v2 = campaign_v1.revoke()

    with pytest.raises(stix2.exceptions.VersioningError) as excinfo:
        campaign_v3 = campaign_v2.revoke()

    str(excinfo.value) == "Cannot revoke an already revoked object"