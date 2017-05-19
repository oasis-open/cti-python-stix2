import pytest

import stix2


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


def test_making_new_version_with_unset():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    campaign_v2 = campaign_v1.new_version(description=None)

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v2.description is None
    assert campaign_v1.modified < campaign_v2.modified


def test_making_new_version_with_embedded_object():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-163"
        }],
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    campaign_v2 = campaign_v1.new_version(external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-164"
        }])

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified
    assert campaign_v1.external_references[0].external_id != campaign_v2.external_references[0].external_id


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

    with pytest.raises(stix2.exceptions.UnmodifiablePropertyError) as excinfo:
        campaign_v1.new_version(type="threat-actor")

    assert str(excinfo.value) == "These properties cannot be changed when making a new version: type."


def test_versioning_error_bad_modified_value():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        campaign_v1.new_version(modified="2015-04-06T20:03:00.000Z")

    assert excinfo.value.cls == stix2.Campaign
    assert excinfo.value.prop_name == "modified"
    assert excinfo.value.reason == "The new modified datetime cannot be before the current modified datatime."


def test_versioning_error_usetting_required_property():
    campaign_v1 = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector."
    )

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        campaign_v1.new_version(name=None)

    assert excinfo.value.cls == stix2.Campaign
    assert excinfo.value.properties == ["name"]


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

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        campaign_v2.new_version(name="barney")

    assert excinfo.value.called_by == "new_version"


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

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        campaign_v2.revoke()

    assert excinfo.value.called_by == "revoke"
