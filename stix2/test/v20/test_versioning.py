import pytest

import stix2

from .constants import CAMPAIGN_MORE_KWARGS


def test_making_new_version():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    campaign_v2 = campaign_v1.new_version(name="fred")

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name != campaign_v2.name
    assert campaign_v2.name == "fred"
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified


def test_making_new_version_with_unset():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    campaign_v2 = campaign_v1.new_version(description=None)

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    with pytest.raises(AttributeError):
        assert campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified


def test_making_new_version_with_embedded_object():
    campaign_v1 = stix2.v20.Campaign(
        external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-163",
        }],
        **CAMPAIGN_MORE_KWARGS
    )

    campaign_v2 = campaign_v1.new_version(external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-164",
    }])

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified
    assert campaign_v1.external_references[0].external_id != campaign_v2.external_references[0].external_id


def test_revoke():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    campaign_v2 = campaign_v1.revoke()

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified

    assert campaign_v2.revoked


def test_versioning_error_invalid_property():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    with pytest.raises(stix2.exceptions.UnmodifiablePropertyError) as excinfo:
        campaign_v1.new_version(type="threat-actor")

    assert str(excinfo.value) == "These properties cannot be changed when making a new version: type."


def test_versioning_error_bad_modified_value():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        campaign_v1.new_version(modified="2015-04-06T20:03:00.000Z")

    assert excinfo.value.cls == stix2.v20.Campaign
    assert excinfo.value.prop_name == "modified"
    assert excinfo.value.reason == "The new modified datetime cannot be before than or equal to the current modified datetime." \
        "It cannot be equal, as according to STIX 2 specification, objects that are different " \
        "but have the same id and modified timestamp do not have defined consumer behavior."

    msg = "Invalid value for {0} '{1}': {2}"
    msg = msg.format(
        stix2.v20.Campaign.__name__, "modified",
        "The new modified datetime cannot be before than or equal to the current modified datetime."
        "It cannot be equal, as according to STIX 2 specification, objects that are different "
        "but have the same id and modified timestamp do not have defined consumer behavior.",
    )
    assert str(excinfo.value) == msg


def test_versioning_error_usetting_required_property():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        campaign_v1.new_version(name=None)

    assert excinfo.value.cls == stix2.v20.Campaign
    assert excinfo.value.properties == ["name"]

    msg = "No values for required properties for {0}: ({1})."
    msg = msg.format(stix2.v20.Campaign.__name__, "name")
    assert str(excinfo.value) == msg


def test_versioning_error_new_version_of_revoked():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)
    campaign_v2 = campaign_v1.revoke()

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        campaign_v2.new_version(name="barney")
    assert str(excinfo.value) == "Cannot create a new version of a revoked object."

    assert excinfo.value.called_by == "new_version"
    assert str(excinfo.value) == "Cannot create a new version of a revoked object."


def test_versioning_error_revoke_of_revoked():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)
    campaign_v2 = campaign_v1.revoke()

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        campaign_v2.revoke()
    assert str(excinfo.value) == "Cannot revoke an already revoked object."

    assert excinfo.value.called_by == "revoke"
    assert str(excinfo.value) == "Cannot revoke an already revoked object."


def test_making_new_version_dict():
    campaign_v1 = CAMPAIGN_MORE_KWARGS
    campaign_v2 = stix2.utils.new_version(CAMPAIGN_MORE_KWARGS, name="fred")

    assert campaign_v1['id'] == campaign_v2['id']
    assert campaign_v1['created_by_ref'] == campaign_v2['created_by_ref']
    assert campaign_v1['created'] == campaign_v2['created']
    assert campaign_v1['name'] != campaign_v2['name']
    assert campaign_v2['name'] == "fred"
    assert campaign_v1['description'] == campaign_v2['description']
    assert stix2.utils.parse_into_datetime(campaign_v1['modified'], precision='millisecond') < campaign_v2['modified']


def test_versioning_error_dict_bad_modified_value():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.utils.new_version(CAMPAIGN_MORE_KWARGS, modified="2015-04-06T20:03:00.000Z")

    assert excinfo.value.cls == dict
    assert excinfo.value.prop_name == "modified"
    assert excinfo.value.reason == "The new modified datetime cannot be before than or equal to the current modified datetime." \
        "It cannot be equal, as according to STIX 2 specification, objects that are different " \
        "but have the same id and modified timestamp do not have defined consumer behavior."


def test_versioning_error_dict_no_modified_value():
    campaign_v1 = {
        'type': 'campaign',
        'id': "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        'created': "2016-04-06T20:03:00.000Z",
        'name': "Green Group Attacks Against Finance",
    }
    campaign_v2 = stix2.utils.new_version(campaign_v1, modified="2017-04-06T20:03:00.000Z")

    assert str(campaign_v2['modified']) == "2017-04-06T20:03:00.000Z"


def test_making_new_version_invalid_cls():
    campaign_v1 = "This is a campaign."
    with pytest.raises(ValueError) as excinfo:
        stix2.utils.new_version(campaign_v1, name="fred")

    assert 'cannot create new version of object of this type' in str(excinfo.value)


def test_revoke_dict():
    campaign_v1 = CAMPAIGN_MORE_KWARGS
    campaign_v2 = stix2.utils.revoke(campaign_v1)

    assert campaign_v1['id'] == campaign_v2['id']
    assert campaign_v1['created_by_ref'] == campaign_v2['created_by_ref']
    assert campaign_v1['created'] == campaign_v2['created']
    assert campaign_v1['name'] == campaign_v2['name']
    assert campaign_v1['description'] == campaign_v2['description']
    assert stix2.utils.parse_into_datetime(campaign_v1['modified'], precision='millisecond') < campaign_v2['modified']

    assert campaign_v2['revoked']


def test_versioning_error_revoke_of_revoked_dict():
    campaign_v1 = CAMPAIGN_MORE_KWARGS
    campaign_v2 = stix2.utils.revoke(campaign_v1)

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        stix2.utils.revoke(campaign_v2)

    assert excinfo.value.called_by == "revoke"


def test_revoke_invalid_cls():
    campaign_v1 = "This is a campaign."
    with pytest.raises(ValueError) as excinfo:
        stix2.utils.revoke(campaign_v1)

    assert 'cannot revoke object of this type' in str(excinfo.value)


def test_remove_custom_stix_property():
    mal = stix2.v20.Malware(
        name="ColePowers",
        labels=["rootkit"],
        x_custom="armada",
        allow_custom=True,
    )

    mal_nc = stix2.utils.remove_custom_stix(mal)

    assert "x_custom" not in mal_nc
    assert (stix2.utils.parse_into_datetime(mal["modified"], precision="millisecond") <
            stix2.utils.parse_into_datetime(mal_nc["modified"], precision="millisecond"))


def test_remove_custom_stix_object():
    @stix2.v20.CustomObject(
        "x-animal", [
            ("species", stix2.properties.StringProperty(required=True)),
            ("animal_class", stix2.properties.StringProperty()),
        ],
    )
    class Animal(object):
        pass

    animal = Animal(species="lion", animal_class="mammal")

    nc = stix2.utils.remove_custom_stix(animal)

    assert nc is None


def test_remove_custom_stix_no_custom():
    campaign_v1 = stix2.v20.Campaign(**CAMPAIGN_MORE_KWARGS)
    campaign_v2 = stix2.utils.remove_custom_stix(campaign_v1)

    assert len(campaign_v1.keys()) == len(campaign_v2.keys())
    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.description == campaign_v2.description
