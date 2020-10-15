import datetime

import pytest

import stix2
import stix2.exceptions
import stix2.utils
import stix2.v21
import stix2.versioning

from .constants import CAMPAIGN_MORE_KWARGS


def test_making_new_version():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)

    campaign_v2 = campaign_v1.new_version(name="fred")

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.spec_version == campaign_v2.spec_version
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name != campaign_v2.name
    assert campaign_v2.name == "fred"
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified


def test_making_new_version_with_unset():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)

    campaign_v2 = campaign_v1.new_version(description=None)

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.spec_version == campaign_v2.spec_version
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    with pytest.raises(AttributeError):
        assert campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified


def test_making_new_version_with_embedded_object():
    campaign_v1 = stix2.v21.Campaign(
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
    assert campaign_v1.spec_version == campaign_v2.spec_version
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified
    assert campaign_v1.external_references[0].external_id != campaign_v2.external_references[0].external_id


def test_revoke():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)

    campaign_v2 = campaign_v1.revoke()

    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.spec_version == campaign_v2.spec_version
    assert campaign_v1.created_by_ref == campaign_v2.created_by_ref
    assert campaign_v1.created == campaign_v2.created
    assert campaign_v1.name == campaign_v2.name
    assert campaign_v1.description == campaign_v2.description
    assert campaign_v1.modified < campaign_v2.modified

    assert campaign_v2.revoked


def test_versioning_error_invalid_property():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)

    with pytest.raises(stix2.exceptions.UnmodifiablePropertyError) as excinfo:
        campaign_v1.new_version(type="threat-actor")

    assert str(excinfo.value) == "These properties cannot be changed when making a new version: type."


def test_versioning_error_bad_modified_value():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        campaign_v1.new_version(modified="2015-04-06T20:03:00.000Z")

    assert excinfo.value.cls == stix2.v21.Campaign
    assert excinfo.value.prop_name == "modified"
    assert excinfo.value.reason == (
        "The new modified datetime cannot be before than or equal to the current modified datetime."
        "It cannot be equal, as according to STIX 2 specification, objects that are different "
        "but have the same id and modified timestamp do not have defined consumer behavior."
    )

    msg = "Invalid value for {0} '{1}': {2}"
    msg = msg.format(
        stix2.v21.Campaign.__name__, "modified",
        "The new modified datetime cannot be before than or equal to the current modified datetime."
        "It cannot be equal, as according to STIX 2 specification, objects that are different "
        "but have the same id and modified timestamp do not have defined consumer behavior.",
    )
    assert str(excinfo.value) == msg


def test_versioning_error_usetting_required_property():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        campaign_v1.new_version(name=None)

    assert excinfo.value.cls == stix2.v21.Campaign
    assert excinfo.value.properties == ["name"]

    msg = "No values for required properties for {0}: ({1})."
    msg = msg.format(stix2.v21.Campaign.__name__, "name")
    assert str(excinfo.value) == msg


def test_versioning_error_new_version_of_revoked():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)
    campaign_v2 = campaign_v1.revoke()

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        campaign_v2.new_version(name="barney")
    assert str(excinfo.value) == "Cannot create a new version of a revoked object."

    assert excinfo.value.called_by == "new_version"
    assert str(excinfo.value) == "Cannot create a new version of a revoked object."


def test_versioning_error_revoke_of_revoked():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)
    campaign_v2 = campaign_v1.revoke()

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        campaign_v2.revoke()
    assert str(excinfo.value) == "Cannot revoke an already revoked object."

    assert excinfo.value.called_by == "revoke"
    assert str(excinfo.value) == "Cannot revoke an already revoked object."


def test_making_new_version_dict():
    campaign_v1 = CAMPAIGN_MORE_KWARGS
    campaign_v2 = stix2.versioning.new_version(CAMPAIGN_MORE_KWARGS, name="fred")

    assert campaign_v1['id'] == campaign_v2['id']
    assert campaign_v1['spec_version'] == campaign_v2['spec_version']
    assert campaign_v1['created_by_ref'] == campaign_v2['created_by_ref']
    assert campaign_v1['created'] == campaign_v2['created']
    assert campaign_v1['name'] != campaign_v2['name']
    assert campaign_v2['name'] == "fred"
    assert campaign_v1['description'] == campaign_v2['description']
    assert stix2.utils.parse_into_datetime(campaign_v1['modified'], precision='millisecond') < campaign_v2['modified']


def test_versioning_error_dict_bad_modified_value():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.versioning.new_version(CAMPAIGN_MORE_KWARGS, modified="2015-04-06T20:03:00.000Z")

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
    campaign_v2 = stix2.versioning.new_version(campaign_v1, modified="2017-04-06T20:03:00.000Z")

    assert str(campaign_v2['modified']) == "2017-04-06T20:03:00.000Z"


def test_making_new_version_invalid_cls():
    campaign_v1 = "This is a campaign."
    with pytest.raises(ValueError) as excinfo:
        stix2.versioning.new_version(campaign_v1, name="fred")

    assert 'cannot create new version of object of this type' in str(excinfo.value)


def test_revoke_dict():
    campaign_v1 = CAMPAIGN_MORE_KWARGS
    campaign_v2 = stix2.versioning.revoke(campaign_v1)

    assert campaign_v1['id'] == campaign_v2['id']
    assert campaign_v1['spec_version'] == campaign_v2['spec_version']
    assert campaign_v1['created_by_ref'] == campaign_v2['created_by_ref']
    assert campaign_v1['created'] == campaign_v2['created']
    assert campaign_v1['name'] == campaign_v2['name']
    assert campaign_v1['description'] == campaign_v2['description']
    assert stix2.utils.parse_into_datetime(campaign_v1['modified'], precision='millisecond') < campaign_v2['modified']

    assert campaign_v2['revoked']


def test_revoke_unversionable():
    sco = stix2.v21.File(name="data.txt")
    with pytest.raises(ValueError):
        sco.revoke()


def test_versioning_error_revoke_of_revoked_dict():
    campaign_v1 = CAMPAIGN_MORE_KWARGS
    campaign_v2 = stix2.versioning.revoke(campaign_v1)

    with pytest.raises(stix2.exceptions.RevokeError) as excinfo:
        stix2.versioning.revoke(campaign_v2)

    assert excinfo.value.called_by == "revoke"


def test_revoke_invalid_cls():
    campaign_v1 = "This is a campaign."
    with pytest.raises(ValueError) as excinfo:
        stix2.versioning.revoke(campaign_v1)

    assert 'cannot revoke object of this type' in str(excinfo.value)


def test_remove_custom_stix_property():
    mal = stix2.v21.Malware(
        name="ColePowers",
        malware_types=["rootkit"],
        x_custom="armada",
        allow_custom=True,
        is_family=False,
    )

    mal_nc = stix2.versioning.remove_custom_stix(mal)

    assert "x_custom" not in mal_nc
    assert mal["modified"] < mal_nc["modified"]


def test_remove_custom_stix_object():
    @stix2.v21.CustomObject(
        "x-animal", [
            ("species", stix2.properties.StringProperty(required=True)),
            ("animal_class", stix2.properties.StringProperty()),
        ],
    )
    class Animal(object):
        pass

    animal = Animal(species="lion", animal_class="mammal")

    nc = stix2.versioning.remove_custom_stix(animal)

    assert nc is None


def test_remove_custom_stix_no_custom():
    campaign_v1 = stix2.v21.Campaign(**CAMPAIGN_MORE_KWARGS)
    campaign_v2 = stix2.versioning.remove_custom_stix(campaign_v1)

    assert len(campaign_v1.keys()) == len(campaign_v2.keys())
    assert campaign_v1.id == campaign_v2.id
    assert campaign_v1.description == campaign_v2.description


@pytest.mark.parametrize(
    "old, candidate_new, expected_new, use_stix21", [
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.001Z", "1999-08-15T00:19:07.001Z", False),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.001Z", False),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:06.000Z", "1999-08-15T00:19:07.001Z", False),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:06.999Z", "1999-08-15T00:19:07.001Z", False),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.0001Z", "1999-08-15T00:19:07.001Z", False),
        ("1999-08-15T00:19:07.999Z", "1999-08-15T00:19:07.9999Z", "1999-08-15T00:19:08.000Z", False),

        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.001Z", "1999-08-15T00:19:07.001Z", True),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.000001Z", True),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:06.000Z", "1999-08-15T00:19:07.000001Z", True),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:06.999999Z", "1999-08-15T00:19:07.000001Z", True),
        ("1999-08-15T00:19:07.000Z", "1999-08-15T00:19:07.000001Z", "1999-08-15T00:19:07.000001Z", True),
        ("1999-08-15T00:19:07.999Z", "1999-08-15T00:19:07.999999Z", "1999-08-15T00:19:07.999999Z", True),
    ],
)
def test_fudge_modified(old, candidate_new, expected_new, use_stix21):
    old_dt = datetime.datetime.strptime(old, "%Y-%m-%dT%H:%M:%S.%fZ")
    candidate_new_dt = datetime.datetime.strptime(
        candidate_new, "%Y-%m-%dT%H:%M:%S.%fZ",
    )
    expected_new_dt = datetime.datetime.strptime(
        expected_new, "%Y-%m-%dT%H:%M:%S.%fZ",
    )

    fudged = stix2.versioning._fudge_modified(
        old_dt, candidate_new_dt, use_stix21,
    )
    assert fudged == expected_new_dt


def test_version_unversionable_dict():
    f = {
        "type": "file",
        "id": "file--4efb5217-e987-4438-9a1b-c800099401df",
        "name": "data.txt",
    }

    with pytest.raises(ValueError):
        stix2.versioning.new_version(f)


def test_version_sco_with_custom():
    """
    If we add custom properties named like versioning properties to an object
    type which is otherwise unversionable, versioning should start working.
    """

    file_sco_obj = stix2.v21.File(
        name="data.txt",
        created="1973-11-23T02:31:37Z",
        modified="1991-05-13T19:24:57Z",
        revoked=False,
        allow_custom=True,
    )

    new_file_sco_obj = stix2.versioning.new_version(
        file_sco_obj, size=1234,
    )

    assert new_file_sco_obj.size == 1234

    revoked_obj = stix2.versioning.revoke(new_file_sco_obj)
    assert revoked_obj.revoked


def test_version_disable_custom():
    m = stix2.v21.Malware(
        name="foo", description="Steals your identity!", is_family=False,
        x_custom=123, allow_custom=True,
    )

    # Remove the custom property, and disallow custom properties in the
    # resulting object.
    m2 = stix2.versioning.new_version(m, x_custom=None, allow_custom=False)
    assert "x_custom" not in m2

    # Remove a regular property and leave the custom one, disallow custom
    # properties, and make sure we get an error.
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.versioning.new_version(m, description=None, allow_custom=False)


def test_version_enable_custom():
    m = stix2.v21.Malware(
        name="foo", description="Steals your identity!", is_family=False,
    )

    # Add a custom property to an object for which it was previously disallowed
    m2 = stix2.versioning.new_version(m, x_custom=123, allow_custom=True)
    assert "x_custom" in m2

    # Add a custom property without enabling it, make sure we get an error
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.versioning.new_version(m, x_custom=123, allow_custom=False)


def test_version_propagate_custom():
    m = stix2.v21.Malware(
        name="foo", is_family=False,
    )

    # Remember custom-not-allowed setting from original; produce error
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.versioning.new_version(m, x_custom=123)

    m2 = stix2.versioning.new_version(m, description="Steals your identity!")
    assert "description" in m2
    assert m2.description == "Steals your identity!"

    m_custom = stix2.v21.Malware(
        name="foo", is_family=False, x_custom=123, allow_custom=True,
    )

    # Remember custom-allowed setting from original; should work
    m2_custom = stix2.versioning.new_version(m_custom, x_other_custom="abc")
    assert "x_other_custom" in m2_custom
    assert m2_custom.x_other_custom == "abc"
