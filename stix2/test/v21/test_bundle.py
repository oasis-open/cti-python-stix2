import json

import pytest

import stix2

from .constants import IDENTITY_ID

EXPECTED_BUNDLE = """{
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-000000000007",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--00000000-0000-4000-8000-000000000001",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "valid_from": "2017-01-01T12:34:56Z"
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--00000000-0000-4000-8000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "malware_types": [
                "ransomware"
            ]
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--00000000-0000-4000-8000-000000000005",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
            "target_ref": "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e"
        }
    ]
}"""

EXPECTED_BUNDLE_DICT = {
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-000000000007",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--00000000-0000-4000-8000-000000000001",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "valid_from": "2017-01-01T12:34:56Z",
            "indicator_types": [
                "malicious-activity",
            ],
        },
        {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--00000000-0000-4000-8000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "malware_types": [
                "ransomware",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--00000000-0000-4000-8000-000000000005",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
            "target_ref": "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        },
    ],
}


def test_empty_bundle():
    bundle = stix2.v21.Bundle()

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    with pytest.raises(AttributeError):
        assert bundle.objects


def test_bundle_with_wrong_type():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Bundle(type="not-a-bundle")

    assert excinfo.value.cls == stix2.v21.Bundle
    assert excinfo.value.prop_name == "type"
    assert excinfo.value.reason == "must equal 'bundle'."
    assert str(excinfo.value) == "Invalid value for Bundle 'type': must equal 'bundle'."


def test_bundle_id_must_start_with_bundle():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Bundle(id='my-prefix--')

    assert excinfo.value.cls == stix2.v21.Bundle
    assert excinfo.value.prop_name == "id"
    assert excinfo.value.reason == "must start with 'bundle--'."
    assert str(excinfo.value) == "Invalid value for Bundle 'id': must start with 'bundle--'."


def test_create_bundle1(indicator, malware, relationship):
    bundle = stix2.v21.Bundle(objects=[indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE
    assert bundle.serialize(pretty=True) == EXPECTED_BUNDLE


def test_create_bundle2(indicator, malware, relationship):
    bundle = stix2.v21.Bundle(objects=[indicator, malware, relationship])

    assert json.loads(bundle.serialize()) == EXPECTED_BUNDLE_DICT


def test_create_bundle_with_positional_args(indicator, malware, relationship):
    bundle = stix2.v21.Bundle(indicator, malware, relationship)

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_positional_listarg(indicator, malware, relationship):
    bundle = stix2.v21.Bundle([indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_listarg_and_positional_arg(indicator, malware, relationship):
    bundle = stix2.v21.Bundle([indicator, malware], relationship)

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_listarg_and_kwarg(indicator, malware, relationship):
    bundle = stix2.v21.Bundle([indicator, malware], objects=[relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_arg_listarg_and_kwarg(indicator, malware, relationship):
    bundle = stix2.v21.Bundle([indicator], malware, objects=[relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_invalid(indicator, malware, relationship):
    with pytest.raises(ValueError) as excinfo:
        stix2.v21.Bundle(objects=[1])
    assert excinfo.value.reason == "This property may only contain a dictionary or object"

    with pytest.raises(ValueError) as excinfo:
        stix2.v21.Bundle(objects=[{}])
    assert excinfo.value.reason == "This property may only contain a non-empty dictionary or object"

    with pytest.raises(ValueError) as excinfo:
        stix2.v21.Bundle(objects=[{'type': 'bundle'}])
    assert excinfo.value.reason == 'This property may not contain a Bundle object'


@pytest.mark.parametrize("version", ["2.1"])
def test_parse_bundle(version):
    bundle = stix2.parse(EXPECTED_BUNDLE, version=version)

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    assert type(bundle.objects[0]) is stix2.v21.Indicator
    assert bundle.objects[0].type == 'indicator'
    assert bundle.objects[1].type == 'malware'
    assert bundle.objects[2].type == 'relationship'


def test_parse_unknown_type():
    unknown = {
        "type": "other",
        "spec_version": "2.1",
        "id": "other--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:00Z",
        "modified": "2016-04-06T20:03:00Z",
        "created_by_ref": IDENTITY_ID,
        "description": "Campaign by Green Group against a series of targets in the financial services sector.",
        "name": "Green Group Attacks Against Finance",
    }

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(unknown, version="2.1")
    assert str(excinfo.value) == "Can't parse unknown object type 'other'! For custom types, use the CustomObject decorator."


def test_stix_object_property():
    prop = stix2.properties.STIXObjectProperty(spec_version='2.1')

    identity = stix2.v21.Identity(name="test", identity_class="individual")
    assert prop.clean(identity) is identity
