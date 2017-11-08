import json

import pytest

import stix2

EXPECTED_BUNDLE = """{
    "type": "bundle",
    "id": "bundle--00000000-0000-0000-0000-000000000004",
    "spec_version": "2.0",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--00000000-0000-0000-0000-000000000001",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "valid_from": "2017-01-01T12:34:56Z",
            "labels": [
                "malicious-activity"
            ]
        },
        {
            "type": "malware",
            "id": "malware--00000000-0000-0000-0000-000000000002",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "labels": [
                "ransomware"
            ]
        },
        {
            "type": "relationship",
            "id": "relationship--00000000-0000-0000-0000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--01234567-89ab-cdef-0123-456789abcdef",
            "target_ref": "malware--fedcba98-7654-3210-fedc-ba9876543210"
        }
    ]
}"""

EXPECTED_BUNDLE_DICT = {
    "type": "bundle",
    "id": "bundle--00000000-0000-0000-0000-000000000004",
    "spec_version": "2.0",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--00000000-0000-0000-0000-000000000001",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "valid_from": "2017-01-01T12:34:56Z",
            "labels": [
                "malicious-activity"
            ]
        },
        {
            "type": "malware",
            "id": "malware--00000000-0000-0000-0000-000000000002",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "labels": [
                "ransomware"
            ]
        },
        {
            "type": "relationship",
            "id": "relationship--00000000-0000-0000-0000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--01234567-89ab-cdef-0123-456789abcdef",
            "target_ref": "malware--fedcba98-7654-3210-fedc-ba9876543210"
        }
    ]
}


def test_empty_bundle():
    bundle = stix2.Bundle()

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    assert bundle.spec_version == "2.0"
    with pytest.raises(AttributeError):
        assert bundle.objects


def test_bundle_with_wrong_type():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.Bundle(type="not-a-bundle")

    assert excinfo.value.cls == stix2.Bundle
    assert excinfo.value.prop_name == "type"
    assert excinfo.value.reason == "must equal 'bundle'."
    assert str(excinfo.value) == "Invalid value for Bundle 'type': must equal 'bundle'."


def test_bundle_id_must_start_with_bundle():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.Bundle(id='my-prefix--')

    assert excinfo.value.cls == stix2.Bundle
    assert excinfo.value.prop_name == "id"
    assert excinfo.value.reason == "must start with 'bundle--'."
    assert str(excinfo.value) == "Invalid value for Bundle 'id': must start with 'bundle--'."


def test_bundle_with_wrong_spec_version():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.Bundle(spec_version="1.2")

    assert excinfo.value.cls == stix2.Bundle
    assert excinfo.value.prop_name == "spec_version"
    assert excinfo.value.reason == "must equal '2.0'."
    assert str(excinfo.value) == "Invalid value for Bundle 'spec_version': must equal '2.0'."


def test_create_bundle1(indicator, malware, relationship):
    bundle = stix2.Bundle(objects=[indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE
    assert bundle.serialize(pretty=True) == EXPECTED_BUNDLE


def test_create_bundle2(indicator, malware, relationship):
    bundle = stix2.Bundle(objects=[indicator, malware, relationship])

    assert json.loads(bundle.serialize()) == EXPECTED_BUNDLE_DICT


def test_create_bundle_with_positional_args(indicator, malware, relationship):
    bundle = stix2.Bundle(indicator, malware, relationship)

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_positional_listarg(indicator, malware, relationship):
    bundle = stix2.Bundle([indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_listarg_and_positional_arg(indicator, malware, relationship):
    bundle = stix2.Bundle([indicator, malware], relationship)

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_listarg_and_kwarg(indicator, malware, relationship):
    bundle = stix2.Bundle([indicator, malware], objects=[relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_arg_listarg_and_kwarg(indicator, malware, relationship):
    bundle = stix2.Bundle([indicator], malware, objects=[relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_invalid(indicator, malware, relationship):
    with pytest.raises(ValueError) as excinfo:
        stix2.Bundle(objects=[1])
    assert excinfo.value.reason == "This property may only contain a dictionary or object"

    with pytest.raises(ValueError) as excinfo:
        stix2.Bundle(objects=[{}])
    assert excinfo.value.reason == "This property may only contain a non-empty dictionary or object"

    with pytest.raises(ValueError) as excinfo:
        stix2.Bundle(objects=[{'type': 'bundle'}])
    assert excinfo.value.reason == 'This property may not contain a Bundle object'


@pytest.mark.parametrize("version", ["2.0"])
def test_parse_bundle(version):
    bundle = stix2.parse(EXPECTED_BUNDLE, version=version)

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    assert bundle.spec_version == "2.0"
    assert type(bundle.objects[0]) is stix2.Indicator
    assert bundle.objects[0].type == 'indicator'
    assert bundle.objects[1].type == 'malware'
    assert bundle.objects[2].type == 'relationship'


def test_parse_unknown_type():
    unknown = {
        "type": "other",
        "id": "other--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:00Z",
        "modified": "2016-04-06T20:03:00Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "description": "Campaign by Green Group against a series of targets in the financial services sector.",
        "name": "Green Group Attacks Against Finance",
    }

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(unknown)
    assert str(excinfo.value) == "Can't parse unknown object type 'other'! For custom types, use the CustomObject decorator."


def test_stix_object_property():
    prop = stix2.core.STIXObjectProperty()

    identity = stix2.Identity(name="test", identity_class="individual")
    assert prop.clean(identity) is identity
