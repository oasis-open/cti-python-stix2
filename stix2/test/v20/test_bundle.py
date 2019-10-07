import json

import pytest

import stix2

from ...exceptions import InvalidValueError
from .constants import IDENTITY_ID

EXPECTED_BUNDLE = """{
    "type": "bundle",
    "id": "bundle--00000000-0000-4000-8000-000000000007",
    "spec_version": "2.0",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--00000000-0000-4000-8000-000000000001",
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
            "id": "malware--00000000-0000-4000-8000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "labels": [
                "ransomware"
            ]
        },
        {
            "type": "relationship",
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
    "spec_version": "2.0",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--00000000-0000-4000-8000-000000000001",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "valid_from": "2017-01-01T12:34:56Z",
            "labels": [
                "malicious-activity",
            ],
        },
        {
            "type": "malware",
            "id": "malware--00000000-0000-4000-8000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "labels": [
                "ransomware",
            ],
        },
        {
            "type": "relationship",
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
    bundle = stix2.v20.Bundle()

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    with pytest.raises(AttributeError):
        assert bundle.objects


def test_bundle_with_wrong_type():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v20.Bundle(type="not-a-bundle")

    assert excinfo.value.cls == stix2.v20.Bundle
    assert excinfo.value.prop_name == "type"
    assert excinfo.value.reason == "must equal 'bundle'."
    assert str(excinfo.value) == "Invalid value for Bundle 'type': must equal 'bundle'."


def test_bundle_id_must_start_with_bundle():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v20.Bundle(id='my-prefix--')

    assert excinfo.value.cls == stix2.v20.Bundle
    assert excinfo.value.prop_name == "id"
    assert excinfo.value.reason == "must start with 'bundle--'."
    assert str(excinfo.value) == "Invalid value for Bundle 'id': must start with 'bundle--'."


def test_create_bundle1(indicator, malware, relationship):
    bundle = stix2.v20.Bundle(objects=[indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE
    assert bundle.serialize(pretty=True) == EXPECTED_BUNDLE


def test_create_bundle2(indicator, malware, relationship):
    bundle = stix2.v20.Bundle(objects=[indicator, malware, relationship])

    assert json.loads(bundle.serialize()) == EXPECTED_BUNDLE_DICT


def test_create_bundle_with_positional_args(indicator, malware, relationship):
    bundle = stix2.v20.Bundle(indicator, malware, relationship)

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_positional_listarg(indicator, malware, relationship):
    bundle = stix2.v20.Bundle([indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_listarg_and_positional_arg(indicator, malware, relationship):
    bundle = stix2.v20.Bundle([indicator, malware], relationship)

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_listarg_and_kwarg(indicator, malware, relationship):
    bundle = stix2.v20.Bundle([indicator, malware], objects=[relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_arg_listarg_and_kwarg(indicator, malware, relationship):
    bundle = stix2.v20.Bundle([indicator], malware, objects=[relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_invalid(indicator, malware, relationship):
    with pytest.raises(InvalidValueError) as excinfo:
        stix2.v20.Bundle(objects=[1])
    assert excinfo.value.reason == "This property may only contain a dictionary or object"

    with pytest.raises(InvalidValueError) as excinfo:
        stix2.v20.Bundle(objects=[{}])
    assert excinfo.value.reason == "This property may only contain a non-empty dictionary or object"

    with pytest.raises(InvalidValueError) as excinfo:
        stix2.v20.Bundle(objects=[{'type': 'bundle'}])
    assert excinfo.value.reason == 'This property may not contain a Bundle object'


@pytest.mark.parametrize("version", ["2.0"])
def test_parse_bundle(version):
    bundle = stix2.parse(EXPECTED_BUNDLE, version=version)

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    assert isinstance(bundle.objects[0], stix2.v20.Indicator)
    assert bundle.objects[0].type == 'indicator'
    assert bundle.objects[1].type == 'malware'
    assert bundle.objects[2].type == 'relationship'


def test_parse_unknown_type():
    unknown = {
        "type": "other",
        "id": "other--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:00Z",
        "modified": "2016-04-06T20:03:00Z",
        "created_by_ref": IDENTITY_ID,
        "description": "Campaign by Green Group against a series of targets in the financial services sector.",
        "name": "Green Group Attacks Against Finance",
    }

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(unknown, version="2.0")
    assert str(excinfo.value) == "Can't parse unknown object type 'other'! For custom types, use the CustomObject decorator."


def test_stix_object_property():
    prop = stix2.properties.STIXObjectProperty(spec_version='2.0')

    identity = stix2.v20.Identity(name="test", identity_class="individual")
    assert prop.clean(identity) is identity


def test_bundle_with_different_spec_objects():
    # This is a 2.0 case only...

    data = [
        {
            "spec_version": "2.1",
            "type": "indicator",
            "id": "indicator--00000000-0000-4000-8000-000000000001",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "valid_from": "2017-01-01T12:34:56Z",
            "labels": [
                "malicious-activity",
            ],
        },
        {
            "type": "malware",
            "id": "malware--00000000-0000-4000-8000-000000000003",
            "created": "2017-01-01T12:34:56.000Z",
            "modified": "2017-01-01T12:34:56.000Z",
            "name": "Cryptolocker",
            "labels": [
                "ransomware",
            ],
        },
    ]

    with pytest.raises(InvalidValueError) as excinfo:
        stix2.v20.Bundle(objects=data)

    assert "Spec version 2.0 bundles don't yet support containing objects of a different spec version." in str(excinfo.value)


def test_bundle_obj_id_found():
    bundle = stix2.parse(EXPECTED_BUNDLE)

    mal_list = bundle.get_obj("malware--00000000-0000-4000-8000-000000000003")
    assert bundle.objects[1] == mal_list[0]
    assert len(mal_list) == 1


@pytest.mark.parametrize(
    "bundle_data", [{
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000007",
        "spec_version": "2.0",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--00000000-0000-4000-8000-000000000001",
                "created": "2017-01-01T12:34:56.000Z",
                "modified": "2017-01-01T12:34:56.000Z",
                "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
                "valid_from": "2017-01-01T12:34:56Z",
                "labels": [
                    "malicious-activity",
                ],
            },
            {
                "type": "malware",
                "id": "malware--00000000-0000-4000-8000-000000000003",
                "created": "2017-01-01T12:34:56.000Z",
                "modified": "2017-01-01T12:34:56.000Z",
                "name": "Cryptolocker1",
                "labels": [
                    "ransomware",
                ],
            },
            {
                "type": "malware",
                "id": "malware--00000000-0000-4000-8000-000000000003",
                "created": "2017-01-01T12:34:56.000Z",
                "modified": "2017-12-21T12:34:56.000Z",
                "name": "CryptolockerOne",
                "labels": [
                    "ransomware",
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--00000000-0000-4000-8000-000000000005",
                "created": "2017-01-01T12:34:56.000Z",
                "modified": "2017-01-01T12:34:56.000Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
                "target_ref": "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
            },
        ],
    }],
)
def test_bundle_objs_ids_found(bundle_data):
    bundle = stix2.parse(bundle_data)

    mal_list = bundle.get_obj("malware--00000000-0000-4000-8000-000000000003")
    assert bundle.objects[1] == mal_list[0]
    assert bundle.objects[2] == mal_list[1]
    assert len(mal_list) == 2


def test_bundle_getitem_overload_property_found():
    bundle = stix2.parse(EXPECTED_BUNDLE)

    assert bundle.type == "bundle"
    assert bundle['type'] == "bundle"


def test_bundle_getitem_overload_obj_id_found():
    bundle = stix2.parse(EXPECTED_BUNDLE)

    mal_list = bundle["malware--00000000-0000-4000-8000-000000000003"]
    assert bundle.objects[1] == mal_list[0]
    assert len(mal_list) == 1


def test_bundle_obj_id_not_found():
    bundle = stix2.parse(EXPECTED_BUNDLE)

    with pytest.raises(KeyError) as excinfo:
        bundle.get_obj('non existent')
    assert "does not match the id property of any of the bundle" in str(excinfo.value)


def test_bundle_getitem_overload_obj_id_not_found():
    bundle = stix2.parse(EXPECTED_BUNDLE)

    with pytest.raises(KeyError) as excinfo:
        bundle['non existent']
    assert "neither a property on the bundle nor does it match the id property" in str(excinfo.value)
