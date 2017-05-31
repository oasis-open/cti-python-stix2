import pytest

import stix2


EXPECTED_BUNDLE = """{
    "id": "bundle--00000000-0000-0000-0000-000000000004",
    "objects": [
        {
            "created": "2017-01-01T12:34:56Z",
            "id": "indicator--00000000-0000-0000-0000-000000000001",
            "labels": [
                "malicious-activity"
            ],
            "modified": "2017-01-01T12:34:56Z",
            "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "type": "indicator",
            "valid_from": "2017-01-01T12:34:56Z"
        },
        {
            "created": "2017-01-01T12:34:56Z",
            "id": "malware--00000000-0000-0000-0000-000000000002",
            "labels": [
                "ransomware"
            ],
            "modified": "2017-01-01T12:34:56Z",
            "name": "Cryptolocker",
            "type": "malware"
        },
        {
            "created": "2017-01-01T12:34:56Z",
            "id": "relationship--00000000-0000-0000-0000-000000000003",
            "modified": "2017-01-01T12:34:56Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--01234567-89ab-cdef-0123-456789abcdef",
            "target_ref": "malware--fedcba98-7654-3210-fedc-ba9876543210",
            "type": "relationship"
        }
    ],
    "spec_version": "2.0",
    "type": "bundle"
}"""


def test_empty_bundle():
    bundle = stix2.Bundle()

    assert bundle.type == "bundle"
    assert bundle.id.startswith("bundle--")
    assert bundle.spec_version == "2.0"
    assert bundle.objects is None


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


def test_create_bundle(indicator, malware, relationship):
    bundle = stix2.Bundle(objects=[indicator, malware, relationship])

    assert str(bundle) == EXPECTED_BUNDLE


def test_create_bundle_with_positional_args(indicator, malware, relationship):
    bundle = stix2.Bundle(indicator, malware, relationship)

    assert str(bundle) == EXPECTED_BUNDLE
