from collections import OrderedDict

import pytest

from stix2 import DEFAULT_VERSION, exceptions, parsing, registration, registry

BUNDLE = {
    "type": "bundle",
    "spec_version": "2.0",
    "id": "bundle--00000000-0000-4000-8000-000000000007",
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


def test_dict_to_stix2_bundle_with_version():
    with pytest.raises(exceptions.ExtraPropertiesError) as excinfo:
        parsing.dict_to_stix2(BUNDLE, version='2.1')

    assert str(excinfo.value) == "Unexpected properties for Bundle: (spec_version)."


def test_parse_observable_with_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = parsing.parse_observable(observable, version='2.0')
    v = 'v20'

    assert v in str(obs_obj.__class__)


@pytest.mark.xfail(reason="The default version is no longer 2.0", condition=DEFAULT_VERSION != "2.0")
def test_parse_observable_with_no_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = parsing.parse_observable(observable)
    v = 'v20'

    assert v in str(obs_obj.__class__)


def test_register_marking_with_version():
    class NewMarking1:
        _type = 'x-new-marking1'
        _properties = OrderedDict()

    registration._register_marking(NewMarking1, version='2.0')

    assert NewMarking1._type in registry.STIX2_OBJ_MAPS['2.0']['markings']
    assert 'v20' in str(registry.STIX2_OBJ_MAPS['2.0']['markings'][NewMarking1._type])
