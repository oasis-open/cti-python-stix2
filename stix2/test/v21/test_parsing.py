from collections import OrderedDict

import pytest

from stix2 import DEFAULT_VERSION, exceptions, parsing, registration, registry

BUNDLE = {
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
            "pattern_type": "stix",
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
            "is_family": False,
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


def test_dict_to_stix2_bundle_with_version():
    with pytest.raises(exceptions.InvalidValueError) as excinfo:
        parsing.dict_to_stix2(BUNDLE, version='2.0')

    msg = "Invalid value for Bundle 'objects': Spec version 2.0 bundles don't yet support containing objects of a different spec version."
    assert str(excinfo.value) == msg


def test_parse_observable_with_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = parsing.parse_observable(observable, version='2.1')
    v = 'v21'

    assert v in str(obs_obj.__class__)


@pytest.mark.xfail(reason="The default version is not 2.1", condition=DEFAULT_VERSION != "2.1")
def test_parse_observable_with_no_version():
    observable = {"type": "file", "name": "foo.exe", "spec_version": "2.1"}
    obs_obj = parsing.parse_observable(observable)
    v = 'v21'

    assert v in str(obs_obj.__class__)


def test_register_marking_with_version():
    class NewMarking1:
        _type = 'x-new-marking1'
        _properties = OrderedDict()

    registration._register_marking(NewMarking1, version='2.1')

    assert NewMarking1._type in registry.STIX2_OBJ_MAPS['2.1']['markings']
    assert 'v21' in str(registry.STIX2_OBJ_MAPS['2.1']['markings'][NewMarking1._type])


@pytest.mark.xfail(reason="The default version is not 2.1", condition=DEFAULT_VERSION != "2.1")
def test_register_marking_with_no_version():
    # Uses default version (2.1 in this case)
    class NewMarking2:
        _type = 'x-new-marking2'
        _properties = OrderedDict()

    registration._register_marking(NewMarking2)

    assert NewMarking2._type in registry.STIX2_OBJ_MAPS['2.1']['markings']
    assert 'v21' in str(registry.STIX2_OBJ_MAPS['2.1']['markings'][NewMarking2._type])
