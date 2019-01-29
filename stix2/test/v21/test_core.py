import pytest

import stix2
from stix2 import core, exceptions

from .constants import IDENTITY_ID, OBSERVED_DATA_ID

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


def test_dict_to_stix2_bundle_with_version():
    with pytest.raises(exceptions.InvalidValueError) as excinfo:
        core.dict_to_stix2(BUNDLE, version='2.0')

    msg = "Invalid value for Bundle 'objects': Spec version 2.0 bundles don't yet support containing objects of a different spec version."
    assert str(excinfo.value) == msg


def test_parse_observable_with_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = core.parse_observable(observable, version='2.1')
    v = 'v21'

    assert v in str(obs_obj.__class__)


@pytest.mark.xfail(reason="The default version is not 2.1", condition=stix2.DEFAULT_VERSION != "2.1")
def test_parse_observable_with_no_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = core.parse_observable(observable)
    v = 'v21'

    assert v in str(obs_obj.__class__)


def test_register_object_with_version():
    bundle = core.dict_to_stix2(BUNDLE, version='2.1')
    core._register_object(bundle.objects[0].__class__)
    v = 'v21'

    assert bundle.objects[0].type in core.STIX2_OBJ_MAPS[v]['objects']
    assert v in str(bundle.objects[0].__class__)


def test_register_marking_with_version():
    core._register_marking(stix2.v21.TLP_WHITE.__class__, version='2.1')
    v = 'v21'

    assert stix2.v21.TLP_WHITE.definition._type in core.STIX2_OBJ_MAPS[v]['markings']
    assert v in str(stix2.v21.TLP_WHITE.__class__)


@pytest.mark.xfail(reason="The default version is not 2.1", condition=stix2.DEFAULT_VERSION != "2.1")
def test_register_marking_with_no_version():
    # Uses default version (2.0 in this case)
    core._register_marking(stix2.v21.TLP_WHITE.__class__)
    v = 'v21'

    assert stix2.v21.TLP_WHITE.definition._type in core.STIX2_OBJ_MAPS[v]['markings']
    assert v in str(stix2.v21.TLP_WHITE.__class__)


def test_register_observable_with_default_version():
    observed_data = stix2.v21.ObservedData(
        id=OBSERVED_DATA_ID,
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T19:58:16.000Z",
        modified="2016-04-06T19:58:16.000Z",
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=50,
        objects={
            "0": {
                "name": "foo.exe",
                "type": "file",
                "extensions": {
                    "ntfs-ext": {
                        "alternate_data_streams": [
                            {
                                "name": "second.stream",
                                "size": 25536,
                            },
                        ],
                    },
                },
            },
            "1": {
                "type": "directory",
                "path": "/usr/home",
                "contains_refs": ["0"],
            },
        },
    )
    core._register_observable(observed_data.objects['0'].__class__)
    v = 'v21'

    assert observed_data.objects['0'].type in core.STIX2_OBJ_MAPS[v]['observables']
    assert v in str(observed_data.objects['0'].__class__)


def test_register_observable_extension_with_default_version():
    observed_data = stix2.v21.ObservedData(
        id=OBSERVED_DATA_ID,
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T19:58:16.000Z",
        modified="2016-04-06T19:58:16.000Z",
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=50,
        objects={
            "0": {
                "name": "foo.exe",
                "type": "file",
                "extensions": {
                    "ntfs-ext": {
                        "alternate_data_streams": [
                            {
                                "name": "second.stream",
                                "size": 25536,
                            },
                        ],
                    },
                },
            },
            "1": {
                "type": "directory",
                "path": "/usr/home",
                "contains_refs": ["0"],
            },
        },
    )
    core._register_observable_extension(observed_data.objects['0'], observed_data.objects['0'].extensions['ntfs-ext'].__class__)
    v = 'v21'

    assert observed_data.objects['0'].type in core.STIX2_OBJ_MAPS[v]['observables']
    assert v in str(observed_data.objects['0'].__class__)

    assert observed_data.objects['0'].extensions['ntfs-ext']._type in core.STIX2_OBJ_MAPS[v]['observable-extensions']['file']
    assert v in str(observed_data.objects['0'].extensions['ntfs-ext'].__class__)
