import pytest

import stix2
from stix2 import core, exceptions

from .constants import IDENTITY_ID

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
        core.dict_to_stix2(BUNDLE, version='2.1')

    assert str(excinfo.value) == "Unexpected properties for Bundle: (spec_version)."


def test_parse_observable_with_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = core.parse_observable(observable, version='2.0')
    v = 'v20'

    assert v in str(obs_obj.__class__)


@pytest.mark.xfail(reason="The default version is no longer 2.0", condition=stix2.DEFAULT_VERSION != "2.0")
def test_parse_observable_with_no_version():
    observable = {"type": "file", "name": "foo.exe"}
    obs_obj = core.parse_observable(observable)
    v = 'v20'

    assert v in str(obs_obj.__class__)


def test_register_object_with_version():
    bundle = core.dict_to_stix2(BUNDLE, version='2.0')
    core._register_object(bundle.objects[0].__class__, version='2.0')
    v = 'v20'

    assert bundle.objects[0].type in core.STIX2_OBJ_MAPS[v]['objects']
    # spec_version is not in STIX 2.0, and is required in 2.1, so this
    # suffices as a test for a STIX 2.0 object.
    assert "spec_version" not in bundle.objects[0]


def test_register_marking_with_version():
    core._register_marking(stix2.v20.TLP_WHITE.__class__, version='2.0')
    v = 'v20'

    assert stix2.v20.TLP_WHITE.definition._type in core.STIX2_OBJ_MAPS[v]['markings']
    assert v in str(stix2.v20.TLP_WHITE.__class__)


@pytest.mark.xfail(reason="The default version is no longer 2.0", condition=stix2.DEFAULT_VERSION != "2.0")
def test_register_marking_with_no_version():
    # Uses default version (2.0 in this case)
    core._register_marking(stix2.v20.TLP_WHITE.__class__)
    v = 'v20'

    assert stix2.v20.TLP_WHITE.definition._type in core.STIX2_OBJ_MAPS[v]['markings']
    assert v in str(stix2.v20.TLP_WHITE.__class__)


def test_register_observable_with_version():
    observed_data = stix2.v20.ObservedData(
        id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
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
    core._register_observable(observed_data.objects['0'].__class__, version='2.0')
    v = 'v20'

    assert observed_data.objects['0'].type in core.STIX2_OBJ_MAPS[v]['observables']
    assert v in str(observed_data.objects['0'].__class__)


def test_register_observable_extension_with_version():
    observed_data = stix2.v20.ObservedData(
        id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
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
    core._register_observable_extension(observed_data.objects['0'], observed_data.objects['0'].extensions['ntfs-ext'].__class__, version='2.0')
    v = 'v20'

    assert observed_data.objects['0'].type in core.STIX2_OBJ_MAPS[v]['observables']
    assert v in str(observed_data.objects['0'].__class__)

    assert observed_data.objects['0'].extensions['ntfs-ext']._type in core.STIX2_OBJ_MAPS[v]['observable-extensions']['file']
    assert v in str(observed_data.objects['0'].extensions['ntfs-ext'].__class__)
