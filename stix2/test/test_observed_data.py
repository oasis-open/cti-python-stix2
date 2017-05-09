import datetime as dt
import re

import pytest
import pytz
import stix2

from .constants import OBSERVED_DATA_ID
from ..exceptions import InvalidValueError

EXPECTED = """{
    "created": "2016-04-06T19:58:16Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "first_observed": "2015-12-21T19:00:00Z",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "last_observed": "2015-12-21T19:00:00Z",
    "modified": "2016-04-06T19:58:16Z",
    "number_observed": 50,
    "objects": {
        "0": {
            "type": "file"
        }
    },
    "type": "observed-data"
}"""


def test_observed_data_example():
    observed_data = stix2.ObservedData(
        id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T19:58:16Z",
        modified="2016-04-06T19:58:16Z",
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=50,
        objects={
            "0": {
              "type": "file",
            },
        },
    )

    assert str(observed_data) == EXPECTED


EXPECTED_WITH_REF = """{
    "created": "2016-04-06T19:58:16Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "first_observed": "2015-12-21T19:00:00Z",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "last_observed": "2015-12-21T19:00:00Z",
    "modified": "2016-04-06T19:58:16Z",
    "number_observed": 50,
    "objects": {
        "0": {
            "name": "foo.exe",
            "type": "file"
        },
        "1": {
            "contains_refs": [
                "0"
            ],
            "path": "/usr/home",
            "type": "directory"
        }
    },
    "type": "observed-data"
}"""


def test_observed_data_example_with_refs():
    observed_data = stix2.ObservedData(
        id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T19:58:16Z",
        modified="2016-04-06T19:58:16Z",
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=50,
        objects={
            "0": {
                "type": "file",
                "name": "foo.exe"
            },
            "1": {
                "type": "directory",
                "path": "/usr/home",
                "contains_refs": ["0"]
            }
        },
    )

    assert str(observed_data) == EXPECTED_WITH_REF


def test_observed_data_example_with_bad_refs():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.ObservedData(
            id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
            created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
            created="2016-04-06T19:58:16Z",
            modified="2016-04-06T19:58:16Z",
            first_observed="2015-12-21T19:00:00Z",
            last_observed="2015-12-21T19:00:00Z",
            number_observed=50,
            objects={
                "0": {
                    "type": "file",
                    "name": "foo.exe"
                },
                "1": {
                    "type": "directory",
                    "path": "/usr/home",
                    "contains_refs": ["2"]
                }
            },
        )

    assert excinfo.value.cls == stix2.ObservedData
    assert excinfo.value.prop_name == "objects"
    assert excinfo.value.reason == "Invalid object reference for 'Directory:contains_refs': '2' is not a valid object in local scope"


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "type": "observed-data",
        "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        "created": "2016-04-06T19:58:16Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "modified": "2016-04-06T19:58:16Z",
        "number_observed": 50,
        "objects": {
            "0": {
                "type": "file"
            }
        }
    },
])
def test_parse_observed_data(data):
    odata = stix2.parse(data)

    assert odata.type == 'observed-data'
    assert odata.id == OBSERVED_DATA_ID
    assert odata.created == dt.datetime(2016, 4, 6, 19, 58, 16, tzinfo=pytz.utc)
    assert odata.modified == dt.datetime(2016, 4, 6, 19, 58, 16, tzinfo=pytz.utc)
    assert odata.first_observed == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert odata.last_observed == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert odata.created_by_ref == "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    assert odata.objects["0"].type == "file"


@pytest.mark.parametrize("data", [
    """"0": {
        "type": "artifact",
        "mime_type": "image/jpeg",
        "payload_bin": "VBORw0KGgoAAAANSUhEUgAAADI=="
    }""",
    """"0": {
        "type": "artifact",
        "mime_type": "image/jpeg",
        "url": "https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg",
        "hashes": {
            "MD5": "6826f9a05da08134006557758bb3afbb"
        }
    }""",
])
def test_parse_artifact_valid(data):
    odata_str = re.compile('"objects".+\},', re.DOTALL).sub('"objects": { %s },' % data, EXPECTED)
    odata = stix2.parse(odata_str)
    assert odata.objects["0"].type == "artifact"


@pytest.mark.parametrize("data", [
    """"0": {
        "type": "artifact",
        "mime_type": "image/jpeg",
        "payload_bin": "abcVBORw0KGgoAAAANSUhEUgAAADI=="
    }""",
    """"0": {
        "type": "artifact",
        "mime_type": "image/jpeg",
        "url": "https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg",
        "hashes": {
            "MD5": "a"
        }
    }""",
])
def test_parse_artifact_invalid(data):
    odata_str = re.compile('"objects".+\},', re.DOTALL).sub('"objects": { %s },' % data, EXPECTED)
    with pytest.raises(ValueError):
        stix2.parse(odata_str)


@pytest.mark.parametrize("data", [
    """"0": {
        "type": "autonomous-system",
        "number": 15139,
        "name": "Slime Industries",
        "rir": "ARIN"
    }""",
])
def test_parse_autonomous_system_valid(data):
    odata_str = re.compile('"objects".+\},', re.DOTALL).sub('"objects": { %s },' % data, EXPECTED)
    odata = stix2.parse(odata_str)
    assert odata.objects["0"].type == "autonomous-system"
    assert odata.objects["0"].number == 15139
    assert odata.objects["0"].name == "Slime Industries"
    assert odata.objects["0"].rir == "ARIN"


@pytest.mark.parametrize("data", [
    """"1": {
        "type": "email-address",
        "value": "john@example.com",
        "display_name": "John Doe",
        "belongs_to_ref": "0"
    }""",
])
def test_parse_email_address(data):
    odata_str = re.compile('\}.+\},', re.DOTALL).sub('}, %s},' % data, EXPECTED)
    odata = stix2.parse(odata_str)
    assert odata.objects["1"].type == "email-address"

    odata_str = re.compile('"belongs_to_ref": "0"', re.DOTALL).sub('"belongs_to_ref": "3"', odata_str)
    with pytest.raises(InvalidValueError):
        stix2.parse(odata_str)


#  creating cyber observables directly

def test_directory_example():
    dir = stix2.Directory(_valid_refs=["1"],
                          path='/usr/lib',
                          created="2015-12-21T19:00:00Z",
                          modified="2015-12-24T19:00:00Z",
                          accessed="2015-12-21T20:00:00Z",
                          contains_refs=["1"])

    assert dir.path == '/usr/lib'
    assert dir.created == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert dir.modified == dt.datetime(2015, 12, 24, 19, 0, 0, tzinfo=pytz.utc)
    assert dir.accessed == dt.datetime(2015, 12, 21, 20, 0, 0, tzinfo=pytz.utc)
    assert dir.contains_refs == ["1"]


def test_directory_example_ref_error():
    with pytest.raises(stix2.exceptions.InvalidObjRefError) as excinfo:
        stix2.Directory(_valid_refs=[],
                        path='/usr/lib',
                        created="2015-12-21T19:00:00Z",
                        modified="2015-12-24T19:00:00Z",
                        accessed="2015-12-21T20:00:00Z",
                        contains_refs=["1"])

    assert excinfo.value.cls == stix2.Directory
    assert excinfo.value.prop_name == "contains_refs"


def test_domain_name_example():
    dn = stix2.DomainName(_valid_refs=["1"],
                          value="example.com",
                          resolves_to_refs=["1"])

    assert dn.value == "example.com"
    assert dn.resolves_to_refs == ["1"]


def test_file_example():
    f = stix2.File(name="qwerty.dll",
                   hashes={
                    "SHA-256": "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"},
                   size=100,
                   magic_number_hex="1C",
                   mime_type="application/msword",
                   created="2016-12-21T19:00:00Z",
                   modified="2016-12-24T19:00:00Z",
                   accessed="2016-12-21T20:00:00Z",
                   is_encrypted=True,
                   encyption_algorithm="AES128-CBC",
                   decryption_key="fred"
                   )

    assert f.name == "qwerty.dll"
    assert f.size == 100
    assert f.magic_number_hex == "1C"
    assert f.hashes["SHA-256"] == "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"
    assert f.mime_type == "application/msword"
    assert f.created == dt.datetime(2016, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert f.modified == dt.datetime(2016, 12, 24, 19, 0, 0, tzinfo=pytz.utc)
    assert f.accessed == dt.datetime(2016, 12, 21, 20, 0, 0, tzinfo=pytz.utc)
    assert f.is_encrypted
    assert f.encyption_algorithm == "AES128-CBC"
    assert f.decryption_key == "fred"   # does the key have a format we can test for?


# def test_file_example_encyption_error():
#     f = stix2.File(name="qwerty.dll",
#                    is_encrypted=False,
#                    encyption_algorithm="AES128-CBC"
#                    )
#
#     assert f.name == "qwerty.dll"
#     assert f.is_encrypted == False
#     assert f.encyption_algorithm == "AES128-CBC"


def test_ip4_address_example():
    ip4 = stix2.IPv4Address(_valid_refs=["1", "4", "5"],
                            value="198.51.100.3",
                            resolves_to_refs=["4", "5"])

    assert ip4.value == "198.51.100.3"
    assert ip4.resolves_to_refs == ["4", "5"]


def test_ip4_address_example_cidr():
    ip4 = stix2.IPv4Address(value="198.51.100.0/24")

    assert ip4.value == "198.51.100.0/24"


def test_ip6_address_example():
    ip6 = stix2.IPv6Address(value="2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    assert ip6.value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_mac_address_example():
    ip6 = stix2.MACAddress(value="d2:fb:49:24:37:18")

    assert ip6.value == "d2:fb:49:24:37:18"


def test_mutex_example():
    m = stix2.Mutex(name="barney")

    assert m.name == "barney"


def test_software_example():
    s = stix2.Software(name="Word",
                       cpe="cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
                       version="2002",
                       vendor="Microsoft")

    assert s.name == "Word"
    assert s.cpe == "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*"
    assert s.version == "2002"
    assert s.vendor == "Microsoft"
