import datetime as dt
import re

import pytest
import pytz

import stix2

from ..exceptions import InvalidValueError
from .constants import OBSERVED_DATA_ID


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
            "name": "foo.exe",
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
                "name": "foo.exe",
                "type": "file"
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
                "name": "foo.exe",
                "type": "file"
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
                "name": "foo.exe",
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


@pytest.mark.parametrize("data", [
    """
    {
        "type": "email-message",
        "is_multipart": true,
        "content_type": "multipart/mixed",
        "date": "2016-06-19T14:20:40.000Z",
        "from_ref": "1",
        "to_refs": [
          "2"
        ],
        "cc_refs": [
          "3"
        ],
        "subject": "Check out this picture of a cat!",
        "additional_header_fields": {
          "Content-Disposition": "inline",
          "X-Mailer": "Mutt/1.5.23",
          "X-Originating-IP": "198.51.100.3"
        },
        "body_multipart": [
          {
            "content_type": "text/plain; charset=utf-8",
            "content_disposition": "inline",
            "body": "Cats are funny!"
          },
          {
            "content_type": "image/png",
            "content_disposition": "attachment; filename=\\"tabby.png\\"",
            "body_raw_ref": "4"
          },
          {
            "content_type": "application/zip",
            "content_disposition": "attachment; filename=\\"tabby_pics.zip\\"",
            "body_raw_ref": "5"
          }
        ]
    }
    """
])
def test_parse_email_message(data):
    odata = stix2.parse_observable(data, [str(i) for i in range(1, 6)])
    assert odata.type == "email-message"
    assert odata.body_multipart[0].content_disposition == "inline"


@pytest.mark.parametrize("data", [
    """"0": {
            "type": "file",
            "hashes": {
                "SHA-256": "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"
            }
        },
        "1": {
            "type": "file",
            "hashes": {
                "SHA-256": "19c549ec2628b989382f6b280cbd7bb836a0b461332c0fe53511ce7d584b89d3"
            }
        },
        "2": {
            "type": "file",
            "hashes": {
                "SHA-256": "0969de02ecf8a5f003e3f6d063d848c8a193aada092623f8ce408c15bcb5f038"
            }
        },
        "3": {
            "type": "file",
            "name": "foo.zip",
            "hashes": {
                "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "mime_type": "application/zip",
            "extensions": {
                "archive-ext": {
                    "contains_refs": [
                        "0",
                        "1",
                        "2"
                    ],
                    "version": "5.0"
                }
            }
        }""",
])
def test_parse_file_archive(data):
    odata_str = re.compile('"objects".+\},', re.DOTALL).sub('"objects": { %s },' % data, EXPECTED)
    odata = stix2.parse(odata_str)
    assert odata.objects["3"].extensions['archive-ext'].version == "5.0"


@pytest.mark.parametrize("data", [
    """
    {
        "type": "email-message",
        "is_multipart": true,
        "content_type": "multipart/mixed",
        "date": "2016-06-19T14:20:40.000Z",
        "from_ref": "1",
        "to_refs": [
          "2"
        ],
        "cc_refs": [
          "3"
        ],
        "subject": "Check out this picture of a cat!",
        "additional_header_fields": {
          "Content-Disposition": "inline",
          "X-Mailer": "Mutt/1.5.23",
          "X-Originating-IP": "198.51.100.3"
        },
        "body_multipart": [
          {
            "content_type": "text/plain; charset=utf-8",
            "content_disposition": "inline",
            "body": "Cats are funny!"
          },
          {
            "content_type": "image/png",
            "content_disposition": "attachment; filename=\\"tabby.png\\""
          },
          {
            "content_type": "application/zip",
            "content_disposition": "attachment; filename=\\"tabby_pics.zip\\"",
            "body_raw_ref": "5"
          }
        ]
    }
    """
])
def test_parse_email_message_with_at_least_one_error(data):
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.parse_observable(data, [str(i) for i in range(1, 6)])

    assert excinfo.value.cls == stix2.EmailMIMEComponent
    assert excinfo.value.fields == ["body", "body_raw_ref"]


@pytest.mark.parametrize("data", [
    """
    {
        "type": "network-traffic",
        "src_ref": "0",
        "dst_ref": "1",
        "protocols": [
          "tcp"
        ]
    }
    """
])
def test_parse_basic_tcp_traffic(data):
    odata = stix2.parse_observable(data, ["0", "1"])

    assert odata.type == "network-traffic"
    assert odata.src_ref == "0"
    assert odata.dst_ref == "1"
    assert odata.protocols == ["tcp"]


@pytest.mark.parametrize("data", [
    """
    {
        "type": "network-traffic",
        "src_port": 2487,
        "dst_port": 1723,
        "protocols": [
          "ipv4",
          "pptp"
        ],
        "src_byte_count": 35779,
        "dst_byte_count": 935750,
        "encapsulates_refs": [
          "4"
        ]
  }
    """
])
def test_parse_basic_tcp_traffic_with_error(data):
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.parse_observable(data, ["4"])

    assert excinfo.value.cls == stix2.NetworkTraffic
    assert excinfo.value.fields == ["dst_ref", "src_ref"]


EXPECTED_PROCESS_OD = """{
    "created": "2016-04-06T19:58:16Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "first_observed": "2015-12-21T19:00:00Z",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "last_observed": "2015-12-21T19:00:00Z",
    "modified": "2016-04-06T19:58:16Z",
    "number_observed": 50,
    "objects": {
        "0": {
            "type": "file",
            "hashes": {
                "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100fSHA"
             },
        },
        "1": {
            "type": "process",
            "pid": 1221,
            "name": "gedit-bin",
            "created": "2016-01-20T14:11:25.55Z",
            "arguments" :[
              "--new-window"
            ],
            "binary_ref": "0"
          }
    },
    "type": "observed-data"
}"""


def test_observed_data_with_process_example():
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
                "hashes": {
                    "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
                },
            },
            "1": {
                "type": "process",
                "pid": 1221,
                "name": "gedit-bin",
                "created": "2016-01-20T14:11:25.55Z",
                "arguments": [
                  "--new-window"
                ],
                "binary_ref": "0"
            }
        })

    assert observed_data.objects["0"].type == "file"
    assert observed_data.objects["0"].hashes["SHA-256"] == "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
    assert observed_data.objects["1"].type == "process"
    assert observed_data.objects["1"].pid == 1221
    assert observed_data.objects["1"].name == "gedit-bin"
    assert observed_data.objects["1"].arguments[0] == "--new-window"


#  creating cyber observables directly

def test_artifact_example():
    art = stix2.Artifact(mime_type="image/jpeg",
                         url="https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg",
                         hashes={
                            "MD5": "6826f9a05da08134006557758bb3afbb"
                         })
    assert art.mime_type == "image/jpeg"
    assert art.url == "https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg"
    assert art.hashes["MD5"] == "6826f9a05da08134006557758bb3afbb"


def test_artifact_mutual_exclusion_error():
    with pytest.raises(stix2.exceptions.MutuallyExclusivePropertiesError) as excinfo:
        stix2.Artifact(mime_type="image/jpeg",
                       url="https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg",
                       hashes={
                            "MD5": "6826f9a05da08134006557758bb3afbb"
                       },
                       payload_bin="VBORw0KGgoAAAANSUhEUgAAADI==")

    assert excinfo.value.cls == stix2.Artifact
    assert excinfo.value.fields == ["payload_bin", "url"]


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
                   encryption_algorithm="AES128-CBC",
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
    assert f.encryption_algorithm == "AES128-CBC"
    assert f.decryption_key == "fred"   # does the key have a format we can test for?


def test_file_example_encryption_error():
    with pytest.raises(stix2.exceptions.DependentPropertiestError) as excinfo:
        stix2.File(name="qwerty.dll",
                   is_encrypted=False,
                   encryption_algorithm="AES128-CBC"
                   )

    assert excinfo.value.cls == stix2.File
    assert excinfo.value.dependencies == [("is_encrypted", "encryption_algorithm")]


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


def test_url_example():
    s = stix2.URL(value="https://example.com/research/index.html")

    assert s.type == "url"
    assert s.value == "https://example.com/research/index.html"


def test_user_account_example():
    a = stix2.UserAccount(user_id="1001",
                          account_login="jdoe",
                          account_type="unix",
                          display_name="John Doe",
                          is_service_account=False,
                          is_privileged=False,
                          can_escalate_privs=True,
                          account_created="2016-01-20T12:31:12Z",
                          password_last_changed="2016-01-20T14:27:43Z",
                          account_first_login="2016-01-20T14:26:07Z",
                          account_last_login="2016-07-22T16:08:28Z")

    assert a.user_id == "1001"
    assert a.account_login == "jdoe"
    assert a.account_type == "unix"
    assert a.display_name == "John Doe"
    assert not a.is_service_account
    assert not a.is_privileged
    assert a.can_escalate_privs
    assert a.account_created == dt.datetime(2016, 1, 20, 12, 31, 12, tzinfo=pytz.utc)
    assert a.password_last_changed == dt.datetime(2016, 1, 20, 14, 27, 43, tzinfo=pytz.utc)
    assert a.account_first_login == dt.datetime(2016, 1, 20, 14, 26, 7, tzinfo=pytz.utc)
    assert a.account_last_login == dt.datetime(2016, 7, 22, 16, 8, 28, tzinfo=pytz.utc)


def test_windows_registry_key_example():
    with pytest.raises(ValueError):
        v = stix2.WindowsRegistryValueType(name="Foo",
                                           data="qwerty",
                                           data_type="string")

    v = stix2.WindowsRegistryValueType(name="Foo",
                                       data="qwerty",
                                       data_type="REG_SZ")
    w = stix2.WindowsRegistryKey(key="hkey_local_machine\\system\\bar\\foo",
                                 values=[v])
    assert w.key == "hkey_local_machine\\system\\bar\\foo"
    assert w.values[0].name == "Foo"
    assert w.values[0].data == "qwerty"
    assert w.values[0].data_type == "REG_SZ"


def test_x509_certificate_example():
    x509 = stix2.X509Certificate(
        issuer="C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",  # noqa
        validity_not_before="2016-03-12T12:00:00Z",
        validity_not_after="2016-08-21T12:00:00Z",
        subject="C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org")  # noqa

    assert x509.type == "x509-certificate"
    assert x509.issuer == "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com"  # noqa
    assert x509.subject == "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org"  # noqa
