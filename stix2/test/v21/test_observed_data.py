import datetime as dt
import re

import pytest
import pytz

import stix2

from .constants import IDENTITY_ID, OBSERVED_DATA_ID

OBJECTS_REGEX = re.compile('\"objects\": {(?:.*?)(?:(?:[^{]*?)|(?:{[^{]*?}))*}', re.DOTALL)


EXPECTED = """{
    "type": "observed-data",
    "spec_version": "2.1",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T19:58:16.000Z",
    "modified": "2016-04-06T19:58:16.000Z",
    "first_observed": "2015-12-21T19:00:00Z",
    "last_observed": "2015-12-21T19:00:00Z",
    "number_observed": 50,
    "objects": {
        "0": {
            "type": "file",
            "name": "foo.exe"
        }
    }
}"""


def test_observed_data_example():
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
            },
        },
    )

    assert str(observed_data) == EXPECTED


EXPECTED_WITH_REF = """{
    "type": "observed-data",
    "spec_version": "2.1",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T19:58:16.000Z",
    "modified": "2016-04-06T19:58:16.000Z",
    "first_observed": "2015-12-21T19:00:00Z",
    "last_observed": "2015-12-21T19:00:00Z",
    "number_observed": 50,
    "objects": {
        "0": {
            "type": "file",
            "name": "foo.exe"
        },
        "1": {
            "type": "directory",
            "path": "/usr/home",
            "contains_refs": [
                "0"
            ]
        }
    }
}"""


def test_observed_data_example_with_refs():
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
            },
            "1": {
                "type": "directory",
                "path": "/usr/home",
                "contains_refs": ["0"],
            },
        },
    )

    assert str(observed_data) == EXPECTED_WITH_REF


def test_observed_data_example_with_bad_refs():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.ObservedData(
            id=OBSERVED_DATA_ID,
            created_by_ref=IDENTITY_ID,
            created="2016-04-06T19:58:16.000Z",
            modified="2016-04-06T19:58:16.000Z",
            first_observed="2015-12-21T19:00:00Z",
            last_observed="2015-12-21T19:00:00Z",
            number_observed=50,
            objects={
                "0": {
                    "type": "file",
                    "name": "foo.exe",
                },
                "1": {
                    "type": "directory",
                    "path": "/usr/home",
                    "contains_refs": ["2"],
                },
            },
        )

    assert excinfo.value.cls == stix2.v21.ObservedData
    assert excinfo.value.prop_name == "objects"
    assert excinfo.value.reason == "Invalid object reference for 'Directory:contains_refs': '2' is not a valid object in local scope"


def test_observed_data_example_with_non_dictionary():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.ObservedData(
            id=OBSERVED_DATA_ID,
            created_by_ref=IDENTITY_ID,
            created="2016-04-06T19:58:16.000Z",
            modified="2016-04-06T19:58:16.000Z",
            first_observed="2015-12-21T19:00:00Z",
            last_observed="2015-12-21T19:00:00Z",
            number_observed=50,
            objects="file: foo.exe",
        )

    assert excinfo.value.cls == stix2.v21.ObservedData
    assert excinfo.value.prop_name == "objects"
    assert 'must contain a dictionary' in excinfo.value.reason


def test_observed_data_example_with_empty_dictionary():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.ObservedData(
            id=OBSERVED_DATA_ID,
            created_by_ref=IDENTITY_ID,
            created="2016-04-06T19:58:16.000Z",
            modified="2016-04-06T19:58:16.000Z",
            first_observed="2015-12-21T19:00:00Z",
            last_observed="2015-12-21T19:00:00Z",
            number_observed=50,
            objects={},
        )

    assert excinfo.value.cls == stix2.v21.ObservedData
    assert excinfo.value.prop_name == "objects"
    assert 'must contain a non-empty dictionary' in excinfo.value.reason


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": OBSERVED_DATA_ID,
            "created": "2016-04-06T19:58:16.000Z",
            "created_by_ref": IDENTITY_ID,
            "first_observed": "2015-12-21T19:00:00Z",
            "last_observed": "2015-12-21T19:00:00Z",
            "modified": "2016-04-06T19:58:16.000Z",
            "number_observed": 50,
            "objects": {
                "0": {
                    "name": "foo.exe",
                    "type": "file",
                },
            },
        },
    ],
)
def test_parse_observed_data(data):
    odata = stix2.parse(data, version="2.1")

    assert odata.type == 'observed-data'
    assert odata.spec_version == '2.1'
    assert odata.id == OBSERVED_DATA_ID
    assert odata.created == dt.datetime(2016, 4, 6, 19, 58, 16, tzinfo=pytz.utc)
    assert odata.modified == dt.datetime(2016, 4, 6, 19, 58, 16, tzinfo=pytz.utc)
    assert odata.first_observed == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert odata.last_observed == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert odata.created_by_ref == IDENTITY_ID
    assert odata.objects["0"].type == "file"


@pytest.mark.parametrize(
    "data", [
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
    ],
)
def test_parse_artifact_valid(data):
    odata_str = OBJECTS_REGEX.sub('"objects": { %s }' % data, EXPECTED)
    odata = stix2.parse(odata_str, version="2.1")
    assert odata.objects["0"].type == "artifact"


@pytest.mark.parametrize(
    "data", [
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
    ],
)
def test_parse_artifact_invalid(data):
    odata_str = OBJECTS_REGEX.sub('"objects": { %s }' % data, EXPECTED)
    with pytest.raises(ValueError):
        stix2.parse(odata_str, version="2.1")


def test_artifact_example_dependency_error():
    with pytest.raises(stix2.exceptions.DependentPropertiesError) as excinfo:
        stix2.v21.Artifact(url="http://example.com/sirvizio.exe")

    assert excinfo.value.dependencies == [("hashes", "url")]
    assert str(excinfo.value) == "The property dependencies for Artifact: (hashes, url) are not met."


@pytest.mark.parametrize(
    "data", [
        """"0": {
        "type": "autonomous-system",
        "number": 15139,
        "name": "Slime Industries",
        "rir": "ARIN"
    }""",
    ],
)
def test_parse_autonomous_system_valid(data):
    odata_str = OBJECTS_REGEX.sub('"objects": { %s }' % data, EXPECTED)
    odata = stix2.parse(odata_str, version="2.1")
    assert odata.objects["0"].type == "autonomous-system"
    assert odata.objects["0"].number == 15139
    assert odata.objects["0"].name == "Slime Industries"
    assert odata.objects["0"].rir == "ARIN"


@pytest.mark.parametrize(
    "data", [
        """{
        "type": "email-addr",
        "value": "john@example.com",
        "display_name": "John Doe",
        "belongs_to_ref": "0"
    }""",
    ],
)
def test_parse_email_address(data):
    odata = stix2.parse_observable(data, {"0": "user-account"}, version='2.1')
    assert odata.type == "email-addr"

    odata_str = re.compile('"belongs_to_ref": "0"', re.DOTALL).sub('"belongs_to_ref": "3"', data)
    with pytest.raises(stix2.exceptions.InvalidObjRefError):
        stix2.parse_observable(odata_str, {"0": "user-account"}, version='2.1')


@pytest.mark.parametrize(
    "data", [
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
    """,
    ],
)
def test_parse_email_message(data):
    valid_refs = {
        "0": "email-message",
        "1": "email-addr",
        "2": "email-addr",
        "3": "email-addr",
        "4": "artifact",
        "5": "file",
    }
    odata = stix2.parse_observable(data, valid_refs, version='2.1')
    assert odata.type == "email-message"
    assert odata.body_multipart[0].content_disposition == "inline"


@pytest.mark.parametrize(
    "data", [
        """
    {
         "type": "email-message",
         "from_ref": "0",
         "to_refs": ["1"],
         "is_multipart": true,
         "date": "1997-11-21T15:55:06.000Z",
         "subject": "Saying Hello",
         "body": "Cats are funny!"
    }
    """,
    ],
)
def test_parse_email_message_not_multipart(data):
    valid_refs = {
        "0": "email-addr",
        "1": "email-addr",
    }
    with pytest.raises(stix2.exceptions.DependentPropertiesError) as excinfo:
        stix2.parse_observable(data, valid_refs, version='2.1')

    assert excinfo.value.cls == stix2.v21.EmailMessage
    assert excinfo.value.dependencies == [("is_multipart", "body")]


@pytest.mark.parametrize(
    "data", [
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
                    ]
                }
            }
        }""",
    ],
)
def test_parse_file_archive(data):
    odata_str = OBJECTS_REGEX.sub('"objects": { %s }' % data, EXPECTED)
    odata = stix2.parse(odata_str, version="2.1")
    assert all(x in odata.objects["3"].extensions['archive-ext'].contains_refs
               for x in ["0", "1", "2"])


@pytest.mark.parametrize(
    "data", [
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
    """,
    ],
)
def test_parse_email_message_with_at_least_one_error(data):
    valid_refs = {
        "0": "email-message",
        "1": "email-addr",
        "2": "email-addr",
        "3": "email-addr",
        "4": "artifact",
        "5": "file",
    }
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.parse_observable(data, valid_refs, version='2.1')

    assert excinfo.value.cls == stix2.v21.EmailMIMEComponent
    assert excinfo.value.properties == ["body", "body_raw_ref"]
    assert "At least one of the" in str(excinfo.value)
    assert "must be populated" in str(excinfo.value)


@pytest.mark.parametrize(
    "data", [
        """
    {
        "type": "network-traffic",
        "src_ref": "0",
        "dst_ref": "1",
        "protocols": [
          "tcp"
        ]
    }
    """,
    ],
)
def test_parse_basic_tcp_traffic(data):
    odata = stix2.parse_observable(
        data, {"0": "ipv4-addr", "1": "ipv4-addr"},
        version='2.1',
    )

    assert odata.type == "network-traffic"
    assert odata.src_ref == "0"
    assert odata.dst_ref == "1"
    assert odata.protocols == ["tcp"]


@pytest.mark.parametrize(
    "data", [
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
    """,
    ],
)
def test_parse_basic_tcp_traffic_with_error(data):
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.parse_observable(data, {"4": "network-traffic"}, version='2.1')

    assert excinfo.value.cls == stix2.v21.NetworkTraffic
    assert excinfo.value.properties == ["dst_ref", "src_ref"]


EXPECTED_PROCESS_OD = """{
    "created": "2016-04-06T19:58:16.000Z",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "first_observed": "2015-12-21T19:00:00Z",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "last_observed": "2015-12-21T19:00:00Z",
    "modified": "2016-04-06T19:58:16.000Z",
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
            "created": "2016-01-20T14:11:25.55Z",
            "command_line": "./gedit-bin --new-window",
            "binary_ref": "0"
          }
    },
    "spec_version": "2.1",
    "type": "observed-data"
}"""


def test_observed_data_with_process_example():
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
                "type": "file",
                "hashes": {
                    "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f",
                },
            },
            "1": {
                "type": "process",
                "pid": 1221,
                "created": "2016-01-20T14:11:25.55Z",
                "command_line": "./gedit-bin --new-window",
                "image_ref": "0",
            },
        },
    )

    assert observed_data.objects["0"].type == "file"
    assert observed_data.objects["0"].hashes["SHA-256"] == "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
    assert observed_data.objects["1"].type == "process"
    assert observed_data.objects["1"].pid == 1221
    assert observed_data.objects["1"].command_line == "./gedit-bin --new-window"


#  creating cyber observables directly

def test_artifact_example():
    art = stix2.v21.Artifact(
        mime_type="image/jpeg",
        url="https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg",
        hashes={
            "MD5": "6826f9a05da08134006557758bb3afbb",
        },
    )
    assert art.mime_type == "image/jpeg"
    assert art.url == "https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg"
    assert art.hashes["MD5"] == "6826f9a05da08134006557758bb3afbb"


def test_artifact_mutual_exclusion_error():
    with pytest.raises(stix2.exceptions.MutuallyExclusivePropertiesError) as excinfo:
        stix2.v21.Artifact(
            mime_type="image/jpeg",
            url="https://upload.wikimedia.org/wikipedia/commons/b/b4/JPEG_example_JPG_RIP_100.jpg",
            hashes={
                "MD5": "6826f9a05da08134006557758bb3afbb",
            },
            payload_bin="VBORw0KGgoAAAANSUhEUgAAADI==",
        )

    assert excinfo.value.cls == stix2.v21.Artifact
    assert excinfo.value.properties == ["payload_bin", "url"]
    assert 'are mutually exclusive' in str(excinfo.value)


def test_directory_example():
    dir = stix2.v21.Directory(
        _valid_refs={"1": "file"},
        path='/usr/lib',
        created="2015-12-21T19:00:00Z",
        modified="2015-12-24T19:00:00Z",
        accessed="2015-12-21T20:00:00Z",
        contains_refs=["1"],
    )

    assert dir.path == '/usr/lib'
    assert dir.created == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert dir.modified == dt.datetime(2015, 12, 24, 19, 0, 0, tzinfo=pytz.utc)
    assert dir.accessed == dt.datetime(2015, 12, 21, 20, 0, 0, tzinfo=pytz.utc)
    assert dir.contains_refs == ["1"]


def test_directory_example_ref_error():
    with pytest.raises(stix2.exceptions.InvalidObjRefError) as excinfo:
        stix2.v21.Directory(
            _valid_refs=[],
            path='/usr/lib',
            created="2015-12-21T19:00:00Z",
            modified="2015-12-24T19:00:00Z",
            accessed="2015-12-21T20:00:00Z",
            contains_refs=["1"],
        )

    assert excinfo.value.cls == stix2.v21.Directory
    assert excinfo.value.prop_name == "contains_refs"


def test_domain_name_example():
    dn = stix2.v21.DomainName(
        _valid_refs={"1": 'domain-name'},
        value="example.com",
        resolves_to_refs=["1"],
    )

    assert dn.value == "example.com"
    assert dn.resolves_to_refs == ["1"]


def test_domain_name_example_invalid_ref_type():
    with pytest.raises(stix2.exceptions.InvalidObjRefError) as excinfo:
        stix2.v21.DomainName(
            _valid_refs={"1": "file"},
            value="example.com",
            resolves_to_refs=["1"],
        )

    assert excinfo.value.cls == stix2.v21.DomainName
    assert excinfo.value.prop_name == "resolves_to_refs"


def test_file_example():
    f = stix2.v21.File(
        name="qwerty.dll",
        hashes={
            "SHA-256": "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a",
        },
        size=100,
        magic_number_hex="1C",
        mime_type="application/msword",
        created="2016-12-21T19:00:00Z",
        modified="2016-12-24T19:00:00Z",
        accessed="2016-12-21T20:00:00Z",
    )

    assert f.name == "qwerty.dll"
    assert f.size == 100
    assert f.magic_number_hex == "1C"
    assert f.hashes["SHA-256"] == "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"
    assert f.mime_type == "application/msword"
    assert f.created == dt.datetime(2016, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert f.modified == dt.datetime(2016, 12, 24, 19, 0, 0, tzinfo=pytz.utc)
    assert f.accessed == dt.datetime(2016, 12, 21, 20, 0, 0, tzinfo=pytz.utc)


def test_file_example_with_NTFSExt():
    f = stix2.v21.File(
        name="abc.txt",
        extensions={
            "ntfs-ext": {
                "alternate_data_streams": [
                    {
                        "name": "second.stream",
                        "size": 25536,
                    },
                ],
            },
        },
    )

    assert f.name == "abc.txt"
    assert f.extensions["ntfs-ext"].alternate_data_streams[0].size == 25536


def test_file_example_with_empty_NTFSExt():
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.v21.File(
            name="abc.txt",
            extensions={
                "ntfs-ext": {},
            },
        )

    assert excinfo.value.cls == stix2.v21.NTFSExt
    assert excinfo.value.properties == sorted(list(stix2.NTFSExt._properties.keys()))


def test_file_example_with_PDFExt():
    f = stix2.v21.File(
        name="qwerty.dll",
        extensions={
            "pdf-ext": {
                "version": "1.7",
                "document_info_dict": {
                    "Title": "Sample document",
                    "Author": "Adobe Systems Incorporated",
                    "Creator": "Adobe FrameMaker 5.5.3 for Power Macintosh",
                    "Producer": "Acrobat Distiller 3.01 for Power Macintosh",
                    "CreationDate": "20070412090123-02",
                },
                "pdfid0": "DFCE52BD827ECF765649852119D",
                "pdfid1": "57A1E0F9ED2AE523E313C",
            },
        },
    )

    assert f.name == "qwerty.dll"
    assert f.extensions["pdf-ext"].version == "1.7"
    assert f.extensions["pdf-ext"].document_info_dict["Title"] == "Sample document"


def test_file_example_with_PDFExt_Object():
    f = stix2.v21.File(
        name="qwerty.dll",
        extensions={
            "pdf-ext": stix2.v21.PDFExt(
                version="1.7",
                document_info_dict={
                    "Title": "Sample document",
                    "Author": "Adobe Systems Incorporated",
                    "Creator": "Adobe FrameMaker 5.5.3 for Power Macintosh",
                    "Producer": "Acrobat Distiller 3.01 for Power Macintosh",
                    "CreationDate": "20070412090123-02",
                },
                pdfid0="DFCE52BD827ECF765649852119D",
                pdfid1="57A1E0F9ED2AE523E313C",
            ),
        },
    )

    assert f.name == "qwerty.dll"
    assert f.extensions["pdf-ext"].version == "1.7"
    assert f.extensions["pdf-ext"].document_info_dict["Title"] == "Sample document"


def test_file_example_with_RasterImageExt_Object():
    f = stix2.v21.File(
        name="qwerty.jpeg",
        extensions={
            "raster-image-ext": {
                "bits_per_pixel": 123,
                "exif_tags": {
                    "Make": "Nikon",
                    "Model": "D7000",
                    "XResolution": 4928,
                    "YResolution": 3264,
                },
            },
        },
    )
    assert f.name == "qwerty.jpeg"
    assert f.extensions["raster-image-ext"].bits_per_pixel == 123
    assert f.extensions["raster-image-ext"].exif_tags["XResolution"] == 4928


RASTER_IMAGE_EXT = """{
"type": "observed-data",
"spec_version": "2.1",
"id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
"created": "2016-04-06T19:58:16.000Z",
"modified": "2016-04-06T19:58:16.000Z",
"first_observed": "2015-12-21T19:00:00Z",
"last_observed": "2015-12-21T19:00:00Z",
"number_observed": 1,
"objects": {
  "0": {
    "type": "file",
    "name": "picture.jpg",
    "hashes": {
      "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
    },
    "extensions": {
      "raster-image-ext": {
        "image_height": 768,
        "image_width": 1024,
        "bits_per_pixel": 72,
        "exif_tags": {
          "Make": "Nikon",
          "Model": "D7000",
          "XResolution": 4928,
          "YResolution": 3264
        }
      }
    }
  }
}
}
"""


def test_raster_image_ext_parse():
    obj = stix2.parse(RASTER_IMAGE_EXT, version="2.1")
    assert obj.objects["0"].extensions['raster-image-ext'].image_width == 1024


def test_raster_images_ext_create():
    ext = stix2.v21.RasterImageExt(image_width=1024)
    assert "image_width" in str(ext)


def test_file_example_with_WindowsPEBinaryExt():
    f = stix2.v21.File(
        name="qwerty.dll",
        extensions={
            "windows-pebinary-ext": {
                "pe_type": "exe",
                "machine_hex": "014c",
                "number_of_sections": 4,
                "time_date_stamp": "2016-01-22T12:31:12Z",
                "pointer_to_symbol_table_hex": "74726144",
                "number_of_symbols": 4542568,
                "size_of_optional_header": 224,
                "characteristics_hex": "818f",
                "optional_header": {
                    "magic_hex": "010b",
                    "major_linker_version": 2,
                    "minor_linker_version": 25,
                    "size_of_code": 512,
                    "size_of_initialized_data": 283648,
                    "size_of_uninitialized_data": 0,
                    "address_of_entry_point": 4096,
                    "base_of_code": 4096,
                    "base_of_data": 8192,
                    "image_base": 14548992,
                    "section_alignment": 4096,
                    "file_alignment": 4096,
                    "major_os_version": 1,
                    "minor_os_version": 0,
                    "major_image_version": 0,
                    "minor_image_version": 0,
                    "major_subsystem_version": 4,
                    "minor_subsystem_version": 0,
                    "win32_version_value_hex": "00",
                    "size_of_image": 299008,
                    "size_of_headers": 4096,
                    "checksum_hex": "00",
                    "subsystem_hex": "03",
                    "dll_characteristics_hex": "00",
                    "size_of_stack_reserve": 100000,
                    "size_of_stack_commit": 8192,
                    "size_of_heap_reserve": 100000,
                    "size_of_heap_commit": 4096,
                    "loader_flags_hex": "abdbffde",
                    "number_of_rva_and_sizes": 3758087646,
                },
                "sections": [
                    {
                        "name": "CODE",
                        "entropy": 0.061089,
                    },
                    {
                        "name": "DATA",
                        "entropy": 7.980693,
                    },
                    {
                        "name": "NicolasB",
                        "entropy": 0.607433,
                    },
                    {
                        "name": ".idata",
                        "entropy": 0.607433,
                    },
                ],
            },
        },
    )
    assert f.name == "qwerty.dll"
    assert f.extensions["windows-pebinary-ext"].sections[2].entropy == 0.607433


def test_file_example_encryption_error():
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.v21.File(magic_number_hex="010b")

    assert excinfo.value.cls == stix2.v21.File
    assert "At least one of the (hashes, name)" in str(excinfo.value)


def test_ip4_address_example():
    ip4 = stix2.v21.IPv4Address(
        _valid_refs={"4": "mac-addr", "5": "mac-addr"},
        value="198.51.100.3",
        resolves_to_refs=["4", "5"],
    )

    assert ip4.value == "198.51.100.3"
    assert ip4.resolves_to_refs == ["4", "5"]


def test_ip4_address_example_cidr():
    ip4 = stix2.v21.IPv4Address(value="198.51.100.0/24")

    assert ip4.value == "198.51.100.0/24"


def test_ip6_address_example():
    ip6 = stix2.v21.IPv6Address(value="2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    assert ip6.value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_mac_address_example():
    ip6 = stix2.v21.MACAddress(value="d2:fb:49:24:37:18")

    assert ip6.value == "d2:fb:49:24:37:18"


def test_network_traffic_example():
    nt = stix2.v21.NetworkTraffic(
        _valid_refs={"0": "ipv4-addr", "1": "ipv4-addr"},
        protocols="tcp",
        src_ref="0",
        dst_ref="1",
    )
    assert nt.protocols == ["tcp"]
    assert nt.src_ref == "0"
    assert nt.dst_ref == "1"


def test_network_traffic_http_request_example():
    h = stix2.v21.HTTPRequestExt(
        request_method="get",
        request_value="/download.html",
        request_version="http/1.1",
        request_header={
            "Accept-Encoding": "gzip,deflate",
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113",
            "Host": "www.example.com",
        },
    )
    nt = stix2.v21.NetworkTraffic(
        _valid_refs={"0": "ipv4-addr"},
        protocols="tcp",
        src_ref="0",
        extensions={'http-request-ext': h},
    )
    assert nt.extensions['http-request-ext'].request_method == "get"
    assert nt.extensions['http-request-ext'].request_value == "/download.html"
    assert nt.extensions['http-request-ext'].request_version == "http/1.1"
    assert nt.extensions['http-request-ext'].request_header['Accept-Encoding'] == "gzip,deflate"
    assert nt.extensions['http-request-ext'].request_header['User-Agent'] == "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113"
    assert nt.extensions['http-request-ext'].request_header['Host'] == "www.example.com"


def test_network_traffic_icmp_example():
    h = stix2.v21.ICMPExt(icmp_type_hex="08", icmp_code_hex="00")
    nt = stix2.v21.NetworkTraffic(
        _valid_refs={"0": "ipv4-addr"},
        protocols="tcp",
        src_ref="0",
        extensions={'icmp-ext': h},
    )
    assert nt.extensions['icmp-ext'].icmp_type_hex == "08"
    assert nt.extensions['icmp-ext'].icmp_code_hex == "00"


def test_network_traffic_socket_example():
    h = stix2.v21.SocketExt(
        is_listening=True,
        address_family="AF_INET",
        protocol_family="PF_INET",
        socket_type="SOCK_STREAM",
    )
    nt = stix2.v21.NetworkTraffic(
        _valid_refs={"0": "ipv4-addr"},
        protocols="tcp",
        src_ref="0",
        extensions={'socket-ext': h},
    )
    assert nt.extensions['socket-ext'].is_listening
    assert nt.extensions['socket-ext'].address_family == "AF_INET"
    assert nt.extensions['socket-ext'].protocol_family == "PF_INET"
    assert nt.extensions['socket-ext'].socket_type == "SOCK_STREAM"


def test_network_traffic_tcp_example():
    h = stix2.v21.TCPExt(src_flags_hex="00000002")
    nt = stix2.v21.NetworkTraffic(
        _valid_refs={"0": "ipv4-addr"},
        protocols="tcp",
        src_ref="0",
        extensions={'tcp-ext': h},
    )
    assert nt.extensions['tcp-ext'].src_flags_hex == "00000002"


def test_mutex_example():
    m = stix2.v21.Mutex(name="barney")

    assert m.name == "barney"


def test_process_example():
    p = stix2.v21.Process(
        _valid_refs={"0": "file"},
        pid=1221,
        created="2016-01-20T14:11:25.55Z",
        command_line="./gedit-bin --new-window",
        image_ref="0",
    )

    assert p.command_line == "./gedit-bin --new-window"


def test_process_example_empty_error():
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.v21.Process()

    assert excinfo.value.cls == stix2.v21.Process
    properties_of_process = list(stix2.v21.Process._properties.keys())
    properties_of_process.remove("type")
    assert excinfo.value.properties == sorted(properties_of_process)
    msg = "At least one of the ({1}) properties for {0} must be populated."
    msg = msg.format(
        stix2.v21.Process.__name__,
        ", ".join(sorted(properties_of_process)),
    )
    assert str(excinfo.value) == msg


def test_process_example_empty_with_extensions():
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.v21.Process(extensions={
            "windows-process-ext": {},
        })

    assert excinfo.value.cls == stix2.v21.WindowsProcessExt
    properties_of_extension = list(stix2.v21.WindowsProcessExt._properties.keys())
    assert excinfo.value.properties == sorted(properties_of_extension)


def test_process_example_windows_process_ext():
    proc = stix2.v21.Process(
        pid=314,
        extensions={
            "windows-process-ext": {
                "aslr_enabled": True,
                "dep_enabled": True,
                "priority": "HIGH_PRIORITY_CLASS",
                "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309",
            },
        },
    )
    assert proc.extensions["windows-process-ext"].aslr_enabled
    assert proc.extensions["windows-process-ext"].dep_enabled
    assert proc.extensions["windows-process-ext"].priority == "HIGH_PRIORITY_CLASS"
    assert proc.extensions["windows-process-ext"].owner_sid == "S-1-5-21-186985262-1144665072-74031268-1309"


def test_process_example_windows_process_ext_empty():
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.v21.Process(
            pid=1221,
            extensions={
                "windows-process-ext": {},
            },
        )

    assert excinfo.value.cls == stix2.v21.WindowsProcessExt
    properties_of_extension = list(stix2.v21.WindowsProcessExt._properties.keys())
    assert excinfo.value.properties == sorted(properties_of_extension)


def test_process_example_extensions_empty():
    proc = stix2.v21.Process(
        pid=314,
        extensions={},
    )

    assert '{}' in str(proc)


def test_process_example_with_WindowsProcessExt_Object():
    p = stix2.v21.Process(extensions={
        "windows-process-ext": stix2.v21.WindowsProcessExt(
            aslr_enabled=True,
            dep_enabled=True,
            priority="HIGH_PRIORITY_CLASS",
            owner_sid="S-1-5-21-186985262-1144665072-74031268-1309",
        ),   # noqa
    })

    assert p.extensions["windows-process-ext"].dep_enabled
    assert p.extensions["windows-process-ext"].owner_sid == "S-1-5-21-186985262-1144665072-74031268-1309"


def test_process_example_with_WindowsServiceExt():
    p = stix2.v21.Process(extensions={
        "windows-service-ext": {
            "service_name": "sirvizio",
            "display_name": "Sirvizio",
            "start_type": "SERVICE_AUTO_START",
            "service_type": "SERVICE_WIN32_OWN_PROCESS",
            "service_status": "SERVICE_RUNNING",
        },
    })

    assert p.extensions["windows-service-ext"].service_name == "sirvizio"
    assert p.extensions["windows-service-ext"].service_type == "SERVICE_WIN32_OWN_PROCESS"


def test_process_example_with_WindowsProcessServiceExt():
    p = stix2.v21.Process(extensions={
        "windows-service-ext": {
            "service_name": "sirvizio",
            "display_name": "Sirvizio",
            "start_type": "SERVICE_AUTO_START",
            "service_type": "SERVICE_WIN32_OWN_PROCESS",
            "service_status": "SERVICE_RUNNING",
        },
        "windows-process-ext": {
            "aslr_enabled": True,
            "dep_enabled": True,
            "priority": "HIGH_PRIORITY_CLASS",
            "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309",
        },
    })

    assert p.extensions["windows-service-ext"].service_name == "sirvizio"
    assert p.extensions["windows-service-ext"].service_type == "SERVICE_WIN32_OWN_PROCESS"
    assert p.extensions["windows-process-ext"].dep_enabled
    assert p.extensions["windows-process-ext"].owner_sid == "S-1-5-21-186985262-1144665072-74031268-1309"


def test_software_example():
    s = stix2.v21.Software(
        name="Word",
        cpe="cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
        version="2002",
        vendor="Microsoft",
    )

    assert s.name == "Word"
    assert s.cpe == "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*"
    assert s.version == "2002"
    assert s.vendor == "Microsoft"


def test_url_example():
    s = stix2.v21.URL(value="https://example.com/research/index.html")

    assert s.type == "url"
    assert s.value == "https://example.com/research/index.html"


def test_user_account_example():
    a = stix2.v21.UserAccount(
        user_id="1001",
        account_login="jdoe",
        account_type="unix",
        display_name="John Doe",
        is_service_account=False,
        is_privileged=False,
        can_escalate_privs=True,
        account_created="2016-01-20T12:31:12Z",
        credential_last_changed="2016-01-20T14:27:43Z",
        account_first_login="2016-01-20T14:26:07Z",
        account_last_login="2016-07-22T16:08:28Z",
    )

    assert a.user_id == "1001"
    assert a.account_login == "jdoe"
    assert a.account_type == "unix"
    assert a.display_name == "John Doe"
    assert not a.is_service_account
    assert not a.is_privileged
    assert a.can_escalate_privs
    assert a.account_created == dt.datetime(2016, 1, 20, 12, 31, 12, tzinfo=pytz.utc)
    assert a.credential_last_changed == dt.datetime(2016, 1, 20, 14, 27, 43, tzinfo=pytz.utc)
    assert a.account_first_login == dt.datetime(2016, 1, 20, 14, 26, 7, tzinfo=pytz.utc)
    assert a.account_last_login == dt.datetime(2016, 7, 22, 16, 8, 28, tzinfo=pytz.utc)


def test_user_account_unix_account_ext_example():
    u = stix2.v21.UNIXAccountExt(
        gid=1001,
        groups=["wheel"],
        home_dir="/home/jdoe",
        shell="/bin/bash",
    )
    a = stix2.v21.UserAccount(
        user_id="1001",
        account_login="jdoe",
        account_type="unix",
        extensions={'unix-account-ext': u},
    )
    assert a.extensions['unix-account-ext'].gid == 1001
    assert a.extensions['unix-account-ext'].groups == ["wheel"]
    assert a.extensions['unix-account-ext'].home_dir == "/home/jdoe"
    assert a.extensions['unix-account-ext'].shell == "/bin/bash"


def test_windows_registry_key_example():
    with pytest.raises(ValueError):
        stix2.v21.WindowsRegistryValueType(
            name="Foo",
            data="qwerty",
            data_type="string",
        )

    v = stix2.v21.WindowsRegistryValueType(
        name="Foo",
        data="qwerty",
        data_type="REG_SZ",
    )
    w = stix2.v21.WindowsRegistryKey(
        key="hkey_local_machine\\system\\bar\\foo",
        values=[v],
    )
    assert w.key == "hkey_local_machine\\system\\bar\\foo"
    assert w.values[0].name == "Foo"
    assert w.values[0].data == "qwerty"
    assert w.values[0].data_type == "REG_SZ"
    # ensure no errors in serialization because of 'values'
    assert "Foo" in str(w)


def test_x509_certificate_example():
    x509 = stix2.v21.X509Certificate(
        issuer="C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",  # noqa
        validity_not_before="2016-03-12T12:00:00Z",
        validity_not_after="2016-08-21T12:00:00Z",
        subject="C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
    )  # noqa

    assert x509.type == "x509-certificate"
    assert x509.issuer == "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com"  # noqa
    assert x509.subject == "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org"  # noqa


def test_new_version_with_related_objects():
    data = stix2.v21.ObservedData(
        first_observed="2016-03-12T12:00:00Z",
        last_observed="2016-03-12T12:00:00Z",
        number_observed=1,
        objects={
            'src_ip': {
                'type': 'ipv4-addr',
                'value': '127.0.0.1/32',
            },
            'domain': {
                'type': 'domain-name',
                'value': 'example.com',
                'resolves_to_refs': ['src_ip'],
            },
        },
    )
    new_version = data.new_version(last_observed="2017-12-12T12:00:00Z")
    assert new_version.last_observed.year == 2017
    assert new_version.objects['domain'].resolves_to_refs[0] == 'src_ip'
