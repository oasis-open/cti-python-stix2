import datetime as dt
import re
import uuid

import pytest
import pytz

import stix2
import stix2.exceptions

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
            "id": "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f",
            "spec_version": "2.1",
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
                "type": "file",
                "id": "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f",
                "name": "foo.exe",
            },
        },
    )

    assert observed_data.id == "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
    assert observed_data.created_by_ref == "identity--311b2d2d-f010-4473-83ec-1edf84858f4c"
    assert observed_data.created == observed_data.modified == dt.datetime(2016, 4, 6, 19, 58, 16, tzinfo=pytz.utc)
    assert observed_data.first_observed == observed_data.last_observed == dt.datetime(2015, 12, 21, 19, 00, 00, tzinfo=pytz.utc)
    assert observed_data.number_observed == 50
    assert observed_data.objects['0'] == stix2.v21.File(name="foo.exe")


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
            "id": "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f",
            "spec_version": "2.1",
            "name": "foo.exe"
        },
        "1": {
            "type": "directory",
            "id": "directory--536a61a4-0934-516b-9aad-fcbb75e0583a",
            "spec_version": "2.1",
            "path": "/usr/home",
            "contains_refs": [
                "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f"
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
                "type": "file",
                "id": "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f",
                "name": "foo.exe",
            },
            "1": {
                "type": "directory",
                "id": "directory--536a61a4-0934-516b-9aad-fcbb75e0583a",
                "path": "/usr/home",
                "contains_refs": ["file--5956efbb-a7b0-566d-a7f9-a202eb05c70f"],
            },
        },
    )
    assert observed_data.id == "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
    assert observed_data.created_by_ref == "identity--311b2d2d-f010-4473-83ec-1edf84858f4c"
    assert observed_data.created == observed_data.modified == dt.datetime(2016, 4, 6, 19, 58, 16, tzinfo=pytz.utc)
    assert observed_data.first_observed == observed_data.last_observed == dt.datetime(2015, 12, 21, 19, 00, 00, tzinfo=pytz.utc)
    assert observed_data.number_observed == 50
    assert observed_data.objects['0'] == stix2.v21.File(name="foo.exe")
    assert observed_data.objects['1'] == stix2.v21.Directory(path="/usr/home", contains_refs=["file--5956efbb-a7b0-566d-a7f9-a202eb05c70f"])


EXPECTED_OBJECT_REFS = """{
    "type": "observed-data",
    "spec_version": "2.1",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T19:58:16.000Z",
    "modified": "2016-04-06T19:58:16.000Z",
    "first_observed": "2015-12-21T19:00:00Z",
    "last_observed": "2015-12-21T19:00:00Z",
    "number_observed": 50,
    "object_refs": [
        "file--758bf2c0-a6f1-56d1-872e-6b727467739a",
        "url--d97ed5c4-3f33-46d9-b25b-c3d7b94d1457",
        "mutex--eca0b3ba-8d76-11e9-a1fd-34415dabec0c"
    ]
}"""


def test_observed_data_example_with_object_refs():
    observed_data = stix2.v21.ObservedData(
        id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T19:58:16.000Z",
        modified="2016-04-06T19:58:16.000Z",
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=50,
        object_refs=[
            "file--758bf2c0-a6f1-56d1-872e-6b727467739a",
            "url--d97ed5c4-3f33-46d9-b25b-c3d7b94d1457",
            "mutex--eca0b3ba-8d76-11e9-a1fd-34415dabec0c",
        ],
    )

    assert str(observed_data) == EXPECTED_OBJECT_REFS


def test_observed_data_object_constraint():
    with pytest.raises(stix2.exceptions.MutuallyExclusivePropertiesError):
        stix2.v21.ObservedData(
            id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
            created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
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
            object_refs=[
                "file--758bf2c0-a6f1-56d1-872e-6b727467739a",
                "url--d97ed5c4-3f33-46d9-b25b-c3d7b94d1457",
                "mutex--eca0b3ba-8d76-11e9-a1fd-34415dabec0c",
            ],
        )


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
                    "id": "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f",
                    "name": "foo.exe",
                },
                "1": {
                    "type": "directory",
                    "path": "/usr/home",
                    "contains_refs": ["monkey--5956efbb-a7b0-566d-a7f9-a202eb05c70f"],
                },
            },
        )

    assert excinfo.value.cls == stix2.v21.Directory
    assert excinfo.value.prop_name == "contains_refs"
    assert "The type-specifying prefix 'monkey' for this property is not valid" in excinfo.value.reason


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
                    "id": "file--5956efbb-a7b0-566d-a7f9-a202eb05c70f",
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
    with pytest.raises(stix2.exceptions.InvalidValueError):
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
        "belongs_to_ref": "user-account--fc07c1af-6b11-41f8-97a4-47920d866a91"
    }""",
    ],
)
def test_parse_email_address(data):
    odata = stix2.parse(data, version='2.1')
    assert odata.type == "email-addr"

    odata_str = re.compile(
        '"belongs_to_ref": "user-account--fc07c1af-6b11-41f8-97a4-47920d866a91"', re.DOTALL,
    ).sub(
        '"belongs_to_ref": "mutex--9be6365f-b89c-48c0-9340-6953f6595718"', data,
    )
    with pytest.raises(stix2.exceptions.InvalidValueError):
        stix2.parse(odata_str, version='2.1')


@pytest.mark.parametrize(
    "data", [
        """
    {
        "type": "email-message",
        "is_multipart": true,
        "content_type": "multipart/mixed",
        "date": "2016-06-19T14:20:40.000Z",
        "from_ref": "email-addr--d4ef7e1f-086d-5ff4-bce4-312ddc3eae76",
        "to_refs": [
          "email-addr--8b0eb924-208c-5efd-80e5-84e2d610e54b"
        ],
        "cc_refs": [
          "email-addr--1766f860-5cf3-5697-8789-35f1242663d5"
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
            "body_raw_ref": "artifact--80b04ad8-db52-464b-a85a-a44a5f3a60c5"
          },
          {
            "content_type": "application/zip",
            "content_disposition": "attachment; filename=\\"tabby_pics.zip\\"",
            "body_raw_ref": "file--e63474fc-b386-5630-a003-1b555e22f99b"
          }
        ]
    }
    """,
    ],
)
def test_parse_email_message(data):
    odata = stix2.parse(data, version='2.1')
    assert odata.type == "email-message"
    assert odata.body_multipart[0].content_disposition == "inline"


@pytest.mark.parametrize(
    "data", [
        """
    {
         "type": "email-message",
         "from_ref": "email-addr--d4ef7e1f-086d-5ff4-bce4-312ddc3eae76",
         "to_refs": ["email-addr--8b0eb924-208c-5efd-80e5-84e2d610e54b"],
         "is_multipart": true,
         "date": "1997-11-21T15:55:06.000Z",
         "subject": "Saying Hello",
         "body": "Cats are funny!"
    }
    """,
    ],
)
def test_parse_email_message_not_multipart(data):
    with pytest.raises(stix2.exceptions.DependentPropertiesError) as excinfo:
        stix2.parse(data, version='2.1')

    assert excinfo.value.cls == stix2.v21.EmailMessage
    assert excinfo.value.dependencies == [("is_multipart", "body")]


@pytest.mark.parametrize(
    "data", [
        """"0": {
            "type": "file",
            "id": "file--ecd47d73-15e4-5250-afda-ef8897b22340",
            "hashes": {
                "SHA-256": "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"
            }
        },
        "1": {
            "type": "file",
            "id": "file--65f2873d-38c2-56b4-bfa5-e3ef21e8a3c3",
            "hashes": {
                "SHA-1": "6e71b3cac15d32fe2d36c270887df9479c25c640"
            }
        },
        "2": {
            "type": "file",
            "id": "file--ef2d6dca-ec7d-5ab7-8dd9-ec9c0dee0eac",
            "hashes": {
                "SHA-512": "b7e98c78c24fb4c2c7b175e90474b21eae0ccf1b5ea4708b4e0f2d2940004419edc7161c18a1e71b2565df099ba017bcaa67a248e2989b6268ce078b88f2e210"
            }
        },
        "3": {
            "type": "file",
            "name": "foo.zip",
            "hashes": {
                "SHA3-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
            },
            "mime_type": "application/zip",
            "extensions": {
                "archive-ext": {
                    "contains_refs": [
                        "file--ecd47d73-15e4-5250-afda-ef8897b22340",
                        "file--65f2873d-38c2-56b4-bfa5-e3ef21e8a3c3",
                        "file--ef2d6dca-ec7d-5ab7-8dd9-ec9c0dee0eac"
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
               for x in [
                   "file--ecd47d73-15e4-5250-afda-ef8897b22340",
                   "file--65f2873d-38c2-56b4-bfa5-e3ef21e8a3c3",
                   "file--ef2d6dca-ec7d-5ab7-8dd9-ec9c0dee0eac",
               ])


@pytest.mark.parametrize(
    "data", [
        """
    {
        "type": "email-message",
        "is_multipart": true,
        "content_type": "multipart/mixed",
        "date": "2016-06-19T14:20:40.000Z",
        "from_ref": "email-addr--d4ef7e1f-086d-5ff4-bce4-312ddc3eae76",
        "to_refs": [
          "email-addr--8b0eb924-208c-5efd-80e5-84e2d610e54b"
        ],
        "cc_refs": [
          "email-addr--1766f860-5cf3-5697-8789-35f1242663d5"
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
            "body_raw_ref": "file--e63474fc-b386-5630-a003-1b555e22f99b"
          }
        ]
    }
    """,
    ],
)
def test_parse_email_message_with_at_least_one_error(data):
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.parse(data, version='2.1')

    assert excinfo.value.cls == stix2.v21.EmailMessage
    assert "At least one of the" in str(excinfo.value)
    assert "must be populated" in str(excinfo.value)


@pytest.mark.parametrize(
    "data", [
        """
    {
        "type": "network-traffic",
        "src_ref": "ipv4-addr--e535b017-cc1c-566b-a3e2-f69f92ed9c4c",
        "dst_ref": "ipv4-addr--78327430-9ad9-5632-ae3d-8e2fce8f5483",
        "protocols": [
          "tcp"
        ]
    }
    """,
    ],
)
def test_parse_basic_tcp_traffic(data):
    odata = stix2.parse(
        data, version='2.1',
    )

    assert odata.type == "network-traffic"
    assert odata.src_ref == "ipv4-addr--e535b017-cc1c-566b-a3e2-f69f92ed9c4c"
    assert odata.dst_ref == "ipv4-addr--78327430-9ad9-5632-ae3d-8e2fce8f5483"
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
          "network-traffic--016914c3-b680-5df2-81c4-bb9ccf8dc8b0"
        ]
  }
    """,
    ],
)
def test_parse_basic_tcp_traffic_with_error(data):
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.parse(data, version='2.1')

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
                "id": "file--0d16c8d3-c177-5f5d-a022-b1bdac329bea",
                "hashes": {
                    "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f",
                },
            },
            "1": {
                "type": "process",
                "id": "process--f6c4a02c-23e1-4a6d-a0d7-d862e893817a",
                "pid": 1221,
                "created_time": "2016-01-20T14:11:25.55Z",
                "command_line": "./gedit-bin --new-window",
                "image_ref": "file--0d16c8d3-c177-5f5d-a022-b1bdac329bea",
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
    f = stix2.v21.File(
        name="penguin.exe",
    )

    dir1 = stix2.v21.Directory(
        path='/usr/lib',
        ctime="2015-12-21T19:00:00Z",
        mtime="2015-12-24T19:00:00Z",
        atime="2015-12-21T20:00:00Z",
        contains_refs=[str(f.id)],
    )

    assert dir1.path == '/usr/lib'
    assert dir1.ctime == dt.datetime(2015, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert dir1.mtime == dt.datetime(2015, 12, 24, 19, 0, 0, tzinfo=pytz.utc)
    assert dir1.atime == dt.datetime(2015, 12, 21, 20, 0, 0, tzinfo=pytz.utc)
    assert dir1.contains_refs == ["file--9d050a3b-72cd-5b57-bf18-024e74e1e5eb"]


def test_directory_example_ref_error():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Directory(
            path='/usr/lib',
            ctime="2015-12-21T19:00:00Z",
            mtime="2015-12-24T19:00:00Z",
            atime="2015-12-21T20:00:00Z",
            contains_refs=["domain-name--02af94ea-7e38-5718-87c3-5cc023e3d49d"],
        )

    assert excinfo.value.cls == stix2.v21.Directory
    assert excinfo.value.prop_name == "contains_refs"


def test_domain_name_example():
    dn1 = stix2.v21.DomainName(
        value="mitre.org",
    )

    dn2 = stix2.v21.DomainName(
        value="example.com",
        resolves_to_refs=[str(dn1.id)],
    )

    assert dn2.value == "example.com"
    assert dn2.resolves_to_refs == ["domain-name--02af94ea-7e38-5718-87c3-5cc023e3d49d"]


def test_domain_name_example_invalid_ref_type():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.DomainName(
            value="example.com",
            resolves_to_refs=["file--44a431e6-764b-5556-a3f5-bf655930a581"],
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
        ctime="2016-12-21T19:00:00Z",
        mtime="2016-12-24T19:00:00Z",
        atime="2016-12-21T20:00:00Z",
    )

    assert f.name == "qwerty.dll"
    assert f.size == 100
    assert f.magic_number_hex == "1C"
    assert f.hashes["SHA-256"] == "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"
    assert f.mime_type == "application/msword"
    assert f.ctime == dt.datetime(2016, 12, 21, 19, 0, 0, tzinfo=pytz.utc)
    assert f.mtime == dt.datetime(2016, 12, 24, 19, 0, 0, tzinfo=pytz.utc)
    assert f.atime == dt.datetime(2016, 12, 21, 20, 0, 0, tzinfo=pytz.utc)


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
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.File(
            name="abc.txt",
            extensions={
                "ntfs-ext": {},
            },
        )

    assert excinfo.value.cls == stix2.v21.File


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
    "id": "file--44a431e6-764b-5556-a3f5-bf655930a581",
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


def test_ipv4_address_example():
    ip4 = stix2.v21.IPv4Address(
        value="198.51.100.3",
        resolves_to_refs=["mac-addr--a85820f7-d9b7-567a-a3a6-dedc34139342", "mac-addr--9a59b496-fdeb-510f-97b5-7137210bc699"],
    )

    assert ip4.value == "198.51.100.3"
    assert ip4.resolves_to_refs == ["mac-addr--a85820f7-d9b7-567a-a3a6-dedc34139342", "mac-addr--9a59b496-fdeb-510f-97b5-7137210bc699"]


def test_ipv4_address_valid_refs():
    mac1 = stix2.v21.MACAddress(
        value="a1:b2:c3:d4:e5:f6",
    )
    mac2 = stix2.v21.MACAddress(
        value="a7:b8:c9:d0:e1:f2",
    )

    ip4 = stix2.v21.IPv4Address(
        value="177.60.40.7",
        resolves_to_refs=[str(mac1.id), str(mac2.id)],
    )

    assert ip4.value == "177.60.40.7"
    assert ip4.resolves_to_refs == ["mac-addr--a85820f7-d9b7-567a-a3a6-dedc34139342", "mac-addr--9a59b496-fdeb-510f-97b5-7137210bc699"]


def test_ipv4_address_example_cidr():
    ip4 = stix2.v21.IPv4Address(value="198.51.100.0/24")

    assert ip4.value == "198.51.100.0/24"


def test_ipv6_address_example():
    ip6 = stix2.v21.IPv6Address(value="2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    assert ip6.value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_mac_address_example():
    ip6 = stix2.v21.MACAddress(value="d2:fb:49:24:37:18")

    assert ip6.value == "d2:fb:49:24:37:18"


def test_network_traffic_example():
    nt = stix2.v21.NetworkTraffic(
        protocols=["tcp"],
        src_ref="ipv4-addr--29a591d9-533a-5ecd-a5a1-cadee4411e88",
        dst_ref="ipv4-addr--6d39dd0b-1f74-5faf-8d76-d8762c2a57cb",
    )
    assert nt.protocols == ["tcp"]
    assert nt.src_ref == "ipv4-addr--29a591d9-533a-5ecd-a5a1-cadee4411e88"
    assert nt.dst_ref == "ipv4-addr--6d39dd0b-1f74-5faf-8d76-d8762c2a57cb"


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
        protocols=["tcp"],
        src_ref="ipv4-addr--29a591d9-533a-5ecd-a5a1-cadee4411e88",
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
        protocols=["tcp"],
        src_ref="ipv4-addr--29a591d9-533a-5ecd-a5a1-cadee4411e88",
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
        protocols=["tcp"],
        src_ref="ipv4-addr--29a591d9-533a-5ecd-a5a1-cadee4411e88",
        extensions={'socket-ext': h},
    )
    assert nt.extensions['socket-ext'].is_listening
    assert nt.extensions['socket-ext'].address_family == "AF_INET"
    assert nt.extensions['socket-ext'].protocol_family == "PF_INET"
    assert nt.extensions['socket-ext'].socket_type == "SOCK_STREAM"


def test_correct_socket_options():
    se1 = stix2.v21.SocketExt(
        is_listening=True,
        address_family="AF_INET",
        protocol_family="PF_INET",
        socket_type="SOCK_STREAM",
        options={"ICMP6_RCVTIMEO": 100},
    )

    assert se1.address_family == "AF_INET"
    assert se1.socket_type == "SOCK_STREAM"
    assert se1.options == {"ICMP6_RCVTIMEO": 100}


def test_incorrect_socket_options():
    with pytest.raises(ValueError) as excinfo:
        stix2.v21.SocketExt(
            is_listening=True,
            address_family="AF_INET",
            protocol_family="PF_INET",
            socket_type="SOCK_STREAM",
            options={"RCVTIMEO": 100},
        )
    assert "Incorrect options key" == str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        stix2.v21.SocketExt(
            is_listening=True,
            address_family="AF_INET",
            protocol_family="PF_INET",
            socket_type="SOCK_STREAM",
            options={"SO_RCVTIMEO": '100'},
        )
    assert "Options value must be an integer" == str(excinfo.value)


def test_network_traffic_tcp_example():
    h = stix2.v21.TCPExt(src_flags_hex="00000002")
    nt = stix2.v21.NetworkTraffic(
        protocols=["tcp"],
        src_ref="ipv4-addr--29a591d9-533a-5ecd-a5a1-cadee4411e88",
        extensions={'tcp-ext': h},
    )
    assert nt.extensions['tcp-ext'].src_flags_hex == "00000002"


def test_mutex_example():
    m = stix2.v21.Mutex(name="barney")

    assert m.name == "barney"


def test_process_example():
    p = stix2.v21.Process(
        pid=1221,
        created_time="2016-01-20T14:11:25.55Z",
        command_line="./gedit-bin --new-window",
        image_ref="file--ea587d87-5ed2-5625-a9ac-01fd64161fd8",
    )

    assert p.command_line == "./gedit-bin --new-window"


def test_process_example_empty_error():
    with pytest.raises(stix2.exceptions.AtLeastOnePropertyError) as excinfo:
        stix2.v21.Process()

    assert excinfo.value.cls == stix2.v21.Process
    properties_of_process = list(stix2.v21.Process._properties.keys())
    properties_of_process = [prop for prop in properties_of_process if prop not in ["type", "id", "defanged", "spec_version"]]
    assert excinfo.value.properties == sorted(properties_of_process)
    msg = "At least one of the ({1}) properties for {0} must be populated."
    msg = msg.format(
        stix2.v21.Process.__name__,
        ", ".join(sorted(properties_of_process)),
    )
    assert str(excinfo.value) == msg


def test_process_example_empty_with_extensions():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Process(extensions={
            "windows-process-ext": {},
        })

    assert excinfo.value.cls == stix2.v21.Process


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
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Process(
            pid=1221,
            extensions={
                "windows-process-ext": {},
            },
        )

    assert excinfo.value.cls == stix2.v21.Process


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
        swid="com.acme.rms-ce-v4-1-5-0",
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
    with pytest.raises(stix2.exceptions.InvalidValueError):
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
    assert w["values"][0].name == "Foo"
    assert w["values"][0].data == "qwerty"
    assert w["values"][0].data_type == "REG_SZ"
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


def test_x509_certificate_error():

    with pytest.raises(stix2.exceptions.PropertyPresenceError) as excinfo:
        stix2.v21.X509Certificate(
            defanged=True,
        )

    assert excinfo.value.cls == stix2.v21.X509Certificate
    assert "At least one of the" in str(excinfo.value)
    assert "properties for X509Certificate must be populated." in str(excinfo.value)


def test_new_version_with_related_objects():
    data = stix2.v21.ObservedData(
        first_observed="2016-03-12T12:00:00Z",
        last_observed="2016-03-12T12:00:00Z",
        number_observed=1,
        objects={
            'src_ip': {
                'type': 'ipv4-addr',
                'id': 'ipv4-addr--2b94bc65-17d4-54f6-9ffe-7d103551bb9f',
                'value': '127.0.0.1/32',
            },
            'domain': {
                'type': 'domain-name',
                'id': 'domain-name--220a2699-5ebf-5b57-bf02-424964bb19c0',
                'value': 'example.com',
                'resolves_to_refs': ['ipv4-addr--2b94bc65-17d4-54f6-9ffe-7d103551bb9f'],
            },
        },
    )
    new_version = data.new_version(last_observed="2017-12-12T12:00:00Z")
    assert new_version.last_observed.year == 2017
    assert new_version.objects['domain'].resolves_to_refs[0] == 'ipv4-addr--2b94bc65-17d4-54f6-9ffe-7d103551bb9f'


def test_objects_deprecation():
    with pytest.warns(stix2.exceptions.STIXDeprecationWarning):

        stix2.v21.ObservedData(
            first_observed="2016-03-12T12:00:00Z",
            last_observed="2016-03-12T12:00:00Z",
            number_observed=1,
            objects={
                "0": {
                    "type": "file",
                    "name": "foo",
                },
            },
        )


def test_deterministic_id_same_extra_prop_vals():
    email_addr_1 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    email_addr_2 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    assert email_addr_1.id == email_addr_2.id

    uuid_obj_1 = uuid.UUID(email_addr_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 5

    uuid_obj_2 = uuid.UUID(email_addr_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 5


def test_deterministic_id_diff_extra_prop_vals():
    email_addr_1 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    email_addr_2 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Janey Doe",
    )

    assert email_addr_1.id == email_addr_2.id

    uuid_obj_1 = uuid.UUID(email_addr_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 5

    uuid_obj_2 = uuid.UUID(email_addr_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 5


def test_deterministic_id_diff_contributing_prop_vals():
    email_addr_1 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    email_addr_2 = stix2.v21.EmailAddress(
        value="jane@example.com",
        display_name="Janey Doe",
    )

    assert email_addr_1.id != email_addr_2.id

    uuid_obj_1 = uuid.UUID(email_addr_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 5

    uuid_obj_2 = uuid.UUID(email_addr_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 5


def test_deterministic_id_no_contributing_props():
    email_msg_1 = stix2.v21.EmailMessage(
        is_multipart=False,
    )

    email_msg_2 = stix2.v21.EmailMessage(
        is_multipart=False,
    )

    assert email_msg_1.id != email_msg_2.id

    uuid_obj_1 = uuid.UUID(email_msg_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 4

    uuid_obj_2 = uuid.UUID(email_msg_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 4


def test_id_gen_recursive_dict_conversion_1():
    file_observable = stix2.v21.File(
        name="example.exe",
        size=68 * 1000,
        magic_number_hex="50000000",
        hashes={
            "SHA-256": "841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649",
        },
        extensions={
            "windows-pebinary-ext": stix2.v21.WindowsPEBinaryExt(
                pe_type="exe",
                machine_hex="014c",
                sections=[
                    stix2.v21.WindowsPESection(
                        name=".data",
                        size=4096,
                        entropy=7.980693,
                        hashes={"SHA-256": "6e3b6f3978e5cd96ba7abee35c24e867b7e64072e2ecb22d0ee7a6e6af6894d0"},
                    ),
                ],
            ),
        },
    )

    assert file_observable.id == "file--5219d93d-13c1-5f1f-896b-039f10ec67ea"


def test_id_gen_recursive_dict_conversion_2():
    wrko = stix2.v21.WindowsRegistryKey(
        values=[
            stix2.v21.WindowsRegistryValueType(
                name="Foo",
                data="qwerty",
            ),
            stix2.v21.WindowsRegistryValueType(
                name="Bar",
                data="42",
            ),
        ],
    )

    assert wrko.id == "windows-registry-key--c087d9fe-a03e-5922-a1cd-da116e5b8a7b"
