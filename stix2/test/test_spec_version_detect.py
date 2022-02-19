from __future__ import unicode_literals

import pytest

from stix2.utils import detect_spec_version


@pytest.mark.parametrize(
    "obj_dict, expected_ver", [
        # STIX 2.0 examples
        (
            {
                "type": "identity",
                "id": "identity--d7f72e8d-657a-43ec-9324-b3ec67a97486",
                "created": "1972-05-21T05:33:09.000Z",
                "modified": "1973-05-28T02:10:54.000Z",
                "name": "alice",
                "identity_class": "individual",
            },
            "2.0",
        ),
        (
            {
                "type": "relationship",
                "id": "relationship--63b0f1b7-925e-4795-ac9b-61fb9f235f1a",
                "created": "1981-08-11T13:48:19.000Z",
                "modified": "2000-02-16T15:33:15.000Z",
                "source_ref": "attack-pattern--9391504a-ef29-4a41-a257-5634d9edc391",
                "target_ref": "identity--ba18dde2-56d3-4a34-aa0b-fc56f5be568f",
                "relationship_type": "targets",
            },
            "2.0",
        ),
        (
            {
                "type": "file",
                "name": "notes.txt",
            },
            "2.0",
        ),
        (
            {
                "type": "marking-definition",
                "id": "marking-definition--2a13090f-a493-4b70-85fe-fa021d91dcd2",
                "created": "1998-03-27T19:44:53.000Z",
                "definition_type": "statement",
                "definition": {
                    "statement": "Copyright (c) ACME Corp.",
                },
            },
            "2.0",
        ),
        (
            {
                "type": "bundle",
                "id": "bundle--8379cb02-8131-47c8-8a7c-9a1f0e0986b1",
                "spec_version": "2.0",
                "objects": [
                    {
                        "type": "identity",
                        "id": "identity--d7f72e8d-657a-43ec-9324-b3ec67a97486",
                        "created": "1972-05-21T05:33:09.000Z",
                        "modified": "1973-05-28T02:10:54.000Z",
                        "name": "alice",
                        "identity_class": "individual",
                    },
                    {
                        "type": "marking-definition",
                        "id": "marking-definition--2a13090f-a493-4b70-85fe-fa021d91dcd2",
                        "created": "1998-03-27T19:44:53.000Z",
                        "definition_type": "statement",
                        "definition": {
                            "statement": "Copyright (c) ACME Corp.",
                        },
                    },
                ],
            },
            "2.0",
        ),
        (
            {
                "type": "bundle",
                "id": "bundle--8379cb02-8131-47c8-8a7c-9a1f0e0986b1",
                "spec_version": "2.1",
                "objects": [
                    {
                        "type": "identity",
                        "spec_version": "2.1",
                        "id": "identity--d7f72e8d-657a-43ec-9324-b3ec67a97486",
                        "created": "1972-05-21T05:33:09.000Z",
                        "modified": "1973-05-28T02:10:54.000Z",
                        "name": "alice",
                        "identity_class": "individual",
                    },
                    {
                        "type": "marking-definition",
                        "spec_version": "2.1",
                        "id": "marking-definition--2a13090f-a493-4b70-85fe-fa021d91dcd2",
                        "created": "1998-03-27T19:44:53.000Z",
                        "definition_type": "statement",
                        "definition": {
                            "statement": "Copyright (c) ACME Corp.",
                        },
                    },
                ],
            },
            "2.0",
        ),
        # STIX 2.1 examples
        (
            {
                "type": "identity",
                "id": "identity--22299b4c-bc38-4485-ad7d-8222f01c58c7",
                "spec_version": "2.1",
                "created": "1995-07-24T04:07:48.000Z",
                "modified": "2001-07-01T09:33:17.000Z",
                "name": "alice",
            },
            "2.1",
        ),
        (
            {
                "type": "relationship",
                "id": "relationship--0eec232d-e1ea-4f85-8e78-0de6ae9d09f0",
                "spec_version": "2.1",
                "created": "1975-04-05T10:47:22.000Z",
                "modified": "1983-04-25T20:56:00.000Z",
                "source_ref": "attack-pattern--9391504a-ef29-4a41-a257-5634d9edc391",
                "target_ref": "identity--ba18dde2-56d3-4a34-aa0b-fc56f5be568f",
                "relationship_type": "targets",
            },
            "2.1",
        ),
        (
            {
                "type": "file",
                "id": "file--5eef3404-6a94-4db3-9a1a-5684cbea0dfe",
                "spec_version": "2.1",
                "name": "notes.txt",
            },
            "2.1",
        ),
        (
            {
                "type": "file",
                "id": "file--5eef3404-6a94-4db3-9a1a-5684cbea0dfe",
                "name": "notes.txt",
            },
            "2.1",
        ),
        (
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": "TLP:GREEN",
                "definition": {
                    "tlp": "green",
                },
            },
            "2.1",
        ),
        (
            {
                "type": "bundle",
                "id": "bundle--d5787acd-1ffd-4630-ada3-6857698f6287",
                "objects": [
                    {
                        "type": "identity",
                        "id": "identity--22299b4c-bc38-4485-ad7d-8222f01c58c7",
                        "spec_version": "2.1",
                        "created": "1995-07-24T04:07:48.000Z",
                        "modified": "2001-07-01T09:33:17.000Z",
                        "name": "alice",
                    },
                    {
                        "type": "file",
                        "id": "file--5eef3404-6a94-4db3-9a1a-5684cbea0dfe",
                        "name": "notes.txt",
                    },
                ],
            },
            "2.1",
        ),
        # Mixed spec examples
        (
            {
                "type": "bundle",
                "id": "bundle--e1a01e29-3432-401a-ab9f-c1082b056605",
                "objects": [
                    {
                        "type": "identity",
                        "id": "identity--d7f72e8d-657a-43ec-9324-b3ec67a97486",
                        "created": "1972-05-21T05:33:09.000Z",
                        "modified": "1973-05-28T02:10:54.000Z",
                        "name": "alice",
                        "identity_class": "individual",
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--63b0f1b7-925e-4795-ac9b-61fb9f235f1a",
                        "created": "1981-08-11T13:48:19.000Z",
                        "modified": "2000-02-16T15:33:15.000Z",
                        "source_ref": "attack-pattern--9391504a-ef29-4a41-a257-5634d9edc391",
                        "target_ref": "identity--ba18dde2-56d3-4a34-aa0b-fc56f5be568f",
                        "relationship_type": "targets",
                    },
                ],
            },
            "2.1",
        ),
        (
            {
                "type": "bundle",
                "id": "bundle--eecad3d9-bb9a-4263-93f6-1c0ccc984574",
                "objects": [
                    {
                        "type": "identity",
                        "id": "identity--d7f72e8d-657a-43ec-9324-b3ec67a97486",
                        "created": "1972-05-21T05:33:09.000Z",
                        "modified": "1973-05-28T02:10:54.000Z",
                        "name": "alice",
                        "identity_class": "individual",
                    },
                    {
                        "type": "file",
                        "id": "file--5eef3404-6a94-4db3-9a1a-5684cbea0dfe",
                        "name": "notes.txt",
                    },
                ],
            },
            "2.1",
        ),
    ],
)
def test_spec_version_detect(obj_dict, expected_ver):
    detected_ver = detect_spec_version(obj_dict)

    assert detected_ver == expected_ver
