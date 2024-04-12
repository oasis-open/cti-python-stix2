import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

email_msg_dict = {
    "type": "email-message",
    "spec_version": "2.1",
    "id": "email-message--8c57a381-2a17-5e61-8754-5ef96efb286c",
    "from_ref": "email-addr--9b7e29b3-fd8d-562e-b3f0-8fc8134f5dda",
    "sender_ref": "email-addr--9b7e29b3-fd8d-562e-b3f0-8fc8134f5eeb",
    "to_refs": ["email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868"],
    "cc_refs": [
        "email-addr--d2b3bf0c-f02a-51a1-8102-11aba7959868",
        "email-addr--d3b3bf0c-f02a-51a1-8102-11aba7959868"
    ],
    "bcc_refs": [
        "email-addr--d4b3bf0c-f02a-51a1-8102-11aba7959868",
        "email-addr--d5b3bf0c-f02a-51a1-8102-11aba7959868"
    ],
    "message_id": "message01",
    "is_multipart": False,
    "date": "2004-04-19T12:22:23.000Z",
    "subject": "Did you see this?",
    "received_lines": [
        "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id \
        q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 \
        bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)"
    ],
    "additional_header_fields": {
        "Reply-To": [
            "steve@example.com",
            "jane@example.com"
        ]
    },
    "body": "message body",
    "raw_email_ref": "artifact--cb37bcf8-9846-5ab4-8662-75c1bf6e63ee"
}

multipart_email_msg_dict = {
    "type": "email-message",
    "spec_version": "2.1",
    "id": "email-message--ef9b4b7f-14c8-5955-8065-020e0316b559",
    "is_multipart": True,
    "received_lines": [
        "from mail.example.com ([198.51.100.3]) by smtp.gmail.com with ESMTPSA id \
        q23sm23309939wme.17.2016.07.19.07.20.32 (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 \
        bits=128/128); Tue, 19 Jul 2016 07:20:40 -0700 (PDT)"
    ],
    "content_type": "multipart/mixed",
    "date": "2016-06-19T14:20:40.000Z",
    "from_ref": "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
    "to_refs": ["email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868"],
    "cc_refs": ["email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194"],
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
        "content_disposition": "attachment; filename=\"tabby.png\"",
        "body_raw_ref": "artifact--4cce66f8-6eaa-53cb-85d5-3a85fca3a6c5"
        },
        {
        "content_type": "application/zip",
        "content_disposition": "attachment; filename=\"tabby_pics.zip\"",
        "body_raw_ref": "file--6ce09d9c-0ad3-5ebf-900c-e3cb288955b5"
        }
    ]
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True
)

def test_email_msg():
    store.sink.generate_stix_schema()
    email_msg_stix_object = stix2.parse(email_msg_dict)
    store.add(email_msg_stix_object)
    read_obj = json.loads(store.get(email_msg_stix_object['id']).serialize())

    for attrib in email_msg_dict.keys():
        if attrib == "to_refs" or attrib == "cc_refs" or attrib == "bcc_refs" \
            or attrib == "additional_header_fields": # join multiple tables not implemented yet
            continue
        if attrib == "date":
            assert stix2.utils.parse_into_datetime(email_msg_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        print(email_msg_dict[attrib], type(email_msg_dict[attrib]))
        print(read_obj[attrib], type(read_obj[attrib]))
        assert email_msg_dict[attrib] == read_obj[attrib]

def test_multipart_email_msg():
    store.sink.generate_stix_schema()
    multipart_email_msg_stix_object = stix2.parse(multipart_email_msg_dict)
    store.add(multipart_email_msg_stix_object)
    read_obj = json.loads(store.get(multipart_email_msg_stix_object['id']).serialize())

    for attrib in multipart_email_msg_dict.keys():
        if attrib == "to_refs" or attrib == "cc_refs" or attrib == "bcc_refs" \
            or attrib == "additional_header_fields" or attrib == "body_multipart": # join multiple tables not implemented yet
            continue
        if attrib == "date":
            assert stix2.utils.parse_into_datetime(multipart_email_msg_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        print(multipart_email_msg_dict[attrib], type(multipart_email_msg_dict[attrib]))
        print(read_obj[attrib], type(read_obj[attrib]))
        assert multipart_email_msg_dict[attrib] == read_obj[attrib]

