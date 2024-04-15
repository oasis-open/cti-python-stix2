import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

email_addr_dict = {
    "type": "email-addr",
    "spec_version": "2.1",
    "id": "email-addr--2d77a846-6264-5d51-b586-e43822ea1ea3",
    "value": "john@example.com",
    "display_name": "John Doe",
    "belongs_to_ref": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c"
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True
)

def test_email_addr():
    store.sink.generate_stix_schema()
    email_addr_stix_object = stix2.parse(email_addr_dict)
    store.add(email_addr_stix_object)
    read_obj = json.loads(store.get(email_addr_stix_object['id']).serialize())

    for attrib in email_addr_dict.keys():
        assert email_addr_dict[attrib] == read_obj[attrib]
