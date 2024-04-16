import json

import pytest

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

software_dict = {
    "type": "software",
    "spec_version": "2.1",
    "id": "software--a1827f6d-ca53-5605-9e93-4316cd22a00a",
    "name": "Word",
    "cpe": "cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
    "version": "2002",
    "vendor": "Microsoft",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)

def test_software():
    store.sink.generate_stix_schema()
    software_stix_object = stix2.parse(software_dict)
    store.add(software_stix_object)
    read_obj = store.get(software_stix_object['id'])
    read_obj = json.loads(store.get(software_stix_object['id']).serialize())

    for attrib in software_dict.keys():
        assert software_dict[attrib] == read_obj[attrib]

