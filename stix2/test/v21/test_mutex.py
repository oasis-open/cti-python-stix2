import json

import pytest

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

mutex_dict = {
    "type": "mutex",
    "spec_version": "2.1",
    "id": "mutex--fba44954-d4e4-5d3b-814c-2b17dd8de300",
    "name": "__CLEANSWEEP__",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)

def test_mutex():
    store.sink.generate_stix_schema()
    mutex_stix_object = stix2.parse(mutex_dict)
    store.add(mutex_stix_object)
    read_obj = store.get(mutex_stix_object['id'])

    for attrib in mutex_dict.keys():
        assert mutex_dict[attrib] == read_obj[attrib]

