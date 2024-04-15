import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

# errors when adding magic_number_hex to store, so ignoring for now

process_dict = {
    "type": "process",
    "spec_version": "2.1",
    "id": "process--f52a906a-0dfc-40bd-92f1-e7778ead38a9",
    "is_hidden": False,
    "pid": 1221,
    "created_time": "2016-01-20T14:11:25.55Z",
    "cwd": "/tmp/",
    "environment_variables": {
        "ENVTEST": "/path/to/bin"
    },
    "command_line": "./gedit-bin --new-window",
    "opened_connection_refs": [
        "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3"
    ],
    "creator_user_ref": "user-account--cb37bcf8-9846-5ab4-8662-75c1bf6e63ee",
    "image_ref": "file--e04f22d1-be2c-59de-add8-10f61d15fe20", 
    "parent_ref": "process--f52a906a-1dfc-40bd-92f1-e7778ead38a9", 
    "child_refs": [
        "process--ff2a906a-1dfc-40bd-92f1-e7778ead38a9",
        "process--fe2a906a-1dfc-40bd-92f1-e7778ead38a9"
    ]
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True
)

def test_process():
    store.sink.generate_stix_schema()
    process_stix_object = stix2.parse(process_dict)
    store.add(process_stix_object)
    read_obj = store.get(process_stix_object['id'])
    read_obj = json.loads(store.get(process_stix_object['id']).serialize())

    for attrib in process_dict.keys():
        if attrib == "child_refs" or attrib == "opened_connection_refs" or attrib == "environment_variables": # join multiple tables not implemented yet
            continue
        if attrib == "created_time":
            assert stix2.utils.parse_into_datetime(process_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert process_dict[attrib] == read_obj[attrib]

