import json

import pytest

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

# errors when adding magic_number_hex to store, so ignoring for now

file_dict = {
    "type": "file",
    "spec_version": "2.1",
    "id": "file--66156fad-2a7d-5237-bbb4-ba1912887cfe",
    "hashes": {
        "SHA-256": "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a",
    },
    "parent_directory_ref": "directory--93c0a9b0-520d-545d-9094-1a08ddf46b05",
    "name": "qwerty.dll",
    "size": 25536,
    "name_enc": "windows-1252",
    "mime_type": "application/msword",
    "ctime": "2018-11-23T08:17:27.000Z",
    "mtime": "2018-11-23T08:17:27.000Z",
    "atime": "2018-11-23T08:17:27.000Z",
    "contains_refs": [
        "file--77156fad-2a0d-5237-bba4-ba1912887cfe",
    ],
    "content_ref": "artifact--cb37bcf8-9846-5ab4-8662-75c1bf6e63ee",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)

def test_file():
    store.sink.generate_stix_schema()
    file_stix_object = stix2.parse(file_dict)
    store.add(file_stix_object)
    read_obj = store.get(file_stix_object['id'])
    read_obj = json.loads(store.get(file_stix_object['id']).serialize())

    for attrib in file_dict.keys():
        if attrib == "contains_refs" or attrib == "hashes": # join multiple tables not implemented yet
            continue
        if attrib == "ctime" or attrib == "mtime" or attrib == "atime":
            assert stix2.utils.parse_into_datetime(file_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert file_dict[attrib] == read_obj[attrib]

