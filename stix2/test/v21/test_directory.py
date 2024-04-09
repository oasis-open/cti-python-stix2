import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore

# Ctime and mtime will return as stix2 objects from the DB get function so comparison doesn't work for those
directory_dict = {
    "type": "directory",
    "spec_version": "2.1",
    "id": "directory--67c0a9b0-520d-545d-9094-1a08ddf46b05",
    "path": "C:\\Windows\\System32",
    "path_enc": "cGF0aF9lbmM",
    "contains_refs": [
        "directory--94c0a9b0-520d-545d-9094-1a08ddf46b05",
        "file--95c0a9b0-520d-545d-9094-1a08ddf46b05"
    ]
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True
)

def test_directory():
    store.sink.generate_stix_schema()
    directory_obj = stix2.parse(directory_dict)
    store.add(directory_obj)
    read_obj = json.loads(store.get(directory_obj['id']).serialize())

    for attrib in directory_dict.keys():
        if attrib == "contains_refs": # TODO remove skip once we can pull from table join
            continue
        assert directory_dict[attrib] == read_obj[attrib]