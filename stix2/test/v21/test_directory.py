import json

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore

directory_dict = {
    "type": "directory",
    "spec_version": "2.1",
    "id": "directory--17c909b1-521d-545d-9094-1a08ddf46b05",
    "ctime": "2018-11-23T08:17:27.000Z",
    "mtime": "2018-11-23T08:17:27.000Z",
    "path": "C:\\Windows\\System32",
    "path_enc": "cGF0aF9lbmM",
    "contains_refs": [
        "directory--94c0a9b0-520d-545d-9094-1a08ddf46b05",
        "file--95c0a9b0-520d-545d-9094-1a08ddf46b05",
    ],
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)


def test_directory():
    store.sink.generate_stix_schema()
    directory_obj = stix2.parse(directory_dict)
    store.add(directory_obj)
    read_obj = json.loads(store.get(directory_obj['id']).serialize())

    for attrib in directory_dict.keys():
        if attrib == "contains_refs":  # TODO remove skip once we can pull from table join
            continue
        if attrib == "ctime" or attrib == "mtime":  # convert both into stix2 date format for consistency
            assert stix2.utils.parse_into_datetime(directory_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert directory_dict[attrib] == read_obj[attrib]
