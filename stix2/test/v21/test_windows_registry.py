import datetime as dt
import json

import pytest

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

windows_registry_dict = {
    "type": "windows-registry-key",
    "spec_version": "2.1",
    "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
    "key": "hkey_local_machine\\system\\bar\\foo",
    "values": [
        {
        "name": "Foo",
        "data": "qwerty",
        "data_type": "REG_SZ",
        },
        {
        "name": "Bar",
        "data": "42",
        "data_type": "REG_DWORD",
        },
    ],
    "modified_time": "2018-01-20T12:31:12Z",
    "creator_user_ref": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
    "number_of_subkeys": 2,
}

store = RelationalDBStore(
        "postgresql://postgres:admin@localhost/postgres",
        False,
        None,
        True,
)

def test_windows_registry():
    store.sink.generate_stix_schema()
    windows_registry_stix_object = stix2.parse(windows_registry_dict)
    store.add(windows_registry_stix_object)
    read_obj = json.loads(store.get(windows_registry_stix_object['id']).serialize())

    for attrib in windows_registry_dict.keys():
        if attrib == "values": # skip multiple table join
            continue
        if attrib == "modified_time":
            assert stix2.utils.parse_into_datetime(windows_registry_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert windows_registry_dict[attrib] == read_obj[attrib]

