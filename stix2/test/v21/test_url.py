import datetime as dt
import json

import pytest

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

url_dict = {
    "type": "url",
    "id": "url--a5477287-23ac-5971-a010-5c287877fa60",
    "value" : "https://example.com/research/index.html",
}

store = RelationalDBStore(
        "postgresql://postgres:admin@localhost/postgres",
        False,
        None,
        True,
)

def test_url():
    store.sink.generate_stix_schema()
    url_stix_object = stix2.parse(url_dict)
    store.add(url_stix_object)
    read_obj = json.loads(store.get(url_stix_object['id']).serialize())

    for attrib in url_dict.keys():
        assert url_dict[attrib] == read_obj[attrib]