import datetime as dt
import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

url_dict = {
    "type": "url",
    "id": "url--c1477287-23ac-5971-a010-5c287877fa60",
    "value" : "https://example.com/research/index.html"
}

store = RelationalDBStore(
        "postgresql://localhost/stix-data-sink",
        False,
        None,
        True
)

def test_url():
    store.sink.generate_stix_schema()
    url_stix_object = stix2.parse(url_dict)
    store.add(url_stix_object)
    read_obj = json.loads(store.get(url_stix_object).serialize())

    for attrib in url_dict.keys():
        assert url_dict[attrib] == read_obj[attrib]