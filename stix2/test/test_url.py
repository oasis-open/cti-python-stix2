import datetime as dt
import pytest
import stix2
from stix2.datastore.realtional_db.relational_db import RelationalDBStore
import stix2.properties

url_stix_object = stix2.URL(
    type = "url",
    id = "url--c1477287-23ac-5971-a010-5c287877fa60",
    value = "https://example.com/research/index.html"
)

store = RelationalDBStore(
        "postgresql://localhost/stix-data-sink",
        False,
        None,
        True,
        stix2.URL,
)

def test_url():
    store.sink.generate_stix_schema()
    store.add(url_stix_object)
    read_obj = store.get(url_stix_object)
    assert read_obj == url_stix_object
