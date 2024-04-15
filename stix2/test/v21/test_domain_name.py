import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore

domain_name_dict = {    
    "type": "domain-name",
    "spec_version": "2.1",
    "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
    "value": "example.com",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True
)

def test_autonomous_system():
    store.sink.generate_stix_schema()
    domain_name_obj = stix2.parse(domain_name_dict)
    store.add(domain_name_obj)
    read_obj = json.loads(store.get(domain_name_obj['id']).serialize())

    for attrib in domain_name_dict.keys():
        assert domain_name_dict[attrib] == read_obj[attrib]