import json

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore

as_dict = {
    "type": "autonomous-system",
    "spec_version": "2.1",
    "id": "autonomous-system--f822c34b-98ae-597f-ade5-27dc241e8c74",
    "number": 15139,
    "name": "Slime Industries",
    "rir": "ARIN",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)


def test_autonomous_system():
    store.sink.generate_stix_schema()
    as_obj = stix2.parse(as_dict)
    store.add(as_obj)
    read_obj = json.loads(store.get(as_obj['id']).serialize())

    for attrib in as_dict.keys():
        assert as_dict[attrib] == read_obj[attrib]
