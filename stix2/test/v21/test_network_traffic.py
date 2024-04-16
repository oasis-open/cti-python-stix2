import json

import pytest

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

# ipfix property results in a unconsumed value error with the store add

network_traffic_dict = {
    "type": "network-traffic",
    "spec_version": "2.1",
    "id": "network-traffic--631d7bb1-6bbc-53a6-a6d4-f3c2d35c2734",
    "src_ref": "ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53",
    "dst_ref": "ipv4-addr--03b708d9-7761-5523-ab75-5ea096294a68",
    "start": "2018-11-23T08:17:27.000Z",
    "end": "2018-11-23T08:18:27.000Z",
    "is_active": False,
    "src_port": 1000,
    "dst_port": 1000,
    "protocols": [
        "ipv4",
        "tcp",
    ],
    "src_byte_count": 147600,
    "dst_byte_count": 147600,
    "src_packets": 100,
    "dst_packets": 100,
    "src_payload_ref": "artifact--3857f78d-7d16-5092-99fe-ecff58408b02",
    "dst_payload_ref": "artifact--3857f78d-7d16-5092-99fe-ecff58408b03",
    "encapsulates_refs" : [
        "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a3",
        "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a4",
    ],
    "encapsulated_by_ref": "network-traffic--53e0bf48-2eee-5c03-8bde-ed7049d2c0a5",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)

def test_network_traffic():
    store.sink.generate_stix_schema()
    network_traffic_stix_object = stix2.parse(network_traffic_dict)
    store.add(network_traffic_stix_object)
    read_obj = store.get(network_traffic_stix_object['id'])

    for attrib in network_traffic_dict.keys():
        if attrib == "encapsulates_refs": # multiple table join not implemented
            continue
        if attrib == "start" or attrib == "end":
            assert stix2.utils.parse_into_datetime(network_traffic_dict[attrib]) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert network_traffic_dict[attrib] == read_obj[attrib]



