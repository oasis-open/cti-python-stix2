import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

ipv4_dict = {
    "type": "ipv4-addr",
    "spec_version": "2.1",
    "id": "ipv4-addr--ff26c255-6336-5bc5-b98d-13d6226742dd",
    "value": "198.51.100.3",
}

ipv6_dict = {
    "type": "ipv6-addr",
    "spec_version": "2.1",
    "id": "ipv6-addr--1e61d36c-a26c-53b7-a80f-2a00161c96b1",
    "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)


def test_ipv4():
    store.sink.generate_stix_schema()
    ipv4_stix_object = stix2.parse(ipv4_dict)
    store.add(ipv4_stix_object)
    read_obj = store.get(ipv4_stix_object['id'])

    for attrib in ipv4_dict.keys():
        assert ipv4_dict[attrib] == read_obj[attrib]


def test_ipv6():
    store.sink.generate_stix_schema()
    ipv6_stix_object = stix2.parse(ipv6_dict)
    store.add(ipv6_stix_object)
    read_obj = store.get(ipv6_stix_object['id'])

    for attrib in ipv6_dict.keys():
        assert ipv6_dict[attrib] == read_obj[attrib]
