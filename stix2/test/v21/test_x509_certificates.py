import json

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

basic_x509_certificate_dict = {
    "type": "x509-certificate",
    "spec_version": "2.1",
    "id": "x509-certificate--463d7b2a-8516-5a50-a3d7-6f801465d5de",
    "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification  \
    Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
    "validity_not_before": "2016-03-12T12:00:00Z",
    "validity_not_after": "2016-08-21T12:00:00Z",
    "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, \
    CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
    "serial_number": "36:f7:d4:32:f4:ab:70:ea:d3:ce:98:6e:ea:99:93:49:32:0a:b7:06",
}

extensions_x509_certificate_dict = {
    "type": "x509-certificate",
    "spec_version": "2.1",
    "id": "x509-certificate--b595eaf0-0b28-5dad-9e8e-0fab9c1facc9",
    "issuer": "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification \
    Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
    "validity_not_before": "2016-03-12T12:00:00Z",
    "validity_not_after": "2016-08-21T12:00:00Z",
    "subject": "C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, \
    CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
    "serial_number": "02:08:87:83:f2:13:58:1f:79:52:1e:66:90:0a:02:24:c9:6b:c7:dc",
    "x509_v3_extensions": {
        "basic_constraints": "critical,CA:TRUE, pathlen:0",
        "name_constraints": "permitted;IP:192.168.0.0/255.255.0.0",
        "policy_constraints": "requireExplicitPolicy:3",
        "key_usage": "critical, keyCertSign",
        "extended_key_usage": "critical,codeSigning,1.2.3.4",
        "subject_key_identifier": "hash",
        "authority_key_identifier": "keyid,issuer",
        "subject_alternative_name": "email:my@other.address,RID:1.2.3.4",
        "issuer_alternative_name": "issuer:copy",
        "crl_distribution_points": "URI:http://myhost.com/myca.crl",
        "inhibit_any_policy": "2",
        "private_key_usage_period_not_before": "2016-03-12T12:00:00Z",
        "private_key_usage_period_not_after": "2018-03-12T12:00:00Z",
        "certificate_policies": "1.2.4.5, 1.1.3.4",
    },
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)


def test_basic_x509_certificate():
    store.sink.generate_stix_schema()
    basic_x509_certificate_stix_object = stix2.parse(basic_x509_certificate_dict)
    store.add(basic_x509_certificate_stix_object)
    read_obj = json.loads(store.get(basic_x509_certificate_stix_object['id']).serialize())

    for attrib in basic_x509_certificate_dict.keys():
        if attrib == "validity_not_before" or attrib == "validity_not_after":
            assert stix2.utils.parse_into_datetime(
                basic_x509_certificate_dict[attrib],
            ) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert basic_x509_certificate_dict[attrib] == read_obj[attrib]


def test_x509_certificate_with_extensions():
    store.sink.generate_stix_schema()
    extensions_x509_certificate_stix_object = stix2.parse(extensions_x509_certificate_dict)
    store.add(extensions_x509_certificate_stix_object)
    read_obj = json.loads(store.get(extensions_x509_certificate_stix_object['id']).serialize())

    for attrib in extensions_x509_certificate_dict.keys():
        if attrib == "x509_v3_extensions":  # skipping multi-table join
            continue
        if attrib == "validity_not_before" or attrib == "validity_not_after":
            assert stix2.utils.parse_into_datetime(
                extensions_x509_certificate_dict[attrib],
            ) == stix2.utils.parse_into_datetime(read_obj[attrib])
            continue
        assert extensions_x509_certificate_dict[attrib] == read_obj[attrib]
