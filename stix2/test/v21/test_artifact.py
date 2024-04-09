import pytest
import stix2
import json

from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

basic_artifact_dict = {
    "type": "artifact",
    "spec_version": "2.1",
    "id": "artifact--cb17bcf8-9846-5ab4-8662-75c1bf6e63ee",
    "mime_type": "image/jpeg",
    "payload_bin": "VGhpcyBpcyBhIHBsYWNlaG9sZGVyIGZvciBhIHNhZmUgbWFsd2FyZSBiaW5hcnkh"
}

encrypted_artifact_dict = {
    "type": "artifact",
    "spec_version": "2.1",
    "id": "artifact--3157f78d-7d16-5092-99fe-ecff58408b02",
    "mime_type": "application/zip",
    "payload_bin": "VGhpcyBpcyBhIHBsYWNlaG9sZGVyIGZvciBhbiB1bnNhZmUgbWFsd2FyZSBiaW5hcnkh",
    "hashes": {
        "MD5": "6b885a1e1d42c0ca66e5f8a17e5a5d29",
        "SHA-256": "3eea3c4819e9d387ff6809f13dde5426b9466285b7d923016b2842a13eb2888b"
    },
    "encryption_algorithm": "mime-type-indicated",
    "decryption_key": "My voice is my passport"
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True
)

def test_basic_artifact():
    store.sink.generate_stix_schema()
    artifact_stix_object = stix2.parse(basic_artifact_dict)
    store.add(artifact_stix_object)
    read_obj = json.loads(store.get(artifact_stix_object['id']).serialize())

    for attrib in basic_artifact_dict.keys():
        assert basic_artifact_dict[attrib] == read_obj[attrib]

def test_encrypted_artifact():
    store.sink.generate_stix_schema()
    artifact_stix_object = stix2.parse(encrypted_artifact_dict)
    store.add(artifact_stix_object)
    read_obj = json.loads(store.get(artifact_stix_object['id']).serialize())

    for attrib in encrypted_artifact_dict.keys():
        assert encrypted_artifact_dict[attrib] == read_obj[attrib]


def main():
    test_encrypted_artifact()

main()