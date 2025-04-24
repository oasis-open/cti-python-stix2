
import json
import sys

from identity_contact_information import \
    identity_contact_information  # noqa F401
# needed so the relational db code knows to create tables for this
from incident import event, impact, incident, task  # noqa F401
from observed_string import observed_string  # noqa F401

import stix2
from stix2.datastore.neo4j.neo4j import Neo4jStore
import stix2.properties


def main():
    with open(sys.argv[1], "r") as f:
        bundle = stix2.parse(json.load(f), allow_custom=True)
    store = Neo4jStore(clear_database=True)

    for obj in bundle.objects:
        store.add(obj)


if __name__ == '__main__':
    main()
