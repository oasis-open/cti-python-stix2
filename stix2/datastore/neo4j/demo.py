
import sys
import json

import stix2
from stix2.datastore.neo4j.neo4j import Neo4jStore
import stix2.properties

# needed so the relational db code knows to create tables for this
from incident import incident, event, task, impact
from identity_contact_information import identity_contact_information
from observed_string import observed_string


def main():
    with open(sys.argv[1], "r") as f:
        bundle = stix2.parse(json.load(f), allow_custom=True)
    store = Neo4jStore(clear_database=True)

    for obj in bundle.objects:
        store.add(obj)


if __name__ == '__main__':
    main()
