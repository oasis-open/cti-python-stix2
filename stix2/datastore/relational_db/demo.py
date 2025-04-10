import json
import sys

from database_backends.postgres_backend import PostgresBackend  # noqa F401
from database_backends.sqlite_backend import SQLiteBackend  # noqa F401
# needed so the relational db code knows to create tables for this
from identity_contact_information import \
    identity_contact_information  # noqa F401
from incident import event, impact, incident, task  # noqa F401
from observed_string import observed_string  # noqa F401

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties


def main():
    with open(sys.argv[1], "r") as f:
        bundle = stix2.parse(json.load(f), allow_custom=True)
    store = RelationalDBStore(
        PostgresBackend("postgresql://localhost/stix-data-sink", force_recreate=True),
        True,
        None,
        True,
        print_sql=True,
    )

    if store.sink.db_backend.database_exists:
        for obj in bundle.objects:
            store.add(obj)
    else:
        print("database does not exist")


if __name__ == '__main__':
    main()
