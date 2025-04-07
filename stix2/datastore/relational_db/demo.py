import datetime as dt

from database_backends.postgres_backend import PostgresBackend
from database_backends.sqlite_backend import SQLiteBackend
import sys
import json

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

# needed so the relational db code knows to create tables for this
from incident import incident, event, task, impact
from identity_contact_information import identity_contact_information
from observed_string import observed_string


def main():
    with open(sys.argv[1], "r") as f:
        bundle = stix2.parse(json.load(f), allow_custom=True)
    store = RelationalDBStore(
        PostgresBackend("postgresql://localhost/stix-data-sink", force_recreate=True),
        # SQLiteBackend("sqlite:///stix-data-sink.db", force_recreate=True),
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
