
from typing import Any
import os

from sqlalchemy import create_engine
from sqlalchemy_utils import create_database, database_exists, drop_database


class DatabaseBackend:
    def __init__(self, database_connection_url, force_recreate=False, **kwargs: Any):
        self.database_connection_url = database_connection_url
        self.database_exists = database_exists(database_connection_url)

        if force_recreate:
            if self.database_exists:
                drop_database(database_connection_url)
            create_database(database_connection_url)
            self.database_exists = database_exists(database_connection_url)

        self.database_connection = create_engine(database_connection_url)

    def _create_schemas(self):
        pass

    @staticmethod
    def _determine_schema_name(stix_object):
        return ""

    def _create_database(self):
        if self.database_exists:
            drop_database(self.database_connection.url)
        create_database(self.database_connection.url)
        self.database_exists = database_exists(self.database_connection.url)


