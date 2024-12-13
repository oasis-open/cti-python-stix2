import os
from typing import Any

from sqlalchemy import TIMESTAMP, LargeBinary, Text
from sqlalchemy import event

from stix2.base import (
    _DomainObject, _MetaObject, _Observable, _RelationshipObject,
)
from stix2.datastore.relational_db.utils import schema_for

from .database_backend_base import DatabaseBackend


class SQLiteBackend(DatabaseBackend):
    default_database_connection_url = f"sqlite:///stix-data-sink.db"

    temp_sequence_count = 0

    def __init__(self, database_connection_url=default_database_connection_url, force_recreate=False, **kwargs: Any):
        super().__init__(database_connection_url, force_recreate=force_recreate, **kwargs)

        @event.listens_for(self.database_connection, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            result = cursor.execute("PRAGMA foreign_keys")
            for row in result:
                print('PRAGMA foreign_keys:', row)
            cursor.close()

    # =========================================================================
    # sql type methods (overrides)

    @staticmethod
    def determine_sql_type_for_binary_property():  # noqa: F811
        return SQLiteBackend.determine_sql_type_for_string_property()

    @staticmethod
    def determine_sql_type_for_hex_property():  # noqa: F811
        # return LargeBinary
        return SQLiteBackend.determine_sql_type_for_string_property()

    @staticmethod
    def determine_sql_type_for_reference_property():  # noqa: F811
        return Text

    @staticmethod
    def determine_sql_type_for_string_property():  # noqa: F811
        return Text

    @staticmethod
    def determine_sql_type_for_key_as_id():  # noqa: F811
        return Text

    @staticmethod
    def determine_sql_type_for_timestamp_property():  # noqa: F811
        return TIMESTAMP(timezone=True)

    # =========================================================================
    # Other methods

    @staticmethod
    def array_allowed():
        return False

    def create_regex_constraint_expression(self, column_name, pattern):
        return None

    def create_regex_constraint_and_expression(self, clause1, clause2):
        return None

    @staticmethod
    def next_id(data_sink):
        SQLiteBackend.temp_sequence_count += 1
        return SQLiteBackend.temp_sequence_count
