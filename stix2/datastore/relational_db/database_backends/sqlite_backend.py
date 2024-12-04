import os
from typing import Any

from sqlalchemy import TIMESTAMP, LargeBinary, Text
from sqlalchemy.engine import Engine
from sqlalchemy import event

from stix2.base import (
    _DomainObject, _MetaObject, _Observable, _RelationshipObject,
)
from stix2.datastore.relational_db.utils import schema_for

from .database_backend_base import DatabaseBackend


class SQLiteBackend(DatabaseBackend):
    default_database_connection_url = f"sqlite:///stix-data-sink.db"

    def __init__(self, database_connection_url=default_database_connection_url, force_recreate=False, **kwargs: Any):
        super().__init__(database_connection_url, force_recreate=force_recreate, **kwargs)

        set_sqlite_pragma(self)

    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(self):
        self.database_connection.execute("PRAGMA foreign_keys=ON")

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
    def determine_sql_type_for_timestamp_property():  # noqa: F811
        return TIMESTAMP(timezone=True)

    # =========================================================================
    # Other methods

    @staticmethod
    def array_allowed():
        return False
