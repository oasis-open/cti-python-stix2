
from typing import Any
import os

from sqlalchemy import create_engine
from sqlalchemy_utils import create_database, database_exists, drop_database
from sqlalchemy import (  # create_engine,; insert,
    ARRAY, TIMESTAMP, Boolean, CheckConstraint, Column, Float, ForeignKey,
    Integer, LargeBinary, Table, Text, UniqueConstraint,
)

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

    def schema_for(stix_class):
        return ""

    @staticmethod
    def schema_for_core():
        return ""

    @staticmethod
    def determine_sql_type_for_property():  # noqa: F811
        pass

    @staticmethod
    def determine_sql_type_for_kill_chain_phase():  # noqa: F811
        return None

    @staticmethod
    def determine_sql_type_for_boolean_property():  # noqa: F811
        return Boolean

    @staticmethod
    def determine_sql_type_for_float_property():  # noqa: F811
        return Float

    @staticmethod
    def determine_sql_type_for_integer_property():  # noqa: F811
        return Integer

    @staticmethod
    def determine_sql_type_for_reference_property():  # noqa: F811
        return Text

    @staticmethod
    def determine_sql_type_for_string_property():  # noqa: F811
        return Text

    @staticmethod
    def determine_sql_type_for_key_as_int():  # noqa: F811
        return Integer

    @staticmethod
    def determine_sql_type_for_key_as_id():  # noqa: F811
        return Text

    @staticmethod
    def array_allowed():
        return False



