from typing import Any

from sqlalchemy import Boolean, Float, Integer, Text, create_engine
from sqlalchemy_utils import create_database, database_exists, drop_database

from stix2.base import (
    _DomainObject, _MetaObject, _Observable, _RelationshipObject,
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
    def determine_schema_name(stix_object):
        return ""

    @staticmethod
    def determine_stix_type(stix_object):
        if isinstance(stix_object, _DomainObject):
            return "sdo"
        elif isinstance(stix_object, _Observable):
            return "sco"
        elif isinstance(stix_object, _RelationshipObject):
            return "sro"
        elif isinstance(stix_object, _MetaObject):
            return "common"

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

    # you must implement the next 4 methods in the subclass

    @staticmethod
    def determine_sql_type_for_property():  # noqa: F811
        pass

    @staticmethod
    def determine_sql_type_for_binary_property():  # noqa: F811
        pass

    @staticmethod
    def determine_sql_type_for_hex_property():  # noqa: F811
        pass

    @staticmethod
    def determine_sql_type_for_timestamp_property():  # noqa: F811
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

    def generate_value(self, stix_type, value):
        sql_type = stix_type.determine_sql_type(self)
        if sql_type == self.determine_sql_type_for_string_property():
            return value
        elif sql_type == self.determine_sql_type_for_hex_property():
            return bytes.fromhex(value)
