import os
from typing import Any

from sqlalchemy import TIMESTAMP, LargeBinary, Text
from sqlalchemy.schema import CreateSchema

from stix2.base import (
    _DomainObject, _MetaObject, _Observable, _RelationshipObject,
)
from stix2.datastore.relational_db.utils import schema_for

from .database_backend_base import DatabaseBackend


class PostgresBackend(DatabaseBackend):
    default_database_connection_url = \
        f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:" + \
        f"{os.getenv('POSTGRES_PASSWORD', 'postgres')}@" + \
        f"{os.getenv('POSTGRES_IP_ADDRESS', '0.0.0.0')}:" + \
        f"{os.getenv('POSTGRES_PORT', '5432')}/postgres"

    def __init__(self, database_connection_url=default_database_connection_url, force_recreate=False, **kwargs: Any):
        super().__init__(database_connection_url, force_recreate=force_recreate, **kwargs)

    # =========================================================================
    # schema methods

    def _create_schemas(self):
        with self.database_connection.begin() as trans:
            trans.execute(CreateSchema("common", if_not_exists=True))
            trans.execute(CreateSchema("sdo", if_not_exists=True))
            trans.execute(CreateSchema("sco", if_not_exists=True))
            trans.execute(CreateSchema("sro", if_not_exists=True))

    @staticmethod
    def determine_schema_name(stix_object):
        if isinstance(stix_object, _DomainObject):
            return "sdo"
        elif isinstance(stix_object, _Observable):
            return "sco"
        elif isinstance(stix_object, _RelationshipObject):
            return "sro"
        elif isinstance(stix_object, _MetaObject):
            return "common"

    @staticmethod
    def schema_for(stix_class):
        return schema_for(stix_class)

    @staticmethod
    def schema_for_core():
        return "common"

    # =========================================================================
    # sql type methods (overrides)

    @staticmethod
    def determine_sql_type_for_binary_property():  # noqa: F811
        return PostgresBackend.determine_sql_type_for_string_property()

    @staticmethod
    def determine_sql_type_for_hex_property():  # noqa: F811
        # return LargeBinary
        return PostgresBackend.determine_sql_type_for_string_property()

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
        return True

    @staticmethod
    def create_regex_constraint_expression(column_name, pattern):
        return f"{column_name} ~ {pattern}"
