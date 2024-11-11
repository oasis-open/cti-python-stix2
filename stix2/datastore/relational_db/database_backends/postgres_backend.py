import os
from typing import Any

from sqlalchemy import (  # create_engine,; insert,
    ARRAY, TIMESTAMP, Boolean, CheckConstraint, Column, Float, ForeignKey,
    Integer, LargeBinary, Table, Text, UniqueConstraint,
)
from sqlalchemy.schema import CreateSchema

from stix2.base import (
    _DomainObject, _Extension, _MetaObject, _Observable, _RelationshipObject,
    _STIXBase,
)
from stix2.datastore.relational_db.utils import schema_for
from stix2.properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    ObjectReferenceProperty, Property, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)

from .database_backend_base import DatabaseBackend


class PostgresBackend(DatabaseBackend):
    default_database_connection_url = \
        f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:" + \
        f"{os.getenv('POSTGRES_PASSWORD', 'postgres')}@" + \
        f"{os.getenv('POSTGRES_IP_ADDRESS', '0.0.0.0')}:" + \
        f"{os.getenv('POSTGRES_PORT', '5432')}/postgres"

    def __init__(self, database_connection_url=default_database_connection_url, force_recreate=False, **kwargs: Any):
        super().__init__(database_connection_url, force_recreate=False, **kwargs)

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

    @staticmethod
    def determine_sql_type_for_binary_property():  # noqa: F811
        return Text

    @staticmethod
    def determine_sql_type_for_hex_property():  # noqa: F811
        return LargeBinary

    @staticmethod
    def determine_sql_type_for_timestamp_property():  # noqa: F811
        return TIMESTAMP(timezone=True)

    @staticmethod
    def array_allowed():
        return True
