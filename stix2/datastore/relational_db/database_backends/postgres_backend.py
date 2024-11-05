import os
from typing import Any
from sqlalchemy.schema import CreateSchema

from .database_backend_base import DatabaseBackend

from stix2.base import (
    _DomainObject, _MetaObject, _Observable, _RelationshipObject, _STIXBase,
)


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
    def _determine_schema_name(stix_object):
        if isinstance(stix_object, _DomainObject):
            return "sdo"
        elif isinstance(stix_object, _Observable):
            return "sco"
        elif isinstance(stix_object, _RelationshipObject):
            return "sro"
        elif isinstance(stix_object, _MetaObject):
            return "common"