import postgres
from sqlalchemy import create_engine

from stix2.datastore.relational_db import DatabaseConnection


class PostgresDatabaseConnection(DatabaseConnection):

    def __init__(self, host, dbname, user):
        self.db = postgres.Postgres(url=f"host={host} dbname={dbname} user={user}")
        self.engine = create_engine(f"postgresql://{host}/{dbname}", max_identifier_length=200)

    def execute(self, sql_statement, bindings):
        self.db.run(sql_statement, parameters=bindings)

    def create_insert_statement(self, table_name, bindings, **kwargs):
        return f"INSERT INTO {table_name} ({','.join(bindings.keys())}) VALUES ({','.join(kwargs['values'])})"
