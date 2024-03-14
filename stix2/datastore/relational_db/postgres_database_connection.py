import postgres

from stix2.datastore.relational_db import DatabaseConnection


class PostgresDatabaseConnection(DatabaseConnection):

    def __init__(self, host, dbname, user):
        self.db = postgres.Postgres(url=f"host={host} dbname={dbname} user={user}")

    def execute(self, sql_statement, bindings):
        self.db.run(sql_statement, parameters=bindings)
