from typing import Any

from sqlalchemy import Column, Table, Text, event, insert, select, update
from sqlalchemy.schema import CreateTable

from .database_backend_base import DatabaseBackend


class SQLiteBackend(DatabaseBackend):
    default_database_connection_url = "sqlite:///stix-data-sink.db"

    temp_sequence_count = 0

    select_stmt_for_sequence = None

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
        return Text

    # =========================================================================
    # Other methods

    @staticmethod
    def array_allowed():
        return False

    def create_regex_constraint_clause(self, column_name, pattern):
        return f"{column_name} REGEXP {pattern}"

    def next_id(self, data_sink):
        # hack, which is not reliable, must look for a better solution
        # SQLiteBackend.temp_sequence_count += 1
        # return SQLiteBackend.temp_sequence_count
        # ALWAYS CALL WITHIN A TRANSACTION?????

        # better solution, but probably not best
        value = 0
        conn = self.database_connection.connect()
        for row in conn.execute(self.select_stmt_for_sequence):
            value = row[0]
        if value == 0:
            stmt = insert(data_sink.sequence).values({"id": 1, "value": 0})
            conn = self.database_connection.connect()
            conn.execute(stmt)
            conn.commit()
        value += 1
        conn.execute(update(data_sink.sequence).where(data_sink.sequence.c.id == 1).values({"value": value}))
        conn.commit()
        return value

    def create_sequence(self, metadata):
        # need id column, so update has something to work with (see above)
        t = Table(
            "my_general_seq",
            metadata,
            Column("id", SQLiteBackend.determine_sql_type_for_key_as_int()),
            Column("value", SQLiteBackend.determine_sql_type_for_integer_property()),
            schema=self.schema_for_core(),
        )
        CreateTable(t).compile(self.database_connection)
        self.select_stmt_for_sequence = select(t.c.value)
        return t
