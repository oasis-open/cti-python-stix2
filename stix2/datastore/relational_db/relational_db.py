from sqlalchemy import MetaData, create_engine, delete, select
from sqlalchemy.schema import CreateSchema, CreateTable, Sequence
from sqlalchemy_utils import create_database, database_exists, drop_database

from stix2.base import (
    _DomainObject, _MetaObject, _Observable, _RelationshipObject, _STIXBase,
)
from stix2.datastore import DataSink, DataSource, DataStoreMixin
from stix2.datastore.relational_db.input_creation import (
    generate_insert_for_object,
)
from stix2.datastore.relational_db.query import read_object
from stix2.datastore.relational_db.table_creation import create_table_objects
from stix2.datastore.relational_db.utils import (
    canonicalize_table_name, schema_for, table_name_for,
)
from stix2.parsing import parse
import stix2.registry
import stix2.utils


def _add(store, stix_data, allow_custom=True, version="2.1"):
    """Add STIX objects to MemoryStore/Sink.

    Adds STIX objects to an in-memory dictionary for fast lookup.
    Recursive function, breaks down STIX Bundles and lists.

    Args:
        store: A MemoryStore, MemorySink or MemorySource object.
        stix_data (list OR dict OR STIX object): STIX objects to be added
        allow_custom (bool): Whether to allow custom properties as well unknown
            custom objects. Note that unknown custom objects cannot be parsed
            into STIX objects, and will be returned as is. Default: False.
        version (str): Which STIX2 version to lock the parser to. (e.g. "2.0",
            "2.1"). If None, the library makes the best effort to figure
            out the spec representation of the object.

    """
    if isinstance(stix_data, list):
        # STIX objects are in a list- recurse on each object
        for stix_obj in stix_data:
            _add(store, stix_obj, allow_custom, version)

    elif stix_data["type"] == "bundle":
        # adding a json bundle - so just grab STIX objects
        for stix_obj in stix_data.get("objects", []):
            _add(store, stix_obj, allow_custom, version)

    else:
        # Adding a single non-bundle object
        if isinstance(stix_data, _STIXBase):
            stix_obj = stix_data
        else:
            stix_obj = parse(stix_data, allow_custom, version)

        store.insert_object(stix_obj)


class RelationalDBStore(DataStoreMixin):
    def __init__(
        self, database_connection_url, allow_custom=True, version=None,
        instantiate_database=True, force_recreate=False, *stix_object_classes,
    ):
        """
        Initialize this store.

        Args:
            database_connection_url: An SQLAlchemy URL referring to a database
            allow_custom: Whether custom content is allowed when processing
                dict content to be added to the store
            version: TODO: unused so far
            instantiate_database: Whether tables, etc should be created in the
                database (only necessary the first time)
            force_recreate: Drops old database and creates new one (useful if
                the schema has changed and the tables need to be updated)
            *stix_object_classes: STIX object classes to map into table schemas
                (and ultimately database tables, if instantiation is desired).
                This can be used to limit which table schemas are created, if
                one is only working with a subset of STIX types.  If not given,
                auto-detect all classes and create table schemas for all of
                them.
        """

        # The typical usage of SQLAlchemy's create_engine() function is once per
        # particular database connection url and held globally for the lifetime of
        # a single application process. Among the various databases/dialects supported
        # by SQLAlchemy, this function call appears to work well for the following
        # three variants using a single url argument as below:
        #
        # PostgreSQL:
        #   url = f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@127.0.0.1:5432/rdb"
        # SQLite:
        #   url = f"sqlite:///sqlite_rdb.db"
        # MariaDB:
        #   url = f"mariadb+pymysql://{os.getenv('MARIADB_USER')}:{os.getenv('MARIADB_PASSWORD')}@127.0.0.1:3306/rdb"
        # MS-SQL:
        #   url = f"mssql+pymssql://{os.getenv('MSSQL_USERNAME'):{os.getenv('MSSQL_PASSWORD')}@127.0.0.1:1433/tempdb")
        database_connection = create_engine(database_connection_url)

        # For MySQL, which happens to use the same default port 3306 as for MariaDB,
        # we can use a different port so multiple SQL service instances can be running
        # on the same machine. Below is a workaround for connecting to the MySQL server
        # at port 3307 using the connect_args dictionary parameter:
        #
        # MySQL:
        #    url = f"mysql+pymysql://os.getenv('MYSQL_USER'):os.getenv('MYSQL_PASSWORD')@127.0.0.1/rdb"
        #    connect_args = dict(unix_socket="/var/mysql/mysql.sock", port=3307)
        #
        # database_connection = create_engine(database_connection_url,
        #                                    connect_args=dict(unix_socket="/var/mysql/mysql.sock", port=3307))


        self.metadata = MetaData()
        create_table_objects(
             self.metadata, stix_object_classes,
        )

        super().__init__(
            source=RelationalDBSource(
                database_connection,
                metadata=self.metadata,
            ),
            sink=RelationalDBSink(
                database_connection,
                allow_custom=allow_custom,
                version=version,
                instantiate_database=instantiate_database,
                force_recreate=force_recreate,
                metadata=self.metadata,
            ),
        )


class RelationalDBSink(DataSink):
    def __init__(
        self, database_connection_or_url, allow_custom=True, version=None,
        instantiate_database=True, force_recreate=False, *stix_object_classes, metadata=None,
    ):
        """
        Initialize this sink.  Only one of stix_object_classes and metadata
        should be given: if the latter is given, assume table schemas are
        already created.

        Args:
            database_connection_or_url: An SQLAlchemy engine object, or URL
            allow_custom: Whether custom content is allowed when processing
                dict content to be added to the sink
            version: TODO: unused so far
            instantiate_database: Whether the database, tables, etc should be
                created (only necessary the first time)
            force_recreate: Drops old database and creates new one (useful if
                the schema has changed and the tables need to be updated)
            *stix_object_classes: STIX object classes to map into table schemas
                (and ultimately database tables, if instantiation is desired).
                This can be used to limit which table schemas are created, if
                one is only working with a subset of STIX types.  If not given,
                auto-detect all classes and create table schemas for all of
                them.  If metadata is given, the table data therein is used and
                this argument is ignored.
            metadata: SQLAlchemy MetaData object containing table information.
                Only applicable when this class is instantiated via a store,
                so that table information can be constructed once and shared
                between source and sink.
        """
        super(RelationalDBSink, self).__init__()

        if isinstance(database_connection_or_url, str):
            self.database_connection = create_engine(database_connection_or_url)
        else:
            self.database_connection = database_connection_or_url

        self.database_exists = database_exists(self.database_connection.url)
        if force_recreate:
            self._create_database()

        if metadata:
            self.metadata = metadata
        else:
            self.metadata = MetaData()
            create_table_objects(
                self.metadata, stix_object_classes,
            )
        self.sequence = Sequence("my_general_seq", metadata=self.metadata, start=1, schema="common")

        self.allow_custom = allow_custom

        self.tables_dictionary = dict()
        for t in self.metadata.tables.values():
            self.tables_dictionary[canonicalize_table_name(t.name, t.schema)] = t

        if instantiate_database:
            if not self.database_exists:
                self._create_database()
            self._create_schemas()
            self._instantiate_database()

    def _create_schemas(self):
        with self.database_connection.begin() as trans:
            trans.execute(CreateSchema("common", if_not_exists=True))
            trans.execute(CreateSchema("sdo", if_not_exists=True))
            trans.execute(CreateSchema("sco", if_not_exists=True))
            trans.execute(CreateSchema("sro", if_not_exists=True))

    def _instantiate_database(self):
        self.metadata.create_all(self.database_connection)

    def _create_database(self):
        if self.database_exists:
            drop_database(self.database_connection.url)
        create_database(self.database_connection.url)
        self.database_exists = database_exists(self.database_connection.url)

    def generate_stix_schema(self):
        for t in self.metadata.tables.values():
            print(CreateTable(t).compile(self.database_connection))

    def add(self, stix_data, version=None):
        _add(self, stix_data)
    add.__doc__ = _add.__doc__

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

    def insert_object(self, stix_object):
        schema_name = self._determine_schema_name(stix_object)
        with self.database_connection.begin() as trans:
            statements = generate_insert_for_object(self, stix_object, schema_name)
            for stmt in statements:
                print("executing: ", stmt)
                trans.execute(stmt)
            trans.commit()

    def clear_tables(self):
        tables = list(reversed(self.metadata.sorted_tables))
        with self.database_connection.begin() as trans:
            for table in tables:
                delete_stmt = delete(table)
                print(f'delete_stmt: {delete_stmt}')
                trans.execute(delete_stmt)


class RelationalDBSource(DataSource):
    def __init__(
        self, database_connection_or_url, *stix_object_classes, metadata=None,
    ):
        """
        Initialize this source.  Only one of stix_object_classes and metadata
        should be given: if the latter is given, assume table schemas are
        already created.  Instances of this class do not create the actual
        database tables; see the source/sink for that.

        Args:
            database_connection_or_url: An SQLAlchemy engine object, or URL
            *stix_object_classes: STIX object classes to map into table schemas.
                This can be used to limit which schemas are created, if one is
                only working with a subset of STIX types.  If not given,
                auto-detect all classes and create schemas for all of them.
                If metadata is given, the table data therein is used and this
                argument is ignored.
            metadata: SQLAlchemy MetaData object containing table information.
                Only applicable when this class is instantiated via a store,
                so that table information can be constructed once and shared
                between source and sink.
        """
        super().__init__()

        if isinstance(database_connection_or_url, str):
            self.database_connection = create_engine(database_connection_or_url)
        else:
            self.database_connection = database_connection_or_url

        if metadata:
            self.metadata = metadata
        else:
            self.metadata = MetaData()
            create_table_objects(
                self.metadata, stix_object_classes,
            )

    def get(self, stix_id, version=None, _composite_filters=None):
        with self.database_connection.connect() as conn:
            stix_obj = read_object(
                stix_id,
                self.metadata,
                conn,
            )

        return stix_obj

    def all_versions(self, stix_id, version=None, _composite_filters=None):
        pass

    def query(self, query=None):
        pass
